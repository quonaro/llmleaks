#!/usr/bin/env python3
"""
llmleaks — unified CLI for finding leaked AI API keys.

Commands:
  scan       Search sources for leaked keys, verify, store (replaces all
             *_scan.py scripts — old scripts are profiles now)
  verify     Verify keys from a file (txt / json / engine result file)
  monitor    Real-time GitHub PushEvent monitor
  stats      Show findings DB statistics
  report     Generate markdown research report from DB
  export     Export findings (hash + preview only, never raw keys)
  providers  List supported providers and detection patterns
  sources    List available scan sources

All options can live in config.yaml (auto-loaded next to cli.py or via
--config). Precedence: CLI flag > config.yaml > --profile > defaults.
"""

import asyncio
import os
import sys
import time
from types import SimpleNamespace

import click

from scanner_engine import ScannerEngine, BUILTIN_QUERIES, DEFAULT_USD_CNY_RATE
from detectors import PROVIDERS, provider_table, AMBIGUOUS_ORDER, GENERIC_TOKEN
from store import Store

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ALL_SOURCES = ["github", "gist", "issues", "commits", "gitlab", "gitee",
               "huggingface", "pypi", "npm", "stackoverflow", "docker",
               "wayback", "commoncrawl"]
ALL_PROVIDERS = list(PROVIDERS)

# Old scan scripts → profiles
PROFILES = {
    # was quick_batch.py
    "quick":    dict(duration=900,   scan_pages=3,  search_delay=4.0, concurrency=15),
    # was full_scan.py / six_hour_scan.py
    "standard": dict(duration=3600,  scan_pages=3,  search_delay=5.0, concurrency=15),
    # was max_scan.py
    "max":      dict(duration=7200,  scan_pages=5,  search_delay=4.0, concurrency=25),
    # was deep_scan.py
    "deep":     dict(duration=10800, scan_pages=3,  search_delay=6.0, concurrency=12),
    # was expanded_scan.py (multi-source phase)
    "expanded": dict(duration=14400, scan_pages=5,  search_delay=3.5, concurrency=20,
                     sources="github,gist,issues,commits,huggingface,pypi,npm"),
    # was ultimate_scan.py (10 pages/query + multi-source)
    "ultimate": dict(duration=0,     scan_pages=10, search_delay=3.0, concurrency=20,
                     sources="github,gist,issues,commits,gitlab,gitee,huggingface"),
    # was marathon_scan.py — cyclic until interrupted
    "marathon": dict(duration=3600,  scan_pages=3,  search_delay=5.0,
                     concurrency=15, loop=True),
}


def log_func(msg, level="info"):
    if level == "warning":
        click.echo(f"[!] {msg}", err=True)
    elif level == "error":
        click.echo(f"[ERROR] {msg}", err=True)
    else:
        click.echo(msg)


def _split_csv(s) -> list:
    if isinstance(s, (list, tuple)):
        return [str(x).strip() for x in s if str(x).strip()]
    return [x.strip() for x in str(s or "").split(",") if x.strip()]


# ──────────────────────────── config.yaml ────────────────────────────

# attr → ("section.key", join_list_to_csv?)
CFG_MAP = {
    "profile":          ("scan.profile", False),
    "sources":          ("scan.sources", True),
    "providers":        ("scan.providers", True),
    "queries_file":     ("scan.queries_file", False),
    "skip_builtin":     ("scan.skip_builtin", False),
    "query":            ("scan.extra_queries", False),
    "pages":            ("scan.pages", False),
    "workers":          ("scan.workers", False),
    "duration":         ("scan.duration", False),
    "max_keys":         ("scan.max_keys", False),
    "loop":             ("scan.loop", False),
    "min_balance":      ("scan.min_balance", False),
    "min_key_length":   ("scan.min_key_length", False),
    "max_key_length":   ("scan.max_key_length", False),
    "exclude_repo":     ("scan.exclude_repos", False),
    "dry_run":          ("scan.dry_run", False),
    "concurrency":      ("network.concurrency", False),
    "search_delay":     ("network.search_delay", False),
    "timeout":          ("network.timeout", False),
    "github_token":     ("network.github_token", False),
    "github_tokens":    ("network.github_tokens", True),
    "github_tokens_file": ("network.github_tokens_file", False),
    "gitlab_token":     ("network.gitlab_token", False),
    "gitee_token":      ("network.gitee_token", False),
    "proxy":            ("network.proxies", False),
    "proxy_file":       ("network.proxy_file", False),
    "vless":            ("network.vless", False),
    "vless_file":       ("network.vless_file", False),
    "vless_base_port":  ("network.vless_base_port", False),
    "user_agent":       ("network.user_agent", False),
    "with_balance":     ("verification.with_balance", False),
    "store_raw":        ("verification.store_raw", False),
    "poll_interval":    ("monitor.poll_interval", False),
    "verify":           ("monitor.verify", False),
    "output_dir":       ("output.dir", False),
    "db":               ("output.db", False),
    "no_db":            ("output.no_db", False),
    "usd_cny_rate":     ("output.usd_cny_rate", False),
    "quiet":            ("output.quiet", False),
}


def load_config(path: str | None) -> dict:
    """Explicit path → must exist; no path → auto-detect ./config.yaml
    next to cli.py."""
    if not path:
        auto = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "config.yaml")
        path = auto if os.path.exists(auto) else None
    if not path:
        return {}
    if not os.path.exists(path):
        raise click.ClickException(f"config not found: {path}")
    import yaml
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg if isinstance(cfg, dict) else {}


def _apply_config(ns, cfg: dict):
    """Fill params that are still unset (None / empty tuple) from config."""
    for attr, (path, join_csv) in CFG_MAP.items():
        cur = getattr(ns, attr, None)
        if cur is not None and cur != () and cur != "":
            continue
        sec, key = path.split(".", 1)
        val = (cfg.get(sec) or {}).get(key)
        if val is None:
            continue
        if join_csv and isinstance(val, (list, tuple)):
            val = ",".join(str(x) for x in val)
        setattr(ns, attr, val)


def _params(ctx, kw) -> SimpleNamespace:
    """click kwargs → namespace with config applied."""
    ns = SimpleNamespace(**kw)
    _apply_config(ns, ctx.obj["cfg"])
    return ns


# ──────────────────────────── shared helpers ────────────────────────────

_VLESS_POOL = None  # keeps the sing-box subprocess alive for the process


def _load_proxies(ns) -> list:
    global _VLESS_POOL
    proxies = [p for p in (getattr(ns, "proxy", None) or []) if p]
    pf = getattr(ns, "proxy_file", None)
    if pf and os.path.exists(pf):
        with open(pf, encoding="utf-8") as f:
            proxies += [ln.strip() for ln in f
                        if ln.strip() and not ln.startswith("#")]

    # VLESS links → local sing-box inbounds → http://127.0.0.1:* proxies
    links = [v for v in (getattr(ns, "vless", None) or []) if v]
    vf = getattr(ns, "vless_file", None)
    if vf and os.path.exists(vf):
        with open(vf, encoding="utf-8") as f:
            links += [ln.strip() for ln in f
                      if ln.strip() and not ln.startswith("#")]
    if links:
        from vless_pool import VlessPool
        base_port = getattr(ns, "vless_base_port", None) or 20800
        _VLESS_POOL = VlessPool(links, base_port=base_port)
        started = _VLESS_POOL.start()
        click.echo(f"vless: sing-box up, {len(started)} local proxies "
                   f"@{base_port}-{base_port + len(started) - 1}")
        proxies += started
    return proxies


def _load_tokens(ns) -> list:
    tokens = _split_csv(getattr(ns, "github_tokens", None))
    tf = getattr(ns, "github_tokens_file", None)
    if tf and os.path.exists(tf):
        with open(tf, encoding="utf-8") as f:
            tokens += [ln.strip() for ln in f
                       if ln.strip() and not ln.startswith("#")]
    if getattr(ns, "github_token", None):
        tokens.append(ns.github_token)
    return tokens


def build_engine(ns) -> ScannerEngine:
    providers = _split_csv(getattr(ns, "providers", None)) or ALL_PROVIDERS
    output_dir = getattr(ns, "output_dir", None) or "./results"
    db_path = getattr(ns, "db", None) or os.path.join(output_dir,
                                                      "findings.db")
    return ScannerEngine(
        concurrency=getattr(ns, "concurrency", None) or 15,
        timeout=getattr(ns, "timeout", None) or 15,
        search_delay=getattr(ns, "search_delay", None)
        or ScannerEngine.suggested_search_delay(),
        min_key_length=getattr(ns, "min_key_length", None) or 20,
        max_key_length=getattr(ns, "max_key_length", None) or 120,
        output_dir=output_dir,
        providers=providers,
        usd_cny_rate=getattr(ns, "usd_cny_rate", None)
        or DEFAULT_USD_CNY_RATE,
        exclude_repos=list(getattr(ns, "exclude_repo", None) or []),
        max_duration=getattr(ns, "duration", None) or 0,
        max_valid_keys=getattr(ns, "max_keys", None) or 0,
        scan_pages=getattr(ns, "pages", None) or 3,
        search_workers=getattr(ns, "workers", None) or 0,
        github_tokens=_load_tokens(ns),
        proxies=_load_proxies(ns),
        check_balance=bool(getattr(ns, "with_balance", None)),
        db_path=None if getattr(ns, "no_db", None) else db_path,
        store_raw_keys=bool(getattr(ns, "store_raw", None)),
        user_agent=getattr(ns, "user_agent", None),
        log_callback=log_func if not getattr(ns, "quiet", None)
        else (lambda m, l="info": None),
    )


def _resolve_queries(ns) -> list:
    queries = []
    if not getattr(ns, "skip_builtin", None):
        queries.extend(BUILTIN_QUERIES)
    for q in getattr(ns, "query", None) or []:
        queries.append(q)
    qf = getattr(ns, "queries_file", None)
    if qf and os.path.exists(qf):
        queries.extend(ScannerEngine.load_queries_file(qf))
    return queries or BUILTIN_QUERIES


# ──────────────────────────── command logic ────────────────────────────

def cmd_scan(ns):
    ns.profile = ns.profile or "standard"
    prof = PROFILES.get(ns.profile, PROFILES["standard"])
    # profile supplies defaults; config file and explicit flags win
    for k, v in prof.items():
        if k == "sources":
            if not ns.sources:
                ns.sources = v
        elif k == "loop":
            if ns.loop is None:
                ns.loop = v
        else:
            attr = {"duration": "duration", "scan_pages": "pages",
                    "search_delay": "search_delay",
                    "concurrency": "concurrency"}[k]
            if getattr(ns, attr) is None:
                setattr(ns, attr, v)

    queries = _resolve_queries(ns)
    sources = _split_csv(ns.sources) or ["github"]
    if sources == ["all"]:
        sources = ALL_SOURCES

    engine = build_engine(ns)

    if ns.dry_run:
        click.echo("--- dry run: search only, no verification ---")
        all_keys = engine.scan_github(queries)
        click.echo(f"\nfound {len(all_keys)} candidate keys (unverified)")
        if all_keys:
            engine.save_progress(all_keys)
            click.echo(f"progress saved — verify later with: "
                       f"cli.py verify {engine.output_dir}/.akh_progress.json")
        return

    # workers: explicit flag/config, else #proxies, else #tokens, else seq
    if ns.workers is None:
        n = max(len(engine._proxy_pool._proxies), len(engine._gh_tokens), 1)
        engine.search_workers = min(n, 8)
    else:
        engine.search_workers = ns.workers

    authed = ScannerEngine.check_gh_auth()
    click.echo(f"llmleaks scan | profile={ns.profile} sources={sources}")
    click.echo(f"queries={len(queries)} providers={engine.providers}")
    click.echo(f"concurrency={engine.concurrency} workers={engine.search_workers} "
               f"pages={engine.scan_pages} delay={engine.search_delay}s "
               f"duration={engine.max_duration or '∞'}s")
    click.echo(f"github_auth={'yes' if authed else 'NO (10 req/min!)'} "
               f"tokens={len(engine._token_pool._tokens)} "
               f"proxies={len(engine._proxy_pool._proxies)} "
               f"balance_check={'ON' if engine.check_balance else 'off'} "
               f"raw_keys_on_disk={'YES (--store-raw)' if engine.store_raw_keys else 'no'}")
    if engine._store:
        click.echo(f"db={engine._store.path}")
    click.echo()

    merged = {}
    cycle = 0
    t0 = time.time()
    while True:
        cycle += 1
        if ns.loop:
            click.echo(f"===== cycle {cycle} =====")
        try:
            if sources == ["github"]:
                results = engine.run(queries)
            else:
                pool_tokens = _load_tokens(ns)
                gh_tok = pool_tokens[0] if pool_tokens \
                    else ScannerEngine.get_gh_token()
                results = engine.run_multi_source(
                    sources, queries=queries,
                    github_token=gh_tok or "",
                    gitlab_token=ns.gitlab_token or "",
                    gitee_token=ns.gitee_token or "")
        except KeyboardInterrupt:
            click.echo("\n[!] interrupted — results saved")
            break
        for r in results:
            merged[r["key"]] = r
        if not ns.loop:
            break
        time.sleep(5)

    results = list(merged.values())
    if ns.min_balance:
        results = [r for r in results
                   if r.get("balance_usd", 0) >= ns.min_balance]
    engine._save_final(results)
    _print_summary(results)
    click.echo(f"\ntotal time: {time.time()-t0:.0f}s")


def cmd_verify(ns):
    path = ns.file
    keys = {}
    if path.endswith(".json"):
        keys = ScannerEngine.load_keys_from_file(path)
    else:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                if not ln.strip() or ln.startswith("#"):
                    continue
                m = GENERIC_TOKEN.search(ln)
                if m:
                    k = m.group(0)
                    keys[k] = {"key": k,
                               "key_preview": k[:10] + "..." + k[-4:],
                               "repos": []}
    click.echo(f"verifying {len(keys)} keys from {path}")
    engine = build_engine(ns)
    # rank provider candidates per key — avoids probing all 15 providers
    for k, info in keys.items():
        if not info.get("providers"):
            provs, _ = engine._detector.classify(k)
            info["providers"] = provs or engine.providers
    results = engine.verify_keys(keys)
    engine._save_final(results)
    _print_summary(results)


def cmd_monitor(ns):
    from scanners.github_events import EventsMonitor
    engine = build_engine(ns)

    def on_key(k, repo, fpath, url):
        click.echo(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")
        if ns.verify:
            providers, _ = engine._detector.classify(
                k, context=f"{repo} {fpath}")
            res = engine._verify_dict({k: {
                "key": k, "key_preview": k[:10] + "..." + k[-4:],
                "providers": providers or engine.providers,
                "source": "events",
                "repos": [{"repo": repo, "file": fpath, "url": url}]}})
            engine._save_incremental([r for r in res if r.get("valid")], 0, 1)

    async def run():
        m = EventsMonitor(token=ns.github_token or "",
                          poll_interval=ns.poll_interval or 60,
                          concurrency=ns.concurrency or 15,
                          timeout=ns.timeout or 15,
                          max_events_per_poll=30)
        m.on_key_found = on_key
        await m.search()

    click.echo("monitoring GitHub PushEvents (Ctrl+C to stop)…")
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        click.echo("stopped")


def _open_store(ns) -> Store:
    db = getattr(ns, "db", None) or os.path.join(
        getattr(ns, "output_dir", None) or "./results", "findings.db")
    if not os.path.exists(db):
        raise click.ClickException(f"no DB at {db} — run a scan first")
    return Store(db)


def cmd_stats(ns):
    s = _open_store(ns).stats()
    click.echo(f"scans:            {s['scans']}")
    click.echo(f"total findings:   {s['total_findings']}")
    for st, n in sorted(s["by_status"].items(), key=lambda x: -x[1]):
        click.echo(f"  status={st:<14} {n}")
    click.echo("valid by provider:")
    for p, n in sorted(s["valid_by_provider"].items(), key=lambda x: -x[1]):
        click.echo(f"  {p:<14} {n}")
    click.echo("unique by source:")
    for src, n in sorted(s["unique_by_source"].items(), key=lambda x: -x[1]):
        click.echo(f"  {src or '?':<14} {n}")
    click.echo(f"total balance (valid): ${s['total_balance_usd']:.2f}")


def cmd_report(ns):
    store = _open_store(ns)
    out = ns.out or os.path.join(os.path.dirname(store.path),
                                 "research_report.md")
    store.report_markdown(out)
    click.echo(f"report → {out}")


def cmd_export(ns):
    store = _open_store(ns)
    out = ns.out or os.path.join(
        os.path.dirname(store.path), f"findings.{ns.format}")
    if ns.format == "csv":
        store.export_csv(out, status=ns.status)
    else:
        store.export_json(out, status=ns.status)
    click.echo(f"exported → {out} (hash+preview only, no raw keys)")


def cmd_providers(ns):
    click.echo(provider_table())
    click.echo("\nambiguous sk- fallback order: " + ", ".join(AMBIGUOUS_ORDER))


def cmd_sources(ns):
    click.echo("available sources:")
    for s in ALL_SOURCES:
        click.echo(f"  {s}")
    click.echo("\nprofiles:")
    for name, p in PROFILES.items():
        click.echo(f"  {name:<10} {p}")


# ──────────────────────────── click wiring ────────────────────────────
# Every option defaults to None = "unset" so config.yaml and profiles can
# fill it in. Booleans use --flag/--no-flag pairs.

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"],
                    "max_content_width": 110}


def common_options(f):
    opts = [
        click.option("-c", "--concurrency", type=int, default=None,
                     help="verify/fetch concurrency"),
        click.option("--timeout", type=int, default=None,
                     help="HTTP timeout, seconds"),
        click.option("--output-dir", type=click.Path(), default=None,
                     help="output directory"),
        click.option("--db", type=click.Path(), default=None,
                     help="findings DB path (default: <output-dir>/findings.db)"),
        click.option("--no-db", is_flag=True, flag_value=True, default=None,
                     help="don't write SQLite (config: output.no_db)"),
        click.option("--providers", default=None,
                     help="comma list; default = all known providers"),
        click.option("--with-balance/--no-with-balance", default=None,
                     help="probe billing endpoints (default: off)"),
        click.option("--store-raw/--no-store-raw", default=None,
                     help="write raw keys to output files (default: hash only)"),
        click.option("-q", "--quiet/--no-quiet", default=None,
                     help="suppress engine output"),
    ]
    for o in opts:
        f = o(f)
    return f


def network_options(f):
    opts = [
        click.option("--github-token", default=None,
                     help="GitHub token (gh CLI / GITHUB_TOKEN also work)"),
        click.option("--github-tokens", default=None,
                     help="comma-separated extra GitHub tokens (pool)"),
        click.option("--github-tokens-file", type=click.Path(), default=None,
                     help="file with tokens, one per line"),
        click.option("--gitlab-token", default=None),
        click.option("--gitee-token", default=None),
        click.option("--proxy", multiple=True, default=None,
                     help="collection-phase proxy (repeatable); "
                          "NEVER used for provider verification"),
        click.option("--proxy-file", type=click.Path(), default=None,
                     help="file with proxies, one per line"),
        click.option("--vless", multiple=True, default=None,
                     help="vless:// link (repeatable) — spawned via sing-box"),
        click.option("--vless-file", type=click.Path(), default=None,
                     help="file with vless:// links, one per line"),
        click.option("--vless-base-port", type=int, default=None,
                     help="first local inbound port for VLESS rotation"),
        click.option("--user-agent", default=None,
                     help="override research User-Agent"),
    ]
    for o in opts:
        f = o(f)
    return f


@click.group(context_settings=CONTEXT_SETTINGS,
             epilog="Docs: USAGE.md · Config: config.yaml (auto-loaded)")
@click.option("--config", type=click.Path(), default=None,
              help="config.yaml path (auto-detected next to cli.py)")
@click.version_option("2.0", prog_name="llmleaks")
@click.pass_context
def cli(ctx, config):
    """llmleaks — leaked AI API key research scanner."""
    ctx.ensure_object(dict)
    ctx.obj["cfg"] = load_config(config)


@cli.command(epilog="""
\b
Examples:
  llmleaks scan --profile quick
  llmleaks scan --sources github,gist,issues --workers 5
  llmleaks scan --vless-file vless.txt --github-tokens-file tokens.txt
  llmleaks scan --query "openai sk- filename:env" --no-skip-builtin
""")
@click.option("--profile", type=click.Choice(list(PROFILES)), default=None,
              help="preset (replaces old *_scan.py scripts)")
@click.option("--sources", default=None,
              help="comma list or 'all' (default: github)")
@click.option("--query", multiple=True, default=None,
              help="extra search query (repeatable)")
@click.option("--queries-file", type=click.Path(exists=True), default=None,
              help="file with queries, one per line")
@click.option("--skip-builtin/--no-skip-builtin", default=None,
              help="ignore the built-in query library")
@click.option("--duration", type=int, default=None,
              help="max seconds (0=unlimited)")
@click.option("--workers", type=int, default=None,
              help="parallel search workers, one proxy/token each "
                   "(default: #proxies or #tokens, max 8)")
@click.option("--max-keys", type=int, default=None,
              help="stop after N valid keys")
@click.option("--pages", type=int, default=None,
              help="search result pages per query (100/page)")
@click.option("--search-delay", type=float, default=None,
              help="seconds between queries")
@click.option("--min-balance", type=float, default=None,
              help="keep only keys with balance_usd >= N")
@click.option("--exclude-repo", multiple=True, default=None,
              help="fnmatch repo pattern to exclude (repeatable)")
@click.option("--usd-cny-rate", type=float, default=None,
              help="USD/CNY exchange rate")
@click.option("--min-key-length", type=int, default=None)
@click.option("--max-key-length", type=int, default=None)
@click.option("--loop/--no-loop", default=None,
              help="repeat cycles until Ctrl+C (marathon)")
@click.option("--dry-run/--no-dry-run", default=None,
              help="search only, no verify; saves .akh_progress.json")
@common_options
@network_options
@click.pass_context
def scan(ctx, **kw):
    """Search + verify + store pipeline."""
    cmd_scan(_params(ctx, kw))


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@common_options
@network_options
@click.pass_context
def verify(ctx, **kw):
    """Verify keys from a txt/json file."""
    cmd_verify(_params(ctx, kw))


@cli.command()
@click.option("--poll-interval", type=int, default=None,
              help="seconds between GitHub Events polls")
@click.option("--verify/--no-verify", default=None,
              help="verify each key as it appears")
@click.option("--duration", type=int, default=None)
@click.option("--pages", type=int, default=None)
@click.option("--search-delay", type=float, default=None)
@click.option("--max-keys", type=int, default=None)
@common_options
@network_options
@click.pass_context
def monitor(ctx, **kw):
    """Real-time GitHub PushEvent monitor."""
    cmd_monitor(_params(ctx, kw))


@cli.command()
@click.option("--db", type=click.Path(), default=None)
@click.option("--output-dir", type=click.Path(), default=None)
@click.pass_context
def stats(ctx, **kw):
    """Show findings DB statistics."""
    cmd_stats(_params(ctx, kw))


@cli.command()
@click.option("--db", type=click.Path(), default=None)
@click.option("--output-dir", type=click.Path(), default=None)
@click.option("--out", type=click.Path(), default=None,
              help="output file (default: <db dir>/research_report.md)")
@click.pass_context
def report(ctx, **kw):
    """Generate markdown research report from DB."""
    cmd_report(_params(ctx, kw))


@cli.command()
@click.option("--db", type=click.Path(), default=None)
@click.option("--output-dir", type=click.Path(), default=None)
@click.option("--format", "format",
              type=click.Choice(["csv", "json"]), default="csv",
              show_default=True)
@click.option("--status", default=None,
              help="filter: valid|revoked|no_quota|…")
@click.option("--out", type=click.Path(), default=None)
@click.pass_context
def export(ctx, **kw):
    """Export findings (hash + preview only, never raw keys)."""
    cmd_export(_params(ctx, kw))


@cli.command()
@click.pass_context
def providers(ctx):
    """List supported providers and detection patterns."""
    cmd_providers(None)


@cli.command()
@click.pass_context
def sources(ctx):
    """List available scan sources and profiles."""
    cmd_sources(None)


def _print_summary(results):
    valid = [r for r in results if r.get("valid")]
    by_status = {}
    for r in results:
        st = r.get("status") or ("valid" if r.get("valid") else "?")
        by_status[st] = by_status.get(st, 0) + 1
    click.echo(f"\n{'='*56}\n  summary\n{'='*56}")
    click.echo(f"  verified: {len(results)}  valid: {len(valid)}")
    for st, n in sorted(by_status.items(), key=lambda x: -x[1]):
        click.echo(f"    {st:<14} {n}")
    by_prov = {}
    for r in valid:
        by_prov[r.get("provider", "?")] = \
            by_prov.get(r.get("provider", "?"), 0) + 1
    if by_prov:
        click.echo("  valid by provider:")
        for p_, n in sorted(by_prov.items(), key=lambda x: -x[1]):
            click.echo(f"    {p_:<14} {n}")
    pos = [r for r in valid if r.get("balance_usd", 0) > 0]
    if pos:
        click.echo(f"  positive-balance keys: {len(pos)}  "
                   f"total ${sum(r['balance_usd'] for r in pos):.2f}")
    click.echo("=" * 56)


if __name__ == "__main__":
    cli()
