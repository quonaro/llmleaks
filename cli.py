#!/usr/bin/env python3
"""
llmleaks — unified CLI for finding leaked AI API keys.

Subcommands:
  scan       Search sources for leaked keys, verify, store (replaces all
             *_scan.py scripts — old scripts are profiles now)
  verify     Verify keys from a file (txt / json / engine result file)
  monitor    Real-time GitHub PushEvent monitor
  stats      Show findings DB statistics
  report     Generate markdown research report from DB
  export     Export findings (hash + preview only, never raw keys)
  providers  List supported providers and detection patterns
  sources    List available scan sources
"""

import argparse
import asyncio
import os
import sys
import time

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
        print(f"[!] {msg}")
    elif level == "error":
        print(f"[ERROR] {msg}")
    else:
        print(msg)


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
        print(f"[ERROR] config not found: {path}")
        sys.exit(1)
    import yaml
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg if isinstance(cfg, dict) else {}


def _apply_config(args, cfg: dict):
    """Fill args that are still None (not set on CLI) from config values."""
    for attr, (path, join_csv) in CFG_MAP.items():
        if not hasattr(args, attr) or getattr(args, attr) is not None:
            continue
        sec, key = path.split(".", 1)
        val = (cfg.get(sec) or {}).get(key)
        if val is None:
            continue
        if join_csv and isinstance(val, (list, tuple)):
            val = ",".join(str(x) for x in val)
        setattr(args, attr, val)


_VLESS_POOL = None  # keeps the sing-box subprocess alive for the process


def _load_proxies(args) -> list:
    global _VLESS_POOL
    proxies = list(getattr(args, "proxy", None) or [])
    pf = getattr(args, "proxy_file", None)
    if pf and os.path.exists(pf):
        with open(pf, encoding="utf-8") as f:
            proxies += [ln.strip() for ln in f
                        if ln.strip() and not ln.startswith("#")]

    # VLESS links → local sing-box inbounds → http://127.0.0.1:* proxies
    links = list(getattr(args, "vless", None) or [])
    vf = getattr(args, "vless_file", None)
    if vf and os.path.exists(vf):
        with open(vf, encoding="utf-8") as f:
            links += [ln.strip() for ln in f
                      if ln.strip() and not ln.startswith("#")]
    if links:
        from vless_pool import VlessPool
        base_port = getattr(args, "vless_base_port", None) or 20800
        _VLESS_POOL = VlessPool(links, base_port=base_port)
        started = _VLESS_POOL.start()
        print(f"vless: sing-box up, {len(started)} local proxies "
              f"@{base_port}-{base_port + len(started) - 1}")
        proxies += started
    return proxies


def _load_tokens(args) -> list:
    tokens = _split_csv(getattr(args, "github_tokens", "") or "")
    tf = getattr(args, "github_tokens_file", None)
    if tf and os.path.exists(tf):
        with open(tf, encoding="utf-8") as f:
            tokens += [ln.strip() for ln in f
                       if ln.strip() and not ln.startswith("#")]
    if getattr(args, "github_token", ""):
        tokens.append(args.github_token)
    return tokens


def build_engine(args) -> ScannerEngine:
    providers = _split_csv(getattr(args, "providers", None)) or ALL_PROVIDERS
    output_dir = getattr(args, "output_dir", None) or "./results"
    db_path = getattr(args, "db", None) or os.path.join(output_dir,
                                                       "findings.db")
    return ScannerEngine(
        concurrency=getattr(args, "concurrency", None) or 15,
        timeout=getattr(args, "timeout", None) or 15,
        search_delay=getattr(args, "search_delay", None) or 4.0,
        min_key_length=getattr(args, "min_key_length", None) or 20,
        max_key_length=getattr(args, "max_key_length", None) or 120,
        output_dir=output_dir,
        providers=providers,
        usd_cny_rate=getattr(args, "usd_cny_rate", None)
        or DEFAULT_USD_CNY_RATE,
        exclude_repos=getattr(args, "exclude_repo", None) or [],
        max_duration=getattr(args, "duration", None) or 0,
        max_valid_keys=getattr(args, "max_keys", None) or 0,
        scan_pages=getattr(args, "pages", None) or 3,
        search_workers=getattr(args, "workers", None) or 0,
        github_tokens=_load_tokens(args),
        proxies=_load_proxies(args),
        check_balance=bool(getattr(args, "with_balance", None)),
        db_path=None if getattr(args, "no_db", None) else db_path,
        store_raw_keys=bool(getattr(args, "store_raw", None)),
        user_agent=getattr(args, "user_agent", None),
        log_callback=log_func if not getattr(args, "quiet", None)
        else (lambda m, l="info": None),
    )


def _resolve_queries(args) -> list:
    queries = []
    if not getattr(args, "skip_builtin", None):
        queries.extend(BUILTIN_QUERIES)
    for q in getattr(args, "query", None) or []:
        queries.append(q)
    qf = getattr(args, "queries_file", None)
    if qf and os.path.exists(qf):
        queries.extend(ScannerEngine.load_queries_file(qf))
    return queries or BUILTIN_QUERIES


# ──────────────────────────── subcommands ────────────────────────────

def cmd_scan(args):
    args.profile = args.profile or "standard"
    prof = PROFILES.get(args.profile, PROFILES["standard"])
    # profile supplies defaults; config file and explicit flags win
    for k, v in prof.items():
        if k == "sources":
            if not args.sources:
                args.sources = v
        elif k == "loop":
            if args.loop is None:
                args.loop = v
        else:
            attr = {"duration": "duration", "scan_pages": "pages",
                    "search_delay": "search_delay",
                    "concurrency": "concurrency"}[k]
            if getattr(args, attr) is None:
                setattr(args, attr, v)

    queries = _resolve_queries(args)
    sources = _split_csv(args.sources) or ["github"]
    if sources == ["all"]:
        sources = ALL_SOURCES

    engine = build_engine(args)
    # workers: explicit flag/config, else #proxies, else #tokens, else seq
    if args.workers is None:
        n = max(len(engine._proxy_pool._proxies), len(engine._gh_tokens), 1)
        engine.search_workers = min(n, 8)
    else:
        engine.search_workers = args.workers
    authed = ScannerEngine.check_gh_auth()
    print(f"llmleaks scan | profile={args.profile} sources={sources}")
    print(f"queries={len(queries)} providers={engine.providers}")
    print(f"concurrency={engine.concurrency} workers={engine.search_workers} "
          f"pages={engine.scan_pages} delay={engine.search_delay}s "
          f"duration={engine.max_duration or '∞'}s")
    print(f"github_auth={'yes' if authed else 'NO (10 req/min!)'} "
          f"tokens={len(engine._token_pool._tokens)} "
          f"proxies={len(engine._proxy_pool._proxies)} "
          f"balance_check={'ON' if engine.check_balance else 'off'} "
          f"raw_keys_on_disk={'YES (--store-raw)' if engine.store_raw_keys else 'no'}")
    if engine._store:
        print(f"db={engine._store.path}")
    print()

    merged = {}
    cycle = 0
    t0 = time.time()
    while True:
        cycle += 1
        if args.loop:
            print(f"===== cycle {cycle} =====")
        try:
            if sources == ["github"]:
                results = engine.run(queries)
            else:
                pool_tokens = _load_tokens(args)
                gh_tok = pool_tokens[0] if pool_tokens \
                    else ScannerEngine.get_gh_token()
                results = engine.run_multi_source(
                    sources, queries=queries,
                    github_token=gh_tok or "",
                    gitlab_token=args.gitlab_token or "",
                    gitee_token=args.gitee_token or "")
        except KeyboardInterrupt:
            print("\n[!] interrupted — results saved")
            break
        for r in results:
            merged[r["key"]] = r
        if not args.loop:
            break
        time.sleep(5)

    results = list(merged.values())
    if args.min_balance:
        results = [r for r in results if r.get("balance_usd", 0) >= args.min_balance]
    engine._save_final(results)
    _print_summary(results)
    print(f"\ntotal time: {time.time()-t0:.0f}s")


def cmd_verify(args):
    path = args.file
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
    print(f"verifying {len(keys)} keys from {path}")
    engine = build_engine(args)
    # rank provider candidates per key — avoids probing all 15 providers
    for k, info in keys.items():
        if not info.get("providers"):
            provs, _ = engine._detector.classify(k)
            info["providers"] = provs or engine.providers
    results = engine.verify_keys(keys)
    engine._save_final(results)
    _print_summary(results)


def cmd_monitor(args):
    from scanners.github_events import EventsMonitor
    engine = build_engine(args)

    def on_key(k, repo, fpath, url):
        print(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")
        if args.verify:
            providers, _ = engine._detector.classify(
                k, context=f"{repo} {fpath}")
            res = engine._verify_dict({k: {
                "key": k, "key_preview": k[:10] + "..." + k[-4:],
                "providers": providers or engine.providers,
                "source": "events",
                "repos": [{"repo": repo, "file": fpath, "url": url}]}})
            engine._save_incremental([r for r in res if r.get("valid")], 0, 1)

    async def run():
        m = EventsMonitor(token=args.github_token or "",
                          poll_interval=args.poll_interval or 60,
                          concurrency=args.concurrency or 15,
                          timeout=args.timeout or 15,
                          max_events_per_poll=30)
        m.on_key_found = on_key
        await m.search()

    print("monitoring GitHub PushEvents (Ctrl+C to stop)…")
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("stopped")


def _open_store(args) -> Store:
    db = getattr(args, "db", None) or os.path.join(
        getattr(args, "output_dir", None) or "./results", "findings.db")
    if not os.path.exists(db):
        print(f"[ERROR] no DB at {db} — run a scan first")
        sys.exit(1)
    return Store(db)


def cmd_stats(args):
    s = _open_store(args).stats()
    print(f"scans:            {s['scans']}")
    print(f"total findings:   {s['total_findings']}")
    for st, n in sorted(s["by_status"].items(), key=lambda x: -x[1]):
        print(f"  status={st:<14} {n}")
    print(f"valid by provider:")
    for p, n in sorted(s["valid_by_provider"].items(), key=lambda x: -x[1]):
        print(f"  {p:<14} {n}")
    print(f"unique by source:")
    for src, n in sorted(s["unique_by_source"].items(), key=lambda x: -x[1]):
        print(f"  {src or '?':<14} {n}")
    print(f"total balance (valid): ${s['total_balance_usd']:.2f}")


def cmd_report(args):
    store = _open_store(args)
    out = args.out or os.path.join(os.path.dirname(store.path),
                                   "research_report.md")
    store.report_markdown(out)
    print(f"report → {out}")


def cmd_export(args):
    store = _open_store(args)
    out = args.out or os.path.join(
        os.path.dirname(store.path), f"findings.{args.format}")
    if args.format == "csv":
        store.export_csv(out, status=args.status)
    else:
        store.export_json(out, status=args.status)
    print(f"exported → {out} (hash+preview only, no raw keys)")


def cmd_providers(args):
    print(provider_table())
    print("\nambiguous sk- fallback order:", ", ".join(AMBIGUOUS_ORDER))


def cmd_sources(args):
    print("available sources:")
    for s in ALL_SOURCES:
        print(f"  {s}")
    print("\nprofiles:")
    for name, p in PROFILES.items():
        print(f"  {name:<10} {p}")


# ──────────────────────────── argparse ────────────────────────────
# Every optional arg defaults to None = "unset" so config.yaml and
# profiles can fill it in. Precedence: CLI flag > config.yaml > profile.

_BOOL = argparse.BooleanOptionalAction


def _add_common(p):
    p.add_argument("-c", "--concurrency", type=int, default=None,
                   help="verify/fetch concurrency")
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--db", default=None,
                   help="findings DB path (default: <output-dir>/findings.db)")
    p.add_argument("--no-db", action="store_true", default=None,
                   help="don't write SQLite (config: output.no_db)")
    p.add_argument("--providers", default=None,
                   help="comma list; default = all known providers")
    p.add_argument("--with-balance", action=_BOOL, default=None,
                   help="probe billing endpoints (default: off)")
    p.add_argument("--store-raw", action=_BOOL, default=None,
                   help="write raw keys to output files (default: hash only)")
    p.add_argument("-q", "--quiet", action=_BOOL, default=None)


def _add_network(p):
    p.add_argument("--github-token", default=None)
    p.add_argument("--github-tokens", default=None,
                   help="comma-separated extra GitHub tokens (pool)")
    p.add_argument("--github-tokens-file", default=None)
    p.add_argument("--gitlab-token", default=None)
    p.add_argument("--gitee-token", default=None)
    p.add_argument("--proxy", action="append", default=None,
                   help="collection-phase proxy (repeatable); "
                        "NEVER used for provider verification")
    p.add_argument("--proxy-file", default=None)
    p.add_argument("--vless", action="append", default=None,
                   help="vless:// link (repeatable) — spawned via sing-box")
    p.add_argument("--vless-file", default=None,
                   help="file with vless:// links, one per line")
    p.add_argument("--vless-base-port", type=int, default=None,
                   help="first local inbound port for VLESS rotation")
    p.add_argument("--user-agent", default=None)


def build_parser():
    p = argparse.ArgumentParser(
        prog="llmleaks",
        description="llmleaks — leaked AI API key research scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default=None,
                   help="config.yaml path (auto-detected next to cli.py)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="search + verify pipeline")
    s.add_argument("--profile", choices=list(PROFILES), default=None,
                   help="preset (replaces old *_scan.py scripts)")
    s.add_argument("--sources", default=None,
                   help="comma list or 'all' (default: github)")
    s.add_argument("--query", action="append", default=None,
                   help="extra search query")
    s.add_argument("--queries-file", default=None)
    s.add_argument("--skip-builtin", action=_BOOL, default=None)
    s.add_argument("--duration", type=int, default=None,
                   help="max seconds (0=unlimited)")
    s.add_argument("--workers", type=int, default=None,
                   help="parallel search workers — each on its own "
                        "proxy/token (default: #proxies or #tokens, max 8)")
    s.add_argument("--max-keys", type=int, default=None)
    s.add_argument("--pages", type=int, default=None,
                   help="search pages/query")
    s.add_argument("--search-delay", type=float, default=None)
    s.add_argument("--min-balance", type=float, default=None)
    s.add_argument("--exclude-repo", action="append", default=None)
    s.add_argument("--usd-cny-rate", type=float, default=None)
    s.add_argument("--min-key-length", type=int, default=None)
    s.add_argument("--max-key-length", type=int, default=None)
    s.add_argument("--loop", action=_BOOL, default=None,
                   help="repeat cycles until Ctrl+C (marathon)")
    _add_common(s); _add_network(s)
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify", help="verify keys from file")
    v.add_argument("file", help="txt (one per line) or engine json")
    _add_common(v); _add_network(v)
    v.set_defaults(func=cmd_verify)

    m = sub.add_parser("monitor", help="real-time GitHub events monitor")
    m.add_argument("--poll-interval", type=int, default=None)
    m.add_argument("--verify", action=_BOOL, default=None,
                   help="verify each key as it appears")
    m.add_argument("--duration", type=int, default=None)
    m.add_argument("--pages", type=int, default=None)
    m.add_argument("--search-delay", type=float, default=None)
    m.add_argument("--max-keys", type=int, default=None)
    _add_common(m); _add_network(m)
    m.set_defaults(func=cmd_monitor)

    for name, fn in [("stats", cmd_stats), ("report", cmd_report),
                     ("export", cmd_export)]:
        sp = sub.add_parser(name)
        sp.add_argument("--db", default=None)
        sp.add_argument("--output-dir", default=None)
        if name == "report":
            sp.add_argument("--out", default=None)
        if name == "export":
            sp.add_argument("--format", choices=["csv", "json"],
                            default="csv")
            sp.add_argument("--status", default=None,
                            help="filter: valid|revoked|no_quota|…")
            sp.add_argument("--out", default=None)
        sp.set_defaults(func=fn)

    sub.add_parser("providers").set_defaults(func=cmd_providers)
    sub.add_parser("sources").set_defaults(func=cmd_sources)
    return p


def _print_summary(results):
    valid = [r for r in results if r.get("valid")]
    by_status = {}
    for r in results:
        by_status[r.get("status") or ("valid" if r.get("valid") else "?")] = \
            by_status.get(r.get("status") or ("valid" if r.get("valid") else "?"), 0) + 1
    print(f"\n{'='*56}\n  summary\n{'='*56}")
    print(f"  verified: {len(results)}  valid: {len(valid)}")
    for st, n in sorted(by_status.items(), key=lambda x: -x[1]):
        print(f"    {st:<14} {n}")
    by_prov = {}
    for r in valid:
        by_prov[r.get("provider", "?")] = by_prov.get(r.get("provider", "?"), 0) + 1
    if by_prov:
        print("  valid by provider:")
        for p_, n in sorted(by_prov.items(), key=lambda x: -x[1]):
            print(f"    {p_:<14} {n}")
    pos = [r for r in valid if r.get("balance_usd", 0) > 0]
    if pos:
        print(f"  positive-balance keys: {len(pos)}  "
              f"total ${sum(r['balance_usd'] for r in pos):.2f}")
    print("=" * 56)


def main():
    args = build_parser().parse_args()
    cfg = load_config(getattr(args, "config", None))
    _apply_config(args, cfg)
    args.func(args)


if __name__ == "__main__":
    main()
