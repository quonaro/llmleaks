# llmleaks — Usage Guide

## Setup

```bash
pip install aiohttp requests click pyyaml   # Python 3.10+

# GitHub auth (30 req/min vs 10 req/min unauthenticated):
gh auth login
# or: export GITHUB_TOKEN="ghp_..."  / extra pool tokens below

# Optional, only for VLESS proxy rotation:
#   sing-box must be in PATH (https://sing-box.sagernet.org)
```

## CLI

Single entry point: `cli.py` (click-based, `-h`/`--help` everywhere).

```
python cli.py scan       search + verify + store
python cli.py verify     verify keys from a file / checkpoint
python cli.py monitor    real-time GitHub PushEvent monitor
python cli.py stats      findings DB statistics
python cli.py report     markdown research report from DB
python cli.py export     CSV/JSON export (hash + preview only)
python cli.py providers  list providers & detection patterns
python cli.py sources    list sources & profiles
```

## Configuration

All settings live in `config.yaml` (auto-loaded when it sits next to
`cli.py`, or `--config path/to.yaml`). Copy `config.example.yaml` as a
starting point. `config.yaml` is gitignored — tokens belong here,
not in git.

Precedence: **CLI flag > config.yaml > --profile preset > built-in
defaults**. Every CLI flag has a config key; sections mirror the help
groups:

```yaml
scan:       profile, sources, providers, queries_file, skip_builtin,
            extra_queries, pages, workers, duration, max_keys, loop,
            dry_run, min_balance, exclude_repos, min/max_key_length
network:    timeout, concurrency, search_delay, github_token(s),
            gitlab_token, gitee_token, proxies, proxy_file,
            vless, vless_file, vless_base_port, user_agent
verification: with_balance, store_raw
monitor:    poll_interval, verify
output:     dir, db, no_db, usd_cny_rate, quiet
```

Every boolean flag accepts its negation (`--with-balance` /
`--no-with-balance`, `--loop` / `--no-loop`, `--dry-run` /
`--no-dry-run`, ...) so config values can be overridden in either
direction from the CLI. Keep several configs for different modes and
switch with `--config`:

```bash
python cli.py --config marathon.yaml scan
python cli.py --config stealth.yaml scan --duration 600   # flag wins
```

## Scanning

```bash
# Profiles (presets replacing the old *_scan.py scripts)
python cli.py scan --profile quick      # ~15 min
python cli.py scan --profile standard   # ~1 h
python cli.py scan --profile max        # ~2 h
python cli.py scan --profile deep       # ~3 h
python cli.py scan --profile expanded   # multi-source
python cli.py scan --profile ultimate   # everything
python cli.py scan --profile marathon   # cycles until Ctrl+C

# Manual control (flags override profile and config values)
python cli.py scan --sources github,gist,issues,gitlab
python cli.py scan --sources all
python cli.py scan --query "openai sk- filename:env" --skip-builtin
python cli.py scan --queries-file queries_v4.txt --pages 5 -c 20
python cli.py scan --providers deepseek,openai,anthropic
python cli.py scan --duration 3600 --max-keys 100 --loop

# Dry run: search only, no verification — saves .akh_progress.json
# (verify it later with `cli.py verify results/.akh_progress.json`)
python cli.py scan --dry-run --profile quick
```

### Providers

Detection is per-provider (prefix patterns + context disambiguation):
`openai, anthropic, openrouter, deepseek, opencode, groq, xai,
huggingface, replicate, perplexity, fireworks, cerebras, mistral,
together, google`. Plain `sk-` keys are ranked by context and length,
then probed against at most 3 provider endpoints.

### Verification policy (built-in, not configurable)

- one read-only GET per provider candidate, no retries on 401/403
- identifying `User-Agent: llmleaks-research/...`
- `--with-balance` (off by default) enables billing-endpoint probes
- verification traffic never goes through proxies

### Rate limits / tokens / proxies

```bash
python cli.py scan --github-tokens ghp_aaa,ghp_bbb        # token pool
python cli.py scan --github-tokens-file tokens.txt
python cli.py scan --proxy-file proxies.txt   # collection sources only
python cli.py scan --proxy http://host:port   # repeatable

# VLESS rotation (requires sing-box in PATH)
python cli.py scan --vless-file vless.txt
python cli.py scan --vless "vless://uuid@host:443?security=reality&..."
python cli.py scan --vless-file vless.txt --vless-base-port 21000

# Parallel batched search — one worker per VLESS exit
python cli.py scan --vless-file vless.txt --workers 10
```

GitHub search is limited **per token**, so a token pool scales better than
proxies. Proxies apply only to collection sources (Common Crawl, Wayback,
etc.) — provider APIs are hard-excluded.

VLESS links can't be used by HTTP clients directly — `--vless*` spawns a
local `sing-box` with one `mixed` inbound (HTTP CONNECT + SOCKS5) per
link on `127.0.0.1:<base_port+i>`, routed 1:1 to its VLESS outbound, and
feeds those loopback proxies into the pool. The subprocess is killed on
exit.

### Parallel workers

`--workers N` runs search in async batches: each batch fires N queries at
once, worker *i* pinned to `proxies[i]` + `tokens[i]` (pool fallback when
fewer resources than workers). Between batches: verify → incremental save
→ delay, same as sequential mode. Default `0` = auto: `min(#proxies or
#tokens, 8)`; without either it stays sequential.

Pairing matters: one token reused from many IPs is a credential-sharing
abuse pattern — give each worker its own GitHub token when possible.

### Monitor mode

```bash
python cli.py monitor --verify --poll-interval 60
```

Watches GitHub PushEvents, extracts keys as they are pushed, optionally
verifies them immediately — measures leak *incidence*, not just backlog.

## Storage

Everything lands in `results/findings.db` (SQLite):

- `findings` — one row per unique key: **sha256 hash + preview only**,
  provider, status, severity, balance, first/last seen
- `occurrences` — where each key was seen (source/repo/file/url/query)
- `scans` — run metadata

Raw keys are **never** written to disk unless you pass `--store-raw`
(needed only if you must hand keys to a provider disclosure program).
Legacy `api_keys_result.json/csv/md` are still written to `output-dir`,
but with `key_hash` instead of the raw key by default.

```bash
python cli.py stats
python cli.py report --out report.md
python cli.py export --format csv --status valid
python cli.py export --format json > findings.json
```

## Verifying existing keys

```bash
python cli.py verify keys.txt                        # one key per line
python cli.py verify results/api_keys_result.json    # engine output
python cli.py verify keys.txt --with-balance -c 20
```

Statuses: `valid`, `revoked`, `no_quota` (works but out of credit),
`rate_limited`, `unverifiable`, `timeout`, `error`.

## Legacy scripts

Removed. Their functionality maps to:
`scan --profile quick|standard|max|deep|expanded|ultimate|marathon`,
`scan --dry-run` (was `--dry-run`), `verify <file>` (was
`--verify-only`, accepts `.akh_progress.json` checkpoints too),
`monitor` (was `--monitor`).

## Security notes

- `results/` is sensitive even with hash-only storage — keep it private
  and gitignored.
- Validation is deliberately minimal-touch. Do not raise it.
- Found keys belong to someone else: report to the provider first
  (bulk revocation beats emailing owners), never use them.
