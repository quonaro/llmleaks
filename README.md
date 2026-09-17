<br>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Scanners-14-green?style=flat-square" alt="Scanners">
  <img src="https://img.shields.io/badge/Queries-238-red?style=flat-square" alt="Queries">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
</p>

<h1 align="center">llmleaks</h1>

<p align="center"><sub>Forked from <a href="https://github.com/pukpuklouis/DarkForest-Hunter-OpenAI">DarkForest-Hunter-OpenAI</a></sub></p>

<p align="center">
  <em>"The universe is a dark forest. Every civilization is an armed hunter."</em><br>
  <sub>— <strong>Liu Cixin</strong>, <em>The Dark Forest</em></sub>
</p>

---

> A tool that scans 14 platforms with 238 search patterns to find exposed AI provider API keys (OpenAI, DeepSeek, Anthropic, and a dozen more), validates them, and checks their balance. Built because we were shocked by how many live keys with big balances are sitting in public repos, completely unnoticed.

---

## 🌲 The Dark Forest

In the code forest of GitHub, millions of developers commit code every day. Every line of `API_KEY=sk-...` is a **broadcast** — a civilization revealing its coordinates.

**We are the hunters in this forest.**

Not to destroy, but to warn — **before someone else pulls the trigger.**

This mirrors the Dark Forest theory from Liu Cixin's *Three-Body Problem*: every leaked key is a broadcast revealing coordinates. Except in cybersecurity, the hunters could be automated bots, crypto miners, data thieves, or worse.

**We open-source this tool so that ethical hunters find the prey first.**

## 🔭 Why This Exists

LLM APIs like DeepSeek and OpenAI have become some of the most widely used developer services. Every day, thousands of developers hardcode API keys in config files, test scripts, Jupyter Notebooks, Docker Compose files, and GitHub Actions — then accidentally push to public repositories.

We built this tool to answer a simple question: **how many AI provider keys are exposed in public code?** The answer shocked us — not just keys, but many with **significant balances**. These keys had been sitting exposed for months, completely unnoticed.

## 🎯 What It Does

Automatically scans **14 platforms** with **238 search patterns** to find publicly exposed AI provider API keys, then **validates** each one and **checks the balance**.

### Scanning Sources

| Category | Sources |
|----------|---------|
| Code Hosting | GitHub Code Search, Gist, Issues, Commits, GitLab, Gitee |
| AI Platforms | HuggingFace (Models, Datasets, Spaces) |
| Package Registries | PyPI, npm |
| Developer Communities | Stack Overflow |
| Archives | Docker Hub, Wayback Machine, Common Crawl |
| Real-time | GitHub Events (PushEvent stream) |

### Use Cases

- **Security Research** — Quantify the scale and patterns of API key exposure
- **Organization Auditing** — Scan your repos for accidental credential leaks
- **Bug Bounty** — Find exposed keys and perform responsible disclosure
- **Security Education** — Demonstrate real-world risks of hardcoded credentials

## 🚀 Quick Start

```bash
pip install aiohttp requests

# Optional: authenticate GitHub CLI for higher rate limits
gh auth login

# Unified CLI (all scan scripts are now --profile presets)
python cli.py scan --profile quick      # ~15 min
python cli.py scan --profile ultimate   # full multi-source scan
python cli.py scan --sources all --providers openai,anthropic,deepseek
python cli.py verify keys.txt           # verify a key list
python cli.py monitor --verify          # real-time leak monitor
python cli.py stats && python cli.py report
```

Findings land in `results/findings.db` (SQLite) — **raw keys are never
written to disk** (sha256 + preview only; `--store-raw` opts out).
Balance probing is off by default; `--with-balance` enables it.
See [USAGE.md](USAGE.md) for the full reference.

### Scan Profiles (formerly separate scripts)

| Profile | Description | Duration |
|---------|-------------|----------|
| `quick` | Test run | ~15min |
| `standard` | Standard scan | ~1h |
| `max` | Maximum throughput | ~2h |
| `deep` | Deep optimized scan | ~3h |
| `expanded` | Expanded multi-source | ~4h |
| `ultimate` | Full coverage | 10h+ |
| `marathon` | Cyclic until Ctrl+C | continuous |

### Programmatic Usage

```python
from scanner_engine import ScannerEngine, BUILTIN_QUERIES

engine = ScannerEngine(
    concurrency=20,
    scan_pages=5,
    max_duration=3600,
    output_dir="./results",
    providers=["openai", "anthropic", "deepseek"],
    check_balance=False,          # validity only — no billing probes
    db_path="./results/findings.db",
    store_raw_keys=False,         # hash-only persistence
)
results = engine.run(BUILTIN_QUERIES)
```

## 📁 Project Structure

```
llmleaks/
├── cli.py                   # Unified CLI (scan/verify/monitor/stats/report)
├── scanner_engine.py        # Core engine (search + verify + save)
├── detectors.py             # Per-provider key patterns + context ranking
├── verifiers.py             # Minimal-touch verification (1 GET/provider)
├── store.py                 # SQLite findings DB (hash-only, no raw keys)
├── ratelimit.py             # TokenPool / DomainLimiter / ProxyPool
├── scanners/
│   ├── base.py              # Base scanner class
│   ├── github_gist.py       # GitHub Gist scanner
│   ├── github_issues.py     # GitHub Issues/PRs scanner
│   ├── github_commits.py    # Commit history + diff scanner
│   ├── github_events.py     # Real-time PushEvent monitor
│   ├── gitlab.py            # GitLab scanner
│   ├── gitee.py             # Gitee scanner
│   ├── huggingface.py       # HuggingFace scanner
│   ├── pypi.py              # PyPI scanner
│   ├── npm_registry.py      # npm registry scanner
│   ├── stackoverflow.py     # Stack Overflow scanner
│   ├── docker.py            # Docker Hub scanner
│   ├── commoncrawl.py       # Common Crawl scanner
│   └── wayback.py           # Wayback Machine scanner
├── *_scan.py                # Legacy scan scripts (use cli.py instead)
├── queries_v4.txt           # Query library (238 patterns)
├── results/                 # Scan output directory
├── README.md                # This file (English)
├── README_CN.md             # Chinese version
├── USAGE.md                 # Detailed usage guide
└── LICENSE                  # MIT License
```

## ⚠️ Disclaimer

This tool is for **authorized security research, penetration testing, and credential auditing only**. Do not use discovered keys for unauthorized access. The authors assume no liability for misuse. If you discover your own key during a scan, rotate it immediately on the provider's platform.

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲🌲<br>
  <em>"The universe is a dark forest. Every civilization is an armed hunter."</em><br>
  <sub>— Liu Cixin, <em>The Dark Forest</em></sub><br>
  <br>
  <sub>May the ethical hunters reach the prey first.</sub>
</p>
