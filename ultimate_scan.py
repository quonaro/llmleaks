#!/usr/bin/env python3
"""
Ultimate scan — full coverage, deep digging, no time limit
Phases:
  1. GitHub Code Search — all 238 queries, 10 pages per query
  2. GitHub multi-source — Commits + Gist + Issues
  3. External platforms — HuggingFace + PyPI + StackOverflow + npm
  4. Archives/mirrors — Wayback + CommonCrawl
  5. Chinese platforms — Gitee + GitLab
"""
import sys, time, os, json
sys.path.insert(0, ".")

from scanner_engine import ScannerEngine, BUILTIN_QUERIES

def log(msg, level="info"):
    prefix = {"warning": "[!] ", "error": "[ERR] "}.get(level, "")
    t = time.strftime("%m-%d %H:%M:%S")
    print(f"[{t}] {prefix}{msg}", flush=True)

# ── Load existing ──
EXISTING = {}
existing_file = "results/deepseek_keys_result.json"
if os.path.exists(existing_file):
    with open(existing_file, "r", encoding="utf-8") as f:
        for r in json.load(f):
            EXISTING[r["key"]] = r
    log(f"Loaded {len(EXISTING)} existing keys")

def merge_results(new_results):
    """Merge new results into EXISTING dict, return count of new keys."""
    new_count = 0
    for r in new_results:
        k = r["key"]
        if k not in EXISTING:
            EXISTING[k] = r
            new_count += 1
        else:
            old = EXISTING[k]
            # Update balance if changed
            if r.get("balance_usd", 0) != old.get("balance_usd", 0):
                EXISTING[k] = r
            else:
                # Merge repo sources
                old_repos = {x["repo"] for x in old.get("repos", [])}
                for repo in r.get("repos", []):
                    if repo["repo"] not in old_repos:
                        old.setdefault("repos", []).append(repo)
    return new_count

def save_final():
    merged = sorted(EXISTING.values(), key=lambda x: x.get("balance_usd", 0), reverse=True)
    with open("results/deepseek_keys_result.json", "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    return merged

def report_stats():
    merged = save_final()
    valid = [r for r in merged if r.get("valid")]
    pos = [r for r in valid if r.get("balance_usd", 0) > 0]
    zero = [r for r in valid if r.get("balance_usd", 0) == 0]
    neg = [r for r in valid if r.get("balance_usd", 0) < 0]
    total_v = sum(r["balance_usd"] for r in pos)
    log(f"{'='*60}")
    log(f"Total: {len(merged)} | Valid {len(valid)} | Positive {len(pos)} | Zero {len(zero)} | Overdue {len(neg)}")
    log(f"总价值: ${total_v:.2f}")
    if pos:
        log(f"Top 5:")
        for i, r in enumerate(pos[:5]):
            src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
            log(f"  {i+1}. {r['key_preview']} | ${r['balance_usd']:.2f} | {src[:50]}")
    return merged

# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: GitHub Code Search — all queries, deep scan
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("PHASE 1: GitHub Code Search — 238 queries x 10 pages")
log(f"{'='*60}")

engine1 = ScannerEngine(
    concurrency=20,
    timeout=15,
    search_delay=3.0,       # Slightly faster
    scan_pages=10,          # Deep: 10 pages = 1000 results max per query
    max_duration=0,         # No limit
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

t0 = time.time()
results1 = engine1.run(list(BUILTIN_QUERIES))
elapsed1 = time.time() - t0
new1 = merge_results(results1)
log(f"PHASE 1 done: {elapsed1:.0f}s | New keys: {new1}")
report_stats()

# ═══════════════════════════════════════════════════════════════════
#  PHASE 2: GitHub ecosystem deep scan
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("PHASE 2: GitHub ecosystem — Commits + Gist + Issues")
log(f"{'='*60}")

engine2 = ScannerEngine(
    concurrency=15,
    timeout=15,
    search_delay=2.0,
    scan_pages=5,
    max_duration=0,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

sources_gh = ["commits", "gist", "issues"]
results2 = engine2.run_multi_source(sources_gh)
new2 = merge_results(results2)
log(f"PHASE 2 done: New keys: {new2}")
report_stats()

# ═══════════════════════════════════════════════════════════════════
#  PHASE 3: External platforms — HuggingFace + PyPI + StackOverflow + npm
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("PHASE 3: External platforms — HuggingFace + PyPI + StackOverflow + npm")
log(f"{'='*60}")

engine3 = ScannerEngine(
    concurrency=15,
    timeout=15,
    search_delay=2.0,
    scan_pages=5,
    max_duration=0,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

sources_ext = ["huggingface", "pypi", "stackoverflow", "npm"]
results3 = engine3.run_multi_source(sources_ext)
new3 = merge_results(results3)
log(f"PHASE 3 done: New keys: {new3}")
report_stats()

# ═══════════════════════════════════════════════════════════════════
#  PHASE 4: Archives/mirrors — Wayback + CommonCrawl
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("PHASE 4: Archives/mirrors — Wayback + CommonCrawl")
log(f"{'='*60}")

engine4 = ScannerEngine(
    concurrency=10,
    timeout=20,
    search_delay=2.0,
    scan_pages=5,
    max_duration=0,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

sources_archive = ["wayback", "commoncrawl"]
results4 = engine4.run_multi_source(sources_archive)
new4 = merge_results(results4)
log(f"PHASE 4 done: New keys: {new4}")
report_stats()

# ═══════════════════════════════════════════════════════════════════
#  PHASE 5: Chinese platforms — Gitee + GitLab
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("PHASE 5: Chinese platforms — Gitee + GitLab")
log(f"{'='*60}")

engine5 = ScannerEngine(
    concurrency=10,
    timeout=15,
    search_delay=2.0,
    scan_pages=5,
    max_duration=0,
    max_valid_keys=0,
    output_dir="./results/.tmp_batch",
    log_callback=log,
)

sources_cn = ["gitee", "gitlab"]
results5 = engine5.run_multi_source(sources_cn)
new5 = merge_results(results5)
log(f"PHASE 5 done: New keys: {new5}")

# ═══════════════════════════════════════════════════════════════════
#  FINAL REPORT
# ═══════════════════════════════════════════════════════════════════
log("")
log(f"{'='*60}")
log("ULTIMATE SCAN COMPLETE")
log(f"{'='*60}")

merged = report_stats()
total_new = new1 + new2 + new3 + new4 + new5
log(f"")
log(f"New keys this run: {total_new}")
log(f"  Phase 1 (GitHub Code):  {new1}")
log(f"  Phase 2 (GitHub Eco):   {new2}")
log(f"  Phase 3 (External):     {new3}")
log(f"  Phase 4 (Archive):      {new4}")
log(f"  Phase 5 (CN Platforms): {new5}")
