#!/usr/bin/env python3
"""
llmleaks - DeepSeek scanner, legacy CLI version (based on ScannerEngine)
Scan and verify DeepSeek API keys exposed in public repos

Usage:
  python deepseek_key_scanner.py                    # default full pipeline
  python deepseek_key_scanner.py --dry-run          # search only, no verify
  python deepseek_key_scanner.py --resume           # resume from checkpoint
  python deepseek_key_scanner.py -c 50              # concurrency 50
  python deepseek_key_scanner.py --verify-only results/deepseek_keys_result.json
  python deepseek_key_scanner.py --verify-only results/.dkh_progress.json
"""

import argparse
import os
import sys
import time
import json
from datetime import datetime

from scanner_engine import (
    ScannerEngine, BUILTIN_QUERIES, DEFAULT_USD_CNY_RATE
)

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def build_parser():
    p = argparse.ArgumentParser(
        prog="deepseek-key-hunter",
        description="llmleaks - scan public repos for exposed API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                         default full pipeline
  %(prog)s --dry-run                               search only, no verify
  %(prog)s --resume                                resume from checkpoint
  %(prog)s -c 50                                   higher concurrency
  %(prog)s --verify-only results/result.json       verify existing results only
  %(prog)s --verify-only results/.dkh_progress.json
  %(prog)s --queries-file queries_v4.txt           use a custom queries file
  %(prog)s --min-balance 0.01                      filter keys with balance >= $0.01
  %(prog)s --cmd-gen                               open the command generator page
        """,
    )

    g = p.add_argument_group("General")
    g.add_argument("-c", "--concurrency", type=int, default=20, help="concurrency (default: 20)")
    g.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    g.add_argument("--output-dir", type=str, default="./results", help="output directory")
    g.add_argument("-q", "--quiet", action="store_true", help="quiet mode")

    g_search = p.add_argument_group("Search")
    g_search.add_argument("--search-delay", type=float, default=2.5, help="delay between requests in seconds (default: 2.5)")
    g_search.add_argument("--scan-pages", type=int, default=10, help="pages per query 1-10 (default: 10, 100 results per page)")
    g_search.add_argument("--queries-file", type=str, default=None, help="custom queries file")
    g_search.add_argument("--skip-builtin", action="store_true", help="skip built-in queries")

    g_multi = p.add_argument_group("Multi-source scan (new)")
    g_multi.add_argument("--sources", type=str, default="github",
                         help="scan sources, comma-separated. Options: github, gist, issues, gitlab, wayback, docker, commoncrawl, gitee, npm, all (default: github)")
    g_multi.add_argument("--monitor", action="store_true", help="real-time monitor mode (GitHub Events API)")
    g_multi.add_argument("--github-token", type=str, default="", help="GitHub Personal Access Token")
    g_multi.add_argument("--gitlab-token", type=str, default="", help="GitLab Personal Access Token")
    g_multi.add_argument("--gitee-token", type=str, default="", help="Gitee Access Token")

    g_filter = p.add_argument_group("Filter")
    g_filter.add_argument("--min-key-length", type=int, default=32, help="min key length")
    g_filter.add_argument("--max-key-length", type=int, default=64, help="max key length")
    g_filter.add_argument("--min-balance", type=float, default=None, help="only output keys with USD balance >= this value")
    g_filter.add_argument("--exclude-repo", type=str, action="append", default=[], help="exclude repo")
    g_filter.add_argument("--usd-cny-rate", type=float, default=DEFAULT_USD_CNY_RATE,
                          help=f"USD/CNY exchange rate (default: {DEFAULT_USD_CNY_RATE})")

    g_verify = p.add_argument_group("Verify")
    g_verify.add_argument("--dry-run", action="store_true", help="search only, no verify")
    g_verify.add_argument("--verify-only", type=str, default=None, help="only verify a JSON/progress file")

    g_stop = p.add_argument_group("Exit conditions (auto stop)")
    g_stop.add_argument("--max-duration", type=int, default=0,
                       help="max run duration in seconds; auto-save and exit on timeout (default: 0=unlimited)")
    g_stop.add_argument("--max-valid-keys", type=int, default=0,
                       help="auto-save and exit after collecting this many valid keys (default: 0=unlimited)")
    g_stop.add_argument("--auto-save-interval", type=int, default=20,
                       help="auto-save results every N verified keys (default: 20)")

    g_output = p.add_argument_group("Output")
    g_output.add_argument("--format", choices=["all", "json", "csv", "markdown"], default="all", help="output format")

    g_resume = p.add_argument_group("Progress")
    g_resume.add_argument("--resume", action="store_true", help="resume from progress file")

    g_gui = p.add_argument_group("UI")
    g_gui.add_argument("--cmd-gen", action="store_true", help="open the command generator page (cmd_generator.html)")

    return p


def log_func(msg, level="info"):
    if level == "warning":
        print(f"[!] {msg}")
    elif level == "error":
        print(f"[ERROR] {msg}")
    elif msg.startswith("[KEY]"):
        sign = "+" if level == "valid" else ("-" if level == "invalid" else " ")
        print(f"  {sign} {msg}")
    else:
        print(msg)


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Command generator
    if args.cmd_gen:
        import webbrowser
        gen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cmd_generator.html")
        if os.path.exists(gen_path):
            webbrowser.open(f"file://{gen_path}")
            print(f"Opened command generator: {gen_path}")
        else:
            print("[ERROR] cmd_generator.html not found")
        return

    # Load queries
    queries = []
    if not args.skip_builtin:
        queries.extend(BUILTIN_QUERIES)
    if args.queries_file and os.path.exists(args.queries_file):
        queries.extend(ScannerEngine.load_queries_file(args.queries_file))
    if not queries:
        queries = BUILTIN_QUERIES

    # Auto-adjust search delay
    if not args.search_delay or args.search_delay == 2.5:
        suggested = ScannerEngine.suggested_search_delay()
        authed = ScannerEngine.check_gh_auth()
        args.search_delay = suggested

    rate_limit = "30 req/min (authenticated)" if ScannerEngine.check_gh_auth() else "10 req/min (unauthenticated)"

    print(f"llmleaks - legacy DeepSeek scan")
    print(f"Queries: {len(queries)} | Concurrency: {args.concurrency} | Rate: {args.usd_cny_rate}")
    print(f"API limit: {rate_limit} | Search delay: {args.search_delay}s")
    print(f"Output: {args.output_dir}")
    print()

    # Create engine
    engine = ScannerEngine(
        concurrency=args.concurrency,
        timeout=args.timeout,
        search_delay=args.search_delay,
        min_key_length=args.min_key_length,
        max_key_length=args.max_key_length,
        output_dir=args.output_dir,
        usd_cny_rate=args.usd_cny_rate,
        exclude_repos=args.exclude_repo,
        max_duration=args.max_duration,
        max_valid_keys=args.max_valid_keys,
        auto_save_interval=args.auto_save_interval,
        scan_pages=args.scan_pages,
        log_callback=log_func if not args.quiet else (lambda m, l: None),
    )

    # Verify-only mode
    if args.verify_only:
        all_keys = ScannerEngine.load_keys_from_file(args.verify_only)
        print(f"Loaded {len(all_keys)} keys from {args.verify_only}")
        results = engine.verify_keys(all_keys)
        results = engine.sort_results(results)
        engine.save_results(results, fmt=args.format)
        _print_summary(results, engine.usd_cny_rate)
        return

    # Multi-source scan mode
    sources_str = args.sources.lower().strip()
    if sources_str != "github" or args.monitor:
        t0 = time.time()
        if sources_str == "all":
            sources = [s for s in ["github", "gist", "issues", "gitlab", "wayback",
                                   "docker", "commoncrawl", "gitee", "npm"]]
        elif sources_str == "events":
            print("--- Events Monitor (real-time GitHub PushEvent) ---")
            from scanners.github_events import EventsMonitor
            import asyncio

            def on_key(k, repo, fpath, url):
                print(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")

            async def monitor():
                m = EventsMonitor(
                    token=args.github_token,
                    poll_interval=60,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                )
                m.on_key_found = on_key
                results = await m.search()
                if results:
                    engine._save_final([{
                        "key": r["key"],
                        "key_preview": r.get("key_preview", r["key"][:10] + "..." + r["key"][-4:]),
                        "valid": False,
                        "balance": 0,
                        "balance_usd": 0,
                        "balance_cny": 0,
                        "primary_currency": "N/A",
                        "repos": [{"repo": r.get("repo", ""), "file": r.get("file", ""),
                                   "url": r.get("url", "")}],
                        "verified_at": "",
                    } for r in results])

            asyncio.run(monitor())
            return

        elif args.monitor:
            print("--- Real-time monitor mode (GitHub Events API) ---")
            from scanners.github_events import EventsMonitor
            import asyncio

            def on_key(k, repo, fpath, url):
                print(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{fpath}")
                # Also verify immediately
                all_keys = {k: {"key": k, "key_preview": k[:10] + "..." + k[-4:],
                                "repos": [{"repo": repo, "file": fpath, "url": url}]}}
                results = engine._verify_dict(all_keys)
                engine._save_incremental([r for r in results if r.get("valid")], 0, 1)

            async def monitor():
                m = EventsMonitor(
                    token=args.github_token,
                    poll_interval=60,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                    max_events_per_poll=30,
                )
                m.on_key_found = on_key
                await m.search()

            asyncio.run(monitor())
            return
        else:
            sources = [s.strip() for s in sources_str.split(",") if s.strip()]

        print(f"--- Multi-source scan mode: {sources} ---")
        print(f"Sources: {len(sources)} | Concurrency: {args.concurrency} | Rate: {args.usd_cny_rate}")
        print(f"Output: {args.output_dir}")
        print()

        results = engine.run_multi_source(
            sources,
            queries=queries if not args.skip_builtin else [],
            github_token=args.github_token,
            gitlab_token=args.gitlab_token,
            gitee_token=args.gitee_token,
        )

        if args.min_balance is not None and args.min_balance > 0:
            before = len(results)
            results = [r for r in results if r["balance_usd"] >= args.min_balance]
            print(f"Balance filter: {before} -> {len(results)} (min ${args.min_balance})")

        engine._save_final(results)
        _print_summary(results, engine.usd_cny_rate)
        print(f"\nTotal time: {time.time()-t0:.1f}s")
        return

    # Dry run mode
    if args.dry_run:
        print(f"--- Dry Run (search only, no verify) ---")
        all_keys = engine.scan_github(queries)
        print(f"\nFound {len(all_keys)} candidate keys (unverified)")
        if all_keys:
            engine.save_progress(all_keys)
        return

    # Main pipeline: query by query -> search -> verify -> save -> check exit
    t0 = time.time()
    print(f"--- Pipeline: scan/verify/save on the fly (Ctrl+C for safe exit) ---")
    try:
        results = engine.run(queries)
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted, results auto-saved to {args.output_dir}")
        return

    # Min balance filter
    if args.min_balance is not None and args.min_balance > 0:
        before = len(results)
        results = [r for r in results if r["balance_usd"] >= args.min_balance]
        print(f"Balance filter: {before} -> {len(results)} (min ${args.min_balance})")

    # Write final CSV
    engine._save_final(results)
    _print_summary(results, engine.usd_cny_rate)
    print(f"\nTotal time: {time.time()-t0:.1f}s")


def _print_summary(results, rate):
    valid = [r for r in results if r.get("valid")]
    invalid = [r for r in results if r.get("valid") is False]
    positive = [r for r in valid if r["balance_usd"] > 0]
    zero = [r for r in valid if r["balance_usd"] == 0]
    negative = [r for r in valid if r["balance_usd"] < 0]

    print(f"\n{'='*60}")
    print(f"  Scan summary")
    print(f"{'='*60}")
    print(f"  Total keys scanned:  {len(results)}")
    print(f"  Valid keys:          {len(valid)}")
    print(f"  Invalid keys:        {len(invalid)}")
    print(f"  Positive (>$0):      {len(positive)}")
    print(f"  Zero (= $0):         {len(zero)}")
    print(f"  Overdue (< $0):      {len(negative)} (not counted in total value)")

    if positive:
        usd_pos = sum(r["balance_usd"] for r in positive)
        cny_pos = sum(r["balance_cny"] for r in positive)
        print(f"\n  Total positive balance: ${usd_pos:.2f} USD / ¥{cny_pos:.2f} CNY")
        print(f"  Rate: 1 USD = {rate} CNY")
        print(f"\n  Top positive-balance keys:")
        for i, r in enumerate(positive[:30]):
            cur = r.get("primary_currency", "USD")
            src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
            print(f"  {i+1:2d}. {r['key_preview']} | {cur} {r['balance']:.4f} "
                  f"| ≈${r['balance_usd']:.2f} / ¥{r['balance_cny']:.2f} | {src}")
    else:
        print(f"\n  No positive-balance keys (all valid keys have balance <= $0)")

    if zero:
        print(f"\n  Zero-balance keys ({len(zero)}) — may have been used or about to be topped up")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
