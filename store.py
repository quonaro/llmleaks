"""
Findings storage — SQLite, hash-only.

Raw keys are NEVER written to disk. We store sha256(key) + a short preview
(sk-abc…wxyz). The raw key lives only in process memory between detection
and verification; after that it is gone.
"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT, ended_at TEXT,
    sources TEXT, providers TEXT,
    queries_run INTEGER DEFAULT 0,
    candidates INTEGER DEFAULT 0,
    valid INTEGER DEFAULT 0,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    key_hash TEXT PRIMARY KEY,
    key_preview TEXT,
    provider TEXT,
    status TEXT,               -- valid|revoked|no_quota|rate_limited|...
    severity TEXT,
    balance REAL,
    balance_usd REAL,
    balance_cny REAL,
    currency TEXT,
    note TEXT,
    first_seen TEXT,
    last_seen TEXT,
    verified_at TEXT,
    notified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT,
    source TEXT,
    repo TEXT,
    file TEXT,
    url TEXT,
    query TEXT,
    seen_at TEXT,
    UNIQUE(key_hash, source, repo, file)
);
CREATE INDEX IF NOT EXISTS idx_occ_hash ON occurrences(key_hash);
CREATE INDEX IF NOT EXISTS idx_find_status ON findings(status);
"""


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def key_preview(key: str) -> str:
    return key[:10] + "..." + key[-4:] if len(key) > 14 else key[:4] + "..."


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript(SCHEMA)

    # ---- scans ---------------------------------------------------------

    def start_scan(self, sources: list, providers: list) -> int:
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO scans(started_at, sources, providers) VALUES(?,?,?)",
                (datetime.now().isoformat(), ",".join(sources or []),
                 ",".join(providers or [])))
            return cur.lastrowid

    def end_scan(self, scan_id: int, queries: int = 0, candidates: int = 0,
                 valid: int = 0, notes: str = ""):
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE scans SET ended_at=?, queries_run=?, candidates=?, "
                "valid=?, notes=? WHERE id=?",
                (datetime.now().isoformat(), queries, candidates, valid,
                 notes, scan_id))

    # ---- findings ------------------------------------------------------

    def upsert_result(self, r: dict, source: str = "", query: str = "") -> str:
        """Store one engine result dict. Raw key is hashed and discarded."""
        key = r.get("key", "")
        if not key:
            return ""
        h = key_hash(key)
        now = datetime.now().isoformat()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT first_seen FROM findings WHERE key_hash=?", (h,)).fetchone()
            if row:
                self.conn.execute(
                    """UPDATE findings SET status=?, balance=?, balance_usd=?,
                       balance_cny=?, currency=?, note=?, last_seen=?,
                       verified_at=?, provider=?, key_preview=?,
                       severity=? WHERE key_hash=?""",
                    (r.get("status") or ("valid" if r.get("valid") else "revoked"),
                     r.get("balance", 0), r.get("balance_usd", 0),
                     r.get("balance_cny", 0), r.get("primary_currency", ""),
                     r.get("provider_note", "") or r.get("reason", ""),
                     now, r.get("verified_at", now),
                     r.get("provider", "unknown"),
                     r.get("key_preview") or key_preview(key),
                     r.get("severity", ""), h))
            else:
                self.conn.execute(
                    """INSERT INTO findings(key_hash, key_preview, provider,
                       status, severity, balance, balance_usd, balance_cny,
                       currency, note, first_seen, last_seen, verified_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (h, r.get("key_preview") or key_preview(key),
                     r.get("provider", "unknown"),
                     r.get("status") or ("valid" if r.get("valid") else "revoked"),
                     r.get("severity", ""),
                     r.get("balance", 0), r.get("balance_usd", 0),
                     r.get("balance_cny", 0), r.get("primary_currency", ""),
                     r.get("provider_note", "") or r.get("reason", ""),
                     now, now, r.get("verified_at", now)))
            for occ in r.get("repos", [])[:10]:
                self.conn.execute(
                    """INSERT OR IGNORE INTO occurrences
                       (key_hash, source, repo, file, url, query, seen_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (h, source or r.get("source", ""), occ.get("repo", ""),
                     occ.get("file", ""), occ.get("url", ""), query, now))
        return h

    # ---- queries -------------------------------------------------------

    def stats(self) -> dict:
        c = self.conn
        total = c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        by_status = {r["status"]: r["n"] for r in c.execute(
            "SELECT status, COUNT(*) n FROM findings GROUP BY status")}
        by_provider = {r["provider"]: r["n"] for r in c.execute(
            "SELECT provider, COUNT(*) n FROM findings "
            "WHERE status IN ('valid','no_quota') GROUP BY provider")}
        by_source = {r["source"]: r["n"] for r in c.execute(
            "SELECT source, COUNT(DISTINCT key_hash) n FROM occurrences "
            "GROUP BY source")}
        usd = c.execute(
            "SELECT COALESCE(SUM(balance_usd),0) s FROM findings "
            "WHERE status='valid'").fetchone()["s"]
        scans = c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
        return {"total_findings": total, "by_status": by_status,
                "valid_by_provider": by_provider,
                "unique_by_source": by_source,
                "total_balance_usd": usd, "scans": scans}

    def findings(self, status: str | None = None,
                 provider: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE 1=1"
        args = []
        if status:
            q += " AND status=?"; args.append(status)
        if provider:
            q += " AND provider=?"; args.append(provider)
        q += " ORDER BY balance_usd DESC"
        return [dict(r) for r in self.conn.execute(q, args)]

    def occurrences(self, key_hash_: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM occurrences WHERE key_hash=?", (key_hash_,))]

    # ---- export --------------------------------------------------------

    def export_csv(self, path: str, status: str | None = None):
        rows = self.findings(status=status)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("key_hash,key_preview,provider,status,balance_usd,"
                    "balance_cny,currency,first_seen,last_seen,repos\n")
            for r in rows:
                repos = "; ".join(o["repo"] for o in
                                  self.occurrences(r["key_hash"])[:3])
                f.write(f'{r["key_hash"]},{r["key_preview"]},{r["provider"]},'
                        f'{r["status"]},{r["balance_usd"] or 0:.2f},'
                        f'{r["balance_cny"] or 0:.2f},{r["currency"]},'
                        f'{r["first_seen"]},{r["last_seen"]},"{repos}"\n')

    def export_json(self, path: str, status: str | None = None):
        rows = self.findings(status=status)
        for r in rows:
            r["occurrences"] = self.occurrences(r["key_hash"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)

    def report_markdown(self, path: str):
        s = self.stats()
        valid = self.findings(status="valid")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Leaked API Key Research — Findings Report\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write("## Summary\n\n| Metric | Value |\n|---|---|\n")
            f.write(f"| Total unique keys seen | {s['total_findings']} |\n")
            for st, n in s["by_status"].items():
                f.write(f"| status={st} | {n} |\n")
            f.write(f"| Total USD balance (valid keys) | ${s['total_balance_usd']:.2f} |\n")
            f.write(f"| Scan runs | {s['scans']} |\n")
            f.write("\n## Valid keys by provider\n\n| Provider | Count |\n|---|---|\n")
            for p, n in sorted(s["valid_by_provider"].items(),
                               key=lambda x: -x[1]):
                f.write(f"| {p} | {n} |\n")
            f.write("\n## Unique keys by source\n\n| Source | Count |\n|---|---|\n")
            for src, n in sorted(s["unique_by_source"].items(),
                                 key=lambda x: -x[1]):
                f.write(f"| {src or '?'} | {n} |\n")
            f.write("\n## Top findings (valid, by balance)\n\n")
            f.write("| Key preview | Provider | USD | First seen | Repo |\n"
                    "|---|---|---|---|---|\n")
            for r in valid[:50]:
                repos = "; ".join(o["repo"] for o in
                                  self.occurrences(r["key_hash"])[:2])
                f.write(f"| `{r['key_preview']}` | {r['provider']} | "
                        f"${r['balance_usd'] or 0:.2f} | "
                        f"{(r['first_seen'] or '')[:10]} | {repos} |\n")

    def close(self):
        self.conn.close()
