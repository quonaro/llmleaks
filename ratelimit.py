"""
Rate-limit machinery.

TokenPool    — multiple API tokens for search endpoints (GitHub/GitLab);
               picks the token with most remaining quota, honours resets.
DomainLimiter— per-host spacing with jitter + Retry-After handling.
ProxyPool    — round-robin proxies for *collection* sources that rate-limit
               per-IP (Common Crawl, Wayback, paste sites). NEVER used for
               provider verification — excluded domains are hard-blocked.
"""

import random
import threading
import time
import urllib.parse


class TokenPool:
    """Round-robin pool that prefers the token with the most quota left.

    Feed it every response's headers via update() so it learns each
    token's remaining/reset without extra calls.
    """

    def __init__(self, tokens: list[str]):
        self._lock = threading.Lock()
        self._tokens = {}
        for t in dict.fromkeys(t for t in tokens if t):
            self._tokens[t] = {"remaining": None, "reset": 0}
        self._rr = 0

    def __bool__(self):
        return bool(self._tokens)

    def acquire(self) -> str:
        """Best available token, or "" if pool is empty."""
        with self._lock:
            if not self._tokens:
                return ""
            now = int(time.time())
            # prefer tokens that are not exhausted
            avail = [t for t, st in self._tokens.items()
                     if st["remaining"] is None
                     or st["remaining"] > 0 or st["reset"] <= now]
            pool = avail or sorted(self._tokens,
                                   key=lambda t: self._tokens[t]["reset"])
            # among available, pick most remaining (None = unknown = fresh)
            best = max(pool, key=lambda t: self._tokens[t]["remaining"]
                       if self._tokens[t]["remaining"] is not None else 10**9)
            return best

    def update(self, token: str, headers) -> None:
        if not token or token not in self._tokens:
            return
        try:
            remaining = headers.get("X-RateLimit-Remaining")
            reset = headers.get("X-RateLimit-Reset")
            with self._lock:
                st = self._tokens[token]
                if remaining is not None:
                    st["remaining"] = int(remaining)
                if reset:
                    st["reset"] = int(reset)
        except (ValueError, TypeError, AttributeError):
            pass

    def cooldown(self, token: str, seconds: float) -> None:
        """Park a token after a 429/403 so other tokens get used."""
        if token in self._tokens:
            with self._lock:
                self._tokens[token]["remaining"] = 0
                self._tokens[token]["reset"] = int(time.time() + seconds)

    def status(self) -> dict:
        return {t[:8] + "…": dict(st) for t, st in self._tokens.items()}


class DomainLimiter:
    """Simple per-domain pacing: min interval between calls + jitter,
    plus global sleep when a server sends Retry-After."""

    def __init__(self, min_interval: float = 1.0, jitter: float = 0.3):
        self.min_interval = min_interval
        self.jitter = jitter
        self._lock = threading.Lock()
        self._next_ok = {}          # host -> earliest allowed ts
        self._blocked_until = {}    # host -> ts (Retry-After)

    def wait(self, url: str) -> float:
        host = urllib.parse.urlparse(url).netloc
        now = time.time()
        with self._lock:
            earliest = max(self._next_ok.get(host, 0),
                           self._blocked_until.get(host, 0))
            delay = earliest - now
            if delay <= 0:
                delay = 0
            wait_total = delay + self.min_interval * (1 + random.uniform(
                -self.jitter, self.jitter))
            self._next_ok[host] = now + wait_total
        if wait_total > 0:
            time.sleep(wait_total)
        return wait_total

    def on_retry_after(self, url: str, seconds: float) -> None:
        host = urllib.parse.urlparse(url).netloc
        with self._lock:
            self._blocked_until[host] = time.time() + seconds


# Provider API endpoints must never see rotating proxy IPs — fraud systems
# flag the key, which defeats responsible disclosure.
PROXY_EXCLUDED_DOMAINS = {
    "api.openai.com", "api.anthropic.com", "api.deepseek.com",
    "openrouter.ai", "api.groq.com", "api.x.ai", "api.replicate.com",
    "huggingface.co", "api.perplexity.ai", "api.fireworks.ai",
    "api.cerebras.ai", "api.mistral.ai", "api.together.xyz",
    "generativelanguage.googleapis.com", "opencode.ai",
}


class ProxyPool:
    """Round-robin proxies for collection-phase requests only."""

    def __init__(self, proxies: list[str] | None = None):
        self._lock = threading.Lock()
        self._proxies = list(proxies or [])
        self._bad = set()
        self._rr = 0

    @classmethod
    def from_file(cls, path: str) -> "ProxyPool":
        with open(path, "r", encoding="utf-8") as f:
            proxies = [ln.strip() for ln in f
                       if ln.strip() and not ln.startswith("#")]
        return cls(proxies)

    def __bool__(self):
        return bool(self._proxies)

    def allowed_for(self, url: str) -> bool:
        host = urllib.parse.urlparse(url).netloc.lower()
        return not any(host == d or host.endswith("." + d)
                       for d in PROXY_EXCLUDED_DOMAINS)

    def next(self, url: str = "") -> str | None:
        """Next healthy proxy, or None. Returns None for excluded domains."""
        if url and not self.allowed_for(url):
            return None
        with self._lock:
            healthy = [p for p in self._proxies if p not in self._bad]
            if not healthy:
                return None
            self._rr = (self._rr + 1) % len(healthy)
            return healthy[self._rr]

    def mark_bad(self, proxy: str) -> None:
        with self._lock:
            self._bad.add(proxy)

    def status(self) -> dict:
        return {"total": len(self._proxies), "bad": len(self._bad)}
