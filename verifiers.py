"""
Minimal-touch key verification.

Policy (kept deliberately strict — this is what separates research from abuse):
  * exactly ONE read-only GET per provider candidate, MAX_TRIES candidates max
  * no retries on 401/403 — that verdict is final
  * balance endpoints are probed ONLY when check_balance=True
  * every request carries an identifying research User-Agent
  * never send verification traffic through proxies (engine enforces this)
"""

import asyncio
import aiohttp

from detectors import PROVIDERS, ProviderSpec

RESEARCH_UA = "llmleaks-research/1.0 (+leaked-api-key-research; responsible-disclosure)"

# verdict.status values:
#   valid        — provider confirmed the key
#   revoked      — 401/403: key rejected (dead or invalid format)
#   no_quota     — key works but account is out of credit (402)
#   rate_limited — provider throttled us (429); retryable later
#   timeout      — network timeout
#   error        — other network/parse failure
#   unverifiable — provider has no cheap read endpoint / unexpected response


def _auth_headers(spec: ProviderSpec, key: str, url: str) -> tuple[dict, str]:
    """Build auth for the verify request. Returns (headers, possibly-rewritten url)."""
    headers = {"User-Agent": RESEARCH_UA, "Accept": "application/json"}
    headers.update(spec.extra_headers)
    if spec.auth_scheme == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    elif spec.auth_scheme == "x-api-key":
        headers["x-api-key"] = key
    elif spec.auth_scheme == "query-key":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}key={key}"
    return headers, url


def _rate_limit_meta(headers) -> dict:
    """Free impact signal: providers disclose tier limits in response headers."""
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk.startswith(("x-ratelimit", "retry-after", "x-request-id")):
            out[lk] = v
    return out


def _parse_generic_models(data, provider: str) -> dict:
    """OpenAI-compatible GET /models → {"object": "list", "data": [...]}"""
    if isinstance(data, dict) and "data" in data:
        return {"valid": True, "total_balance": 0.0, "balance_details": [],
                "primary_currency": "USD", "balance_unavailable": True,
                "provider_note": "valid (no balance endpoint)"}
    return {"valid": False, "reason": "unexpected_response"}


def _parse_deepseek_balance(data: dict) -> dict:
    infos = data.get("balance_infos", [])
    total, details, primary = 0.0, [], "USD"
    for i in infos:
        cur = i.get("currency", "?")
        t = float(i.get("total_balance", 0))
        total += t
        details.append({"currency": cur, "total_balance": t,
                        "granted_balance": float(i.get("granted_balance", 0)),
                        "tipped_balance": float(i.get("tipped_balance", 0))})
        if cur == "CNY":
            primary = "CNY"
    return {"valid": True, "total_balance": total, "balance_details": details,
            "primary_currency": primary}


def _parse_openai_credits(data: dict) -> dict:
    grants = data.get("grants", {}).get("data", [])
    total = sum(float(g.get("credit_amount", 0)) for g in grants)
    used = sum(float(g.get("used_amount", 0)) for g in grants)
    return {"valid": True, "total_balance": total - used, "balance_details": [],
            "primary_currency": "USD",
            "openai_grants": {"total": total, "used": used}}


def _parse_openrouter_key(data: dict) -> dict:
    """GET /auth/key returns limit+usage — balance metadata without extra calls."""
    d = data.get("data", {}) if isinstance(data, dict) else {}
    if not d:
        return {"valid": False, "reason": "unexpected_response"}
    limit = d.get("limit")
    usage = float(d.get("usage", 0) or 0)
    note = f"limit={limit if limit is not None else 'unlimited'}, usage={usage}"
    out = {"valid": True, "total_balance": (float(limit) - usage) if limit else 0.0,
           "balance_details": [], "primary_currency": "USD",
           "balance_unavailable": limit is None, "provider_note": note}
    return out


def _parse_hf_whoami(data: dict) -> dict:
    if data.get("name") or data.get("fullname") or data.get("type"):
        scope = data.get("auth", {}).get("accessToken", {}).get("role", "")
        return {"valid": True, "total_balance": 0.0, "balance_details": [],
                "primary_currency": "USD", "balance_unavailable": True,
                "provider_note": f"user={data.get('name','?')} role={scope or '?'}"}
    return {"valid": False, "reason": "unexpected_response"}


_RESPONSE_PARSERS = {
    "deepseek": _parse_generic_models,     # /models proves validity; balance is separate
    "openai": _parse_generic_models,
    "openrouter": _parse_openrouter_key,
    "opencode": _parse_generic_models,
    "groq": _parse_generic_models,
    "xai": _parse_generic_models,
    "anthropic": _parse_generic_models,
    "huggingface": _parse_hf_whoami,
    "replicate": _parse_generic_models,
    "perplexity": _parse_generic_models,
    "fireworks": _parse_generic_models,
    "cerebras": _parse_generic_models,
    "mistral": _parse_generic_models,
    "together": _parse_generic_models,
    "google": _parse_generic_models,
}

_BALANCE_PARSERS = {
    "deepseek": _parse_deepseek_balance,
    "openai": _parse_openai_credits,
}


async def _probe(session: aiohttp.ClientSession, spec: ProviderSpec,
                 url: str, key: str, timeout: int) -> tuple[int, dict, dict]:
    """Single GET. Returns (http_status, json_or_empty, response_headers)."""
    headers, url = _auth_headers(spec, key, url)
    async with session.get(url, headers=headers,
                           timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
        status = resp.status
        rl = _rate_limit_meta(resp.headers)
        try:
            data = await resp.json(content_type=None)
        except Exception:
            data = {}
        return status, data if isinstance(data, dict) else {}, rl


async def _verify_at_provider(session, spec: ProviderSpec, key: str,
                              check_balance: bool, timeout: int) -> dict:
    """One verify GET (+ optional balance GET) against a single provider."""
    if not spec.verify_url:
        return {"valid": False, "status": "unverifiable",
                "reason": f"{spec.name}:no_verify_endpoint"}

    try:
        status, data, rl = await _probe(session, spec, spec.verify_url,
                                        key, timeout)
    except asyncio.TimeoutError:
        return {"valid": False, "status": "timeout", "reason": f"{spec.name}:timeout"}
    except Exception as e:
        return {"valid": False, "status": "error",
                "reason": f"{spec.name}:{type(e).__name__}"}

    base = {"provider": spec.name, "http_status": status, "rate_limit": rl}

    if status in spec.invalid_statuses:
        return {**base, "valid": False, "status": "revoked",
                "reason": f"{spec.name}:invalid_key"}
    if status == 402:
        return {**base, "valid": True, "status": "no_quota",
                "total_balance": 0.0, "primary_currency": "USD",
                "balance_unavailable": True,
                "reason": f"{spec.name}:payment_required"}
    if status == 429:
        return {**base, "valid": False, "status": "rate_limited",
                "reason": f"{spec.name}:rate_limited"}
    if status != 200:
        return {**base, "valid": False, "status": "unverifiable",
                "reason": f"{spec.name}:HTTP_{status}"}

    parser = _RESPONSE_PARSERS.get(spec.name, _parse_generic_models)
    parsed = parser(data, spec.name)
    if not parsed.get("valid"):
        return {**base, "valid": False, "status": "unverifiable",
                "reason": f"{spec.name}:{parsed.get('reason', 'parse_error')}"}

    result = {**base, **parsed, "status": "valid"}

    # Optional balance probe — second GET, only when explicitly enabled.
    if check_balance and spec.balance_url:
        try:
            b_status, b_data, _ = await _probe(session, spec, spec.balance_url,
                                               key, timeout)
            if b_status == 200:
                bp = _BALANCE_PARSERS.get(spec.name)
                if bp:
                    b = bp(b_data)
                    result.update({
                        "total_balance": b.get("total_balance", 0.0),
                        "balance_details": b.get("balance_details", []),
                        "primary_currency": b.get("primary_currency", "USD"),
                        "balance_unavailable": False,
                        "provider_note": "",
                    })
                    result.update({k: v for k, v in b.items()
                                   if k not in result})
        except Exception:
            pass  # balance is best-effort; validity already established
    return result


async def verify_key(session: aiohttp.ClientSession, key: str,
                     providers: list, check_balance: bool = False,
                     timeout: int = 15) -> dict:
    """Try provider candidates in order; stop at first confirmed key."""
    candidates = [PROVIDERS[p] for p in providers if p in PROVIDERS]
    if not candidates:
        return {"valid": False, "status": "unverifiable",
                "reason": "no_provider_candidates", "provider": "unknown"}

    last = None
    for spec in candidates:
        r = await _verify_at_provider(session, spec, key, check_balance, timeout)
        if r.get("status") in ("valid", "no_quota"):
            return r
        last = r
        # rate_limited/timeout on this provider → try next candidate anyway
    return last or {"valid": False, "status": "error", "reason": "no_result"}
