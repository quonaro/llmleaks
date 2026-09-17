"""
Provider registry + candidate detection.

Each provider defines:
  - key_patterns    : regexes that identify the raw secret
  - context_keywords: strings that hint at the provider in surrounding code
  - verify spec     : single read-only GET used to check if a key is live
  - balance spec    : optional second GET, gated behind --with-balance

Ambiguous keys (plain `sk-...` shared by DeepSeek/OpenAI/others) get an
ordered provider-candidate list; the verifier tries at most MAX_TRIES.
"""

import math
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    display: str
    key_patterns: tuple  # tuple[re.Pattern]
    context_keywords: tuple = ()
    verify_url: str | None = None
    auth_scheme: str = "bearer"          # bearer | x-api-key | query-key
    extra_headers: dict = field(default_factory=dict)
    invalid_statuses: tuple = (401, 403)  # codes meaning "key rejected"
    balance_url: str | None = None       # probed only when check_balance=True
    severity: str = "medium"             # default severity for live keys
    confidence: str = "high"             # pattern uniqueness: high|medium|low
    needs_context: bool = False          # require context match to emit candidate


def _rx(*patterns: str) -> tuple:
    return tuple(re.compile(p) for p in patterns)


PROVIDERS: dict[str, ProviderSpec] = {p.name: p for p in [
    ProviderSpec(
        name="openai", display="OpenAI",
        key_patterns=_rx(
            r"sk-proj-[A-Za-z0-9_\-]{20,200}",
            r"sk-svcacct-[A-Za-z0-9_\-]{20,200}",
            r"sk-admin-[A-Za-z0-9_\-]{20,200}",
            r"sk-[A-Za-z0-9]{43,100}",          # legacy T1 keys (sk- + 48)
        ),
        context_keywords=("openai", "api.openai.com", "openai_api_key",
                          "openai_key", "openai_token"),
        verify_url="https://api.openai.com/v1/models",
        balance_url="https://api.openai.com/dashboard/billing/credit_grants",
        severity="high",
    ),
    ProviderSpec(
        name="anthropic", display="Anthropic",
        key_patterns=_rx(r"sk-ant-[a-zA-Z0-9_\-]{40,140}"),
        context_keywords=("anthropic", "claude", "api.anthropic.com",
                          "anthropic_api_key"),
        verify_url="https://api.anthropic.com/v1/models",
        auth_scheme="x-api-key",
        extra_headers={"anthropic-version": "2023-06-01"},
        severity="critical",
    ),
    ProviderSpec(
        name="openrouter", display="OpenRouter",
        key_patterns=_rx(r"sk-or-v1-[a-f0-9]{64}"),
        context_keywords=("openrouter", "openrouter.ai", "openrouter_api_key"),
        verify_url="https://openrouter.ai/api/v1/auth/key",
        balance_url=None,  # /auth/key already returns limit+usage for free
        severity="high",
    ),
    ProviderSpec(
        name="deepseek", display="DeepSeek",
        key_patterns=_rx(r"sk-[a-zA-Z0-9]{20,42}"),
        context_keywords=("deepseek", "api.deepseek.com", "deepseek_api_key",
                          "deepseek_key", "deepseek_token", "ds_api_key"),
        verify_url="https://api.deepseek.com/models",
        balance_url="https://api.deepseek.com/user/balance",
        severity="high",
    ),
    ProviderSpec(
        name="opencode", display="OpenCode Zen",
        key_patterns=_rx(),
        context_keywords=("opencode", "opencode.ai", "opencode_api_key",
                          "zen/v1"),
        verify_url=None,  # /zen/v1/models is public (200 without auth)
        confidence="low", needs_context=True,
    ),
    ProviderSpec(
        name="groq", display="Groq",
        key_patterns=_rx(r"gsk_[A-Za-z0-9]{40,60}"),
        context_keywords=("groq", "api.groq.com", "groq_api_key"),
        verify_url="https://api.groq.com/openai/v1/models",
    ),
    ProviderSpec(
        name="xai", display="xAI",
        key_patterns=_rx(r"xai-[A-Za-z0-9]{60,90}"),
        context_keywords=("xai", "x.ai", "grok", "xai_api_key"),
        verify_url="https://api.x.ai/v1/api-key",
        invalid_statuses=(400, 401, 403),  # xAI returns 400 for bad-format keys
    ),
    ProviderSpec(
        name="huggingface", display="HuggingFace",
        key_patterns=_rx(r"hf_[A-Za-z0-9]{30,40}"),
        context_keywords=("huggingface", "hf_", "hf_token", "huggingface_hub"),
        verify_url="https://huggingface.co/api/whoami-v2",
        severity="high",
    ),
    ProviderSpec(
        name="replicate", display="Replicate",
        key_patterns=_rx(r"r8_[A-Za-z0-9]{36,44}"),
        context_keywords=("replicate", "replicate_api_token"),
        verify_url="https://api.replicate.com/v1/models",
    ),
    ProviderSpec(
        name="perplexity", display="Perplexity",
        key_patterns=_rx(r"pplx-[a-f0-9]{48}"),
        context_keywords=("perplexity", "pplx", "perplexity_api_key"),
        verify_url="https://api.perplexity.ai/v1/models",
        confidence="medium",
    ),
    ProviderSpec(
        name="fireworks", display="Fireworks",
        key_patterns=_rx(r"fw_[A-Za-z0-9]{40,60}"),
        context_keywords=("fireworks", "fireworks.ai", "fireworks_api_key"),
        verify_url="https://api.fireworks.ai/inference/v1/models",
        confidence="medium",
    ),
    ProviderSpec(
        name="cerebras", display="Cerebras",
        key_patterns=_rx(r"csk-[a-zA-Z0-9]{40,60}"),
        context_keywords=("cerebras", "cerebras_api_key"),
        verify_url="https://api.cerebras.ai/v1/models",
        confidence="medium",
    ),
    ProviderSpec(
        name="mistral", display="Mistral",
        key_patterns=_rx(),
        context_keywords=("mistral", "api.mistral.ai", "mistral_api_key"),
        verify_url="https://api.mistral.ai/v1/models",
        confidence="low", needs_context=True,
    ),
    ProviderSpec(
        name="together", display="Together",
        key_patterns=_rx(),
        context_keywords=("together", "api.together.xyz", "together_api_key"),
        verify_url="https://api.together.xyz/v1/models",
        confidence="low", needs_context=True,
    ),
    ProviderSpec(
        name="google", display="Google AI",
        key_patterns=_rx(r"AIza[A-Za-z0-9_\-]{35}"),
        context_keywords=("generativelanguage", "gemini", "google_api_key",
                          "googleai", "makersuite"),
        verify_url="https://generativelanguage.googleapis.com/v1beta/models",
        auth_scheme="query-key",
        confidence="medium",  # AIza* covers all of Google Cloud — expect FPs
        severity="high",
    ),
]}

# Ordered fallback for ambiguous `sk-` keys with no context signal.
AMBIGUOUS_ORDER = ["deepseek", "openai", "openrouter", "opencode"]

# Generic catch-all used by scanners; provider-specific patterns run first.
GENERIC_SK = re.compile(r"sk-[a-zA-Z0-9_\-]{20,120}")
GENERIC_TOKEN = re.compile(
    r"(sk-[a-zA-Z0-9_\-]{20,120}|gsk_[A-Za-z0-9]{40,60}|hf_[A-Za-z0-9]{30,40}|"
    r"r8_[A-Za-z0-9]{36,44}|pplx-[a-f0-9]{48}|xai-[A-Za-z0-9]{60,90}|"
    r"fw_[A-Za-z0-9]{40,60}|csk-[a-zA-Z0-9]{40,60}|AIza[A-Za-z0-9_\-]{35})"
)

MAX_TRIES = 3  # max provider endpoints probed for one ambiguous key

# Assignment-style token capture for context-only providers:
#   mistral_api_key = "Ab3d..."  →  captures the quoted/bare value
GENERIC_LONG_TOKEN = re.compile(
    r"[\"'`\s:=]+[\"'`]?([A-Za-z0-9][A-Za-z0-9_\-]{29,79})[\"'`]?"
)

PLACEHOLDER_WORDS = (
    "your", "xxx", "example", "placeholder", "replace", "here", "demo",
    "sample", "fake", "dummy", "changeme", "insert", "redacted", "todo",
    "sk-xxxx", "sk-0000", "sk-1111", "sk-aaaa", "sk-bbbb", "sk-test",
)

LOW_VALUE_PATH_KEYWORDS = (
    "/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/demo/",
    "/examples/", "/samples/", "/target/site/", "/target/classes/",
    "test.py", "test.js", "test.ts", "test.java", "test.kt",
    "example.py", "example.js", "sample.py", "sample.java",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def looks_placeholder(key: str) -> bool:
    lower = key.lower()
    if any(w in lower for w in PLACEHOLDER_WORDS):
        return True
    body = re.sub(r"^[a-z]+[-_]", "", lower)  # strip prefix like sk-, sk-proj-
    if body.isdigit() or len(set(body)) < 4:
        return True
    # low entropy body = repeated/sequential chars
    if shannon_entropy(body) < 3.2:
        return True
    return False


def low_value_context(file_path: str, repo: str = "") -> bool:
    lower = f"{file_path}/{repo}".lower()
    return any(kw in lower for kw in LOW_VALUE_PATH_KEYWORDS)


@dataclass
class Candidate:
    key: str
    providers: list           # ordered provider names to try
    definite: bool = False    # pattern uniquely identifies the provider


class Detector:
    """Extract key candidates from text and rank provider guesses."""

    def __init__(self, providers: list | None = None):
        self.active = providers or list(PROVIDERS)
        self.specs = [PROVIDERS[p] for p in self.active if p in PROVIDERS]

    def _context_hit(self, provider: ProviderSpec, context: str) -> bool:
        ctx = context.lower()
        return any(kw in ctx for kw in provider.context_keywords)

    def classify(self, key: str, context: str = "") -> tuple[list, bool]:
        """Ordered provider candidates + whether the match is definitive."""
        # pattern match: collect providers whose patterns hit
        hits = [s.name for s in self.specs
                if any(rx.fullmatch(key) for rx in s.key_patterns)]
        if len(hits) == 1:
            return hits, True
        # generic sk- hit by several providers → disambiguate by context
        if hits:
            ctx_ranked = [s.name for s in self.specs
                          if s.name in hits and self._context_hit(s, context)]
            # length heuristic: OpenAI legacy keys are longer (~51 total)
            # than DeepSeek (~35). Bias the probe order accordingly.
            if "deepseek" in hits and "openai" in hits:
                first = "openai" if len(key) >= 46 else "deepseek"
                if first not in ctx_ranked:
                    ctx_ranked = [first] + ctx_ranked
            ordered = ctx_ranked + [p for p in AMBIGUOUS_ORDER
                                    if p in hits and p not in ctx_ranked]
            ordered += [p for p in hits if p not in ordered]
            return ordered[:MAX_TRIES], False
        # no pattern hit; context-only providers (mistral/together/...)
        if context:
            ctx = [s.name for s in self.specs
                   if s.needs_context and self._context_hit(s, context)]
            if ctx:
                return ctx, False
        return [], False

    def extract(self, text: str, context: str = "") -> list[Candidate]:
        out, seen = [], set()
        text = text or ""
        for m in GENERIC_TOKEN.finditer(text):
            key = m.group(0)
            if key in seen or looks_placeholder(key):
                continue
            providers, definite = self.classify(key, context)
            if not providers:
                continue  # active provider set doesn't claim this key
            seen.add(key)
            out.append(Candidate(key=key, providers=providers, definite=definite))

        # context-only providers (no unique prefix): if the provider's
        # keywords appear in context OR the text itself, scan a small
        # window after each in-text keyword for a generic long token.
        low_text = text.lower()
        ctx = context.lower()
        for spec in self.specs:
            if not spec.needs_context:
                continue
            if not any(kw in low_text or kw in ctx
                       for kw in spec.context_keywords):
                continue
            for kw in spec.context_keywords:
                for km in re.finditer(re.escape(kw), low_text):
                    window = text[km.start(): km.start() + 300]
                    for tm in GENERIC_LONG_TOKEN.finditer(window):
                        key = tm.group(1)
                        if key not in seen and not looks_placeholder(key):
                            seen.add(key)
                            out.append(Candidate(key=key, providers=[spec.name]))
        return out

    def extract_keys(self, text: str, context: str = "") -> list[str]:
        return [c.key for c in self.extract(text, context)]


def preview(key: str) -> str:
    return key[:10] + "..." + key[-4:] if len(key) > 14 else key[:4] + "..."


def provider_table() -> str:
    rows = []
    for p in PROVIDERS.values():
        pats = ", ".join(rx.pattern[:40] for rx in p.key_patterns) or "(context-only)"
        rows.append(f"  {p.name:<12} {p.display:<12} sev={p.severity:<8} {pats}")
    return "\n".join(rows)
