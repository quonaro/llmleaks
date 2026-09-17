"""
API Key Hunter - multi-provider scan engine core module
Supports DeepSeek / OpenAI / OpenRouter + CLI / GUI
"""

import asyncio
import aiohttp
import subprocess
import json
import re
import time
import os
import sys
import random
import urllib.parse
import fnmatch
import requests
from datetime import datetime
from typing import Callable, Optional

# Scanner imports for multi-source mode
from scanners.base import extract_keys as scanner_extract_keys, is_bad_key as _scanner_is_bad_key
from detectors import Detector, PROVIDERS as _PROVIDER_SPECS
from verifiers import verify_key as _verify_key_external, RESEARCH_UA
from ratelimit import TokenPool, ProxyPool
from store import Store, key_hash as _key_hash
from scanners.github_gist import GistScanner
from scanners.github_issues import IssuesScanner
from scanners.github_events import EventsMonitor
from scanners.github_commits import CommitsScanner
from scanners.gitlab import GitLabScanner
from scanners.wayback import WaybackScanner
from scanners.docker import DockerHubScanner
from scanners.commoncrawl import CommonCrawlScanner
from scanners.gitee import GiteeScanner
from scanners.npm_registry import NpmScanner
from scanners.huggingface import HuggingFaceScanner
from scanners.pypi import PyPIScanner
from scanners.stackoverflow import StackOverflowScanner

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Default exchange rate (1 USD = ? CNY)
DEFAULT_USD_CNY_RATE = 7.25

# sentinel: "use the proxy pool" vs an explicit proxy/None override
_AUTO = object()

KEY_PATTERN = re.compile(r"sk-[a-zA-Z0-9]{32,100}")

# ═══════════════════════════════════════════════════════════════════
#  Multi-Provider Verification — Try each provider until one matches
# ═══════════════════════════════════════════════════════════════════

PROVIDER_CONFIGS = [
    {
        "name": "deepseek",
        "display": "DeepSeek",
        "base": "https://api.deepseek.com",
        "balance_url": "/user/balance",
    },
    {
        "name": "openai",
        "display": "OpenAI",
        "base": "https://api.openai.com",
        "balance_url": "/v1/models",
    },
    {
        "name": "openrouter",
        "display": "OpenRouter",
        "base": "https://openrouter.ai/api/v1",
        "balance_url": "/key",
        "credit_url": "/credits",
    },
    {
        "name": "opencode",
        "display": "OpenCode Zen",
        "base": "https://opencode.ai",
        "balance_url": "/zen/v1/models",
    },
]


def _parse_deepseek_balance(data: dict) -> dict:
    """Parse DeepSeek /user/balance response."""
    balance_infos = data.get("balance_infos", [])
    total = 0.0
    details = []
    primary_currency = "USD"
    for info in balance_infos:
        currency = info.get("currency", "unknown")
        t = float(info.get("total_balance", 0))
        g = float(info.get("granted_balance", 0))
        tp = float(info.get("tipped_balance", 0))
        total += t
        details.append({"currency": currency, "total_balance": t,
                        "granted_balance": g, "tipped_balance": tp})
        if currency == "CNY":
            primary_currency = "CNY"
    return {"valid": True, "total_balance": total, "balance_details": details,
            "primary_currency": primary_currency}


def _parse_openai_models(data: dict) -> dict:
    """Parse OpenAI /v1/models — confirms key validity (official method).
    OpenAI no longer exposes balance/credits via public API.
    For billing info, use https://platform.openai.com/settings/organization/billing/credit-grants"""
    if data.get("object") == "list" and "data" in data:
        return {"valid": True, "total_balance": 0.0, "balance_details": [],
                "primary_currency": "USD", "balance_unavailable": True,
                "provider_note": "Valid key (balance not available via API — check Platform Billing)"}
    return {"valid": False, "reason": "unexpected_response"}


def _parse_openai_credits(data: dict) -> dict:
    """Parse OpenAI /dashboard/billing/credit_grants response."""
    grants = data.get("grants", {}).get("data", [])
    total = sum(float(g.get("credit_amount", 0)) for g in grants)
    used = sum(float(g.get("used_amount", 0)) for g in grants)
    balance = total - used
    return {"valid": True, "total_balance": balance, "balance_details": [],
            "primary_currency": "USD", "openai_grants": {"total": total, "used": used}}


def _parse_openrouter_balance(data: dict) -> dict:
    """Parse OpenRouter /key response — confirms key validity, balance comes from /credits."""
    key_data = data.get("data", {})
    if key_data:
        return {"valid": True, "total_balance": 0.0, "balance_details": [],
                "primary_currency": "USD", "balance_unavailable": True,
                "provider_note": f"limit={key_data.get('limit', '?')}, usage={key_data.get('usage', 0)}"}
    return {"valid": False, "reason": "unexpected_response"}


def _parse_openrouter_credits(data: dict) -> dict:
    """Parse OpenRouter /credits response."""
    credits_data = data.get("data", {})
    total_credits = float(credits_data.get("total_credits", 0))
    total_usage = float(credits_data.get("total_usage", 0))
    balance = total_credits - total_usage
    return {"valid": True, "total_balance": balance, "balance_details": [],
            "primary_currency": "USD",
            "openrouter_credits": {"total_credits": total_credits, "total_usage": total_usage}}


# ═══════════════════════════════════════════════════════════════════
#  Ultimate query library (sorted by yield — high → low)
#  Based on: field-test data + GitGuardian 2025 + TruffleHog + GH Dorking research
# ═══════════════════════════════════════════════════════════════════

BUILTIN_QUERIES = [
    # ═══════════════════════════════════════════════════════
    #  🔥 Tier 1 — highest yield in field tests (Java/Kotlin/PHP/Python)
    # ═══════════════════════════════════════════════════════

    # Java (Spring Boot / Android — 90+ keys in field tests)
    "deepseek sk- filename:java",
    "deepseek sk- filename:properties",
    "deepseek sk- filename:gradle",

    # Kotlin (Android — 22 keys in field tests)
    "deepseek sk- filename:kt",

    # PHP (web backend — 26 keys in field tests)
    "deepseek sk- filename:php",
    "api.deepseek.com sk- filename:php",

    # Python (hardcoded AI/ML code)
    "deepseek sk- language:Python NOT env NOT export",
    "deepseek sk- filename:py NOT env",
    "deepseek OpenAI(api_key sk- filename:py",
    "deepseek client sk- filename:py",
    "deepseek def sk- filename:py",
    "deepseek requests sk- filename:py",
    "api.deepseek.com sk- filename:py",

    # ═══════════════════════════════════════════════════════
    #  🔥 Tier 2 — config file leaks (.env / config)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:env",
    "deepseek sk- filename:env.local",
    "deepseek sk- filename:env.production",
    "deepseek sk- filename:env.development",
    "deepseek sk- filename:env.example",
    "deepseek sk- filename:env.sample",
    "deepseek sk- filename:env.backup",
    "deepseek sk- filename:credentials",
    "deepseek sk- filename:secrets",

    # Config files
    "deepseek sk- filename:yml",
    "deepseek sk- filename:yaml",
    "deepseek sk- filename:json",
    "deepseek sk- filename:toml",
    "deepseek sk- filename:cfg",
    "deepseek sk- filename:ini",
    "deepseek sk- filename:conf",
    "deepseek sk- filename:config",

    # ═══════════════════════════════════════════════════════
    #  🔥 Tier 3 — mobile (Dart/Swift) + Shell scripts
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:dart",
    "api.deepseek.com sk- filename:dart",

    "deepseek sk- filename:swift",

    "deepseek sk- filename:sh",
    "deepseek sk- filename:zsh",
    "deepseek sk- filename:bash",
    "deepseek sk- filename:fish",

    # ═══════════════════════════════════════════════════════
    #  🔥 Tier 4 — JS/TS + C++ + Go + C#
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:js",
    "deepseek sk- filename:ts",
    "deepseek API_KEY sk- filename:js",

    "deepseek sk- filename:cpp",

    "deepseek sk- filename:go",

    "deepseek sk- filename:cs",

    # ═══════════════════════════════════════════════════════
    #  🔥 Tier 5 — Jupyter / Docker / Lua / variable names
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:ipynb",
    "DEEPSEEK_API_KEY sk- filename:ipynb",

    "deepseek sk- filename:dockerfile",
    "deepseek sk- filename:docker-compose",
    "deepseek.com sk- filename:yml path:.github",

    "deepseek sk- filename:lua path:nvim",

    # Variable name variants
    "DEEPSEEK_API_KEY sk-",
    "DEEPSEEK_KEY sk-",
    "deepseek_api_key sk-",
    "deepseek_key sk-",
    "DEEPSEEK_TOKEN sk-",
    "DEEPSEEK_API_TOKEN sk-",

    # ═══════════════════════════════════════════════════════
    #  Tier 6 — API client patterns + text files
    # ═══════════════════════════════════════════════════════

    "api.deepseek.com OpenAI sk-",
    "deepseek Authorization Bearer sk-",
    "deepseek base_url sk-",
    "deepseek OpenAIClient sk-",

    "deepseek sk- filename:txt",
    "deepseek sk- filename:md",

    # ═══════════════════════════════════════════════════════
    #  Tier 7 — cross file types + time filters
    # ═══════════════════════════════════════════════════════

    "deepseek process.env sk- filename:js",
    "deepseek sk- filename:py pushed:>2025-01-01",
    "deepseek sk- filename:envrc",
    "deepseek sk- filename:html",

    # ═══════════════════════════════════════════════════════
    #  Tier 8 — niche languages, occasional hits
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:rb",
    "deepseek sk- filename:rs",
    "deepseek sk- filename:lua",
    "deepseek sk- filename:plist",

    # ═══════════════════════════════════════════════════════
    #  Tier 9 — time filters + 2026 patterns (high yield in v5 tests)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- pushed:>2026-05-01",
    "deepseek sk- pushed:>2026-04-01",
    "deepseek sk- filename:java pushed:>2026-04-01",
    "deepseek sk- filename:py pushed:>2026-04-01",
    "deepseek sk- filename:env pushed:>2026-04-01",
    "deepseek sk- filename:js pushed:>2026-04-01",
    "deepseek sk- filename:yml pushed:>2026-04-01",
    "deepseek sk- filename:json pushed:>2026-04-01",
    "deepseek API_KEY sk- language:Java NOT test NOT example",
    "deepseek Authorization sk- language:Python NOT test",
    "deepseek DEEPSEEK_API_KEY sk- language:TypeScript",
    "deepseek base_url sk- filename:json",
    "deepseek sk- path:config",
    "deepseek sk- path:src/main/resources",
    "deepseek sk- filename:application.yml",
    "deepseek sk- filename:application.properties",
    "deepseek sk- path:.github/workflows",
    "api.deepseek.com sk- path:src",
    "deepseek deepseek_api_key sk- filename:env",
    "deepseek Client sk- filename:kt NOT test",
    "deepseek import sk- filename:dart",
    "deepseek sk- filename:ipynb pushed:>2026-01-01",
    "deepseek OpenAIClient sk- filename:go NOT test",
    "deepseek sk- filename:toml path:config",
    "deepseek Authorization Bearer sk- filename:js NOT test",
    "deepseek process.env.DEEPSEEK sk- filename:ts",

    # ═══════════════════════════════════════════════════════
    #  Tier 10 — alternative platforms + framework integrations (OpenRouter/LangChain/etc)
    # ═══════════════════════════════════════════════════════

    # OpenRouter proxy (people proxy DeepSeek through OpenRouter)
    "OPENROUTER_API_KEY sk-",
    "openrouter deepseek sk-",
    "openrouter api_key sk- filename:py",

    # LangChain integration
    "langchain deepseek api_key",
    "langchain deepseek sk- filename:py",

    # vLLM / open-webui / dify deployment configs
    "vllm deepseek sk- filename:yml",
    "open-webui deepseek sk-",
    "dify deepseek api_key",

    # LLM framework configs
    "llamaindex deepseek sk-",
    "litellm deepseek api_key",

    # CI/CD workflows with hardcoded secrets
    "deepseek sk- path:.github/workflows",
    "DEEPSEEK_API_KEY path:.github/workflows",

    # Keys in README / documentation
    "deepseek sk- filename:README",

    # Terraform / K8s / Helm
    "deepseek sk- filename:tf",
    "deepseek sk- filename:hcl",
    "deepseek sk- path:k8s",
    "deepseek sk- filename:values.yaml",

    # IDE configs
    "deepseek sk- path:.vscode",

    # Package manager configs
    "deepseek sk- filename:.npmrc",
    "deepseek sk- filename:.pypirc",

    # Jupyter / Colab specific
    "deepseek sk- filename:colab",
    "deepseek sk- filename:notebook",

    # Mobile app configs
    "deepseek sk- path:android",
    "deepseek sk- path:ios",

    # Alternative key prefixes (DeepSeek sometimes uses ds-)
    "deepseek ds-",

    # ═══════════════════════════════════════════════════════
    #  Tier 11 — more frameworks/platforms/deployment scenarios
    # ═══════════════════════════════════════════════════════

    # FastGPT / ChatGPT-Next-Web / LobeChat / OneAPI
    "fastgpt deepseek api_key",
    "chatgpt-next-web deepseek sk-",
    "lobechat deepseek sk-",
    "oneapi deepseek sk-",

    # AI agent frameworks
    "autogen deepseek api_key",
    "crewai deepseek api_key",
    "agno deepseek api_key",

    # RAG frameworks
    "ragflow deepseek api_key",
    "quivr deepseek api_key",
    "anythingllm deepseek api_key",

    # API gateway / proxy
    "kong deepseek api_key",
    "apifox deepseek api_key",
    "postman deepseek api_key",

    # Cloud deployment
    "vercel deepseek api_key",
    "netlify deepseek api_key",
    "heroku deepseek api_key",
    "railway deepseek api_key",

    # Serverless functions
    "deepseek sk- path:cloudfunctions",
    "deepseek sk- path:supabase/functions",
    "deepseek sk- path:netlify/functions",

    # More mobile frameworks
    "deepseek sk- filename:xml path:android",
    "deepseek sk- filename:gradle path:android",
    "deepseek sk- filename:plist path:ios",
    "deepseek sk- filename:xcconfig",

    # Game engines
    "deepseek sk- filename:cs path:unity",
    "deepseek sk- filename:gd",

    # More config files
    "deepseek sk- filename:.babelrc",
    "deepseek sk- filename:webpack.config.js",
    "deepseek sk- filename:vite.config.ts",
    "deepseek sk- filename:next.config.js",
    "deepseek sk- filename:nuxt.config.ts",
    "deepseek sk- filename:svelte.config.js",

    # Database / ORM configs
    "deepseek sk- filename:prisma/schema.prisma",
    "deepseek sk- filename:schema.prisma",
    "deepseek sk- filename:supabase/config.toml",

    # Testing configs
    "deepseek sk- filename:cypress.config",
    "deepseek sk- filename:playwright.config",
    "deepseek sk- filename:jest.config",
    "deepseek sk- filename:vitest.config",

    # More shell variants
    "deepseek sk- filename:ps1",
    "deepseek sk- filename:bat",
    "deepseek sk- filename:cmd",

    # WASM / embedded
    "deepseek sk- filename:wasm",
    "deepseek sk- filename:proto",

    # ═══════════════════════════════════════════════════════
    #  Tier 12 — deep time filters (latest 2026)
    # ═══════════════════════════════════════════════════════

    "deepseek sk- pushed:>2026-05-15",
    "deepseek sk- pushed:2026-05-15..2026-05-20",
    "deepseek sk- filename:java pushed:>2026-05-01",
    "deepseek sk- filename:py pushed:>2026-05-01",
    "deepseek sk- filename:js pushed:>2026-05-01",
    "deepseek sk- filename:ts pushed:>2026-05-01",
    "deepseek sk- filename:env pushed:>2026-05-01",
    "deepseek sk- filename:yml pushed:>2026-05-01",
    "deepseek sk- filename:json pushed:>2026-05-01",
    "deepseek sk- filename:kt pushed:>2026-05-01",
    "deepseek sk- filename:php pushed:>2026-05-01",
    "deepseek sk- filename:go pushed:>2026-05-01",
    "deepseek sk- filename:rs pushed:>2026-05-01",
    "deepseek sk- filename:cpp pushed:>2026-05-01",
    "deepseek sk- filename:swift pushed:>2026-05-01",
    "deepseek sk- filename:dart pushed:>2026-05-01",

    # ═══════════════════════════════════════════════════════
    #  Tier 13 — variable name variants + concatenation patterns
    # ═══════════════════════════════════════════════════════

    "deepseek_api_key = sk-",
    "deepseek_key = sk-",
    "deepseek_token = sk-",
    "deepseek_secret = sk-",
    "ds_api_key = sk-",
    "ds_key = sk-",

    # process.env variants
    "process.env.DEEPSEEK",
    "process.env[\"DEEPSEEK",
    "os.environ[\"DEEPSEEK",
    "os.getenv(\"DEEPSEEK",

    # Config class patterns
    "class Config deepseek sk-",
    "dataclass deepseek sk-",
    "pydantic deepseek sk-",

    # ═══════════════════════════════════════════════════════
    #  Tier 14 — API call patterns
    # ═══════════════════════════════════════════════════════

    "deepseek.chat.completions sk-",
    "deepseek.completions sk-",
    "api.deepseek.com/v1 sk-",
    "api.deepseek.com/chat sk-",

    # Client initialization patterns
    "DeepSeekClient sk-",
    "deepseek.Client sk-",
    "create_deepseek_client sk-",

    # More auth patterns
    "x-deepseek-api-key",
    "deepseek-api-key sk-",

    # ═══════════════════════════════════════════════════════
    #  Tier 15 — niche but occasionally productive
    # ═══════════════════════════════════════════════════════

    "deepseek sk- filename:sql",
    "deepseek sk- filename:graphql",
    "deepseek sk- filename:prisma",
    "deepseek sk- filename:eslintrc",
    "deepseek sk- filename:prettierrc",
    "deepseek sk- filename:babelrc",
    "deepseek sk- filename:postcss.config",
    "deepseek sk- filename:tailwind.config",
    "deepseek sk- filename:astro.config",
    "deepseek sk- filename:gatsby-config",
    "deepseek sk- filename:gridsome.config",
    "deepseek sk- filename:vue.config",
    "deepseek sk- filename:nuxt.config",
    "deepseek sk- filename:quasar.conf",
    "deepseek sk- filename:capacitor.config",
    "deepseek sk- filename:ionic.config",
    "deepseek sk- filename:cordova.config",
    "deepseek sk- filename:electron-main",
    "deepseek sk- filename:tauri.conf",
    "deepseek sk- filename:expo.config",
    "deepseek sk- filename:metro.config",
    "deepseek sk- filename:fastlane",
    "deepseek sk- filename:bitrise.yml",
    "deepseek sk- filename:appveyor.yml",
    "deepseek sk- filename:travis.yml",
    "deepseek sk- filename:circleci",
    "deepseek sk- path:.circleci",
    "deepseek sk- path:.travis",
    "deepseek sk- path:deploy",
    "deepseek sk- path:scripts",
    "deepseek sk- path:tools",
    "deepseek sk- path:infra",
    "deepseek sk- path:infrastructure",
    "deepseek sk- path:terraform",
    "deepseek sk- path:ansible",
    "deepseek sk- path:pulumi",
    "deepseek sk- path:cdk",

    # ═══════════════════════════════════════════════════════
    #  Tier 16 — generic sk- queries (no deepseek keyword, covers OpenAI/OpenRouter)
    # ═══════════════════════════════════════════════════════

    # Pure sk- key search (provider-agnostic)
    "sk- filename:env NOT deepseek",
    "sk- filename:env.local NOT deepseek",
    "sk- filename:env.production NOT deepseek",
    "sk- filename:env.development NOT deepseek",
    "sk- filename:env.example NOT deepseek",
    "sk- filename:env.sample NOT deepseek",
    "sk- filename:env.backup NOT deepseek",
    "sk- filename:credentials NOT deepseek",
    "sk- filename:secrets NOT deepseek",

    # API key variable name patterns (OpenAI/OpenRouter)
    "OPENAI_API_KEY sk-",
    "OPENROUTER_API_KEY sk-",
    "OPENAI_KEY sk-",
    "OPENAI_TOKEN sk-",
    "OPENROUTER_KEY sk-",
    "openai_api_key sk- filename:py",
    "openrouter_api_key sk- filename:py",
    "openai_api_key sk- filename:js",
    "openrouter_api_key sk- filename:js",
    "openai_api_key sk- filename:env",
    "openrouter_api_key sk- filename:env",

    # Generic API client patterns
    "api.openai.com sk- filename:py NOT deepseek",
    "api.openai.com sk- filename:js NOT deepseek",
    "openrouter.ai sk- filename:py",
    "openrouter.ai sk- filename:js",
    "OpenAI(api_key sk- filename:py NOT deepseek",
    "OpenAI(api_key sk- filename:js NOT deepseek",
    "Authorization Bearer sk- filename:py NOT deepseek",
    "Authorization Bearer sk- filename:js NOT deepseek",
    "Authorization Bearer sk- filename:env NOT deepseek",

    # Generic config files
    "sk- filename:yml NOT deepseek",
    "sk- filename:yaml NOT deepseek",
    "sk- filename:json NOT deepseek",
    "sk- filename:toml NOT deepseek",
    "sk- filename:ini NOT deepseek",
    "sk- filename:conf NOT deepseek",
    "sk- filename:config NOT deepseek",

    # Generic code files (no deepseek keyword)
    "sk- filename:py NOT deepseek NOT env",
    "sk- filename:js NOT deepseek NOT env",
    "sk- filename:ts NOT deepseek",
    "sk- filename:java NOT deepseek",
    "sk- filename:kt NOT deepseek",
    "sk- filename:go NOT deepseek",
    "sk- filename:php NOT deepseek",
    "sk- filename:rs NOT deepseek",
    "sk- filename:rb NOT deepseek",
    "sk- filename:cpp NOT deepseek",
    "sk- filename:cs NOT deepseek",
    "sk- filename:swift NOT deepseek",
    "sk- filename:dart NOT deepseek",

    # LangChain / framework integrations (no deepseek)
    "langchain openai_api_key",
    "langchain openrouter_api_key",
    "litellm api_key sk-",

    # CI/CD secret leaks
    "OPENAI_API_KEY path:.github/workflows",
    "OPENROUTER_API_KEY path:.github/workflows",
    "API_KEY sk- path:.github/workflows NOT deepseek",

    # Docker / Kubernetes
    "sk- filename:dockerfile NOT deepseek",
    "sk- filename:docker-compose NOT deepseek",
    "sk- path:k8s NOT deepseek",

    # Time filters (latest 2026)
    "sk- pushed:>2026-05-01 NOT deepseek",
    "sk- pushed:>2026-04-01 NOT deepseek",
    "sk- filename:env pushed:>2026-04-01 NOT deepseek",
    "sk- filename:py pushed:>2026-04-01 NOT deepseek",
    "sk- filename:js pushed:>2026-04-01 NOT deepseek",
    "sk- filename:yml pushed:>2026-04-01 NOT deepseek",
    "sk- filename:json pushed:>2026-04-01 NOT deepseek",
    "sk- filename:java pushed:>2026-04-01 NOT deepseek",

    # process.env patterns
    "process.env.OPENAI_API_KEY sk-",
    "process.env.OPENROUTER_API_KEY sk-",
    "process.env sk- filename:js NOT deepseek",
    "os.environ sk- filename:py NOT deepseek",
    "os.getenv sk- filename:py NOT deepseek",

    # AI framework config (no deepseek needed)
    "sk- path:config NOT deepseek",
    "sk- path:src/main/resources NOT deepseek",
    "sk- filename:application.yml NOT deepseek",
    "sk- filename:application.properties NOT deepseek",

    # OpenRouter-specific patterns
    "openrouter sk- filename:py",
    "openrouter sk- filename:js",
    "openrouter sk- filename:ts",
    "openrouter API_KEY sk-",
    "openrouter api_key sk- filename:env",

    # OpenAI-specific patterns
    "openai sk- filename:py NOT deepseek",
    "openai sk- filename:js NOT deepseek",
    "openai sk- filename:env NOT deepseek",
    "openai.Client sk- filename:py",
    "openai.OpenAI sk- filename:py",

    # Generic LLM platforms (LobeChat / Dify / vLLM)
    "lobechat OPENAI_API_KEY",
    "dify OPENAI_API_KEY",
    "fastgpt OPENAI_API_KEY",
    "oneapi sk- token",
    "chatgpt-next-web OPENAI_API_KEY",
    "open-webui OPENAI_API_KEY",
    "vllm api_key sk-",

    # Generic key files
    "sk- filename:txt NOT deepseek",
    "sk- filename:md NOT deepseek",
    "sk- filename:html NOT deepseek",
    "sk- filename:ipynb NOT deepseek",
    "sk- filename:sh NOT deepseek",
    "sk- filename:bash NOT deepseek",

    # ═══════════════════════════════════════════════════════
    #  Tier 17 — OpenCode Zen (opencode.ai)
    # ═══════════════════════════════════════════════════════

    # OpenCode Zen API key patterns
    "OPENCODE_API_KEY sk-",
    "OPENCODE_KEY sk-",
    "opencode_api_key sk- filename:py",
    "opencode_api_key sk- filename:js",
    "opencode_api_key sk- filename:ts",
    "opencode_api_key sk- filename:env",
    "opencode sk- api_key filename:py",
    "opencode sk- api_key filename:js",
    "opencode sk- filename:env",
    "opencode.ai sk- filename:py",
    "opencode.ai sk- filename:js",
    "opencode zen sk- filename:env",
    "opencode zen sk- filename:py",
    "opencode zen sk- filename:js",
    "zen/v1 sk- filename:py",
    "zen/v1 sk- filename:js",
    "zen/v1 sk- filename:env",
    "opencode openai_api_key sk- filename:env",
    "opencode openai_api_key sk- filename:py",
    "opencode API_KEY sk- filename:env",
    "opencode API_KEY sk- path:config",
    "opencode api key sk- filename:md",
    "opencode connect sk- filename:py",
    "opencode connect sk- filename:js",
    "opencode config sk-",
    "OPENCODE_API_KEY path:.github/workflows",

    # OpenCode Zen in AI framework configs
    "langchain opencode api_key",
    "litellm opencode api_key",
    "opencode sk- filename:json",
    "opencode sk- filename:yml",
    "opencode sk- filename:toml",
    "opencode sk- filename:dockerfile",
]


def is_bad_key(key: str, extra_bad: list = None) -> bool:
    return _scanner_is_bad_key(key, extra_bad)


def convert_to_usd(balance: float, currency: str, rate: float = DEFAULT_USD_CNY_RATE) -> float:
    if currency.upper() == "CNY":
        return balance / rate if rate > 0 else 0
    return balance


def convert_to_cny(balance: float, currency: str, rate: float = DEFAULT_USD_CNY_RATE) -> float:
    if currency.upper() == "USD":
        return balance * rate
    return balance


class ScannerEngine:
    def __init__(self,
                 concurrency: int = 20,
                 timeout: int = 15,
                 search_delay: float = 2.5,
                 max_pages: int = 3,
                 min_key_length: int = 32,
                 max_key_length: int = 100,
                 output_dir: str = ".",
                 providers: list = None,
                 deepseek_api_base: str = None,  # deprecated, use providers
                 usd_cny_rate: float = DEFAULT_USD_CNY_RATE,
                 exclude_repos: list = None,
                 extra_bad_patterns: list = None,
                 log_callback: Callable[[str, str], None] = None,
                 progress_callback: Callable[[int, int, str], None] = None,
                 max_duration: int = 0,
                 max_valid_keys: int = 0,
                 auto_save_interval: int = 0,
                 scan_pages: int = 5,
                 github_tokens: list = None,
                 proxies: list = None,
                 search_workers: int = 0,
                 check_balance: bool = True,
                 db_path: str = None,
                 store_raw_keys: bool = True,
                 user_agent: str = None,
                 ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.search_delay = search_delay
        self.max_pages = max_pages
        self.min_key_length = min_key_length
        self.max_key_length = max_key_length
        self.output_dir = output_dir
        # Provider list (backward compat: deepseek_api_base → providers)
        if providers is None:
            if deepseek_api_base:
                self.providers = ["deepseek"]
            else:
                self.providers = ["deepseek", "openai", "openrouter"]
        else:
            self.providers = providers
        self.usd_cny_rate = usd_cny_rate
        self.exclude_repos = exclude_repos or []
        self.extra_bad_patterns = extra_bad_patterns or []
        self.log_callback = log_callback or (lambda msg, level="info": print(msg))
        self.progress_callback = progress_callback or (lambda cur, total, phase: None)

        # Exit conditions
        self.max_duration = max_duration
        self.max_valid_keys = max_valid_keys
        self.auto_save_interval = auto_save_interval or 20
        self.scan_pages = max(1, min(10, scan_pages or 10))  # default 10 pages, clamped to 1-10

        self.key_pattern = re.compile(
            rf"sk-[a-zA-Z0-9]{{{min_key_length},{max_key_length}}}"
        )

        # ---- research-hardening additions ----
        self.check_balance = check_balance          # billing endpoints only if True
        self.store_raw_keys = store_raw_keys        # False → hash+preview on disk
        self.user_agent = user_agent or RESEARCH_UA
        self._detector = Detector(providers=self.providers)

        gh_tokens = list(github_tokens or [])
        env_tok = self.get_gh_token()
        if env_tok and env_tok not in gh_tokens:
            gh_tokens.append(env_tok)
        self._gh_tokens = gh_tokens
        self._token_pool = TokenPool(gh_tokens)
        self._proxy_pool = ProxyPool(proxies or [])
        # parallel search workers: 0/1 = sequential; >1 = one worker per
        # proxy/token pair, queries processed in async batches
        self.search_workers = search_workers
        self._store = Store(db_path) if db_path else None
        self._scan_id = 0

        self._stop_requested = False
        self._start_time = time.time()
        self._valid_count = 0
        self._saved_count = 0
        self.results = []
        self.all_keys = {}

    _gh_authenticated = None  # class-level cache

    @staticmethod
    def check_gh_auth() -> bool:
        """Check whether the gh CLI is authenticated"""
        return bool(ScannerEngine.get_gh_token())

    @staticmethod
    def get_gh_token() -> str:
        """Get GitHub token from gh CLI, env var, or git config."""
        # Try GH_TOKEN / GITHUB_TOKEN env var first
        for env_var in ["GH_TOKEN", "GITHUB_TOKEN"]:
            token = os.environ.get(env_var, "")
            if token:
                return token
        # Try gh CLI
        try:
            r = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, timeout=5,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def suggested_search_delay() -> float:
        """Suggest a safe request interval based on auth state"""
        return 2.5 if ScannerEngine.check_gh_auth() else 6.5

    def log(self, msg: str, level: str = "info"):
        self.log_callback(msg, level)

    def stop(self):
        self._stop_requested = True

    # ================================================================
    #  Main pipeline: search → verify → save → check exit → next round
    #  Each round = one query; scan/verify/save as it goes; exits as soon
    #  as the time/count target is hit
    # ================================================================

    # Provider keywords for query filtering (superset — driven by detectors)
    _PROVIDER_KW = {
        "deepseek": ["deepseek", "api.deepseek.com", "ds_api_key", "ds_key",
                     "DEEPSEEK_API_KEY", "DEEPSEEK_KEY", "DEEPSEEK_TOKEN", "DEEPSEEK_API_TOKEN"],
        "openai": ["openai", "api.openai.com", "OPENAI_API_KEY", "OPENAI_KEY", "OPENAI_TOKEN"],
        "openrouter": ["openrouter", "openrouter.ai", "OPENROUTER_API_KEY", "OPENROUTER_KEY"],
        "opencode": ["opencode", "opencode.ai", "OPENCODE_API_KEY", "OPENCODE_KEY", "opencode zen"],
        "anthropic": ["anthropic", "claude", "api.anthropic.com", "ANTHROPIC_API_KEY", "sk-ant-"],
        "groq": ["groq", "api.groq.com", "GROQ_API_KEY", "gsk_"],
        "xai": ["xai", "api.x.ai", "grok", "XAI_API_KEY"],
        "huggingface": ["huggingface", "hf.co", "HF_TOKEN", "HUGGINGFACE", "hf_"],
        "replicate": ["replicate", "REPLICATE_API_TOKEN", "r8_"],
        "perplexity": ["perplexity", "pplx-", "PERPLEXITY_API_KEY"],
        "fireworks": ["fireworks", "fireworks.ai", "FIREWORKS_API_KEY", "fw_"],
        "cerebras": ["cerebras", "CEREBRAS_API_KEY", "csk-"],
        "mistral": ["mistral", "api.mistral.ai", "MISTRAL_API_KEY"],
        "together": ["together", "api.together.xyz", "TOGETHER_API_KEY"],
        "google": ["generativelanguage", "gemini", "GOOGLE_API_KEY", "makersuite", "AIza"],
    }

    def _filter_queries_for_providers(self, queries: list) -> list:
        """Filter search queries to only those relevant to active providers.
        Generic sk- queries (no provider keyword, or only in NOT clauses) are always kept."""
        if set(self.providers) >= set(self._PROVIDER_KW):
            return list(queries)  # all providers → no filtering

        import re
        filtered = []
        for q in queries:
            q_lower = q.lower()
            # Which providers does this query mention (outside NOT clauses)?
            # Remove NOT clauses before checking
            cleaned = re.sub(r'\bnot\s+\S+', '', q_lower, flags=re.IGNORECASE)
            mentioned = set()
            for prov, keywords in self._PROVIDER_KW.items():
                for kw in keywords:
                    if kw.lower() in cleaned:
                        mentioned.add(prov)
                        break
            # Keep if: generic (no provider mention) OR mentions at least one active provider
            if not mentioned or (mentioned & set(self.providers)):
                filtered.append(q)
        return filtered

    def run(self, queries: list) -> list:
        """Main pipeline: query by query, search→verify→save→check limits→loop
        Supports graceful Ctrl+C exit: saves progress, verifies scanned keys, saves results
        """
        if not queries:
            return []

        all_valid = []      # final valid results
        total_scanned = 0
        current_round = 0
        unverified_keys = {}  # keys from the current round not yet verified (verified on Ctrl+C)
        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()
        if self._store and not self._scan_id:
            self._scan_id = self._store.start_scan(["github"], self.providers)

        # Filter queries by active providers, then sort by heat
        ordered = self._filter_queries_for_providers(queries)
        skipped = len(queries) - len(ordered)

        # work units: single queries (sequential) or batches of
        # search_workers queries run in parallel, one proxy/token each
        if self.search_workers > 1:
            units = [ordered[i:i + self.search_workers]
                     for i in range(0, len(ordered), self.search_workers)]
            self.log(f"Parallel mode: {self.search_workers} workers, "
                     f"{len(units)} batches")
        else:
            units = [[q] for q in ordered]

        self.log(f"Pipeline start: {len(queries)} queries → {len(ordered)} after filtering (skipped {skipped} unrelated), "
                 f"concurrency {self.concurrency}, duration limit {self.max_duration}s, target {self.max_valid_keys} valid keys")

        try:
            for qi, unit in enumerate(units):
                current_round = qi + 1

                # ── Check exit conditions ──
                if self._should_stop():
                    self.log(f"Pipeline exit: {self._stop_reason()}", "warning")
                    break

                self.log(f"\n{'='*40}")
                label = unit[0] if len(unit) == 1 else \
                    f"batch of {len(unit)}: {unit[0]} ..."
                self.log(f"Round [{qi+1}/{len(units)}]: {label}")
                self.progress_callback(qi + 1, len(units), "search")

                # ── Step 1: search ──
                if self.search_workers > 1:
                    round_keys = asyncio.run(self._scan_queries_parallel(unit))
                else:
                    round_keys = self._scan_one_query(unit[0])
                unverified_keys = round_keys  # stash for Ctrl+C recovery
                if not round_keys:
                    self.log(f"  Found this round: 0 keys, skipping verification")
                    unverified_keys = {}
                    time.sleep(self.search_delay)
                    continue

                self.log(f"  Found this round: {len(round_keys)} candidate keys")

                # ── Step 2: verify immediately ──
                self.log(f"  Verifying {len(round_keys)} keys...")
                round_results = self._verify_dict(round_keys)
                unverified_keys = {}  # verified; clear stash

                valid = [r for r in round_results if r.get("valid")]
                invalid = [r for r in round_results if not r.get("valid")]
                self.log(f"  Verification: {len(valid)} valid, {len(invalid)} invalid (dropped)")

                # Add valid keys to the total (dedup)
                existing_keys = {r["key"] for r in all_valid}
                for r in valid:
                    if r["key"] not in existing_keys:
                        all_valid.append(r)
                        existing_keys.add(r["key"])
                # Count all valid keys (original logic: the more the better)
                self._valid_count = len(all_valid)
                total_scanned += len(round_keys)

                # ── Step 3: incremental save (valid keys only) ──
                self._save_incremental(all_valid, qi, len(units))

                # ── Step 4: check exit conditions ──
                if self._should_stop():
                    self.log(f"  After round: {self._stop_reason()}", "warning")
                    break

                time.sleep(self.search_delay)

        except KeyboardInterrupt:
            self.log(f"\n!!! Ctrl+C signal received !!!", "error")
            self.log(f"Scanned {current_round-1}/{len(queries)} rounds, {len(all_valid)} valid keys")

            # Verify keys from the unfinished round
            if unverified_keys:
                self.log(f"Verifying {len(unverified_keys)} unverified keys from the current round...")
                try:
                    emergency_results = self._verify_dict(unverified_keys)
                    valid_emergency = [r for r in emergency_results if r.get("valid")]
                    existing = {r["key"] for r in all_valid}
                    added = 0
                    for r in valid_emergency:
                        if r["key"] not in existing:
                            all_valid.append(r)
                            existing.add(r["key"])
                            added += 1
                    self.log(f"Emergency verification done: {len(valid_emergency)} valid, {added} new")
                except Exception as e:
                    self.log(f"Emergency verification failed: {e}", "error")

            # Save progress
            self._save_final(all_valid)
            self.log(f"Safely saved {len(all_valid)} valid keys, exiting gracefully", "warning")

        # Final save
        self._save_final(all_valid)
        elapsed = time.time() - self._start_time

        positive_only = [r for r in all_valid if r.get("balance_usd", 0) > 0]
        self.log(f"\n{'='*40}")
        self.log(f"Pipeline done: {elapsed:.0f}s | scanned {total_scanned} keys | "
                 f"valid {len(all_valid)} | positive balance {len(positive_only)}")
        if positive_only:
            total_usd = sum(r.get("balance_usd", 0) for r in positive_only)
            total_cny = sum(r.get("balance_cny", 0) for r in positive_only)
            self.log(f"Total positive balance: ${total_usd:.2f} / ¥{total_cny:.2f} (overdue not counted)")

        if self._store and self._scan_id:
            self._store.end_scan(self._scan_id, queries=len(ordered),
                                 candidates=total_scanned, valid=len(all_valid))
            self._scan_id = 0
        return all_valid

    def run_multi_source(self, sources: list, queries: list = None,
                         github_token: str = "", gitlab_token: str = "",
                         gitee_token: str = "") -> list:
        """Multi-source scan: scan GitHub + Gist + Issues + GitLab + Gitee + Docker + ... at once
        sources: ['github', 'gist', 'issues', 'gitlab', 'wayback', 'docker',
                   'commoncrawl', 'gitee', 'npm']
        Each source runs in its own scanner instance, concurrently.
        """
        if not sources:
            self.log("No scan sources specified", "warning")
            return []

        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()
        if self._store and not self._scan_id:
            self._scan_id = self._store.start_scan(list(sources), self.providers)

        scanner_map = {
            "github": ("GitHub Code Search", self._filter_queries_for_providers(queries or BUILTIN_QUERIES)),
            "gist": ("GitHub Gists", None),
            "issues": ("GitHub Issues/PRs", None),
            "commits": ("GitHub Commit History", None),
            "gitlab": ("GitLab", None),
            "wayback": ("Wayback Machine", None),
            "docker": ("Docker Hub", None),
            "commoncrawl": ("Common Crawl", None),
            "gitee": ("Gitee", None),
            "npm": ("npm Registry", None),
            "huggingface": ("HuggingFace", None),
            "pypi": ("PyPI Registry", None),
            "stackoverflow": ("Stack Overflow", None),
        }

        self.log(f"Multi-source scan start: {len(sources)} sources -> {[scanner_map[s][0] for s in sources]}")
        self.log(f"Verify concurrency: {self.concurrency}, duration limit: {self.max_duration}s, target: {self.max_valid_keys}")

        all_discovered = {}

        for src in sources:
            if self._should_stop():
                break

            label, default_query = scanner_map.get(src, (src, None))
            self.log(f"\n{'='*50}")
            self.log(f"  [{label}] scanning...")
            self.log(f"{'='*50}")

            try:
                round_keys = self._run_one_scanner(src, default_query, github_token,
                                                   gitlab_token, gitee_token)
            except Exception as e:
                self.log(f"  [{label}] scan error: {e}", "error")
                continue

            if not round_keys:
                self.log(f"  [{label}] no keys found")
                continue

            self.log(f"  [{label}] found {len(round_keys)} candidate keys")

            # Verify
            self.log(f"  Verifying {len(round_keys)} keys...")
            round_results = self._verify_dict(round_keys)

            valid = [r for r in round_results if r.get("valid")]
            invalid = [r for r in round_results if not r.get("valid")]
            self.log(f"  [{label}] valid: {len(valid)}, invalid: {len(invalid)}")

            for r in valid:
                k = r["key"]
                if k not in all_discovered:
                    all_discovered[k] = r

            self._save_incremental(
                list(all_discovered.values()),
                sources.index(src), len(sources)
            )

            if self._should_stop():
                self.log(f"  Exit condition reached: {self._stop_reason()}", "warning")
                break

            time.sleep(1.0)

        all_results = list(all_discovered.values())
        self._save_final(all_results)
        elapsed = time.time() - self._start_time

        positive_only = [r for r in all_results if r.get("balance_usd", 0) > 0]
        self.log(f"\n{'='*40}")
        self.log(f"Multi-source scan done: {elapsed:.0f}s | valid {len(all_results)} | positive balance {len(positive_only)}")
        if positive_only:
            total_usd = sum(r.get("balance_usd", 0) for r in positive_only)
            total_cny = sum(r.get("balance_cny", 0) for r in positive_only)
            self.log(f"Total positive balance: ${total_usd:.2f} / ¥{total_cny:.2f} (overdue not counted)")

        if self._store and self._scan_id:
            self._store.end_scan(self._scan_id, queries=0,
                                 candidates=0, valid=len(all_results))
            self._scan_id = 0
        return all_results

    # Scanner factory: (class, search_term, extra_init_kwargs)
    _SCANNER_REGISTRY = None

    def _get_scanner_registry(self, github_token: str = "", gitlab_token: str = "",
                              gitee_token: str = ""):
        if self._SCANNER_REGISTRY is None:
            ScannerEngine._SCANNER_REGISTRY = {
                "gist": (GistScanner, None, {"token": github_token}),
                "issues": (IssuesScanner, '"sk-"', {"token": github_token}),
                "commits": (CommitsScanner, None, {"token": github_token}),
                "gitlab": (GitLabScanner, '"sk-"', {"token": gitlab_token, "max_projects": 100}),
                "wayback": (WaybackScanner, "github.com", {"max_snapshots": 100}),
                "docker": (DockerHubScanner, '"sk-"', {"max_images": 50}),
                "commoncrawl": (CommonCrawlScanner, "github.com", {"max_urls": 200}),
                "gitee": (GiteeScanner, '"sk-"', {"token": gitee_token, "max_repos": 100}),
                "npm": (NpmScanner, '"sk-"', {"max_packages": 50}),
                "huggingface": (HuggingFaceScanner, '"sk-"', {"max_items": 150}),
                "pypi": (PyPIScanner, '"sk-"', {"max_packages": 150}),
                "stackoverflow": (StackOverflowScanner, '"sk-"', {"max_posts": 200}),
            }
        return ScannerEngine._SCANNER_REGISTRY

    def _run_one_scanner(self, source: str, queries: list = None,
                         github_token: str = "", gitlab_token: str = "",
                         gitee_token: str = "") -> dict:
        """Run a single scanner by name and return discovered keys dict."""
        discovered = {}

        async def _do():
            nonlocal discovered
            if source == "github":
                qs = queries or BUILTIN_QUERIES
                for query in qs[:50]:
                    if self._should_stop():
                        break
                    batch = self._scan_one_query(query)
                    for k, v in batch.items():
                        if k not in discovered:
                            discovered[k] = v
                    time.sleep(self.search_delay)
                return

            registry = self._get_scanner_registry(github_token, gitlab_token, gitee_token)
            scanner_cls, search_term, extra_kwargs = registry.get(source, (None, None, {}))
            if scanner_cls is None:
                return

            scanner = scanner_cls(concurrency=self.concurrency, timeout=self.timeout, **extra_kwargs)
            results = await scanner.search(search_term)
            for r in results:
                k = r["key"]
                if k not in discovered:
                    providers, _ = self._detector.classify(
                        k, context=f"{r.get('repo','')} {r.get('file','')}")
                    discovered[k] = {
                        "key": k,
                        "key_preview": r.get("key_preview", k[:10] + "..." + k[-4:]),
                        "providers": providers or self.providers,
                        "source": source,
                        "repos": [{"repo": r.get("repo", ""), "file": r.get("file", ""),
                                   "url": r.get("url", "")}],
                    }

        asyncio.run(_do())
        return discovered

    def _is_likely_test_key(self, file_path: str, repo: str) -> bool:
        """Pre-filter to skip test/demo files and build artifacts.
        Test files often contain real keys with balance, so we only skip
        unambiguous low-value patterns."""
        lower = (file_path + "/" + repo).lower()
        # Build artifacts
        for kw in ["/target/site/", "/target/classes/", "/build/resources/",
                    "/bin/main/", "/.html"]:
            if kw in lower:
                return True
        # Common test/demo paths that are almost always zero-balance
        for kw in ["/test/java/", "/test/kotlin/", "testdeepseek", "tongyichat",
                   "/demo/", "/examples/", "/sample/", "/samples/",
                   "/tests/", "/__tests__/", "/spec/", "/fixtures/"]:
            if kw in lower:
                return True
        return False

    def _scan_one_query(self, query: str) -> dict:
        """Scan a single query: fetch up to N pages (100 per page), grab raw files concurrently"""
        max_pages_to_fetch = getattr(self, 'scan_pages', 5)
        items = []
        for page in range(1, max_pages_to_fetch + 1):
            if page > 1:
                time.sleep(4.0)  # 4s delay between pages — safe under the 30/min limit
            batch = self._gh_search(query, per_page=100, page=page)
            if not batch:
                break
            items.extend(batch)
            if len(batch) < 100:  # last page, no need to continue
                break
        if not items:
            return {}
        return asyncio.run(self._scan_one_query_async(items))

    async def _extract_item(self, session, sem, seen, seen_lock, item,
                            proxy=_AUTO):
        """Fetch one search hit's raw file and extract key candidates."""
        repo = item.get("repository", {}).get("full_name", "")
        path = item.get("path", "")
        html_url = item.get("html_url", "")
        if not repo or not path:
            return []
        if any(fnmatch.fnmatch(repo, p) for p in self.exclude_repos):
            return []
        # Skip test/demo files (vast majority are zero-balance)
        if self._is_likely_test_key(path, repo):
            return []

        # Lock-guarded dedup check
        cache = f"{repo}/{path}"
        async with seen_lock:
            if cache in seen:
                return []
            seen.add(cache)

        branch = "main"
        if "/blob/" in html_url:
            branch = html_url.split("/blob/")[1].split("/")[0]

        text = await self._fetch_raw_async(sem, repo, path, branch,
                                           session=session, proxy=proxy)
        if not text:
            return []

        cands = self._detector.extract(text, context=f"{repo} {path}")
        return [(c.key, repo, path, html_url, c.providers) for c in cands]

    def _merge_candidates(self, all_keys: dict, batch_results: list):
        for results in batch_results:
            for k, repo, path, html_url, providers in results:
                if k not in all_keys:
                    all_keys[k] = {"key": k, "key_preview": k[:10] + "..." + k[-4:],
                                   "repos": [], "providers": providers,
                                   "source": "github"}
                if repo not in [r["repo"] for r in all_keys[k]["repos"]]:
                    all_keys[k]["repos"].append({"repo": repo, "file": path, "url": html_url})
                    self.log(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{path}")

    async def _scan_one_query_async(self, items: list, session=None,
                                    proxy=_AUTO) -> dict:
        """Fetch all files concurrently and extract keys"""
        all_keys = {}
        seen = set()
        seen_lock = asyncio.Lock()
        sem = asyncio.Semaphore(15)  # fetch 15 files concurrently

        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession()
            self._async_session = session
        try:
            tasks = [self._extract_item(session, sem, seen, seen_lock,
                                        item, proxy) for item in items]
            batch_results = await asyncio.gather(*tasks)
        finally:
            if own_session:
                self._async_session = None
                await session.close()

        self._merge_candidates(all_keys, batch_results)
        return all_keys

    async def _fetch_raw_async(self, sem: asyncio.Semaphore, repo: str,
                               path: str, branch: str = "main",
                               session=None, proxy=_AUTO) -> str:
        """Fetch raw file content async (tries multiple branch names)"""
        sess = session or self._async_session
        async with sem:
            tried = set()
            for br in [branch, "main", "master", "develop", "dev", "HEAD"]:
                if br in tried:
                    continue
                tried.add(br)
                url = f"https://raw.githubusercontent.com/{repo}/{br}/{path}"
                px = (self._proxy_pool.next(url) if proxy is _AUTO
                      else proxy)
                try:
                    async with sess.get(url,
                                        proxy=px,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        headers={"User-Agent": "Mozilla/5.0"}) as resp:
                        if resp.status == 200:
                            return await resp.text()
                except Exception:
                    if px:
                        self._proxy_pool.mark_bad(px)
            return ""

    # ---- Parallel batched search (one worker per proxy/token pair) ----

    async def _gh_search_async(self, session, query: str, per_page: int = 100,
                               page: int = 1, proxy=None, token=None) -> list:
        """Async GitHub code search. Uses the worker's dedicated token if
        given, else acquires one from the pool. Honours rate-limit headers."""
        encoded = urllib.parse.quote(query, safe=":+")
        url = (f"https://api.github.com/search/code?q={encoded}"
               f"&per_page={per_page}&page={page}")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        for attempt in range(3):
            tok = token or (self._token_pool.acquire() if self._token_pool
                            else self.get_gh_token())
            if tok:
                headers["Authorization"] = f"Bearer {tok}"
            try:
                async with session.get(
                        url, headers=headers, proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if self._token_pool and tok:
                        self._token_pool.update(tok, resp.headers)
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("items", [])
                    if resp.status in (403, 429):
                        ra = resp.headers.get("Retry-After")
                        wait = int(ra) if ra else 10 + (2 ** attempt) * 15
                        if self._token_pool and tok:
                            self._token_pool.cooldown(tok, wait)
                        self.log(f"GitHub rate limit (HTTP {resp.status}), "
                                 f"waiting {wait}s", "warning")
                        await asyncio.sleep(wait)
                        continue
                    if resp.status == 422:
                        return []
                    await asyncio.sleep(5 + attempt * 5)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if proxy:
                    self._proxy_pool.mark_bad(proxy)
                self.log(f"GitHub async network error: {type(e).__name__} "
                         f"(attempt {attempt+1})", "warning")
                await asyncio.sleep(3 + attempt * 3)
        return []

    async def _query_worker(self, query: str, proxy, token) -> dict:
        """One worker: all pages of one query + concurrent raw fetches,
        all through its own proxy/token pair."""
        keys = {}
        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=20)) as session:
            items = []
            for page in range(1, self.scan_pages + 1):
                if self._should_stop():
                    break
                if page > 1:
                    await asyncio.sleep(4.0)
                batch = await self._gh_search_async(
                    session, query, page=page, proxy=proxy, token=token)
                if not batch:
                    break
                items.extend(batch)
                if len(batch) < 100:
                    break
            if not items:
                return keys
            found = await self._scan_one_query_async(
                items, session=session, proxy=proxy)
            return found

    async def _scan_queries_parallel(self, queries: list) -> dict:
        """Run len(queries) workers concurrently — worker i uses
        proxies[i % n_proxies] and tokens[i % n_tokens] (pool fallback)."""
        proxies = list(self._proxy_pool._proxies) or [None]
        tokens = self._gh_tokens or []

        async def run_one(i, q):
            proxy = proxies[i % len(proxies)]
            token = tokens[i % len(tokens)] if tokens else None
            self.log(f"  [worker {i}] {q} "
                     f"(proxy={proxy or 'direct'}, token={'own' if token else 'pool'})")
            try:
                return await self._query_worker(q, proxy, token)
            except Exception as e:
                self.log(f"  [worker {i}] error: {e}", "error")
                return {}

        results = await asyncio.gather(
            *[run_one(i, q) for i, q in enumerate(queries)])
        merged = {}
        for kd in results:
            for k, v in kd.items():
                if k not in merged:
                    merged[k] = v
                else:
                    for r in v["repos"]:
                        if r["repo"] not in [x["repo"] for x in merged[k]["repos"]]:
                            merged[k]["repos"].append(r)
        return merged

    def _verify_dict(self, keys_dict: dict) -> list:
        """Verify a dict of keys, return a result list"""
        if not keys_dict:
            return []
        return asyncio.run(self._verify_all_async(keys_dict))

    def _exportable(self, r: dict) -> dict:
        """Result dict safe to write to disk. When store_raw_keys=False the
        raw key is replaced by its sha256 hash (preview stays)."""
        if self.store_raw_keys:
            return r
        r = dict(r)
        raw = r.pop("key", "")
        r["key_hash"] = _key_hash(raw) if raw else r.get("key_hash", "")
        return r

    def _save_incremental(self, valid_results: list, round_idx: int, total_rounds: int):
        """Incremental save: rewrite JSON + CSV in full (CSV no longer appends, to avoid duplicates)"""
        os.makedirs(self.output_dir, exist_ok=True)
        sorted_r = self.sort_results(valid_results)

        # CSV rewrite (dedup)
        csv_path = os.path.join(self.output_dir, "api_keys_result.csv")
        try:
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                f.write("KeyPreview,KeyID,Provider,Valid,RawBalance,Currency,USDEquiv,CNYEquiv,Repo,FileName,FilePath,RepoURL,VerifiedAt\n")
                for r in sorted_r:
                    er = self._exportable(r)
                    key_id = er.get("key") or er.get("key_hash", "")
                    repos_str = "; ".join([x["repo"] for x in r.get("repos", [])[:3]])
                    file_names = "; ".join([x.get("file", "").split("/")[-1] for x in r.get("repos", [])[:3]])
                    file_paths = "; ".join([x.get("file", "") for x in r.get("repos", [])[:3]])
                    repo_urls = "; ".join([x.get("url", "") for x in r.get("repos", [])[:3]])
                    cur = r.get("primary_currency", "N/A")
                    provider = r.get("provider", "?")
                    f.write(f'{r["key_preview"]},{key_id},{provider},{r["valid"]},'
                            f'{r["balance"]:.4f},{cur},{r["balance_usd"]:.2f},{r["balance_cny"]:.2f},'
                            f'"{repos_str}","{file_names}","{file_paths}","{repo_urls}",{r["verified_at"]}\n')
        except PermissionError:
            pass

        # JSON rewrite
        json_path = os.path.join(self.output_dir, "api_keys_result.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([self._exportable(r) for r in sorted_r],
                          f, ensure_ascii=False, indent=2)
        except PermissionError:
            pass

        self.log(f"  Incremental save: {len(valid_results)} valid keys | round {round_idx+1}/{total_rounds}")

    def _save_final(self, valid_results: list):
        """Final save"""
        sorted_r = self.sort_results(valid_results)
        os.makedirs(self.output_dir, exist_ok=True)

        # JSON
        json_path = os.path.join(self.output_dir, "api_keys_result.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([self._exportable(r) for r in sorted_r],
                          f, ensure_ascii=False, indent=2)
            self.log(f"Final save JSON: {json_path} ({len(sorted_r)} entries)")
        except Exception as e:
            self.log(f"JSON save failed: {e}", "error")

        # Markdown
        md_path = os.path.join(self.output_dir, "api_keys_result.md")
        try:
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("# API Key Hunter - Scan Results\n\n")
                f.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Exchange Rate:** 1 USD = {self.usd_cny_rate} CNY\n\n")
                f.write("## Summary\n\n")
                f.write(f"| Metric | Value |\n|---|---|\n")
                f.write(f"| Valid Keys | {len(sorted_r)} |\n")
                if sorted_r:
                    total_usd = sum(r["balance_usd"] for r in sorted_r)
                    total_cny = sum(r["balance_cny"] for r in sorted_r)
                    f.write(f"| Total USD | ${total_usd:.2f} |\n")
                    f.write(f"| Total CNY | ¥{total_cny:.2f} |\n")
                    f.write(f"| Max Balance | ${max(r['balance_usd'] for r in sorted_r):.2f} |\n")
                f.write(f"\n## Keys by Provider & USD Value\n\n")
                f.write(f"| # | Key | Provider | Balance | USD | CNY | Source |\n")
                f.write(f"|---|---|---|---|---|---|---|\n")
                for i, r in enumerate(sorted_r):
                    src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
                    cur = r.get("primary_currency", "USD")
                    prov = r.get("provider", "?").upper()
                    f.write(f"| {i+1} | `{r['key_preview']}` | {prov} | {cur} {r['balance']:.4f} | "
                            f"${r['balance_usd']:.2f} | ¥{r['balance_cny']:.2f} | {src} |\n")
            self.log(f"Final save Markdown: {md_path}")
        except Exception as e:
            self.log(f"Markdown save failed: {e}", "error")

    def _should_stop(self) -> bool:
        if self._stop_requested:
            return True
        if self.max_duration > 0:
            elapsed = time.time() - self._start_time
            if elapsed >= self.max_duration:
                return True
        if self.max_valid_keys > 0 and self._valid_count >= self.max_valid_keys:
            return True
        return False

    def _stop_reason(self) -> str:
        if self._stop_requested:
            return "manual stop"
        if self.max_duration > 0 and time.time() - self._start_time >= self.max_duration:
            return f"time limit reached ({self.max_duration}s)"
        if self.max_valid_keys > 0 and self._valid_count >= self.max_valid_keys:
            return f"valid key target reached ({self.max_valid_keys})"
        return ""

    def _auto_save(self, results: list, force: bool = False):
        n = len(results)
        if not force and n - self._saved_count < self.auto_save_interval:
            return
        self._saved_count = n
        os.makedirs(self.output_dir, exist_ok=True)
        # Save sorted results as JSON
        sorted_r = self.sort_results(results)
        path = os.path.join(self.output_dir, "api_keys_autosave.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sorted_r, f, ensure_ascii=False, indent=2)
            self.log(f"Auto-save: {n} results → {path}", "info")
        except Exception as e:
            pass  # silent fail for autosave

    # ---- GitHub Search ----

    def _gh_search(self, query: str, per_page: int = 100, page: int = 1) -> list:
        """GitHub Code Search via direct HTTP API (no gh CLI dependency).
        Uses token from env var or gh CLI for authenticated access (30 req/min).
        Tracks X-RateLimit-Remaining to avoid hitting the rate limit."""
        encoded = urllib.parse.quote(query, safe=":+")
        url = f"https://api.github.com/search/code?q={encoded}&per_page={per_page}&page={page}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self.user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        }

        max_retries = 3
        for attempt in range(max_retries):
            token = (self._token_pool.acquire() if self._token_pool
                     else self.get_gh_token())
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                r = requests.get(url, headers=headers, timeout=20)
                if self._token_pool and token:
                    self._token_pool.update(token, r.headers)
                remaining = r.headers.get("X-RateLimit-Remaining")
                if remaining:
                    remaining = int(remaining)
                    if remaining < 5:
                        reset_ts = int(r.headers.get("X-RateLimit-Reset", 0))
                        wait = max(5, reset_ts - int(time.time()) + 1) if reset_ts else 30
                        self.log(f"GitHub rate-limit warning: {remaining} left, waiting {wait}s", "warning")
                        time.sleep(wait)

                if r.status_code == 200:
                    data = r.json()
                    return data.get("items", [])
                elif r.status_code == 429 or r.status_code == 403:
                    # Use Retry-After header if available, else exponential backoff
                    retry_after = r.headers.get("Retry-After")
                    wait = int(retry_after) if retry_after else (10 + (2 ** attempt) * 15)
                    if self._token_pool and token:
                        self._token_pool.cooldown(token, wait)
                    self.log(f"GitHub API rate limit (HTTP {r.status_code}), waiting {wait}s (attempt {attempt+1})...", "warning")
                    time.sleep(wait)
                    continue
                elif r.status_code == 422:
                    return []
                else:
                    self.log(f"GitHub API HTTP {r.status_code} (attempt {attempt+1})", "warning")
                    if attempt < max_retries - 1:
                        time.sleep(5 + attempt * 5)
                        continue
                    return []
            except (requests.RequestException, requests.Timeout) as e:
                self.log(f"GitHub API network error: {e} (attempt {attempt+1})", "warning")
                if attempt < max_retries - 1:
                    time.sleep(3 + attempt * 3)
                else:
                    return []
        return []

    def _fetch_raw(self, repo: str, path: str, branch: str = "main") -> str:
        for br in [branch, "main", "master"]:
            url = f"https://raw.githubusercontent.com/{repo}/{br}/{path}"
            proxy = self._proxy_pool.next(url) if self._proxy_pool else None
            try:
                resp = requests.get(url, timeout=self.timeout,
                                    headers={"User-Agent": "Mozilla/5.0"},
                                    proxies={"http": proxy, "https": proxy}
                                    if proxy else None)
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                if proxy:
                    self._proxy_pool.mark_bad(proxy)
        return ""

    def scan_github(self, queries: list) -> dict:
        all_keys = {}
        seen = set()
        stopped_early = False

        for i, query in enumerate(queries):
            if self._should_stop():
                stopped_early = True
                break

            self.log(f"[{i+1}/{len(queries)}] {query}")
            self.progress_callback(i + 1, len(queries), "search")

            items = self._gh_search(query)
            self.log(f"  Results: {len(items)} files")

            for j, item in enumerate(items):
                # Check for timeout while iterating (bail every 5 files)
                if j % 5 == 0 and self._should_stop():
                    stopped_early = True
                    break

                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                if not repo or not path:
                    continue
                if any(fnmatch.fnmatch(repo, p) for p in self.exclude_repos):
                    continue

                cache = f"{repo}/{path}"
                if cache in seen:
                    continue
                seen.add(cache)

                branch = "main"
                if "/blob/" in html_url:
                    branch = html_url.split("/blob/")[1].split("/")[0]

                text = self._fetch_raw(repo, path, branch)
                if not text:
                    continue

                cands = self._detector.extract(text, context=f"{repo} {path}")

                for c in cands:
                    k = c.key
                    if k not in all_keys:
                        all_keys[k] = {"key": k, "key_preview": k[:10] + "..." + k[-4:],
                                       "repos": [], "providers": c.providers,
                                       "source": "github"}
                    if repo not in [r["repo"] for r in all_keys[k]["repos"]]:
                        all_keys[k]["repos"].append({"repo": repo, "file": path, "url": html_url})
                        self.log(f"  [KEY] {k[:10]}...{k[-4:]} | {repo}/{path}")

            # Check whether to stop right after the current query (don't wait for the next one)
            if stopped_early or self._should_stop():
                stopped_early = True
                break

            time.sleep(self.search_delay)

        if stopped_early:
            elapsed = time.time() - self._start_time
            self.log(f"Scan stopped early: {self._stop_reason()} ({elapsed:.0f}s), collected {len(all_keys)} keys", "warning")
        return all_keys

    # ---- Async Verification (Multi-Provider) ----

    def _get_active_providers(self) -> list:
        """Return list of provider configs matching self.providers."""
        active = []
        for pc in PROVIDER_CONFIGS:
            if pc["name"] in self.providers:
                active.append(pc)
        return active or [PROVIDER_CONFIGS[0]]  # fallback: default to first provider

    async def _try_provider_endpoint(self, session: aiohttp.ClientSession,
                                     api_key: str, provider: dict) -> dict:
        """Try a single provider's balance endpoint. Returns verification result."""
        name = provider["name"]
        url = f"{provider['base']}{provider['balance_url']}"
        headers = {"Authorization": f"Bearer {api_key}"}

        try:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = self._parse_provider_response(name, data)
                    # For OpenAI / OpenRouter: try credit endpoint to get actual balance
                    if provider.get("credit_url"):
                        if name == "openai":
                            balance = await self._try_openai_credits(session, api_key, provider)
                        elif name == "openrouter":
                            balance = await self._try_openrouter_credits(session, api_key, provider)
                        else:
                            balance = None
                        if balance is not None:
                            result.update(balance)
                    return result
                elif resp.status == 401:
                    return {"valid": False, "reason": f"{name}:invalid_key"}
                elif resp.status == 429:
                    await asyncio.sleep(1.5)
                    return {"valid": False, "reason": f"{name}:rate_limited"}
                else:
                    return {"valid": False, "reason": f"{name}:HTTP_{resp.status}"}
        except asyncio.TimeoutError:
            return {"valid": False, "reason": f"{name}:timeout"}
        except Exception as e:
            return {"valid": False, "reason": f"{name}:{str(e)[:60]}"}

    async def _try_openai_credits(self, session: aiohttp.ClientSession,
                                   api_key: str, provider: dict):
        """Try OpenAI credit_grants endpoint to get actual balance.
        Returns balance dict or None if endpoint is unavailable."""
        url = f"{provider['base']}{provider['credit_url']}"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    parsed = _parse_openai_credits(data)
                    return {"total_balance": parsed["total_balance"],
                            "primary_currency": parsed["primary_currency"],
                            "openai_grants": parsed.get("openai_grants"),
                            "balance_unavailable": False,
                            "provider_note": ""}
        except Exception:
            pass
        return None

    async def _try_openrouter_credits(self, session: aiohttp.ClientSession,
                                       api_key: str, provider: dict):
        """Try OpenRouter /credits endpoint to get actual balance.
        Returns balance dict or None if endpoint is unavailable."""
        url = f"{provider['base']}{provider['credit_url']}"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    parsed = _parse_openrouter_credits(data)
                    return {"total_balance": parsed["total_balance"],
                            "primary_currency": parsed["primary_currency"],
                            "openrouter_credits": parsed.get("openrouter_credits"),
                            "balance_unavailable": False,
                            "provider_note": ""}
        except Exception:
            pass
        return None

    def _parse_provider_response(self, provider_name: str, data: dict) -> dict:
        """Parse balance response based on provider name."""
        if provider_name == "deepseek":
            result = _parse_deepseek_balance(data)
        elif provider_name == "openai":
            result = _parse_openai_models(data)
        elif provider_name == "openrouter":
            result = _parse_openrouter_balance(data)
        elif provider_name == "opencode":
            result = _parse_openai_models(data)  # Same OpenAI-compatible /models response
            result["provider_note"] = "Valid key (balance not available via API)"
        else:
            result = {"valid": False, "reason": "unknown_provider"}
        result["provider"] = provider_name
        return result

    async def _verify_one(self, session: aiohttp.ClientSession, api_key: str,
                          semaphore: asyncio.Semaphore,
                          providers_hint: list = None) -> dict:
        """Verify one API key against provider candidates (detector-ranked
        first, falling back to configured provider order). One GET per
        provider; balance probing only when self.check_balance."""
        async with semaphore:
            providers = providers_hint or self.providers
            result = await _verify_key_external(
                session, api_key, providers,
                check_balance=self.check_balance, timeout=self.timeout)
            if not result.get("provider"):
                result["provider"] = providers[0] if providers else "unknown"
            return result

    async def _verify_all_async(self, all_keys: dict) -> list:
        semaphore = asyncio.Semaphore(self.concurrency)
        keys_list = list(all_keys.items())
        total = len(keys_list)
        done = [0]
        results = []
        valid_count = [0]
        batch_stop = [False]  # flag to signal batch completion

        async with aiohttp.ClientSession() as session:
            async def wrapped(key, info):
                nonlocal done
                v = await self._verify_one(session, key, semaphore,
                                           info.get("providers"))
                done[0] += 1

                if v.get("valid"):
                    valid_count[0] += 1
                    self._valid_count = valid_count[0]
                    primary_cur = v.get("primary_currency", "USD")
                    usd_eq = convert_to_usd(v["total_balance"], primary_cur, self.usd_cny_rate)
                    cny_eq = convert_to_cny(v["total_balance"], primary_cur, self.usd_cny_rate)
                    provider_name = v.get("provider", "").upper() if v.get("provider") else ""
                    self.log(f"  [{done[0]}/{total}] {key[:10]}...{key[-4:]} -> "
                             f"[{provider_name}] {primary_cur} {v['total_balance']:.4f} (≈${usd_eq:.2f} / ¥{cny_eq:.2f})")
                else:
                    self.log(f"  [{done[0]}/{total}] {key[:10]}...{key[-4:]} -> {v.get('reason', '?')}")

                self.progress_callback(done[0], total, "verify")

                entry = {
                    "key": key,
                    "key_preview": info["key_preview"],
                    "status": v.get("status", ""),
                    "valid": v.get("valid", False),
                    "balance": v.get("total_balance", 0),
                    "balance_details": v.get("balance_details", []),
                    "primary_currency": v.get("primary_currency", "USD"),
                    "balance_usd": convert_to_usd(v.get("total_balance", 0),
                                                   v.get("primary_currency", "USD"), self.usd_cny_rate),
                    "balance_cny": convert_to_cny(v.get("total_balance", 0),
                                                   v.get("primary_currency", "USD"), self.usd_cny_rate),
                    "reason": v.get("reason", ""),
                    "provider": v.get("provider", "unknown"),
                    "provider_note": v.get("provider_note", ""),
                    "balance_unavailable": v.get("balance_unavailable", False),
                    "repos": info["repos"],
                    "rate_limit": v.get("rate_limit", {}),
                    "verified_at": datetime.now().isoformat(),
                }
                results.append(entry)
                if self._store:
                    self._store.upsert_result(entry,
                                              source=info.get("source", ""),
                                              query=info.get("query", ""))

                # Batch stop: count ALL valid keys (original high-throughput logic)
                if self.max_valid_keys > 0 and valid_count[0] >= self.max_valid_keys and not batch_stop[0]:
                    batch_stop[0] = True

                return entry

            # Process in batches: don't check the timeout for the first batch (ensure at least one batch is verified)
            batch_size = self.concurrency
            first_batch = True
            for start in range(0, len(keys_list), batch_size):
                if not first_batch and (self._should_stop() or batch_stop[0]):
                    unprocessed = len(keys_list) - start
                    self.log(f"Verification stopped: {self._stop_reason()}, skipping remaining {unprocessed} keys")
                    break
                first_batch = False
                batch = keys_list[start:start + batch_size]
                tasks = [wrapped(k, v) for k, v in batch]
                await asyncio.gather(*tasks)

        return results

    def verify_keys(self, all_keys: dict) -> list:
        self.log(f"Verifying {len(all_keys)} keys (concurrency {self.concurrency})...")
        self.progress_callback(0, len(all_keys), "verify")
        t0 = time.time()
        results = asyncio.run(self._verify_all_async(all_keys))
        self.log(f"Verification done: {time.time()-t0:.1f}s")
        return results

    # ---- Result handling ----

    def sort_results(self, results: list) -> list:
        results.sort(key=lambda x: x.get("balance_usd", 0), reverse=True)
        return results

    def _safe_write(self, path: str, write_func, retries: int = 5) -> bool:
        """Safe file write, handles the file being locked"""
        for attempt in range(retries):
            try:
                write_func(path)
                return True
            except PermissionError:
                if attempt < retries - 1:
                    # Fallback filename with a timestamp
                    base, ext = os.path.splitext(path)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    path = f"{base}_{ts}{ext}"
                else:
                    self.log(f"Save failed (file locked): {path}", "warning")
                    return False
            except Exception as e:
                self.log(f"Save failed: {e}", "error")
                return False
        return False

    def save_results(self, results: list, fmt: str = "all") -> list:
        os.makedirs(self.output_dir, exist_ok=True)
        results = self.sort_results(results)

        if fmt in ("all", "json"):
            path = os.path.join(self.output_dir, "api_keys_result.json")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    json.dump([self._exportable(r) for r in results],
                              f, ensure_ascii=False, indent=2)

            if self._safe_write(path, _write):
                self.log(f"JSON: {path}")

        if fmt in ("all", "csv"):
            path = os.path.join(self.output_dir, "api_keys_result.csv")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("KeyPreview,KeyID,Provider,Valid,RawBalance,Currency,USDEquiv,CNYEquiv,Repo,FileName,FilePath,RepoURL,VerifiedAt\n")
                    for r in results:
                        er = self._exportable(r)
                        key_id = er.get("key") or er.get("key_hash", "")
                        repos_str = "; ".join([x["repo"] for x in r["repos"][:3]])
                        cur = r.get("primary_currency", "N/A")
                        provider = r.get("provider", "?")
                        f.write(f'{r["key_preview"]},{key_id},{provider},{r["valid"]},'
                                f'{r["balance"]:.4f},{cur},{r["balance_usd"]:.2f},{r["balance_cny"]:.2f},'
                                f'"{repos_str}",{r["verified_at"]}\n')

            if self._safe_write(path, _write):
                self.log(f"CSV: {path}")

        if fmt in ("all", "markdown"):
            path = os.path.join(self.output_dir, "api_keys_result.md")

            def _write(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# API Key Hunter - Scan Results\n\n")
                    f.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"**Exchange Rate:** 1 USD = {self.usd_cny_rate} CNY\n\n")
                    valid = [r for r in results if r["valid"]]
                    f.write("## Summary\n\n")
                    f.write(f"| Metric | Value |\n|---|---|\n")
                    f.write(f"| Total Keys | {len(results)} |\n")
                    f.write(f"| Valid Keys | {len(valid)} |\n")
                    if valid:
                        total_usd = sum(r["balance_usd"] for r in valid)
                        total_cny = sum(r["balance_cny"] for r in valid)
                        f.write(f"| Total Balance | ${total_usd:.2f} / ¥{total_cny:.2f} |\n")
                    f.write(f"\n## Keys by Provider & USD Value\n\n")
                    f.write(f"| # | Key | Provider | Balance (Original) | USD Equivalent | CNY Equivalent | Source |\n")
                    f.write(f"|---|---|---|---|---|---|---|\n")
                    for i, r in enumerate(valid):
                        src = r["repos"][0]["repo"] if r.get("repos") else "N/A"
                        cur = r.get("primary_currency", "USD")
                        prov = r.get("provider", "?").upper()
                        f.write(f"| {i+1} | `{r['key_preview']}` | {prov} | "
                                f"{cur} {r['balance']:.4f} | ${r['balance_usd']:.2f} | "
                                f"¥{r['balance_cny']:.2f} | {src} |\n")

            if self._safe_write(path, _write):
                self.log(f"Markdown: {path}")

        return results

    # ---- Progress management ----

    def save_progress(self, all_keys: dict, path: str = None):
        path = path or os.path.join(self.output_dir, ".akh_progress.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(all_keys, f, ensure_ascii=False, indent=2)

    def load_progress(self, path: str = None) -> dict:
        path = path or os.path.join(self.output_dir, ".akh_progress.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    @staticmethod
    def load_keys_from_file(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            keys = {}
            for item in raw:
                key = item.get("key", "")
                if key:
                    keys[key] = {
                        "key": key,
                        "key_preview": item.get("key_preview", key[:10] + "..." + key[-4:]),
                        "repos": item.get("repos", []),
                    }
            return keys
        return raw

    @staticmethod
    def load_queries_file(path: str) -> list:
        queries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    queries.append(line)
        return queries
