"""
config/llm_factory.py — Generic LLM provider factory.
Returns the correct LangChain chat model based on YAML config.
Supports: gemini, anthropic, openai, github, groq, ollama (local llama/mistral).

Usage:
    from config.llm_factory import get_llm
    llm = get_llm()                # reads from vuln_config.yaml
    llm = get_llm(config=my_cfg)   # pass config dict directly
"""
import os
import yaml
from typing import Optional


# ── Provider → required env var mapping ──────────────────────────────
PROVIDER_ENV_KEYS = {
    "gemini": "GOOGLE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "github": "GITHUB_TOKEN",
    "groq": "GROQ_API_KEY",
    "ollama": None,  # local, no key needed
}

# ── Default settings if not specified in config ──────────────────────
DEFAULTS = {
    "provider": "gemini",
    "model": "gemini-2.0-flash",
    "temperature": 0,
    "max_retries": 6,
}


def _load_llm_config(config: Optional[dict] = None) -> dict:
    """Extract the llm section from config, falling back to defaults."""
    if config is None:
        config_path = os.path.join(
            os.path.dirname(__file__), "vuln_config.yaml"
        )
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

    llm_cfg = config.get("llm", {})
    return {
        "provider": llm_cfg.get("provider", DEFAULTS["provider"]),
        "model": llm_cfg.get("model", DEFAULTS["model"]),
        "temperature": llm_cfg.get("temperature", DEFAULTS["temperature"]),
        "max_retries": llm_cfg.get("max_retries", DEFAULTS["max_retries"]),
    }


def check_api_key(provider: str) -> None:
    """Raise if the required env var for the provider is missing."""
    env_key = PROVIDER_ENV_KEYS.get(provider)
    if env_key and not os.getenv(env_key):
        raise EnvironmentError(
            f"Provider '{provider}' requires the {env_key} environment variable.\n"
            f"  Set it in your .env file or export it:\n"
            f"  export {env_key}=your-key-here"
        )


def get_llm(config: Optional[dict] = None):
    """
    Build and return a LangChain chat model from config.

    Supported providers:
      - gemini     → ChatGoogleGenerativeAI  (GOOGLE_API_KEY)
      - anthropic  → ChatAnthropic           (ANTHROPIC_API_KEY)
      - openai     → ChatOpenAI              (OPENAI_API_KEY)
      - github     → ChatOpenAI + GitHub Models endpoint (GITHUB_TOKEN)
      - groq       → ChatGroq               (GROQ_API_KEY)
      - ollama     → ChatOllama              (local, no key)
    """
    cfg = _load_llm_config(config)
    provider = cfg["provider"].lower()
    model = cfg["model"]
    temperature = cfg["temperature"]
    max_retries = cfg["max_retries"]

    check_api_key(provider)

    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            max_retries=max_retries,
        )

    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            temperature=temperature,
            max_retries=max_retries,
        )

    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            temperature=temperature,
            max_retries=max_retries,
        )

    elif provider == "github":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            temperature=temperature,
            max_retries=max_retries,
            base_url="https://models.inference.ai.azure.com",
            api_key=os.getenv("GITHUB_TOKEN"),
        )

    elif provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=model,
            temperature=temperature,
            max_retries=max_retries,
        )

    elif provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model,
            temperature=temperature,
        )

    else:
        raise ValueError(
            f"Unknown LLM provider: '{provider}'. "
            f"Supported: gemini, anthropic, openai, github, groq, ollama"
        )


def get_provider_name(config: Optional[dict] = None) -> str:
    """Return the configured provider name (for display/logging)."""
    cfg = _load_llm_config(config)
    return f"{cfg['provider']}:{cfg['model']}"
