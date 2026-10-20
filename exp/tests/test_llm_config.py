import pytest

import app.agent.llm as llm
import app.config as config
from app.agent.llm import (
    LLMConfigurationError,
    ProviderSpec,
    describe_chain,
    get_chain,
    parse_provider_spec,
    structured_method_for,
    validate_spec,
)


def _set_config(monkeypatch, **values):
    for key, value in values.items():
        monkeypatch.setattr(config, key, value)


@pytest.mark.parametrize(
    ("raw", "provider", "model"),
    [
        ("ollama/qwen2.5:14b", "ollama", "qwen2.5:14b"),
        ("groq/llama-3.3-70b-versatile", "groq", "llama-3.3-70b-versatile"),
        (
            "openrouter/meta-llama/llama-3.3-70b-instruct",
            "openrouter",
            "meta-llama/llama-3.3-70b-instruct",
        ),
        ("openai-compatible/deepseek-chat", "openai_compatible", "deepseek-chat"),
    ],
)
def test_parse_provider_spec(monkeypatch, raw, provider, model):
    _set_config(
        monkeypatch,
        GROQ_API_KEY="gsk_test",
        OPENROUTER_API_KEY="or_test",
        OPENAI_COMPATIBLE_API_KEY="compat_test",
        OPENAI_COMPATIBLE_BASE_URL="https://llm.example.com/v1",
    )
    spec = parse_provider_spec(raw)
    assert spec.provider == provider
    assert spec.model == model


def test_primary_provider_keeps_model_slashes(monkeypatch):
    _set_config(monkeypatch, OPENROUTER_API_KEY="or_test")
    spec = parse_provider_spec("meta-llama/llama-3.3-70b-instruct", provider="openrouter")
    assert spec.provider == "openrouter"
    assert spec.model == "meta-llama/llama-3.3-70b-instruct"


def test_provider_aliases():
    assert llm._normalize_provider("openai-compatible") == "openai_compatible"
    assert llm._normalize_provider("custom") == "openai_compatible"


def test_parse_rejects_unknown_provider():
    with pytest.raises(LLMConfigurationError):
        parse_provider_spec("unknown/model")


def test_provider_base_urls(monkeypatch):
    _set_config(monkeypatch, OLLAMA_BASE_URL="http://ollama.local:11434")
    assert parse_provider_spec("ollama/qwen2.5:14b").base_url == "http://ollama.local:11434"
    assert parse_provider_spec("openrouter/x").base_url == "https://openrouter.ai/api/v1"
    assert parse_provider_spec("deepseek/x").base_url == "https://api.deepseek.com/v1"


def test_chain_primary_and_fallback(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="ollama",
        LLM_MODEL="qwen2.5:14b",
        LLM_FALLBACKS=("groq/llama-3.3-70b-versatile",),
        GROQ_API_KEY="gsk_test",
    )
    assert describe_chain() == ["ollama/qwen2.5:14b", "groq/llama-3.3-70b-versatile"]


def test_missing_fallback_key_is_skipped(monkeypatch, caplog):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="ollama",
        LLM_MODEL="qwen2.5:14b",
        LLM_FALLBACKS=("groq/llama-3.3-70b-versatile",),
        GROQ_API_KEY="",
    )
    assert describe_chain() == ["ollama/qwen2.5:14b"]
    assert "Skipping LLM fallback" in caplog.text


def test_missing_primary_key_falls_through_to_valid_fallback(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="groq",
        LLM_MODEL="llama-3.3-70b-versatile",
        LLM_API_KEY="",
        LLM_FALLBACKS=("ollama/qwen2.5:14b",),
        GROQ_API_KEY="",
    )
    assert describe_chain() == ["ollama/qwen2.5:14b"]


def test_no_usable_provider_raises(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="groq",
        LLM_MODEL="llama-3.3-70b-versatile",
        LLM_API_KEY="",
        LLM_FALLBACKS=(),
        GROQ_API_KEY="",
    )
    with pytest.raises(LLMConfigurationError):
        get_chain()


def test_llm_api_key_overrides_provider_key(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="groq",
        LLM_MODEL="llama-3.3-70b-versatile",
        LLM_API_KEY="override-key",
        GROQ_API_KEY="",
    )
    chain = get_chain()
    assert chain[0].label == "groq/llama-3.3-70b-versatile"
    assert chain[0].api_key == "override-key"


def test_provider_specific_key_used_without_override(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="groq",
        LLM_MODEL="llama-3.3-70b-versatile",
        LLM_API_KEY="",
        GROQ_API_KEY="provider-key",
    )
    chain = get_chain()
    assert chain[0].api_key == "provider-key"


def test_invalid_fallback_entries_are_ignored(monkeypatch):
    _set_config(
        monkeypatch,
        LLM_PROVIDER="ollama",
        LLM_MODEL="qwen2.5:14b",
        LLM_FALLBACKS=("not-a-spec", "unknown/model"),
        GROQ_API_KEY="",
    )
    assert describe_chain() == ["ollama/qwen2.5:14b"]


def test_openai_compatible_requires_base_url():
    spec = ProviderSpec(
        provider="openai_compatible",
        model="custom-model",
        api_key="compat_test",
        base_url=None,
    )
    with pytest.raises(LLMConfigurationError):
        validate_spec(spec)


def test_structured_method_defaults():
    assert structured_method_for("ollama") == "json_schema"
    assert structured_method_for("groq") == "function_calling"
    assert structured_method_for("openai") == "function_calling"
    assert structured_method_for("groq", "json_mode") == "json_mode"
    with pytest.raises(LLMConfigurationError):
        structured_method_for("groq", "invalid")


def test_api_key_not_in_configuration_errors(monkeypatch):
    secret = "gsk_super_secret_value"
    _set_config(
        monkeypatch,
        LLM_PROVIDER="groq",
        LLM_MODEL="",
        LLM_FALLBACKS=(),
        GROQ_API_KEY=secret,
    )
    with pytest.raises(LLMConfigurationError) as exc_info:
        get_chain()
    assert secret not in str(exc_info.value)
