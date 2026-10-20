from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables import Runnable
from pydantic import BaseModel

import app.config as config
from app.core.audit import AuditLog

logger = logging.getLogger(__name__)

StructuredMethod = Literal["function_calling", "json_mode", "json_schema"]
VALID_STRUCTURED_METHODS = {"function_calling", "json_mode", "json_schema"}

SUPPORTED_PROVIDERS = {
    "ollama",
    "groq",
    "openai",
    "openrouter",
    "together",
    "deepseek",
    "mistral",
    "xai",
    "openai_compatible",
}

PROVIDER_ALIASES = {
    "openai-compatible": "openai_compatible",
    "openai_compat": "openai_compatible",
    "custom": "openai_compatible",
}

PROVIDER_KEY_ENV = {
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "together": "TOGETHER_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "xai": "XAI_API_KEY",
    "openai_compatible": "OPENAI_COMPATIBLE_API_KEY",
}

PROVIDER_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "together": "https://api.together.xyz/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "xai": "https://api.x.ai/v1",
}


class LLMConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderSpec:
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}"


def _normalize_provider(provider: str) -> str:
    value = (provider or "").strip().lower().replace("-", "_")
    value = PROVIDER_ALIASES.get(value, value)
    if value not in SUPPORTED_PROVIDERS:
        supported = ", ".join(sorted(SUPPORTED_PROVIDERS))
        raise LLMConfigurationError(
            f"Unsupported LLM provider '{provider}'. Supported providers: {supported}"
        )
    return value


def _resolve_api_key(provider: str, override: str | None = None) -> str | None:
    if provider == "ollama":
        return None
    if override:
        return override.strip() or None
    env_name = PROVIDER_KEY_ENV.get(provider)
    if not env_name:
        return None
    value = getattr(config, env_name, "") or ""
    return value.strip() or None


def _resolve_base_url(provider: str, override: str | None = None) -> str | None:
    if provider == "ollama":
        return config.OLLAMA_BASE_URL
    if override and override.strip():
        return override.strip()
    if provider == "openai":
        return config.OPENAI_BASE_URL or None
    if provider == "groq":
        return config.GROQ_BASE_URL or None
    if provider == "openai_compatible":
        return config.OPENAI_COMPATIBLE_BASE_URL or None
    return PROVIDER_BASE_URLS.get(provider)


def parse_provider_spec(
    raw: str,
    *,
    provider: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> ProviderSpec:
    value = (raw or "").strip()
    if not value:
        raise LLMConfigurationError("LLM model is empty")

    if provider is not None:
        raw_provider = provider
        raw_model = value
    else:
        if "/" not in value:
            raise LLMConfigurationError(
                f"Fallback entry '{value}' must use the 'provider/model' format"
            )
        raw_provider, raw_model = value.split("/", 1)

    normalized_provider = _normalize_provider(raw_provider)
    model = raw_model.strip()
    if not model:
        raise LLMConfigurationError(f"Provider '{normalized_provider}' is missing a model")

    return ProviderSpec(
        provider=normalized_provider,
        model=model,
        api_key=_resolve_api_key(normalized_provider, api_key),
        base_url=_resolve_base_url(normalized_provider, base_url),
    )


def validate_spec(spec: ProviderSpec) -> None:
    if not spec.model:
        raise LLMConfigurationError(f"Provider '{spec.provider}' is missing a model")
    if spec.provider != "ollama" and not spec.api_key:
        env_name = PROVIDER_KEY_ENV.get(spec.provider, "LLM_API_KEY")
        raise LLMConfigurationError(f"Provider '{spec.provider}' requires an API key in {env_name}")
    if spec.provider == "openai_compatible" and not spec.base_url:
        raise LLMConfigurationError(
            "Provider 'openai_compatible' requires OPENAI_COMPATIBLE_BASE_URL or LLM_BASE_URL"
        )


def get_chain() -> list[ProviderSpec]:
    provider = config.LLM_PROVIDER or "ollama"
    if not config.LLM_MODEL:
        raise LLMConfigurationError("LLM_MODEL is not set (set LLM_MODEL or OLLAMA_MODEL)")

    candidates = [
        parse_provider_spec(
            config.LLM_MODEL,
            provider=provider,
            api_key=config.LLM_API_KEY or None,
            base_url=config.LLM_BASE_URL or None,
        )
    ]

    for entry in config.LLM_FALLBACKS:
        try:
            candidates.append(parse_provider_spec(entry))
        except LLMConfigurationError as exc:
            logger.warning("Ignoring invalid LLM fallback '%s': %s", entry, exc)

    usable: list[ProviderSpec] = []
    for index, spec in enumerate(candidates):
        try:
            validate_spec(spec)
        except LLMConfigurationError as exc:
            if index == 0:
                logger.warning("Primary LLM is not usable: %s", exc)
            else:
                logger.warning("Skipping LLM fallback %s: %s", spec.label, exc)
            continue
        usable.append(spec)

    if not usable:
        raise LLMConfigurationError(
            "No usable LLM providers configured. Set a provider, model, and API key "
            "(for example LLM_PROVIDER=groq, LLM_MODEL=llama-3.3-70b-versatile, GROQ_API_KEY)."
        )
    return usable


def structured_method_for(provider: str, override: str | None = None) -> StructuredMethod:
    method = (override or config.LLM_STRUCTURED_METHOD or "auto").strip().lower()
    if method and method != "auto":
        if method not in VALID_STRUCTURED_METHODS:
            allowed = ", ".join(sorted(VALID_STRUCTURED_METHODS))
            raise LLMConfigurationError(
                f"Invalid structured output method '{method}'. Allowed: auto, {allowed}"
            )
        return method  # type: ignore[return-value]
    return "json_schema" if provider == "ollama" else "function_calling"


def _common_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"temperature": config.LLM_TEMPERATURE}
    if config.LLM_MAX_TOKENS > 0:
        kwargs["max_tokens"] = config.LLM_MAX_TOKENS
    return kwargs


def build_chat_model(spec: ProviderSpec) -> BaseChatModel:
    if spec.provider == "ollama":
        from langchain_ollama import ChatOllama

        kwargs: dict[str, Any] = {
            "model": spec.model,
            "base_url": spec.base_url or config.OLLAMA_BASE_URL,
            "temperature": config.LLM_TEMPERATURE,
            "client_kwargs": {"timeout": config.LLM_TIMEOUT_SECONDS},
            "async_client_kwargs": {"timeout": config.LLM_TIMEOUT_SECONDS},
        }
        if config.LLM_MAX_TOKENS > 0:
            kwargs["num_predict"] = config.LLM_MAX_TOKENS
        return ChatOllama(**kwargs)

    if spec.provider == "groq":
        from langchain_groq import ChatGroq

        kwargs = _common_kwargs()
        kwargs.update(
            {
                "model": spec.model,
                "api_key": spec.api_key,
                "base_url": spec.base_url,
                "timeout": config.LLM_TIMEOUT_SECONDS,
                "max_retries": config.LLM_MAX_RETRIES,
            }
        )
        return ChatGroq(**kwargs)

    if spec.provider in {
        "openai",
        "openrouter",
        "together",
        "deepseek",
        "mistral",
        "xai",
        "openai_compatible",
    }:
        from langchain_openai import ChatOpenAI

        kwargs = _common_kwargs()
        kwargs.update(
            {
                "model": spec.model,
                "api_key": spec.api_key,
                "base_url": spec.base_url,
                "timeout": config.LLM_TIMEOUT_SECONDS,
                "max_retries": config.LLM_MAX_RETRIES,
            }
        )
        return ChatOpenAI(**kwargs)

    raise LLMConfigurationError(f"Unsupported LLM provider '{spec.provider}'")


class LLMCallLogger(BaseCallbackHandler):
    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.audit.record(
            "llm_start",
            tags=list(tags or []),
            metadata=dict(metadata or {}),
            message_count=sum(len(batch) for batch in messages),
        )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        usage: dict[str, Any] = {}
        llm_output = getattr(response, "llm_output", None) or {}
        if isinstance(llm_output, dict):
            usage = llm_output.get("token_usage") or llm_output.get("usage") or {}
        self.audit.record("llm_end", tags=list(tags or []), usage=usage)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.audit.record(
            "llm_error",
            tags=list(tags or []),
            error=f"{type(error).__name__}: {error}",
        )


def _attach_logging(
    runnable: Runnable[Any, Any], spec: ProviderSpec, call_logger: LLMCallLogger
) -> Runnable[Any, Any]:
    return runnable.with_config(
        {
            "callbacks": [call_logger],
            "tags": [f"llm:{spec.provider}:{spec.model}"],
            "metadata": {"llm_provider": spec.provider, "llm_model": spec.model},
        }
    )


def build_chat_model_chain(
    *,
    specs: list[ProviderSpec] | None = None,
    audit: AuditLog | None = None,
) -> Runnable[Any, Any]:
    chain = list(specs if specs is not None else get_chain())
    if not chain:
        raise LLMConfigurationError("LLM chain is empty")
    call_logger = LLMCallLogger(audit) if audit else None
    runnables: list[Runnable[Any, Any]] = []
    for spec in chain:
        runnable: Runnable[Any, Any] = build_chat_model(spec)
        if call_logger:
            runnable = _attach_logging(runnable, spec, call_logger)
        runnables.append(runnable)
    primary, *rest = runnables
    if not rest:
        return primary
    return primary.with_fallbacks(rest, exceptions_to_handle=(Exception,))


def build_structured_llm(
    schema: type[BaseModel],
    *,
    method: str | None = None,
    specs: list[ProviderSpec] | None = None,
    audit: AuditLog | None = None,
) -> Runnable[Any, Any]:
    chain = list(specs if specs is not None else get_chain())
    if not chain:
        raise LLMConfigurationError("LLM chain is empty")
    call_logger = LLMCallLogger(audit) if audit else None
    runnables: list[Runnable[Any, Any]] = []
    for spec in chain:
        model = build_chat_model(spec)
        runnable = model.with_structured_output(
            schema, method=structured_method_for(spec.provider, method)
        )
        if call_logger:
            runnable = _attach_logging(runnable, spec, call_logger)
        runnables.append(runnable)
    primary, *rest = runnables
    if not rest:
        return primary
    return primary.with_fallbacks(rest, exceptions_to_handle=(Exception,))


def describe_chain(specs: list[ProviderSpec] | None = None) -> list[str]:
    return [spec.label for spec in (specs if specs is not None else get_chain())]
