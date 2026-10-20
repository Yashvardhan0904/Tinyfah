import pytest
from langchain_core.runnables import RunnableLambda
from pydantic import BaseModel

import app.agent.llm as llm
from app.agent.llm import LLMCallLogger, ProviderSpec
from app.core.audit import AuditLog


class Answer(BaseModel):
    value: str


class _FakeChatModel:
    def __init__(self, behavior):
        self.behavior = behavior

    def with_structured_output(self, schema, method=None, **kwargs):
        return RunnableLambda(lambda _input: self.behavior())

    def invoke(self, _input):
        return self.behavior()


def _raise(message: str):
    def _inner():
        raise RuntimeError(message)

    return _inner


def test_structured_chain_falls_back(monkeypatch):
    behaviors = {
        "primary": _raise("primary down"),
        "fallback": lambda: {"value": "from-fallback"},
    }
    monkeypatch.setattr(llm, "build_chat_model", lambda spec: _FakeChatModel(behaviors[spec.model]))

    specs = [
        ProviderSpec(provider="groq", model="primary", api_key="test"),
        ProviderSpec(provider="openai", model="fallback", api_key="test"),
    ]
    chain = llm.build_structured_llm(Answer, specs=specs)
    assert chain.invoke("hello") == {"value": "from-fallback"}


def test_structured_chain_raises_first_error_when_all_fail(monkeypatch):
    behaviors = {
        "primary": _raise("primary down"),
        "fallback": _raise("fallback down"),
    }
    monkeypatch.setattr(llm, "build_chat_model", lambda spec: _FakeChatModel(behaviors[spec.model]))

    specs = [
        ProviderSpec(provider="groq", model="primary", api_key="test"),
        ProviderSpec(provider="openai", model="fallback", api_key="test"),
    ]
    chain = llm.build_structured_llm(Answer, specs=specs)
    with pytest.raises(RuntimeError, match="primary down"):
        chain.invoke("hello")


def test_chat_chain_falls_back(monkeypatch):
    behaviors = {
        "primary": RunnableLambda(_raise("primary down")),
        "fallback": RunnableLambda(lambda _input: "from-fallback"),
    }
    monkeypatch.setattr(llm, "build_chat_model", lambda spec: behaviors[spec.model])

    specs = [
        ProviderSpec(provider="groq", model="primary", api_key="test"),
        ProviderSpec(provider="ollama", model="fallback"),
    ]
    chain = llm.build_chat_model_chain(specs=specs)
    assert chain.invoke("hello") == "from-fallback"


def test_llm_logger_records_errors_without_prompts(tmp_path):
    audit = AuditLog("llm-log-test", directory=tmp_path)
    logger = LLMCallLogger(audit)
    logger.on_llm_error(
        RuntimeError("provider unavailable"),
        run_id="run",
        tags=["llm:groq:test-model"],
    )
    entries = audit.read()
    assert entries[0]["event"] == "llm_error"
    assert entries[0]["tags"] == ["llm:groq:test-model"]
    assert "provider unavailable" in entries[0]["error"]
    assert "prompt" not in entries[0]
