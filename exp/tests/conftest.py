import pytest

import app.config as config

LLM_CONFIG_DEFAULTS = {
    "LLM_PROVIDER": "ollama",
    "LLM_MODEL": "qwen2.5:14b",
    "LLM_API_KEY": "",
    "LLM_BASE_URL": "",
    "LLM_FALLBACKS": (),
    "LLM_TEMPERATURE": 0.0,
    "LLM_TIMEOUT_SECONDS": 30.0,
    "LLM_MAX_RETRIES": 1,
    "LLM_MAX_TOKENS": 0,
    "LLM_STRUCTURED_METHOD": "auto",
    "OLLAMA_BASE_URL": "http://localhost:11434",
    "OLLAMA_MODEL": "qwen2.5:14b",
    "OLLAMA_TEMPERATURE": 0.0,
    "GROQ_API_KEY": "",
    "GROQ_BASE_URL": "",
    "OPENAI_API_KEY": "",
    "OPENAI_BASE_URL": "",
    "OPENROUTER_API_KEY": "",
    "TOGETHER_API_KEY": "",
    "DEEPSEEK_API_KEY": "",
    "MISTRAL_API_KEY": "",
    "XAI_API_KEY": "",
    "OPENAI_COMPATIBLE_API_KEY": "",
    "OPENAI_COMPATIBLE_BASE_URL": "",
    "ENABLE_STATE_CHANGE": False,
    "DRY_RUN": True,
    "OWNER_TOKEN": "",
    "LLM_ANALYSIS_ENABLED": False,
    "EXPLORE_MAX_ACTIONS": 40,
}


@pytest.fixture(autouse=True)
def isolate_llm_config(monkeypatch):
    for name, value in LLM_CONFIG_DEFAULTS.items():
        monkeypatch.setattr(config, name, value)
