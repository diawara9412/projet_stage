import os

LLM_CONFIG = {
    "gpt": {
        "provider": "openrouter",
        "api_key": os.getenv("OPENROUTER_API_KEY", ""),
        "base_url": os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "model": os.getenv("GPT_MODEL", "openai/gpt-4o-mini"),
    },
    "claude": {
        "provider": "anthropic",
        "api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "base_url": os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1"),
        "model": os.getenv("CLAUDE_MODEL", "claude-3-5-haiku-latest"),
    },
    "mistral": {
        "provider": "mistral",
        "api_key": os.getenv("MISTRAL_API_KEY", ""),
        "base_url": os.getenv("MISTRAL_BASE_URL", "https://api.mistral.ai/v1"),
        "model": os.getenv("MISTRAL_MODEL", "mistral-small-latest"),
    },
    "llama": {
        "provider": "ollama",
        "api_key": os.getenv("HUGGINGFACE_API_KEY", ""),
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": os.getenv("LLAMA_MODEL", "llama3.1:8b"),
    },
}
