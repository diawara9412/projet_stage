from config.llm_config import LLM_CONFIG
from llm.providers.claude_provider import ClaudeProvider
from llm.providers.gpt_provider import GPTProvider
from llm.providers.llama_provider import LLaMAProvider
from llm.providers.mistral_provider import MistralProvider


class LLMFactory:
    @staticmethod
    def create(provider_name: str):
        provider_name = provider_name.lower()
        providers = {
            "gpt": GPTProvider,
            "claude": ClaudeProvider,
            "mistral": MistralProvider,
            "llama": LLaMAProvider,
        }
        if provider_name not in providers:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")
        return providers[provider_name](LLM_CONFIG[provider_name])
