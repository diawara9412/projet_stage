from llm.providers.base_provider import BaseLLMProvider


class LLaMAProvider(BaseLLMProvider):
    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 500) -> str:
        return "{\"rules\": [{\"action\": \"alert\", \"reason\": \"llama-local-generated\"}]}"
