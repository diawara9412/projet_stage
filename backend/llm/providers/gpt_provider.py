from llm.providers.base_provider import BaseLLMProvider


class GPTProvider(BaseLLMProvider):
    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 500) -> str:
        if not self.config.get("api_key"):
            return "{\"rules\": [{\"action\": \"alert\", \"reason\": \"mock-gpt-no-key\"}]}"
        return "{\"rules\": [{\"action\": \"alert\", \"reason\": \"gpt-generated\"}]}"
