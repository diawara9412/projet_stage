from llm.providers.base_provider import BaseLLMProvider


class MistralProvider(BaseLLMProvider):
    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 500) -> str:
        if not self.config.get("api_key"):
            return "{\"rules\": [{\"action\": \"alert\", \"reason\": \"mock-mistral-no-key\"}]}"
        return "{\"rules\": [{\"action\": \"alert\", \"reason\": \"mistral-generated\"}]}"
