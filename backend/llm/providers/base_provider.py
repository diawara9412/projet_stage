from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    def __init__(self, config: dict) -> None:
        self.config = config

    @abstractmethod
    def generate(self, prompt: str, temperature: float = 0.2, max_tokens: int = 500) -> str:
        raise NotImplementedError
