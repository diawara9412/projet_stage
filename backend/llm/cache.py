class LLMCache:
    def __init__(self) -> None:
        self._cache: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._cache.get(key)

    def set(self, key: str, value: str) -> None:
        self._cache[key] = value
