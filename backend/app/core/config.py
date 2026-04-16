from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SFC LLM Pipeline"
    sqlite_path: str = "data/metadata.db"
    data_dir: str = "data"

    ollama_base_url: str | None = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    mistral_api_key: str | None = None
    mistral_base_url: str | None = None

    openai_api_key: str | None = None
    openai_base_url: str | None = None

    anthropic_api_key: str | None = None
    anthropic_base_url: str | None = None

    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def repo_root(self) -> Path:
        return Path(__file__).resolve().parents[3]

    @property
    def data_path(self) -> Path:
        return self.repo_root / self.data_dir

    @property
    def sqlite_file(self) -> Path:
        return self.repo_root / self.sqlite_path


settings = Settings()
