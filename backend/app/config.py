"""Application configuration via pydantic-settings."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    APP_NAME: str = "Endpoint Patch Risk & Safe Rollout Agent"
    APP_VERSION: str = "1.0.0"

    DATABASE_URL: str = "sqlite:///./data/patch_risk.db"

    # LLM provider: "mock" (deterministic facts-only) or "openai" (OpenAI-compatible endpoint)
    LLM_MODE: str = "mock"
    LLM_BASE_URL: str = "http://localhost:11434/v1"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-sim-mock"

    CORS_ORIGINS: str = "http://localhost:8014,http://127.0.0.1:8014"

    LOG_LEVEL: str = "INFO"

    # Simulator knobs
    ESTATE_SIZE: int = 2500
    SIM_SEED: int = 1337

    # Rollout safety thresholds (ring -> max tolerated failure rate)
    RING_FAILURE_THRESHOLDS: str = "RING_0:0.10,RING_1:0.05,RING_2:0.03,RING_3:0.02,RING_4:0.02"
    CANARY_FRACTION: float = 0.01
    PILOT_FRACTION: float = 0.05
    DEPARTMENT_FRACTION: float = 0.30

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def ring_thresholds(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for part in self.RING_FAILURE_THRESHOLDS.split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                try:
                    out[k.strip()] = float(v)
                except ValueError:
                    continue
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
