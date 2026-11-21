"""LLM provider abstraction.

MockLLMProvider is the default: fully deterministic and strictly facts-only.
It never invents facts; rationales are composed from the supplied fact strings.

OpenAICompatibleProvider posts to any OpenAI-compatible /chat/completions
endpoint via httpx (Azure OpenAI, vLLM, Ollama openai layer, etc.).
"""
import hashlib
import json
from typing import Protocol

import httpx

from app.config import get_settings
from app.metrics import LLM_LATENCY


class LLMProvider(Protocol):
    mode: str

    def rationale(self, task: str, facts: list[str], context: dict | None = None) -> str:
        ...


_FACT_VERBS = [
    "Reviewing the supplied evidence",
    "Weighing the recorded facts",
    "Cross-checking the provided findings",
    "Assessing the observed signals",
]


class MockLLMProvider:
    """Deterministic, offline, facts-only stand-in for a real LLM."""

    mode = "mock"

    def rationale(self, task: str, facts: list[str], context: dict | None = None) -> str:
        if not facts:
            return (
                f"[mock:{task}] No facts were supplied; no assessment is possible. "
                "Escalate to a human operator rather than guessing."
            )
        # Deterministic verb pick from task hash so output varies by task but is stable.
        h = int.from_bytes(hashlib.sha256(task.encode("utf-8")).digest()[:4], "big")
        verb = _FACT_VERBS[h % len(_FACT_VERBS)]
        cited = "; ".join(f"({i + 1}) {f}" for i, f in enumerate(facts[:8]))
        extra = ""
        if context:
            stable = json.dumps(context, sort_keys=True)
            extra = f" Context keys considered: {sorted(context.keys())} [ctx={stable[:120]}]."
        return (
            f"[mock:{task}] {verb}, this assessment is grounded exclusively in "
            f"{len(facts)} supplied fact(s). Key facts: {cited}.{extra} "
            "No information beyond the supplied facts was used."
        )


class OpenAICompatibleProvider:
    """Thin OpenAI-compatible chat-completions client."""

    mode = "openai"

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def rationale(self, task: str, facts: list[str], context: dict | None = None) -> str:
        system = (
            "You are a patch-rollout reasoning assistant. You MUST base your answer "
            "ONLY on the supplied facts. Never introduce outside facts. Be concise."
        )
        user = f"Task: {task}\nFacts:\n" + "\n".join(f"- {f}" for f in facts)
        if context:
            user += f"\nContext: {json.dumps(context, sort_keys=True)[:2000]}"
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        with LLM_LATENCY.labels(self.mode).time():
            resp = httpx.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"Unexpected LLM response shape: {exc}") from exc


def get_llm_provider() -> LLMProvider:
    settings = get_settings()
    if settings.LLM_MODE.lower() == "openai":
        return OpenAICompatibleProvider(
            settings.LLM_BASE_URL, settings.LLM_API_KEY, settings.LLM_MODEL
        )
    return MockLLMProvider()
