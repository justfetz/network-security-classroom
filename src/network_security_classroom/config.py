"""Configuration helpers for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import tomllib


DEFAULT_CONFIG_DIRNAME = ".nsc"
DEFAULT_CONFIG_FILENAME = "config.toml"


@dataclass(frozen=True)
class AskConfig:
    provider: str = "local"
    model: str = ""
    openai_api_key: str = ""
    hf_api_key: str = ""


def get_config_dir(home: Path | None = None) -> Path:
    base = home or Path.home()
    return base / DEFAULT_CONFIG_DIRNAME


def get_config_path(home: Path | None = None) -> Path:
    return get_config_dir(home) / DEFAULT_CONFIG_FILENAME


def load_ask_config(home: Path | None = None, env: dict[str, str] | None = None) -> AskConfig:
    active_env = env or os.environ
    file_data = _load_config_file(get_config_path(home))

    provider = active_env.get("NSC_ASK_PROVIDER") or file_data.get("ask_provider") or "local"
    model = active_env.get("NSC_ASK_MODEL") or file_data.get("model") or ""
    openai_api_key = active_env.get("OPENAI_API_KEY") or _nested(file_data, "openai", "api_key") or ""
    hf_api_key = active_env.get("HF_TOKEN") or _nested(file_data, "huggingface", "api_key") or ""

    return AskConfig(
        provider=provider.strip().casefold(),
        model=model.strip(),
        openai_api_key=openai_api_key.strip(),
        hf_api_key=hf_api_key.strip(),
    )


def save_ask_config(
    provider: str,
    model: str = "",
    openai_api_key: str = "",
    hf_api_key: str = "",
    home: Path | None = None,
) -> Path:
    config_dir = get_config_dir(home)
    config_dir.mkdir(parents=True, exist_ok=True)
    path = get_config_path(home)

    lines = [f'ask_provider = "{provider}"']
    if model:
        lines.append(f'model = "{model}"')
    if openai_api_key:
        lines.extend(["", "[openai]", f'api_key = "{openai_api_key}"'])
    if hf_api_key:
        lines.extend(["", "[huggingface]", f'api_key = "{hf_api_key}"'])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _load_config_file(path: Path) -> dict:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _nested(data: dict, *keys: str):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
