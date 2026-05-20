from pathlib import Path

from network_security_classroom.config import get_config_path, load_ask_config, save_ask_config


def test_save_and_load_ask_config_round_trip():
    home = Path("tests") / "_tmp_home_config"
    if home.exists():
        for child in home.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(home.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        home.rmdir()

    path = save_ask_config(
        provider="huggingface",
        model="demo-model",
        hf_api_key="hf_123",
        home=home,
    )
    assert path == get_config_path(home)

    config = load_ask_config(home=home)
    assert config.provider == "huggingface"
    assert config.model == "demo-model"
    assert config.hf_api_key == "hf_123"

    for child in sorted(home.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()


def test_env_overrides_file_values():
    home = Path("tests") / "_tmp_home_env"
    if home.exists():
        for child in home.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(home.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        home.rmdir()

    save_ask_config(provider="local", home=home)
    config = load_ask_config(home=home, env={"NSC_ASK_PROVIDER": "openai", "OPENAI_API_KEY": "key-1"})
    assert config.provider == "openai"
    assert config.openai_api_key == "key-1"

    for child in sorted(home.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
