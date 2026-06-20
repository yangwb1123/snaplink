from pathlib import Path
import json

def load_home() -> dict:
    config_path = Path.home() / ".config" / "opencode" / "skills.json"
    if config_path.exists():
        return json.loads(config_path.read_text())
    return {}

def load_project() -> dict:
    config_path = Path.cwd() / ".skills.json"
    if config_path.exists():
        return json.loads(config_path.read_text())
    return {}

def get(key: str, default=None):
    return load_project().get(key, load_home().get(key, default))
