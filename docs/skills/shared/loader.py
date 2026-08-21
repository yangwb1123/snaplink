from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType


def load_skill_run(skill_dir: Path, module_name: str) -> ModuleType:
    spec = spec_from_file_location(module_name, skill_dir / "run.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load skill runner from {skill_dir}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
