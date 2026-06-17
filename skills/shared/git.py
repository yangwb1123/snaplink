from pathlib import Path
import subprocess

def root() -> Path:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("not in a git repository")
    return Path(result.stdout.strip())

def changed_files(base: str = "HEAD") -> list[Path]:
    result = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMR", base], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    repo = root()
    return [repo / f for f in result.stdout.strip().split("\n") if f.strip()]

def staged_files() -> list[Path]:
    result = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    repo = root()
    return [repo / f for f in result.stdout.strip().split("\n") if f.strip()]
