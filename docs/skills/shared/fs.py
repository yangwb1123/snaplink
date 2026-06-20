from pathlib import Path

def count_lines(path: Path) -> int:
    with open(path) as f:
        return sum(1 for _ in f)

def list_go_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.go"))

def list_exported_functions(path: Path) -> list[tuple[str, int]]:
    functions = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            stripped = line.strip()
            if stripped.startswith("func ") or stripped.startswith("func ("):
                name = stripped.split("(")[0].replace("func ", "").replace("func ", "").strip()
                if name and name[0].isupper():
                    functions.append((name, i))
    return functions
