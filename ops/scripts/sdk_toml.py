#!/usr/bin/env python3
"""Small stdlib-only TOML loader for SDK manifest compatibility.

Python 3.11+ uses ``tomllib``. The fallback covers the fixed, deliberately
simple TOML shapes used by the committed Python and Rust manifests so the
repository CLI remains usable on older supported interpreters without adding a
third-party parser.
"""

from __future__ import annotations

import json
import re

try:
    import tomllib as _tomllib
except ImportError:  # Python 3.10 and older.
    _tomllib = None


class _FallbackTomlError(ValueError):
    pass


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_INTEGER = re.compile(r"[+-]?(0|[1-9][0-9_]*)\Z", re.ASCII)
_FLOAT = re.compile(
    r"[+-]?(?:[0-9][0-9_]*\.[0-9_]*|[0-9][0-9_]*[eE][+-]?[0-9_]+)\Z",
    re.ASCII,
)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ][0-9:.+-]+)?\Z", re.ASCII)


def load_toml(text: str) -> dict:
    """Parse TOML with the stdlib or the fixed-format compatibility fallback."""
    if _tomllib is not None:
        return _tomllib.loads(text)
    return _fallback_toml_loads(text)


def _strip_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = ""
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index]
    if quote:
        raise _FallbackTomlError("unterminated string")
    return line


def _key_path(text: str) -> list[str]:
    parts = [part.strip() for part in text.split(".")]
    if not parts or any(not _BARE_KEY.fullmatch(part) for part in parts):
        raise _FallbackTomlError(f"invalid key {text!r}")
    return parts


def _find_assignment(line: str) -> int:
    quote = ""
    escaped = False
    depth = 0
    for index, char in enumerate(line):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = ""
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise _FallbackTomlError("unbalanced value delimiters")
        elif char == "=" and depth == 0:
            return index
    if quote or depth:
        raise _FallbackTomlError("unterminated value")
    return -1


class _ValueParser:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse(self):
        value = self._value()
        self._space()
        if self.pos != len(self.text):
            raise _FallbackTomlError("unexpected value text")
        return value

    def _space(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def _value(self):
        self._space()
        if self.pos >= len(self.text):
            raise _FallbackTomlError("missing value")
        char = self.text[self.pos]
        if char in "\"'":
            return self._string()
        if char == "[":
            return self._array()
        if char == "{":
            return self._inline_table()
        return self._bare()

    def _string(self) -> str:
        quote = self.text[self.pos]
        start = self.pos
        self.pos += 1
        escaped = False
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                self.pos += 1
                token = self.text[start:self.pos]
                if quote == '"':
                    try:
                        return json.loads(token)
                    except json.JSONDecodeError as exc:
                        raise _FallbackTomlError("invalid basic string") from exc
                return token[1:-1]
            self.pos += 1
        raise _FallbackTomlError("unterminated string")

    def _array(self) -> list:
        self.pos += 1
        values = []
        self._space()
        if self._take("]"):
            return values
        while True:
            values.append(self._value())
            self._space()
            if self._take("]"):
                return values
            if not self._take(","):
                raise _FallbackTomlError("array values must be comma-separated")
            self._space()
            if self._take("]"):
                return values

    def _inline_table(self) -> dict:
        self.pos += 1
        value = {}
        self._space()
        if self._take("}"):
            return value
        while True:
            start = self.pos
            while self.pos < len(self.text) and self.text[self.pos] not in "=,":
                self.pos += 1
            key = self.text[start:self.pos].strip()
            if not _BARE_KEY.fullmatch(key) or not self._take("="):
                raise _FallbackTomlError("invalid inline-table entry")
            parsed = self._value()
            if key in value:
                raise _FallbackTomlError(f"duplicate inline-table key {key!r}")
            value[key] = parsed
            self._space()
            if self._take("}"):
                return value
            if not self._take(","):
                raise _FallbackTomlError("inline-table entries must be comma-separated")
            self._space()
            if self._take("}"):
                return value

    def _bare(self):
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in ",]} \t\r\n":
            self.pos += 1
        token = self.text[start:self.pos]
        if token in {"true", "false", "inf", "nan", "+inf", "-inf", "+nan", "-nan"}:
            return token
        if _INTEGER.fullmatch(token) or _FLOAT.fullmatch(token) or _DATE.fullmatch(token):
            return token
        raise _FallbackTomlError(f"invalid bare value {token!r}")

    def _take(self, char: str) -> bool:
        if self.pos < len(self.text) and self.text[self.pos] == char:
            self.pos += 1
            return True
        return False


def _set_nested(root: dict, path: list[str], value, line: int) -> None:
    current = root
    for key in path[:-1]:
        existing = current.get(key)
        if existing is None:
            existing = {}
            current[key] = existing
        if not isinstance(existing, dict):
            raise _FallbackTomlError(f"line {line}: key {key!r} is not a table")
        current = existing
    key = path[-1]
    if key in current:
        raise _FallbackTomlError(f"line {line}: duplicate key {key!r}")
    current[key] = value


def _table(root: dict, path: list[str], line: int) -> dict:
    current = root
    for key in path:
        existing = current.get(key)
        if existing is None:
            existing = {}
            current[key] = existing
        if not isinstance(existing, dict):
            raise _FallbackTomlError(f"line {line}: table path is not an object")
        current = existing
    return current


def _fallback_toml_loads(text: str) -> dict:
    result = {}
    current = result
    declared_tables: set[tuple[str, ...]] = set()
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("["):
            if not line.endswith("]") or line.startswith("[["):
                raise _FallbackTomlError(f"line {line_number}: invalid table header")
            path = tuple(_key_path(line[1:-1].strip()))
            if path in declared_tables:
                raise _FallbackTomlError(f"line {line_number}: duplicate table")
            declared_tables.add(path)
            current = _table(result, list(path), line_number)
            continue
        equal = _find_assignment(line)
        if equal < 0:
            raise _FallbackTomlError(f"line {line_number}: expected key=value")
        key = _key_path(line[:equal].strip())
        value = _ValueParser(line[equal + 1 :]).parse()
        _set_nested(current, key, value, line_number)
    return result
