"""Lossless scalar PostgreSQL wire representation under an explicit column shape."""
import math
import re
import struct

from .compare import INT_RANGES
from .snapshot import GuardFailure, identifier

TAGS = {"text": "text", "int2": "integer", "int4": "integer", "int8": "integer",
        "float8": "real", "bytea": "blob"}


def column_expression(column):
    kind = column["type"]
    if column.get("type_namespace") != "pg_catalog" or kind not in TAGS:
        raise GuardFailure("unsupported_target_content_column_type")
    name = identifier(column["name"])
    expression = name if kind == "text" else name + "::text"
    if kind == "bytea":
        expression = "encode(" + name + ",'hex')"
    if kind == "float8":
        expression = "encode(float8send(" + name + "),'hex')"
    encoded = "json_build_array('" + TAGS[kind] + "'," + expression + ")"
    if column.get("not_null") is True:
        return encoded  # Locked, validated native NOT NULL columns do not need a null CASE.
    return "CASE WHEN " + name + " IS NULL THEN json_build_array('null') ELSE " + encoded + " END"


def decode_integer(value, kind):
    if not re.fullmatch(r"0|-?[1-9][0-9]*", value) or len(value) > 20:
        raise GuardFailure("invalid_target_content_integer")
    number = int(value)
    if not INT_RANGES[kind][0] <= number <= INT_RANGES[kind][1]:
        raise GuardFailure("target_content_integer_out_of_range")
    return number


def decode_binary(value, kind):
    if not re.fullmatch(r"[0-9a-f]*", value) or len(value) % 2:
        raise GuardFailure("invalid_target_content_hex")
    if kind == "bytea":
        return bytes.fromhex(value)
    if len(value) != 16:
        raise GuardFailure("invalid_target_content_float")
    number = struct.unpack("!d", bytes.fromhex(value))[0]
    if not math.isfinite(number):
        raise GuardFailure("nonfinite_target_content_float")
    return number


def decode_cell(cell, column):
    kind = column["type"]
    if kind not in TAGS or not isinstance(cell, list):
        raise GuardFailure("invalid_target_content_cell")
    if cell == ["null"]:
        if column["not_null"]:
            raise GuardFailure("target_content_null_constraint_failed")
        return None
    if len(cell) != 2 or cell[0] != TAGS[kind] or not isinstance(cell[1], str):
        raise GuardFailure("invalid_target_content_cell")
    value = cell[1]
    if kind in INT_RANGES:
        return decode_integer(value, kind)
    if kind == "text":
        value.encode("utf-8", errors="strict")
        return value
    return decode_binary(value, kind)
