from __future__ import annotations

import copy

import pytest

from ops.scripts.capability_registry import (
    BEGIN_MARKER,
    CapabilityRegistryError,
    END_MARKER,
    FEATURE_MATRIX_PATH,
    generated_document,
    load_registry,
    validate_registry,
)


def test_repository_registry_and_generated_matrix_are_current():
    data = load_registry()
    validate_registry(data)
    current = FEATURE_MATRIX_PATH.read_text(encoding="utf-8")
    assert generated_document(data, current) == current


def test_validation_rejects_unknown_availability():
    data = copy.deepcopy(load_registry())
    data["capabilities"][0]["availability"] = ["appliance"]

    with pytest.raises(CapabilityRegistryError, match="unknown values: appliance"):
        validate_registry(data)


def test_validation_rejects_unknown_module_capability():
    data = copy.deepcopy(load_registry())
    data["capabilities"][0]["module_capabilities"] = ["unknown.feature.v1"]

    with pytest.raises(CapabilityRegistryError, match="unknown.feature.v1"):
        validate_registry(data)


def test_validation_rejects_unsorted_capability_ids():
    data = copy.deepcopy(load_registry())
    data["capabilities"][0], data["capabilities"][1] = (
        data["capabilities"][1],
        data["capabilities"][0],
    )

    with pytest.raises(CapabilityRegistryError, match="ids must be sorted"):
        validate_registry(data)


def test_external_frontend_cannot_claim_server_dependencies():
    data = copy.deepcopy(load_registry())
    frontend = next(
        item for item in data["capabilities"] if item["id"] == "frontend.admin"
    )
    frontend["required_stores"] = ["AdminTokenStore"]

    with pytest.raises(CapabilityRegistryError, match="external frontend"):
        validate_registry(data)


def test_every_runtime_feature_gate_requires_a_capability():
    data = copy.deepcopy(load_registry())
    for capability in data["capabilities"]:
        if capability["feature_gate"] == "ciba":
            capability["feature_gate"] = None

    with pytest.raises(CapabilityRegistryError, match="feature gates.*ciba"):
        validate_registry(data)


def test_generated_document_rejects_reversed_markers():
    document = f"{END_MARKER}\nmanual\n{BEGIN_MARKER}\n"

    with pytest.raises(CapabilityRegistryError, match="out of order"):
        generated_document(load_registry(), document)
