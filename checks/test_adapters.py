from pathlib import Path

from checks.adapters_check import (
    CONFORMANCE_SCENARIOS,
    SCENARIO_RE,
    ERROR_CODES_DOC,
    WIRE_CODE_MODEL,
    WIRE_CODE_FLOOR,
    missing_code_rows,
    scenario_inventory,
    stripe_error_rows,
    wire_code_consts,
)


def test_scenario_inventory_parses_the_table_literal():
    source = """
    for _, sc := range []struct {
        name string
        fn   func(*testing.T, func(*testing.T) core.Router)
    }{
        {"FiveMethodDispatch", fiveMethodDispatch},
        {"GateOn_ServesRoute", gateOnServesRoute},
    } {
    """
    assert scenario_inventory(source) == ["FiveMethodDispatch", "GateOn_ServesRoute"]


def test_scenario_inventory_fail_closed_on_malformed_table():
    # A refactor that breaks the literal shape yields an empty list, which
    # fails the pinned comparison instead of silently passing.
    assert scenario_inventory("no table here") == []


def test_scenario_regex_extracts_only_named_table_entries():
    matches = SCENARIO_RE.findall('{"Alpha", a}, {"Beta", b}')
    assert matches == ["Alpha", "Beta"]


def test_pinned_inventory_is_unique_and_complete():
    assert len(CONFORMANCE_SCENARIOS) == len(set(CONFORMANCE_SCENARIOS))
    assert len(CONFORMANCE_SCENARIOS) >= 14


def test_pinned_inventory_matches_the_live_suite():
    root = Path(__file__).resolve().parents[1]
    source = (root / "interfaces/adapters/routertest/conformance.go").read_text()
    assert scenario_inventory(source) == CONFORMANCE_SCENARIOS


def test_wire_code_consts_extracts_only_the_anchored_block():
    # Two const blocks: an unanchored one first (must be ignored), the
    # anchored wire block second (must be the only extraction source).
    source = """
const (
	PlainA = "a"
)
// Wire error codes are exported so the repository contract gate can prove
// every documented adapter response remains backed by executable code.
const (
	ErrBillingUnavailable  = "billing_unavailable"
	ErrProviderUnavailable = "provider_unavailable"
)
"""
    assert wire_code_consts(source) == [
        ("BillingUnavailable", "billing_unavailable"),
        ("ProviderUnavailable", "provider_unavailable"),
    ]


def test_wire_code_consts_fail_closed_when_anchor_missing():
    assert wire_code_consts("const (\n\tErrA = \"a\"\n)\n") is None
    # Anchor present but no following const block.
    assert wire_code_consts("// Wire error codes are exported\nvar x = 1\n") is None


def test_wire_code_consts_tolerates_gofmt_alignment():
    source = """
// Wire error codes are exported so the repository contract gate can prove
const (
	ErrA  = "a"
	ErrB = "b"
)
"""
    assert wire_code_consts(source) == [("A", "a"), ("B", "b")]


def test_stripe_error_rows_bounded_by_next_heading():
    doc = """
## Stripe payment adapter (`cmd/snaplink-stripe-adapter`)

| Code | HTTP |
|------|------|
| `tenant_mismatch` | 403 |
| `unavailable` | 503 |

## Machine usage and entitlement SDK

| Code | HTTP |
|------|------|
| `unavailable` | 503 |
"""
    # The later-section `unavailable` row must not leak in; prose mentions
    # never match the table-cell shape.
    assert stripe_error_rows(doc) == {"tenant_mismatch", "unavailable"}


def test_stripe_error_rows_empty_without_heading():
    assert stripe_error_rows("## Something else\n| `a` | 1 |\n") == set()


def test_missing_code_rows_reports_only_absent_codes():
    codes = [("ErrA", "a"), ("ErrB", "b")]
    assert missing_code_rows(codes, {"a"}) == ["ErrB (b)"]
    assert missing_code_rows(codes, {"a", "b"}) == []


def test_live_wire_codes_have_stripe_rows():
    # Live-source pin, mirroring test_pinned_inventory_matches_the_live_suite:
    # the exported block (>= floor entries) is fully covered by Stripe rows.
    source = WIRE_CODE_MODEL.read_text()
    codes = wire_code_consts(source)
    assert codes is not None
    assert len(codes) >= WIRE_CODE_FLOOR
    assert missing_code_rows(codes, stripe_error_rows(ERROR_CODES_DOC.read_text())) == []


def test_live_nested_openapi_glob_nonempty():
    from checks.adapters_check import ROOT

    found = sorted(ROOT.glob("cmd/*/openapi.yaml"))
    assert found
    assert (ROOT / "cmd/snaplink-stripe-adapter/openapi.yaml") in found
