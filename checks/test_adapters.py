from pathlib import Path

from checks.adapters_check import (
    CONFORMANCE_SCENARIOS,
    SCENARIO_RE,
    scenario_inventory,
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
