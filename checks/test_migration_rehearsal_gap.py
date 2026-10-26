"""The documented bootstrap-credential gap must stay visible in the runbook."""
from pathlib import Path


def test_runbook_documents_the_bootstrap_credential_gap():
    doc = (Path.cwd() / "docs/agent-os/MIGRATION_REHEARSAL.md").read_text()
    for phrase in ("stepSeedAdminUser", "password_credentials", "is **not**\nverified", "401 invalid_credentials"):
        assert phrase in doc, phrase
    assert "bootstrap admin password is not a usable credential" in doc.lower()
