"""The runbook must describe the bootstrap credential the way the code behaves.

The original defect — the banner password could not authenticate — is fixed and
rehearsed by `AUTH_SMOKE=1`. Keeping a test that only demands the defect be
documented would let the runbook drift back to describing a gap that no longer
exists, so this asserts the closure facts instead of deleting the check.
"""
from pathlib import Path


def test_runbook_documents_the_bootstrap_credential_closure():
    doc = (Path.cwd() / "docs/agent-os/MIGRATION_REHEARSAL.md").read_text()
    for phrase in ("stepSeedAdminUser", "SetPassword", "prints nothing",
                   "sso-ctl hash", "login 200", "gap closed"):
        assert phrase in doc, phrase
    lowered = doc.lower()
    assert "bootstrap admin password is not a usable credential" not in lowered
    assert "gap closed" in lowered
