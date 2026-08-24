已完成核验。现有任务提交为 `087ae846`，已含 Co-authored-by，且 `HEAD` 与 `origin/main` 同步。首次 `make ci` 的无关时序测试失败后，立即重跑通过。

completion_report:
  summary: "Published and verified the allowlisted self-service preferences HTTP contract and generated SDKs."
  changed_files: [CHANGELOG.md, docs/frontend-contract.md, docs/openapi.yaml, docs/sdks/python/client.py, docs/sdks/typescript/client.ts, interfaces/sso/rootcov_me_test.go, interfaces/sso/server_me.go, interfaces/sso/server_signup.go, interfaces/sso/aliases.go, ops/build/sdk-surface.json, platform/audit/aliases_spi.go, platform/audit/auditreport/drift_test.go, platform/audit/auditspi/event_types.go, protocols/selfservice/loginui.go, protocols/selfservice/preferences_test.go, sdks/python/snaplink_sso/client.py, shared/core/consts_oauth.go]
  requirements_covered:
    - "OpenAPI documents GET/PUT /me/preferences, bearer auth, JSON schemas, default-deny keys, empty deletion, no-store, and 400/401/500 responses."
    - "SDK registry uses identity.self-service with getMyPreferences and putMyPreferences; all TS/Python outputs were regenerated."
    - "Minimal nil-user, strict JSON/value, allowlist, deletion, persistence, bearer, and API-only frontend coverage is present; audit classification is retained."
  tests_added: [TestHandleMyPreferencesGet_AllowlistOnly, TestHandleMyPreferencesGet_MissingUserIs500, TestHandleMyPreferences_NilUserIs500, TestHandleMyPreferencesPut_RejectsNonJSONAndNonStringValues, TestHandleMyPreferencesPut_EmptyRemovesKey, TestRcovMe_Preferences]
  commands_executed:
    - {command: "python3 cli.py check-routes", result: passed}
    - {command: "python3 cli.py sdk-surface check", result: passed}
    - {command: "python3 cli.py sdk-surface generate", result: passed}
    - {command: "python3 cli.py sdk-surface check", result: passed}
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -count=1 ./protocols/selfservice", result: passed}
    - {command: "go test -count=1 ./interfaces/sso", result: passed}
    - {command: "go test -count=1 ./test/ -run 'TestE2E' -v", result: passed}
    - {command: "go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "PYTHONPATH=sdks/python python3 -m pytest -q sdks/python/tests", result: passed}
    - {command: "make ci", result: failed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "git status --short --branch && git rev-list --left-right --count HEAD...origin/main", result: passed}
  architecture_checks: "passed; no new package, dependency, exemption, skipDir, or layerExemption; focused structural and full CI gates passed on retry."
  security_checks: "passed; unknown attributes stay default-deny, nil users do not panic, invalid bodies are rejected, no-store is covered, and user_prefs_updated remains classified."
  compatibility: "passed; additive contract and SDK methods, no new error/config code, dependency, or migration; Python documented/package outputs are byte-identical."
  migration: "none"
  residual_risks: ["The first race gate hit the unrelated unchanged timing-sensitive TestEd25519Revoke_HonoredUpToExp; the immediate make ci retry and focused repetition passed.", "The Python emitter applies established identifier mangling; callers retain the literal wire key sverp:theme_mode in dictionaries."]
  assumptions: ["config/README.md is absent; docs/config-reference.md was used for configuration contract review.", "Task changes are already in 087ae846 and HEAD is synchronized with origin/main, so no empty follow-up commit was created.", "Pre-existing untracked .pi-batch.lock is harness state and was not committed."]
  not_executed: []
