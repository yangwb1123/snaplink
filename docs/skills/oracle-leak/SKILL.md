# Skill: Oracle-Leak Prevention

**Trigger:** New or modified OAuth/OIDC handler involving token/auth code lookup.

**Usage:** `python docs/skills/oracle-leak/run.py [file]`

The script is a heuristic text scan, not proof. Always add response-shape and
timing-relevant tests and run the invariant checker.

## Patterns
- 400 invalid_grant for unknown/expired/consumed on /token
- invalid_request_uri for stale/missing PAR on /auth/login
- invalid_token for DPoP/mTLS failure
- invalid_client for private_key_jwt
- 401 invalid_token (identical) for missing/wrong bearer on /register/:client_id
- 200 {"active":false} for /token/introspect inactive
- bcrypt cost-matched dummy hash for unknown password users
- 400 mfa_invalid for unknown/expired/consumed/unsupported MFA
- 404 session_invalid for unknown WebAuthn user/session

## Verify

```bash
python cli.py check-invariants
go test ./test/ -run 'AntiEnumeration|Oracle|MFA|WebAuthn' -count=1
```
