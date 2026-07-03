# OIDC Conformance Test Suite

This directory contains the Docker Compose configuration for running the
[OpenID Foundation's Conformance Test Suite](https://gitlab.com/openid/conformance-suite)
against the SSO server.

## Quick Start

```bash
# 1. Build the test Docker image and start all services
docker compose up -d

# 2. Wait for all services to be healthy
docker compose logs -f conformance-suite

# 3. Open http://localhost:8080 in a browser
#    (the conformance suite web UI)
```

## Configuration

Edit `config.env` to customise:
- `SSO_*` — server under test settings
- `CONFORMANCE_TEST_PLANS` — which OIDC profiles to test (basic, implicit, hybrid, config, dynamic, formpost, session, logout, ciba, jarm, fapi)

## Test Plan Selection

Open the conformance suite web UI at http://localhost:8080 and:

1. Create a new test plan
2. Select the modules matching `CONFORMANCE_TEST_PLANS`
3. Point the suite at http://sso-server:8080 (internal Docker network)
4. Enter the RP's test client credentials (created automatically by the suite)
5. Run the tests

## Supported Test Profiles

| Profile | Status | Notes |
|---------|--------|-------|
| OP Basic | ✅ Implemented | Auth Code + ID Token + UserInfo |
| OP Implicit | ✅ Implemented | Implicit Flow (deprecated) |
| OP Hybrid | ✅ Implemented | Hybrid Flow |
| OP Config | ✅ Implemented | Discovery |
| OP Dynamic | ✅ Implemented | DCR |
| OP FormPost | ✅ Implemented | form_post response mode |
| OP Session | ✅ Implemented | session_state + check_session_iframe |
| OP Logout | ✅ Implemented | end_session + BCL + FCL |
| OP CIBA | ✅ Implemented | Backchannel Authentication |
| OP JARM | ✅ Implemented | JWT Secured Auth Response Mode |
| OP FAPI | ✅ Implemented | FAPI 2.0 Security Profile |

## Troubleshooting

- **Server won't start**: Check `docker compose logs sso-server`
- **Tests fail with redirect errors**: Ensure `CONFORMANCE_SSO_SERVER` is reachable from the conformance container
- **Database connection refused**: Check `docker compose logs conformance-db`
