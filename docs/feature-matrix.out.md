The feature matrix at `docs/feature-matrix.md` is already present and its content matches the AGENTS.md extraction perfectly. All 50 features from the §2 Module Map (and referenced in §3 Global Constraints / §4 Coding Conventions) are represented:

- **OAuth 2.0 core**: auth code, client credentials, refresh token, PKCE, introspection, revocation, device code, token exchange, resource indicators, PAR, DCR — all present.
- **OIDC core**: ID Token, discovery, RP-initiated logout, backchannel/front-channel logout, `sid`, `login_hint`, Form Post, JARM, `prompt=none`, `private_key_jwt`, AS Issuer ID, JWT access tokens, mTLS, step-up, DPoP, signed metadata.
- **Profiles & extensions**: OAuth 2.1 strict, FAPI 2.0, RAR, JAR, JWE JAR, id_token/userinfo JWE encryption, CIBA, MFA, account lockout, SPIFFE JWT-SVID.
- **Infrastructure**: CAEP/SSF transmitter & receiver, Envoy ext_authz (HTTP + gRPC), SAML, Kerberos, RADIUS, WebAuthn attestation, multi-region data residency, SCIM 2.0, OpenID Federation 1.0.

No gaps found. The file is complete and up-to-date with AGENTS.md.
