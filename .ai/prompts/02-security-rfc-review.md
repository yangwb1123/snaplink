# Stage 02: Security & Protocol Review

## Roles Active
Principal Security Engineer · Protocol Expert

## Objective
Verify RFC compliance and identify exploitable security flaws.
Do not approve a merge with a Critical or High severity unresolved.

Read `.ai/prompts/shared/engineering-principles.md` and `.ai/prompts/shared/review-checklists.md` before starting.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Applicable Standards / RFCs**:
{{RFC_REFERENCES}}

**Stage 01 Architecture Output (if available)**:
{{ARCHITECTURE_OUTPUT}}

---

## Review Tasks

### 1. RFC Compliance Matrix
For each applicable RFC or standard, produce a compliance table:

| Requirement | Level | Status | Evidence | Notes |
|-------------|-------|--------|----------|-------|
| [Section X.Y: description] | MUST | Pass/Fail/Partial | [code line or protocol excerpt] | |

Classify every requirement as: MUST | SHOULD | MAY | NOT IMPLEMENTED (optional) | VIOLATION

Focus on MUST violations first — these are blocker findings.

### 2. Authentication & Authorization
- Does every protected operation verify credentials before processing?
- Is there a token-less path to any operation that should require a token?
- Are scope checks enforced after token validation, not instead of it?
- Can an attacker with a lower-privilege token escalate by crafting claims?
- Are client identity assertions verified independently of client-supplied data?

### 3. Oracle Leak & Anti-Enumeration
- Do error responses for invalid vs. expired vs. wrong tokens return identical error codes?
- Can an attacker distinguish between "user not found" and "wrong password" from any response?
- Do timing differences between code paths reveal information about existence of resources?
- See `engineering-principles.md` for the required oracle-leak response matrix.

### 4. Token Security
- Is `alg=none` rejected unconditionally?
- Is the algorithm field validated BEFORE signature verification?
- Are `iat`, `exp`, `nbf` validated on every inbound JWT?
- Is `aud` validated against the expected resource server?
- Is `jti` tracked to prevent replay within the token TTL?
- Is refresh family rotation implemented correctly (reuse → DeleteFamily → invalid_grant)?

### 5. Session Security
- Is the session ID unpredictable (cryptographically random, ≥128 bits)?
- Are sessions invalidated server-side on logout (not just cookie deletion)?
- Is session fixation prevented (new session ID after authentication)?
- Are session cookies marked `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`)?
- Does session extension refuse expired or revoked sessions?

### 6. Input Validation & Injection
- Are all redirect URIs validated against exact pre-registered values?
- Are all external URLs (CAEP endpoints, federation endpoints) pre-registered, not caller-supplied?
- Is there any SQL or NoSQL query construction from string concatenation?
- Are file paths or OS commands constructed from user input?
- Are `Content-Type` and body size limits enforced before parsing?

### 7. SSRF & Open Redirect
- Are there any outbound HTTP calls to URLs supplied by the caller?
- Can the `post_logout_redirect_uri` or `redirect_uri` point to an internal network address?
- Is the redirect URI allowed to be a JavaScript URI (`javascript:`) or data URI?

### 8. Cryptographic Review
- Are all cryptographic primitives from the approved set (EdDSA, ES256-512, RS256, PS256)?
- Are symmetric keys (HMAC) used only for internal, non-client-visible tokens?
- Is key rotation handled without a validity gap or hard cutover?
- Are nonces single-use and verified before processing the associated request?
- Is PKCE `code_challenge_method=plain` rejected, or at minimum flagged as weak?

### 9. STRIDE Threat Model

For each STRIDE category, list the most significant threat and its mitigation:

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Spoofing | | | |
| Tampering | | | |
| Repudiation | | | |
| Information Disclosure | | | |
| Denial of Service | | | |
| Elevation of Privilege | | | |

### 10. Trust Boundary Violations
- Where does the system trust data from an untrusted source?
- Is `X-Forwarded-For` or `X-Real-IP` only trusted behind a known-safe edge?
- Is client-supplied `client_id` verified against the credential store before use?
- Are federation trust chains validated before any claims from them are trusted?

---

## Required Output

Produce findings using the format in `.ai/prompts/shared/output-format.md`.

Sort findings: Critical → High → Medium → Low → Info.

Include the RFC Compliance Matrix for every applicable standard.

Include the completed STRIDE table.

Conclude with the Stage Summary Block.
