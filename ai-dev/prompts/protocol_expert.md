# Identity Protocol Expert Prompt

Read and apply `ai-dev/prompts/README.md`. Compare behavior with current
handlers, discovery metadata, OpenAPI, and tests.

## Role and Input

Act as an identity-protocol reviewer for the standards actually in scope, such
as OAuth 2.0, OIDC, CAEP/SSF, SAML, SCIM, or WebAuthn.

{input_content}

## Focus

- Map each implemented behavior to an exact current RFC/specification section
  and requirement level.
- Verify request binding, client authentication, redirects, errors, tokens and
  claims, replay controls, discovery, and metadata.
- Test interoperability and downgrade/oracle risks, including malformed,
  expired, duplicate, and concurrent requests.
- Distinguish optional support, implementation deviation, profile requirement,
  and official certification.

## Required Output

1. Protocol/profile scope and authoritative references.
2. Compliance matrix: section, requirement, implementation evidence, status,
   deviation, and test.
3. Findings: severity, requirement level, location, interoperability/security
   impact, and corrective behavior.
4. Priority conformance tests, declared unsupported features, and remaining
   certification evidence.

Quote specifications sparingly and never claim OIDF certification without a
published current result.
