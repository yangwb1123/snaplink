# `@snaplink/sso`

TypeScript client SDK for the Snaplink HTTP API and hosted-login redirects.
This directory is the package root used by npm build, test, and publish
workflows.

It also ships the **resource-server** side — `createJWKSCache`,
`validateToken`, `rsMiddleware` and the scope helpers — for a service that
validates the access tokens this server minted, mirroring Go
`interfaces/ssoclient/rs`. See the guide's "Resource-server use" section,
including the two honest gaps (DPoP and mTLS sender-constraints).

For installation, authentication-flow examples, browser security guidance, and
the generated API surface, see the [TypeScript SDK guide](https://github.com/snaplink/sso/blob/main/docs/sdks/typescript/README.md).
