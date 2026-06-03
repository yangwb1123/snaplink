// Package saml implements the SAML 2.0 Service Provider (SP) side of the SSO
// server as a SEPARATE nested Go module: this server CONSUMES an upstream SAML
// Identity Provider's (IdP) signed assertion to authenticate a user. It is the
// mirror image of authenticators/oidc_federation.go (which consumes an upstream
// OAuth/OIDC provider) — same redirect-to-IdP-then-validate-the-callback shape,
// expressed in SAML.
//
// # Why a separate module
//
// The SAML/XML/DSig dependency (github.com/crewjam/saml and its etree +
// goxmldsig transitive deps) lives ONLY in this module's go.mod. The core sso
// module stays byte-free of it — the same firm zero-external-SDK invariant that
// isolates kms/awskms (aws-sdk-go-v2) and redis (go-redis). An operator opts in
// by importing this module from their own forked cmd; nothing in the core
// module imports it.
//
// # Architecture: importable root-typed results (no package-main import)
//
// The cmd/sso-server SAML registry types (RegisterSAMLHandlers, SAMLServerDeps,
// SAMLHandlerSet) live in package main — and a separate module's package CANNOT
// import package main. So this module does NOT reference any cmd type. Instead
// it exposes its OWN importable types, built from root-module + stdlib + crewjam
// types only:
//
//   - saml.Deps          — a struct of ROOT-module-typed accessors
//     (sso.ClientStore, sso.SessionManager, sso.UserProvider,
//     IssuerForClient, Issuer, Logger). It mirrors cmd's SAMLServerDeps
//     field-for-field.
//   - saml.Config        — the per-IdP sp.SPConfig list.
//   - saml.HandlerSpec   — { Method, Path string; Handler http.HandlerFunc },
//     mirroring cmd's SAMLHandler.
//   - saml.BuildResult   — { Authenticators []sso.Authenticator;
//     Handlers []saml.HandlerSpec }.
//   - saml.Build(deps, cfg) (*saml.BuildResult, error) — constructs an
//     SPAuthenticator per SPConfig plus the POST /auth/saml/callback ACS
//     handler.
//
// The OPERATOR'S FORK (their own package main, which DOES have cmd's
// RegisterSAMLHandlers) adapts saml.BuildResult onto main.SAMLHandlerSet inside
// the factory closure. Copy-pasteable wiring:
//
//	package main
//
//	import (
//		"context"
//
//		"github.com/snaplink/sso"
//		samlmod "github.com/snaplink/sso/saml"
//		"github.com/snaplink/sso/saml/sp"
//	)
//
//	func init() {
//		// Register a SAML handler factory under the name the operator selects
//		// via cfg.saml.handler (here "crewjam"). cmd calls it once at boot with
//		// its SAMLServerDeps; we adapt those into saml.Deps, call saml.Build,
//		// and map the BuildResult onto cmd's SAMLHandlerSet.
//		RegisterSAMLHandlers("crewjam", func(ctx context.Context, d SAMLServerDeps) (*SAMLHandlerSet, error) {
//			res, err := samlmod.Build(samlmod.Deps{
//				ClientStore:     d.ClientStore,
//				SessionManager:  d.SessionManager,
//				UserProvider:    d.UserProvider,
//				IssuerForClient: d.IssuerForClient,
//				Issuer:          d.Issuer,
//				Logger:          d.Logger,
//			}, samlmod.Config{
//				SPs: []sp.SPConfig{{
//					Name:           "acme-idp",
//					EntityID:       "https://sso.example.com/saml/metadata",
//					ACSURL:         "https://sso.example.com/auth/saml/callback",
//					IDPMetadataURL: "https://idp.acme.com/saml/metadata",
//					AttributeMapping: map[string]string{
//						"urn:oid:0.9.2342.19200300.100.1.3": "email",
//						"urn:oid:2.5.4.42":                   "given_name",
//					},
//				}},
//			})
//			if err != nil {
//				return nil, err
//			}
//
//			// Map []saml.HandlerSpec -> []main.SAMLHandler.
//			handlers := make([]SAMLHandler, len(res.Handlers))
//			for i, h := range res.Handlers {
//				handlers[i] = SAMLHandler{Method: h.Method, Path: h.Path, Handler: h.Handler}
//			}
//			return &SAMLHandlerSet{
//				Handlers:       handlers,
//				Authenticators: res.Authenticators, // already []sso.Authenticator
//			}, nil
//		})
//	}
//
// cmd then registers res.Authenticators (so /auth/login?provider=acme-idp
// redirects to the IdP) and mounts the ACS handler at /auth/saml/callback on the
// SSO router (sharing the built-in middleware stack). Select the factory at boot
// via cfg.saml.handler: "crewjam".
//
// # Security posture
//
// Assertion validation is an authentication gate; the classic attacks are XML
// signature wrapping (XSW) and assertion replay.
//
//   - XSW: validation runs through crewjam's ParseResponse, which resolves the
//     signed element by its DSig SignedInfo Reference URI and verifies the
//     signature against the IdP signing certificate PINNED at boot (from
//     IDPMetadata) — NEVER a certificate embedded in the assertion. The SP
//     additionally rejects any response carrying more than one assertion.
//   - Oracle safety: every validation failure (bad signature, wrong audience,
//     wrong recipient, expired, replayed, multi-assertion, malformed) collapses
//     to ONE wire code, saml_assertion_invalid — no probe can distinguish them.
//   - Replay: a bounded in-memory per-replica AssertionID store (NOT the OAuth
//     JTIReplayStore — a different protocol), pruned by assertion expiry.
//   - The ACS handler stamps no-store cache headers and creates the session
//     through the SessionManager (not a raw store).
package saml
