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
//		"github.com/yangwb1123/snaplink/interfaces/sso"
//		samlmod "github.com/yangwb1123/snaplink/saml"
//		"github.com/yangwb1123/snaplink/saml/sp"
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
//
// # IdP side (Phase C): this server ISSUES signed assertions
//
// With cfg.IdP.Enabled, saml.Build ALSO appends the three IdP handlers, so this
// server acts as a SAML Identity Provider to downstream SPs:
//
//   - GET  /saml/metadata    — the IdP EntityDescriptor. The signing
//     KeyDescriptor wraps a self-signed cert over the per-tenant JWKS public
//     key (resolved through deps.IssuerForClient — the SAME key that signs
//     assertions, so an SP validates against the metadata it fetched). Public +
//     cacheable (Cache-Control: public, max-age + ETag + If-None-Match → 304).
//     Per-tenant via ?client_id= / ?sp_entity_id=; default issuer otherwise.
//   - GET/POST /saml/sso      — the SP-initiated AuthnRequest receiver. Decodes
//     the SAMLRequest, resolves the SP by its registered saml_sp_entity_id,
//     ENFORCES the ACS-URL allowlist (saml_sp_acs_urls — assertion-exfil
//     defense), optionally verifies a signed AuthnRequest, stores a single-use
//     pending request, and redirects to /auth/login to authenticate.
//   - POST /saml/sso/finish   — resumes after login: consumes the pending
//     request (single-use, oracle-safe), validates the live session, resolves
//     the SP's per-tenant signing key (FAIL-CLOSED — no cross-tenant fallback),
//     builds + enveloped-XML-DSig-signs the ASSERTION, and returns an
//     auto-POST form to the REGISTERED ACS.
//
// SP-client registration for the IdP is per-client config on
// sso.Client.Attributes (read at request time, never request input):
//
//	saml_sp_entity_id              — the SP's SAML entity id (AuthnRequest Issuer)
//	saml_sp_acs_urls               — pipe-delimited registered ACS allowlist
//	saml_sp_require_signed_request — "true" to require a signed AuthnRequest
//	saml_sp_signing_cert           — PEM cert verifying that signed AuthnRequest
//	                                 AND a SP-initiated LogoutRequest (SLO)
//	saml_sp_nameid_format          — per-SP NameID format override
//	saml_sp_slo_url                — pipe-delimited registered SLO allowlist (the
//	                                 LogoutResponse goes ONLY here; https)
//
// The IdP signs with an RSA (RS256/PS256) or ECDSA (ES256) issuer key:
// goxmldsig has NO Ed25519/EdDSA XML signature method, so an Ed25519 signing
// key yields saml_assertion_failed (fail loud). The ECDSA signature is ASN.1
// DER (NOT raw R‖S) because goxmldsig v1.4.0 signs and validates ECDSA via the
// stdlib (x509.CheckSignature expects DER) — emitting R‖S would make crewjam's
// own validation reject the assertion.
//
// Operator-fork wiring (adds the IdP to the SP example above):
//
//	res, err := samlmod.Build(samlmod.Deps{
//		ClientStore:     d.ClientStore,
//		SessionManager:  d.SessionManager,
//		UserProvider:    d.UserProvider,
//		IssuerForClient: d.IssuerForClient, // REQUIRED for the IdP (per-tenant signing)
//		Issuer:          d.Issuer,          // REQUIRED for the IdP (entity id = Issuer + "/saml")
//		AuditRecorder:   d.AuditRecorder,   // IdP records login_success (provider "saml-idp")
//		Logger:          d.Logger,
//	}, samlmod.Config{
//		SPs: []sp.SPConfig{ /* ... optional SP federation ... */ },
//		IdP: samlmod.IdPConfig{
//			Enabled:      true,
//			AssertionTTL: 5 * time.Minute,
//			// LoginPath / SSOURL / MetadataTTL default sensibly.
//		},
//	})
//	// res.Handlers now carries the SP ACS (if any SPs) PLUS the three IdP
//	// routes; map them onto main.SAMLHandlerSet exactly as in the SP example.
//
// A downstream SP is registered as an ordinary client with the saml_sp_*
// Attributes set, e.g.:
//
//	clients:
//	  - id: acme-sp
//	    attributes:
//	      saml_sp_entity_id: "https://acme.example.com/saml/metadata"
//	      saml_sp_acs_urls:  "https://acme.example.com/saml/acs"
//	      saml_sp_signing_cert: |          # MANDATORY for SP-initiated SLO
//	        -----BEGIN CERTIFICATE----- ...
//	      saml_sp_slo_url:   "https://acme.example.com/saml/slo"
//
// # Single Logout (SLO)
//
// SLO completes the SAML lifecycle: a logout at one party terminates the
// federated session everywhere. saml.Build mounts BOTH directions.
//
// IdP side — this server logs out downstream SPs (mounted with the IdP, at
// PathSAMLSLO = /saml/slo, GET+POST):
//
//   - A downstream SP redirects/POSTs a SIGNED LogoutRequest to /saml/slo.
//   - The IdP resolves the SP by the LogoutRequest Issuer (registered
//     saml_sp_entity_id) and MANDATORILY verifies the request's enveloped
//     XML-DSig against the SP's registered saml_sp_signing_cert. A LogoutRequest
//     is a destructive action: an unsigned or attacker-signed request is
//     REJECTED and NO session is touched (the crux — unlike the AuthnRequest
//     path where signing is opt-in, SLO signing is required).
//   - It terminates ONLY the matching subject session(s) for the request's
//     NameID (== the SSO user id this IdP minted into assertions), optionally
//     narrowed to a SessionIndex that belongs to that subject — never a global
//     wipe — via deps.SessionManager.
//   - It returns a SIGNED LogoutResponse (Status Success) to the SP's REGISTERED
//     saml_sp_slo_url (allowlist, exactly like the ACS allowlist) — never a
//     request-supplied URL (logout-response-injection defense).
//   - Oracle-safe: malformed / unknown-SP / missing-or-bad-signature / SLO-URL-
//     not-registered all collapse to one saml_request_invalid; a logout of a
//     non-existent session still returns a Success LogoutResponse, so SLO is not
//     a session-enumeration oracle.
//
// SLO BACK-CHANNEL FAN-OUT (global single logout). An SP-initiated /saml/slo now
// completes the SLO chain: after terminating the IdP session it pushes a SIGNED
// SAML LogoutRequest to every OTHER SP the subject has an active SAML session
// with, so those SPs terminate their local sessions too — the SAML analogue of
// OIDC back-channel logout. It is gated by an OPT-IN SAML session index:
//
//   - idp.SAMLSessionIndex (interface + the default bounded idp.MemorySessionIndex)
//     records, per subject (NameID), the SPs that subject federated to —
//     populated at /saml/sso/finish on assertion-issuance (the SP entity id, its
//     REGISTERED SLO URL + binding from Client.Attributes, the NameID), read at
//     /saml/slo, and RemoveAll'd after the fan-out so no stale subject->SP rows
//     leak. Wire it via saml.Deps.SAMLSessionIndex (nil ⇒ fan-out DISABLED ⇒
//     byte-identical to the single-SP SLO; nothing recorded/read, no goroutine).
//   - The fan-out EXCLUDES the initiating SP, SIGNS each LogoutRequest with the
//     SAME per-tenant key the target SP pinned (so the target SP's own saml/sp
//     ProcessLogoutRequest accepts it — cross-validated in the tests), and
//     delivers ONLY to the SP's REGISTERED SLO URL (never request-supplied).
//   - It is ASYNC + BEST-EFFORT + BOUNDED (a detached supervised goroutine, a
//     per-SP timeout + recover, a bounded worker pool), so a slow/dead SP NEVER
//     blocks the LogoutResponse returned to the initiator — a dead SP just drops
//     its request (logged + audited as a logout_notified failure). Per-SP
//     outcomes are recorded as bounded-cardinality logout_notified audit events
//     (provider "saml-idp"), the module's observability seam.
//
// IdP-INITIATED global logout (this server pushing logout from its own logout
// flow, e.g. /end_session or an admin action) is exposed as a HOOK rather than
// invasively wired into the core SessionManager: an operator's forked main calls
// handlers.Fanout(ctx, subject, "") (the exported method on the IdP handler set)
// from wherever it terminates the subject's primary session. The SP-initiated
// path drives the back-channel + front-channel split internally with the
// initiating SP excluded.
//
// SLO FRONT-CHANNEL CHAIN (the browser-redirect SLO mode, for SPs NOT reachable
// from the IdP — the traditional/common SAML SLO mode the back-channel fan-out
// can't serve). An SP opts in per-client via saml_sp_slo_channel: "frontchannel"
// (default "backchannel" ⇒ the async fan-out above; the channel is ORTHOGONAL to
// saml_sp_slo_binding, which still selects the back-channel WIRE binding). For
// front-channel SPs, the IdP redirects the USER'S BROWSER sequentially through
// each SP's SLO endpoint:
//
//		IdP /saml/slo ─(302 signed LogoutRequest)→ SP-A SLO URL ─(SP-A terminates)→
//		  (302 signed LogoutResponse, RelayState=chain-state-id)→ IdP /saml/slo/continue
//		  ─(302 signed LogoutRequest)→ SP-B SLO URL → ... → after the LAST SP →
//		  (302 IdP LogoutResponse)→ the INITIATOR's registered SLO URL.
//
//	  - The chain is driven by an UNGUESSABLE, SINGLE-USE state id (crypto/rand,
//	    256-bit) held in a bounded in-memory store; each /saml/slo/continue hop
//	    ROTATES the id, so a consumed/unknown/expired id collapses to ONE
//	    saml_request_invalid (no chain-state oracle, no replay, no step-skipping).
//	  - Each outbound LogoutRequest is SIGNED (detached §3.4.4.1) with the TARGET
//	    SP's per-tenant key (its own saml/sp ProcessLogoutRequest accepts it —
//	    cross-validated in the tests); the inbound LogoutResponse at /continue is
//	    signature-VALIDATED against THAT SP's registered cert BEFORE the chain
//	    advances (peek → verify → consume), so a FORGED LogoutResponse neither
//	    advances nor burns a legitimate chain.
//	  - The chain ONLY visits SPs from the session index (registered SPs the
//	    subject was actually logged into), with https-only SLO URLs (the same SSRF
//	    gate as the fan-out); the final redirect target is the INITIATOR's
//	    REGISTERED SLO URL, never request-supplied. no-store on every hop.
//	  - Back-channel + front-channel COEXIST: back-channel SPs fan out async while
//	    the front-channel chain runs via the browser. nil session index / no
//	    front-channel SPs ⇒ no chain (byte-identical to the back-channel-only
//	    behavior). Mounted with the IdP at PathSAMLSLOContinue = /saml/slo/continue
//	    (GET).
//
// SP side — this server is logged out by its UPSTREAM IdP (mounted with any SP,
// at PathSAMLSPSLO = /auth/saml/slo, GET+POST):
//
//   - The upstream IdP redirects/POSTs a SIGNED LogoutRequest here.
//   - The SPAuthenticator verifies its enveloped XML-DSig against the BOOT-
//     PINNED IdP signing cert — the SAME trust anchor it validates assertions
//     with, never a request-embedded cert — and checks the Issuer. An unsigned
//     or attacker-signed request is rejected and the local session is NOT
//     terminated.
//   - It terminates the matching LOCAL session(s) for the NameID via
//     deps.SessionManager (subject-scoped, never global) and returns a SIGNED
//     LogoutResponse (302 redirect) to the IdP's SLO endpoint.
//   - SP-initiated logout: SPAuthenticator.LogoutURL(nameID, sessionIndex,
//     relayState) builds a SIGNED LogoutRequest redirect to the upstream IdP's
//     SLO endpoint (the SLO analogue of LoginURL), so this server can ask the
//     IdP to log a user out. It requires an SP signing key (SPPrivateKey) and a
//     resolvable IdP SLO endpoint (IDPSLOURL, or one carried in the pinned IdP
//     metadata) — without either it returns "" (no unsigned logout is ever
//     emitted).
//
// SP-side SLO config (sp.SPConfig): SPSLOURL (this SP's own SLO endpoint),
// IDPSLOURL (the upstream IdP's SLO REQUEST endpoint when the pinned metadata
// lacks one), IDPSLOResponseURL (the upstream IdP's SLO RESPONSE endpoint when it
// differs from the request endpoint — REQUIRED to participate in the IdP's
// FRONT-channel chain: set it to "<idp>/saml/slo/continue" so this SP redirects
// its LogoutResponse to the chain's resume endpoint, echoing the RelayState the
// IdP resumes on; empty ⇒ the response goes to the request endpoint, the
// back-channel/IdP-initiated default, unchanged), and the existing
// SPPrivateKey/SPCert (SLO signing — RSA or ECDSA P-256; goxmldsig has no Ed25519
// method). The IdP signing cert pinned for assertions is REUSED to validate
// inbound IdP LogoutRequests, so SLO adds no new trust anchor.
//
// # Multi-replica storage (sqlite peers)
//
// SAML follows the SDK's §4 "every store gets a memory + sqlite impl" convention
// for the stores whose CORRECTNESS genuinely needs cross-replica sharing. Each
// store is an interface with the bounded in-memory default; the OPT-IN sqlite
// peer (pure-Go modernc.org/sqlite, in saml/sp/sqlite + saml/idp/sqlite) is wired
// via the existing seams. Unwired, the in-memory defaults are byte-identical, so
// a single-replica deployment pays nothing.
//
//   - SP assertion-replay dedup — sp.ReplayStore; sqlite peer
//     sqlite.AssertionReplayStore; wire via sp.SPConfig.AssertionReplayStore.
//     Cross-replica so an AssertionID replayed to a DIFFERENT replica is caught.
//   - SP-side logout-replay dedup — sp.ReplayStore; sqlite peer
//     sqlite.LogoutReplayStore; wire via sp.SPConfig.LogoutReplayStore. SEPARATE
//     namespace from the assertion store so the two ID spaces never collide.
//   - IdP logout-replay dedup — idp.LogoutReplayStore; sqlite peer
//     idp/sqlite.LogoutReplayStore; wire via saml.Deps.SAMLLogoutReplayStore.
//   - IdP session index — idp.SAMLSessionIndex; sqlite peer
//     idp/sqlite.SessionIndex; wire via saml.Deps.SAMLSessionIndex. Cross-replica
//     so the SLO fan-out reaches EVERY SP a subject federated to across the
//     cluster, not just those whose assertion-issuance landed on the logout
//     replica.
//
// Each replay peer dedups via an INSERT ... ON CONFLICT DO NOTHING in a single
// BEGIN IMMEDIATE transaction (race-free first-seen-vs-replay, the analogue of
// the SDK JTI store), bounded by an expires_at TTL with opportunistic prune; the
// session index upserts via ON CONFLICT DO UPDATE (idempotent re-record) +
// DELETE for Remove/RemoveAll, bounded by a per-subject SP cap + age pruning. The
// replay peers FAIL CLOSED on a store error (an unconfirmable freshness check
// rejects — a SAML replay dedup guards an auth/destructive action, unlike the
// availability-first JTI store), and each gate still runs AFTER full signature +
// freshness validation (the callers are unchanged), so the shared store is a
// hardening layer, never the only defense. Memory==sqlite is locked by the
// conformance suites in saml/samltest (+ samltest/sessionindextest).
//
// DELIBERATELY memory-only (NOT given a sqlite peer): the two SHORT-LIVED
// browser-flow stores — the IdP pending-AuthnRequest store (idp.PendingStore,
// the /saml/sso → /saml/sso/finish handoff) and the front-channel SLO chain-state
// store (the /saml/slo → /saml/slo/continue hops). Both are sticky-session-
// covered: the AuthnRequest→finish round-trip and every SLO-chain hop ride the
// SAME replica via the user's session/RelayState cookie, so cross-replica sharing
// buys nothing while adding a hot-path DB write to a single-use, seconds-lived,
// unguessable-id record. Their bounded in-memory stores are the right shape; the
// omission is by design, not an oversight.
package saml
