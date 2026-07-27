// Package kerberosauth implements a Kerberos/SPNEGO (Windows Integrated
// Authentication / desktop SSO) authenticator for snaplink/sso as a SEPARATE
// nested Go module: a browser or desktop client authenticates transparently
// with its existing Kerberos ticket via the HTTP Negotiate scheme (RFC 4559),
// validated against the server's Kerberos keytab. This is the major enterprise
// login method the product otherwise lacked — the silent, password-less
// desktop SSO an Active Directory / MIT-Kerberos shop expects.
//
// This file is the package overview + the OPERATOR-FORK wiring guide. The
// implementation, security rationale, and per-field documentation live in
// handler.go, validator.go, config.go, and kerberos.go.
//
// # Why a separate Go module
//
// The Kerberos dependency (github.com/jcmturner/gokrb5/v8 and its asn1/crypto
// transitive deps) lives ONLY in this module's go.mod
// (github.com/yangwb1123/snaplink/kerberos). The core sso module's go.mod stays
// byte-free of it — the firm zero-external-SDK-in-core invariant that also
// isolates kms/awskms (aws-sdk-go-v2), redis (go-redis), saml (crewjam/saml),
// ldap (go-ldap), and extauthz (envoy go-control-plane). Operators who need
// desktop SSO opt in by importing this submodule from their own forked cmd;
// nothing in the core module imports it. There is deliberately no go.work (a
// workspace would surface gokrb5 in the root module graph); make ci's
// ci-modules target cds in to build + race-test it.
//
// # Architecture: a Negotiate HTTP handler, not an sso.Authenticator
//
// SPNEGO is a Negotiate-HEADER handshake (RFC 4559), NOT a username/password
// exchange, so it does NOT fit the sso.Authenticator SPI (Authenticate takes a
// credential map; there is none here — only the Authorization header). It is
// therefore a cmd-MOUNTED HTTP handler, exactly like the WebAuthn ceremony and
// the SAML IdP endpoints. A separate module's package CANNOT import cmd's
// package main, so this module references no cmd type. Instead it exposes its
// OWN importable types, built from root-module + stdlib + gokrb5 types only:
//
//   - kerberosauth.Deps          — ROOT-module-typed accessors (sso.ClientStore,
//     sso.SessionManager, sso.UserProvider, IssuerForClient, the optional
//     IDTokenIssuerForClient + EncryptIDToken, AuditRecorder, Logger). It
//     mirrors the shape the WebAuthn/SAML mint paths consume.
//   - kerberosauth.Config        — the per-surface config (keytab, service
//     principal, realm, the client_id to mint for, attribute mapping, mount
//     path). Validate() fails the operator's boot closed on a misconfig.
//   - kerberosauth.SPNEGOValidator — the MINIMAL trust seam (Validate(ctx,
//     negotiateToken) -> principal, realm, groups, err). The prod
//     gokrb5Validator wraps gokrb5; tests inject a fake (no KDC/keytab).
//   - kerberosauth.HandlerSpec   — { Method, Path string; Handler
//     http.HandlerFunc }, mirroring saml.HandlerSpec.
//   - kerberosauth.BuildResult   — { Handlers []HandlerSpec }.
//   - kerberosauth.Build(deps, cfg, validator) (*BuildResult, error) —
//     constructs the Negotiate handler.
//
// The OPERATOR'S FORK (their own package main) constructs the prod validator
// from the keytab, calls Build, and mounts the returned HandlerSpec via
// *sso.Server.Handle (sharing the built-in middleware stack). Copy-pasteable:
//
//	package main
//
//	import (
//		"log"
//		"net/http"
//
//		"github.com/yangwb1123/snaplink/interfaces/sso"
//		kerberosauth "github.com/yangwb1123/snaplink/kerberos"
//	)
//
//	func wireKerberos(srv *sso.Server) error {
//		cfg := kerberosauth.Config{
//			Name:             "kerberos",
//			KeytabPath:       "/etc/sso/http.keytab",   // the service keytab (a SECRET)
//			ServicePrincipal: "HTTP/sso.example.com",   // the SPN the keytab holds
//			Realm:            "EXAMPLE.COM",
//			ClientID:         "desktop-sso",            // the registered client tokens mint for
//			AttributeMapping: map[string]string{        // optional: rename derived attrs
//				"realm":  "domain",
//				"groups": "roles",
//			},
//		}
//
//		// 1. Build the keytab-backed validator. This LOADS the keytab ONCE
//		//    (a missing/malformed file fails boot CLOSED) and does NO KDC I/O,
//		//    so a down KDC never blocks startup.
//		validator, err := kerberosauth.NewGokrb5Validator(cfg)
//		if err != nil {
//			return err
//		}
//
//		// 2. Build the handler over the server's per-tenant signing seams.
//		//    The stores come from your fork's existing wiring — the same
//		//    UserProvider / SessionManager / ClientStore / audit.Recorder you
//		//    already constructed for the rest of the server (the SAML cmd wiring
//		//    threads them through a SAMLServerDeps bundle identically). The
//		//    per-tenant signing closures + the session/client accessors are
//		//    exported on *sso.Server: IssuerForClient, IDTokenIssuerForClient,
//		//    EncryptIDTokenForClient, SessionMgr(), ClientStoreAccessor().
//		res, err := kerberosauth.Build(kerberosauth.Deps{
//			ClientStore:            srv.ClientStoreAccessor(),
//			SessionManager:         srv.SessionMgr(),
//			UserProvider:           userProvider, // your fork's UserProvider
//			IssuerForClient:        srv.IssuerForClient,        // per-tenant access-token key
//			IDTokenIssuerForClient: srv.IDTokenIssuerForClient, // per-tenant id_token key
//			EncryptIDToken:         srv.EncryptIDTokenForClient,
//			AuditRecorder:          auditRecorder, // your fork's audit.Recorder
//			Logger:                 logger,
//		}, cfg, validator)
//		if err != nil {
//			return err
//		}
//
//		// 3. Mount each route on the SSO router (shares the middleware stack).
//		for _, h := range res.Handlers {
//			if err := srv.Handle(h.Method, h.Path, h.Handler); err != nil {
//				return err
//			}
//		}
//		return nil
//	}
//
// # The Negotiate flow (RFC 4559)
//
//	Browser ──GET /auth/kerberos (no auth)──▶ Server
//	Browser ◀── 401 WWW-Authenticate: Negotiate ── Server   (the challenge)
//	Browser ──GET /auth/kerberos                            (the browser, having
//	          Authorization: Negotiate <base64 SPNEGO> ──▶   a TGT for the user,
//	                                                          gets a service ticket
//	                                                          for HTTP/<host> and
//	                                                          sends it)
//	                                          Server validates the SPNEGO token
//	                                          against the KEYTAB (gokrb5
//	                                          AcceptSecContext → service.VerifyAPREQ:
//	                                          signature + ticket lifetime + replay
//	                                          cache), maps the principal → Subject
//	                                          (AMR ["krb5"]) → mints SSO tokens.
//	Browser ◀── 200 {access_token, id_token, session_id, ...} ── Server
//
// The 401 + `WWW-Authenticate: Negotiate` is the STANDARD handshake, not an auth
// failure: the browser answers it by re-sending the same GET with a service
// ticket. The same challenge is returned on a VALIDATION failure too (with a
// generic invalid_token), so a client whose ticket went stale can immediately
// retry with a fresh one.
//
// # Security posture (this is a credential-validation gate)
//
//   - The keytab is the TRUST ANCHOR + a HIGH-VALUE SECRET. It holds the
//     long-term key of the server's Kerberos service principal. It is loaded
//     ONCE at construction, NEVER logged, and NEVER placed in an error or
//     response. Protect it like a private signing key (file mode 0600, a secret
//     manager, etc.).
//   - A forged / expired / replayed / wrong-realm / keytab-mismatched SPNEGO
//     token NEVER authenticates: validation FAILS CLOSED against the keytab
//     (gokrb5's service.VerifyAPREQ checks the AP-REQ signature with the keytab
//     key and the ticket lifetime; gokrb5's PER-PROCESS replay cache rejects a
//     captured ticket replayed within its lifetime AGAINST THE SAME REPLICA —
//     see the multi-replica caveat below for the cross-replica gap and the
//     sticky-affinity requirement). The client-asserted
//     principal is NEVER trusted without this validation. A defense-in-depth
//     realm check additionally rejects any authenticated principal from a realm
//     other than the configured one.
//   - Oracle-safe: every validation failure (bad token, bad signature, expired,
//     replayed, wrong realm, undecodable base64) collapses to ONE generic 401
//     invalid_token + a Negotiate retry challenge. No probe can distinguish
//     them; the cause is logged (secret-free), never returned.
//   - The validated principal maps to a Subject with ExternalID =
//     principal@REALM (fully qualified, so identical local names in different
//     realms never collide), AMR ["krb5"], and ONLY the two derived,
//     server-controlled attributes (realm + PAC group SIDs) — a Kerberos ticket
//     can never smuggle an arbitrary claim onto the minted token. Tokens are
//     minted through the SAME per-tenant access/id-token issuer + SessionManager
//     seams as /auth/login + the WebAuthn/SAML mints, so a Kerberos login lands
//     on the one identity model with the one token-signing key per tenant. No
//     Kerberos secret ever enters a token.
//   - no-store cache headers on every response (a credential endpoint, RFC 6749
//     §5.1), including the challenge and every error.
//   - A refresh token is deliberately NOT minted: desktop SSO re-runs the
//     (silent) Negotiate handshake to re-authenticate, so a long-lived refresh
//     token would only widen the blast radius of an exfiltrated token.
//
// # Multi-replica deployment caveat (replay protection is PER-PROCESS)
//
// IMPORTANT operational requirement, not a code bug: gokrb5's AP-REQ replay
// cache is a PROCESS singleton (service.GetReplayCache, gokrb5's OWN service
// package — a sync.Once-guarded package-level var, NOT jcmturner/rpc, which
// gokrb5 uses only for AD PAC/NDR decoding; confirmed against gokrb5 v8.4.4's
// service/cache.go). It is in-memory, per-process, and does NOT span
// replicas or survive a restart. In a horizontally-scaled,
// multi-replica SSO deployment a captured AP-REQ replayed against a DIFFERENT
// replica than the one that first saw it is therefore NOT detected: replica B's
// cache has never seen the ticket replica A consumed. The replay window is
// bounded by the Kerberos clock-skew tolerance (gokrb5's 5-minute default, or
// Config.MaxClockSkew) — after which the ticket's authenticator is stale and
// fails the freshness check on every replica regardless of the cache. An
// attacker still needs a LIVE, validly-signed service ticket to replay (a
// forged or expired one fails the keytab/freshness check on every replica);
// what the cross-replica gap removes is only the single-use guarantee WITHIN
// that bounded window.
//
// To preserve full single-use replay protection across replicas, operators MUST
// pin Negotiate traffic to ONE replica — sticky sessions / session affinity at
// the load balancer keyed so a given client's handshakes always land on the
// same instance — exactly mirroring the redis/ hot-path "run single-use traffic
// on the primary" precedent (AGENTS.md §4): some single-use state (there, the
// cross-region replication lag; here, the per-process replay cache) is not
// globally consistent, so the single-use surface must be funneled to one
// authority. There is deliberately NO distributed replay cache here (it would
// add a hot-path round-trip to a shared store on every Negotiate request and a
// new infrastructure dependency); affinity is the recommended control.
//
// # Testing
//
// The MINIMAL SPNEGOValidator seam keeps the handler tests KDC-free: a FAKE
// validator drives the full challenge → validate → mint flow (and its failure
// paths) with no real keytab, KDC, or clock dependency — mirroring kms/awskms's
// fakeKMS + ldap's fakeDirectory. A separate set of tests exercises the REAL
// gokrb5Validator against gokrb5's own keytab test fixture to prove it
// constructs from a keytab and FAILS CLOSED on forged/garbage/structurally-
// valid-but-not-live tokens — also time-independent (no live ticket is ever
// presented, which would require a running KDC and would expire).
package kerberosauth
