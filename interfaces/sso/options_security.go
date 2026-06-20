package sso

import (
	"time"

	"github.com/snaplink/sso/internal/handler"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
)

func WithJTIReplayStore(store security.JTIReplayStore) Option {
	return func(s *Server) { s.jtiReplayStore = store }
}

// WithJTIReplayFailClosed makes a TRANSIENT jti-replay STORE ERROR
// reject the request instead of falling through (fail-open).
//
// Default OFF (fail-open): a degraded JTIReplayStore — Redis blip,
// etcd partition, DB outage — must not lock out legitimate clients,
// so MarkSeen errors are swallowed and the JWT is treated as
// first-seen. That trades a replay window for availability: while the
// store is down, a captured JAR / DPoP proof / client_assertion /
// actor_token can be replayed because no replica can confirm the jti
// is unseen, and on a multi-replica shared backend the window spans
// every replica.
//
// ON (fail-closed): when MarkSeen can't confirm the jti is unseen the
// server REJECTS, treating store-uncertainty as a replay. The
// rejection is INDISTINGUISHABLE on the wire from a genuinely detected
// replay (same error code per site) so a probing attacker learns
// nothing about backend health — at the cost of failing valid requests
// during a store outage. Replay-sensitive multi-replica deployments
// SHOULD opt in; the DETECTED-replay and happy paths are unchanged
// either way.
func WithJTIReplayFailClosed() Option {
	return func(s *Server) { s.jtiReplayFailClosed = true }
}

// WithSPIFFEJWTSVID accepts a SPIFFE JWT-SVID as a token-exchange
// subject_token (RFC 8693), minting this server's access token for the
// mapped mesh-workload identity. It is the service-to-service analog of
// upstream-IdP federation: a mesh workload holding a SPIRE-issued
// JWT-SVID (a JWT whose `sub` is a spiffe:// URI, signed by the SPIRE
// server's JWT key) swaps it for a local token, instead of a user
// logging in at /auth/login.
//
//   - trustDomain — the ONLY SPIFFE trust domain whose SVIDs are
//     accepted. An SVID whose `sub` trust-domain differs is rejected.
//   - expectedAudience — THIS server's identifier; the SVID `aud` MUST
//     contain it (strict aud-binding stops an SVID minted for another
//     service being replayed here).
//   - source — the SPIRE trust-bundle JWKS (security.NewStaticJWKS from
//     an operator-supplied file is the in-scope minimum).
//
// Routing (subject_token_type=jwt only): an inbound subject_token is
// FIRST tried against this server's own issuers (the existing local-JWT
// path); the SVID validator runs ONLY as a fallback when the local path
// fails AND the validator is wired. So a normal, locally-issued jwt
// subject_token behaves byte-identically to today, and any SVID failure
// collapses to the same 400 invalid_grant a foreign/invalid token already
// returns (oracle-leak hardening §2). Nil (option not passed) ⇒ the
// feature is entirely off and a spiffe-sub subject_token is rejected
// byte-identically.
//
// Any nil/empty argument makes the option a no-op (feature stays off)
// rather than panicking — cmd validates config before wiring.
func WithSPIFFEJWTSVID(trustDomain, expectedAudience string, source security.JWKSSource, opts ...security.SPIFFEValidatorOption) Option {
	return func(s *Server) {
		if trustDomain == "" || expectedAudience == "" || source == nil {
			return
		}
		v, err := security.NewSPIFFEValidator(trustDomain, source, opts...)
		if err != nil {
			return
		}
		s.spiffeValidator = v
		s.spiffeAudience = expectedAudience
	}
}

// WithMeshExtAuthz mounts the Envoy/Istio ext_authz HTTP-mode
// authorization endpoint (cluster C1 mesh data-plane, the HTTP variant).
// A mesh sidecar — Envoy's ext_authz HTTP filter, or an Istio
// AuthorizationPolicy CUSTOM action pointing at an HTTP provider — calls
// this endpoint per request to validate the inbound bearer:
//
//   - 200 = ALLOW. The endpoint stamps DERIVED X-Auth-* identity headers
//     (subject, client_id, scopes, expiry) that the sidecar injects into
//     the upstream request, so the upstream service reads identity from
//     trusted headers instead of re-validating the token. This is the
//     standard "validate the token at the sidecar, inject identity to the
//     upstream" mesh pattern.
//   - 401 = DENY. Missing token → no error= challenge; an invalid /
//     expired / sender-constraint-failing token → invalid_token (the
//     exact /userinfo opaque-failure shape — no oracle leak).
//
// It reuses the SAME alg-confusion-safe validation path /userinfo uses
// (validateAnyToken + the DPoP/mTLS sender-constraint checks), so a
// stolen DPoP- or mTLS-bound token cannot be replayed through the mesh as
// a plain bearer. No new validation logic.
//
// TRUST MODEL: the upstream trusts the injected X-Auth-* headers ONLY
// because the sidecar enforced ext_authz. The endpoint DERIVES every
// X-Auth-* from the validated token and NEVER trusts an inbound X-Auth-*;
// the mesh MUST be configured to STRIP any client-supplied X-Auth-* at
// ingress — the same "edge must strip untrusted headers" model that
// governs X-Forwarded-* and security.mtls.backend: header (AGENTS.md §2).
// The endpoint itself is MESH-INTERNAL: only the trusted sidecar should
// be able to reach it (operator network policy); it is not a public
// endpoint.
//
// path empty ⇒ PathMeshExtAuthz ("/mesh/ext-authz"). Not wired ⇒ the
// route is not mounted; behavior is byte-identical to a build without it.
//
// The gRPC ext_authz variant needs the envoyproxy/go-control-plane proto
// dependency and is intentionally OUT of scope here (a separate operator
// module) — this HTTP variant is plain HTTP and adds zero deps.
func WithMeshExtAuthz(path string) Option {
	return func(s *Server) {
		s.meshExtAuthz = true
		s.meshExtAuthzPath = path
	}
}

// WithSubjectClientIndex enables OIDC Back-Channel Logout multi-RP
// fan-out. Each successful token issuance records (subject, client_id)
// in the index; at /logout and /end_session the AS iterates every
// client the subject has been seen with and emits a logout_token to
// each (filtered to clients that declared a BackchannelLogoutURI).
//
// Without it, BCL only notifies the single client present in the
// bearer / id_token_hint at logout time — the original v1 behavior.
// With it wired, logging out of app A also logs the user out of
// apps B, C, ... — "true single sign-out" at the cost of one HTTP
// POST per signed-in RP.
//
// The default backend (defaultimpl.NewMemorySubjectClientIndex) is
// single-replica only; multi-replica deployments need a shared
// store (Redis, SQL) so a fan-out triggered on replica A reaches
// a client whose last issuance happened on replica B.
func WithSubjectClientIndex(idx security.SubjectClientIndex) Option {
	return func(s *Server) { s.subjectClientIndex = idx }
}

// WithJARFetcher enables the RFC 9101 §5.2.2 `request_uri` URL-fetch
// variant. Without it, /auth/login still accepts PAR's `urn:`
// request_uri prefix but rejects HTTPS URLs with invalid_request_uri.
// With it wired, RPs can host their signed authorization-request
// JWT at a URL and pass that URL on the wire.
//
// Per-client `AllowedRequestURIs` is the SSRF defense — only URLs
// explicitly registered on the client are fetched. Operators MUST
// set the allowlist on every JAR-using client; otherwise an
// attacker who steals client_id could pivot the AS into fetching
// arbitrary internal endpoints.
//
// The default fetcher (defaultimpl-less here: see NewHTTPJARFetcher)
// is HTTPS-only, no-redirects, 5s timeout, 16KB body cap.
func WithJARFetcher(fetcher security.JARFetcher) Option {
	return func(s *Server) { s.jarFetcher = fetcher }
}

// WithJARDecrypter enables RFC 9101 §6.4 encrypted JAR — the request
// object arrives JWE-wrapped (5 segments) instead of plain JWS
// (3 segments). The AS decrypts to plaintext, then validates the
// inner signed JAR via the existing verifyJAR pipeline.
//
// Wire shape:
//   - Without this option, JWE-shaped JAR payloads are rejected with
//     invalid_request_object (fail-closed; the AS can't validate
//     what it can't decrypt).
//   - With it wired, both plain JWS and JWE-wrapped JWS request
//     objects are accepted; the AS branches on segment count.
//
// The decrypter typically also implements [JWKSProvider] so its
// public encryption key shows up at /.well-known/jwks.json with
// `use: "enc"`. RPs introspect that to choose which kid to encrypt
// to. Default impl: [defaultimpl.RSAJWEDecrypter] (RSA-OAEP-256 +
// A256GCM).
//
// Discovery advertises supported alg + enc lists when this option
// is wired — see request_object_encryption_alg_values_supported +
// request_object_encryption_enc_values_supported.
func WithJARDecrypter(d security.JWEDecrypter) Option {
	return func(s *Server) { s.jarDecrypter = d }
}

// WithJWEResponseEncrypter enables OIDC response encryption — the
// response-direction mirror of WithJARDecrypter. When wired, clients
// that registered an `id_token_encrypted_response_alg` get their signed
// ID Token JWS wrapped in a nested JWE(JWS(...)), and clients with
// `userinfo_encrypted_response_alg` get an encrypted /userinfo response
// (`Content-Type: application/jwt`). The recipient public key is taken
// from the client's registered JWKS (`use: "enc"`).
//
// One encrypter covers both id_token + userinfo. Without it, clients
// that registered an encrypted-response alg fail closed (the ID Token is
// omitted, userinfo returns server_error) rather than downgrading to a
// cleartext response.
//
// Default impl: [defaultimpl.RSAJWEResponseEncrypter] (RSA-OAEP-256 +
// A256GCM). Discovery advertises the supported alg + enc lists only when
// this option is wired — see id_token_encryption_*_values_supported +
// userinfo_encryption_*_values_supported.
func WithJWEResponseEncrypter(e security.JWEEncrypter) Option {
	return func(s *Server) { s.jweResponseEncrypter = e }
}

// WithClientCertExtractor enables RFC 8705 §3 mTLS certificate-
// bound access tokens. When wired, every /token request whose
// extractor returns a non-nil cert has the issued access token
// stamped with `cnf.x5t#S256` — the cert's SHA-256 thumbprint.
// Discovery's `tls_client_certificate_bound_access_tokens` flag
// flips true.
//
// Pluggable so reverse-proxy-terminated TLS works: deployments
// where envoy / nginx forward client certs via
// `X-Forwarded-Client-Cert` supply a custom extractor that parses
// the header. Direct-TLS deployments wire
// [DefaultTLSPeerCertExtractor].
//
// mTLS-bound tokens still report `token_type: Bearer` per RFC
// 8705 §3 (the binding is implicit in the cnf claim, not a new
// type). Resource servers MUST check the cert on every protected
// request against the token's cnf — same architectural
// separation as DPoP.
func WithClientCertExtractor(ex ClientCertExtractor) Option {
	return func(s *Server) { s.clientCertExtractor = ex }
}

// WithSupportedACRValues declares the OIDC ACR values this server's
// authenticators can actually deliver. Surfaced as
// `acr_values_supported` in discovery so RPs that branch on ACR
// (step-up auth, FAPI 2.0 compliance) can introspect.
//
// Operators populate this with the full set of ACR strings their
// wired authenticators stamp into `result.AuthMethods` / `.ACR` —
// e.g. ["urn:mace:incommon:iap:bronze", "urn:mace:incommon:iap:silver"].
// Empty / omitted leaves the field absent (legacy behavior, RP must
// infer capabilities out-of-band).
//
// Authenticators that compute ACR dynamically (e.g. MFA combiners)
// SHOULD list every possible output value here so RPs see the
// complete contract.
func WithSupportedACRValues(values ...string) Option {
	return func(s *Server) {
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, v := range values {
			if v == "" {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
		s.supportedACRValues = out
	}
}

// WithOperatorMetadata registers the OIDC Discovery §3 `op_policy_uri`,
// `op_tos_uri`, and `service_documentation` advertisements. RPs
// surface these to their end users when displaying a consent screen
// ("by signing in you accept <op_policy_uri> ...") and integrators
// link to `service_documentation` for SDK reference. Empty values
// omit the corresponding discovery field (omitempty semantics).
func WithOperatorMetadata(policyURI, tosURI, docs string) Option {
	return func(s *Server) {
		s.opPolicyURI = policyURI
		s.opTosURI = tosURI
		s.serviceDocumentation = docs
	}
}

// WithIDTokenIssuer enables OpenID Connect ID Token emission alongside
// the access token whenever a login or token-exchange request carries
// the "openid" scope. Without it, the `id_token` field is omitted from
// every response — relying parties built against the access-token-only
// flows keep working unchanged.
//
// Pass the same Ed25519JWTIssuer as both WithTokenIssuer and
// WithIDTokenIssuer to share one signing key + one JWKS entry —
// that's the canonical wiring for a single-key OIDC deployment.
func WithIDTokenIssuer(issuer oidc.IDTokenIssuer) Option {
	return func(s *Server) { s.idTokenIssuer = issuer }
}

// WithRefreshTokenStore enables the OAuth 2.0 refresh_token grant on the
// /token endpoint and turns on server-managed refresh token issuance on
// every successful access-token mint (login direct flow + authorization_code
// exchange). Without it, POST /token grant_type=refresh_token returns
// 501 and the response_token field passes through whatever the underlying
// TokenIssuer returned (typically empty for stateless JWT).
//
// Rotation: tokens are single-use. Each successful refresh consumes the
// presented token and issues a new one. A presented-twice token always
// fails as invalid_grant (the second presentation can't tell whether
// the first was legitimate or a replay; rejection is the safe default).
//
// ttl is the lifetime of issued tokens (per RFC 6749 §6 typically days
// to weeks; mobile clients often keep them for months). Pass <=0 to use
// [DefaultRefreshTokenTTL] (30 days).
func WithRefreshTokenStore(store oauth.RefreshTokenStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.refreshTokenStore = store
		if ttl > 0 {
			s.refreshTokenTTL = ttl
		}
	}
}

// WithRefreshRotationGrace enables a benign-double-submit grace window on the
// refresh-token rotation grant: when a token is rotated, its successor response
// is cached for `window`, so a near-simultaneous re-presentation of the SAME
// token (multi-tab SPA / mobile cold-start race / HTTP retry after a dropped
// 200) replays that successor instead of tripping family-reuse detection and
// killing the whole token family (a logout storm). Does NOT weaken BCP §4.13 —
// a genuine post-window replay finds no cache entry and still kills the family
// (refresh_grace.go). window <= 0 disables it (byte-identical to the historical
// strict-single-use behavior).
func WithRefreshRotationGrace(window time.Duration) Option {
	return func(s *Server) {
		if window > 0 {
			s.refreshGrace = handler.NewRefreshGraceCache(window)
		}
	}
}

// WithDeviceSecretStore enables OpenID Connect Native SSO 1.0. When wired, a
// /token request that includes the device_sso scope receives a device_secret
// in the response and a ds_hash claim in the id_token; a second native app may
// then exchange that id_token + device_secret (RFC 8693 token exchange,
// actor_token_type = urn:openid:params:token-type:device-secret) for its own
// tokens without re-authenticating the user. ttl bounds a secret's validity
// (0 = DefaultDeviceSecretTTL). Nil store (the default) disables the feature —
// byte-identical to a build without it.
func WithDeviceSecretStore(store DeviceSecretStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.deviceSecretStore = store
		if ttl > 0 {
			s.deviceSecretTTL = ttl
		}
	}
}

// WithSessionTTL is retained for source compatibility but has no effect.
// The Server delegates session lifetime to the configured [SessionManager];
// pass the desired TTL to that constructor instead, e.g.
// defaultimpl.NewMemorySessionManager(24*time.Hour).
//
// Deprecated: configure session lifetime on the SessionManager directly.
func WithSessionTTL(_ time.Duration) Option {
	return func(*Server) {}
}

// WithTokenTTL is retained for source compatibility but has no effect.
// The Server delegates token lifetime to the configured [TokenIssuer];
// pass the desired TTL to that constructor instead, e.g.
// defaultimpl.WithEd25519TokenTTL(time.Hour) when building the issuer.
//
// Deprecated: configure token lifetime on the TokenIssuer directly.
func WithTokenTTL(_ time.Duration) Option {
	return func(*Server) {}
}

// WithBaseURL is retained for source compatibility but has no effect.
// Absolute URLs (callback redirects, JWKS) are derived from incoming
// request headers + reverse-proxy hints, not from a configured constant.
//
// Deprecated: the value is no longer threaded through any handler.
func WithBaseURL(_ string) Option {
	return func(*Server) {}
}

// WithAuditRecorder enables audit-event recording. The Server will emit
// login/logout/code-send/etc. events to r. Without this option, audit calls
// are silent no-ops.
func WithAuditRecorder(r *audit.Recorder) Option {
	return func(s *Server) { s.auditor = r }
}

// WithCAEPTransmitter wires the OpenID Shared Signals (CAEP/RISC)
// transmitter for real-time cross-RP revocation. When set AND an audit
// recorder is also wired, the Server taps its audit pipeline so the
// transmitter sees every recorded event, maps the small mapped subset
// (refresh-token-family reuse, tenant tokens revoked, scoped admin token
// revoke) onto a signed Security Event Token (RFC 8417), and PUSHES it
// async + best-effort to the AFFECTED client's registered receiver —
// scoped to the event's client/tenant so one RP's revocation never leaks
// to another. The SET is signed by the SAME key already in JWKS, so RPs
// validate it with no new trust setup.
//
// Opt-in: omit it and the Server is byte-identical — no SETs, no extra
// sink, no overhead. The transmitter is itself an audit.Sink, so SDK
// consumers who build their own recorder MAY alternatively compose it
// into their sink chain directly instead of using this option.
func WithCAEPTransmitter(t *caep.Transmitter) Option {
	return func(s *Server) { s.caepTransmitter = t }
}

// CAEPTransmitter returns the wired transmitter (nil when unset), so cmd
// can drain its in-flight async sends on shutdown via Close.
func (s *Server) CAEPTransmitter() *caep.Transmitter { return s.caepTransmitter }

// WithCAEPReceiver mounts the OpenID Shared Signals (CAEP/SSF) RECEIVER —
// the inbound half of Shared Signals, the inverse of WithCAEPTransmitter.
// It registers a push-delivery endpoint (PathSSFReceive, default
// "/ssf/receive") that accepts a signed Security Event Token (a compact
// JWS, Content-Type application/secevent+jwt) from a CONFIGURED trusted
// upstream transmitter and, on a fully-validated revocation event for a
// PRECISELY-mapped local subject, revokes that subject's local access
// (sessions + refresh tokens) via the same seams /token/revoke-all uses.
//
// The receiver (built with caep.NewReceiver) carries its own trust:
//
//   - a trusted-transmitter allowlist (each: an `iss` + that transmitter's
//     published JWKS). A SET whose `iss` is not configured, or whose
//     signature doesn't verify against that transmitter's JWKS (via the
//     SAME alg-confusion-safe security.VerifyCompactJWS the SPIFFE path
//     uses), triggers NOTHING.
//   - strict aud-binding (the SET `aud` MUST contain this server's
//     configured audience — no cross-receiver replay), exp/iat freshness,
//     and jti-replay (a replayed SET cannot re-trigger).
//   - precise subject mapping (a subject with no KNOWN local user is acked
//     but NOT acted on — no wrongful revocation, which would be a DoS).
//
// A validation failure returns an oracle-safe SSF error (400) that does
// NOT reveal which gate failed; a valid SET (even one that maps to no
// subject or carries only unknown events) is acked (202). Default-off:
// nil ⇒ the route is NOT mounted, byte-identical to a build without it.
func WithCAEPReceiver(rcv *caep.Receiver) Option {
	return func(s *Server) { s.caepReceiver = rcv }
}

// WithAuditAPI mounts the audit query endpoints
// (GET /api/v1/audit/events, GET /api/v1/audit/events/:id,
// GET /api/v1/audit/facets). Requires a recorder to also be set. The
// facets endpoint needs a Sink implementing the optional
// audit.FacetQuerier (MemorySink + sqlite do; write-only sinks yield 501).
// Endpoints are unauthenticated by default — gate them with middleware or
// a reverse proxy if exposed beyond localhost.
func WithAuditAPI() Option {
	return func(s *Server) { s.auditAPI = true }
}

// WithTracingMiddleware installs TracingMiddleware ahead of all routes.
// It propagates W3C Traceparent (trace_id + span chaining) and X-Request-Id
// (single-hop correlation) so audit events automatically pick them up.
func WithTracingMiddleware() Option {
	return func(s *Server) { s.requestIDMW = true }
}

// WithRequestIDMiddleware is a back-compat alias for WithTracingMiddleware.
// New code should call WithTracingMiddleware directly.
//
// Deprecated: use WithTracingMiddleware. The middleware was renamed once
// it grew W3C Traceparent propagation alongside the original X-Request-Id
// stamping; the name is kept here so existing call sites still compile.
func WithRequestIDMiddleware() Option { return WithTracingMiddleware() }

// WithPermissionProvider enables the per-user permission/role/menu lookup
// endpoints. Without this option, those endpoints respond 501.
