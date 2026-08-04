package kerberosauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HTTP-level Negotiate handshake constants (RFC 4559). The 401 +
// `WWW-Authenticate: Negotiate` challenge is the STANDARD SPNEGO handshake the
// browser/desktop client answers by retrying with a service ticket — it is NOT
// an auth-failure oracle, so it is emitted both when no token is present (the
// initial challenge) and on a validation failure (so a client whose ticket
// went stale can immediately retry with a fresh one).
const (
	headerAuthorization   = "Authorization"
	headerWWWAuthenticate = "WWW-Authenticate"
	negotiateScheme       = "Negotiate"
)

// errInvalidToken is the SINGLE wire error a validation failure surfaces —
// oracle-safe: forged / malformed / expired / replayed / wrong-realm all
// collapse to this one code (AGENTS.md §2). It mirrors the bearer-token
// invalid_token vocabulary the rest of the server uses for a rejected
// credential.
const errInvalidToken = "invalid_token"

// Secret-free reason codes carried on the SERVER-SIDE failure audit event
// (Metadata "reason"), NEVER on the wire. They distinguish the two failure
// classes for a SIEM/anomaly detector without leaking which check failed to the
// client (the wire stays the one generic 401 — oracle-safe, AGENTS.md §2). They
// are an internal audit vocabulary, NOT a wire `error` code, so docs/
// error-codes.md is unaffected.
const (
	// reasonValidate — the SPNEGO token did not validate against the keytab
	// (forged / malformed base64 / bad signature / expired / replayed / not a
	// SPNEGO token — all collapsed). There is NO validated identity, so no
	// principal/realm is attached.
	reasonValidate = "krb5_validate"
	// reasonRealmMismatch — the ticket validated against the keytab but the
	// authenticated principal's realm is not the configured one (the
	// load-bearing realm gate). Here the principal/realm ARE keytab-validated,
	// so they may be attached for the operator's triage.
	reasonRealmMismatch = "krb5_realm_mismatch"
)

// negotiateHandler serves the SPNEGO/Negotiate flow for one configured
// surface: challenge -> validate the ticket against the keytab -> mint SSO
// tokens for the validated principal.
type negotiateHandler struct {
	cfg       Config
	validator SPNEGOValidator
	deps      Deps
	logger    spi.Logger
}

// serve handles GET/POST on the configured mount path. It is a credential-
// bearing endpoint (it mints tokens + session state), so it stamps no-store
// headers at entry, on EVERY path including the challenge + every error (a
// cached cross-user 200 — or even a cached 401 challenge — would be wrong),
// matching the RFC 6749 §5.1 treatment the SDK applies to /token + /userinfo +
// the SAML ACS.
//
// Flow (RFC 4559 SPNEGO + the SDK's mint-from-validated-subject path):
//
//  1. no-store at entry.
//  2. No `Authorization: Negotiate <b64>` header -> 401 + `WWW-Authenticate:
//     Negotiate` (the handshake challenge that triggers the client to send its
//     ticket). This is the normal first leg, NOT a failure.
//  3. Header present -> base64-decode -> validator.Validate against the keytab.
//     ANY failure -> ONE generic 401 invalid_token + a fresh Negotiate
//     challenge (oracle-safe; the cause is logged, never returned).
//  4. Success -> enforce the configured realm -> map principal -> Subject (AMR
//     ["krb5"]) -> upsert user -> create session -> mint access (+ id) token ->
//     return the token/session JSON.
func (h *negotiateHandler) serve(w http.ResponseWriter, r *http.Request) {
	// (1) no-store before any branch.
	noStore(w)

	// (2) Extract the Negotiate token. Absent/malformed-scheme -> challenge.
	raw, ok := negotiateToken(r.Header.Get(headerAuthorization))
	if !ok {
		// Standard SPNEGO handshake: ask the client to Negotiate. 401 WITHOUT an
		// error= (no credential was offered — RFC 6750 §3.1 / RFC 4559).
		h.challenge(w, http.StatusUnauthorized, "")
		return
	}

	// (3) base64-decode the token. A malformed base64 value collapses to the
	// SAME generic failure as a bad ticket (no decode-vs-validate oracle).
	tokenBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(tokenBytes) == 0 {
		h.logger.Error("kerberos: malformed Negotiate token", "error", "base64 decode")
		h.recordLoginFailure(r.Context(), reasonValidate, "", "")
		h.challenge(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	// (3) Validate against the keytab. This is the trust gate — only a nil
	// error means the principal was cryptographically proven.
	principal, realm, groups, err := h.validator.Validate(r.Context(), tokenBytes)
	if err != nil {
		// Oracle-safe: log the reason (already secret-free; never the keytab or
		// token), return ONE generic 401 + a Negotiate challenge so a stale
		// ticket can be retried. A secret-free failure audit event surfaces the
		// attempt to the audit pipeline + anomaly detectors (parity with the
		// SAML/MFA *_failure side channel) WITHOUT changing the wire response.
		// No principal is emitted: validation FAILED, so there is no validated
		// identity to attribute — only a generic reason.
		h.logger.Error("kerberos: SPNEGO validation failed", "error", err.Error())
		h.recordLoginFailure(r.Context(), reasonValidate, "", "")
		h.challenge(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	// (4) Realm check. This is LOAD-BEARING, not cosmetic, and MUST NOT be
	// removed: the keytab validates the AP-REQ *signature* but does NOT pin the
	// client's realm — a keytab provisioned for cross-realm trust will happily
	// validate a ticket whose client lives in a FOREIGN trusted realm. This
	// EqualFold comparison is therefore the SOLE constraint binding the
	// authenticated principal to the one realm this surface accepts; without it
	// a principal from any transitively-trusted realm could mint here. A
	// mismatch collapses to the same generic 401 (oracle-safe).
	if !strings.EqualFold(strings.TrimSpace(realm), strings.TrimSpace(h.cfg.Realm)) {
		h.logger.Error("kerberos: principal realm not permitted", "expected_realm", h.cfg.Realm)
		h.recordLoginFailure(r.Context(), reasonRealmMismatch, realm, principal)
		h.challenge(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	h.mint(w, r, principal, realm, groups)
}

// mint upserts the validated principal and issues SSO tokens for the
// configured client, mirroring issueWebAuthnToken (the WebAuthn mint-from-
// validated-subject path) and the SAML ACS user-upsert + session-create. On
// any post-validation failure it returns a generic error WITHOUT leaking which
// step failed.
func (h *negotiateHandler) mint(w http.ResponseWriter, r *http.Request, principal, realm string, groups []string) {
	ctx := r.Context()

	// Resolve the minting client FRESH (no cache) so an inactive/deleted client
	// fails here, never a stale picture. A missing client is a server
	// misconfiguration (the operator named a client that doesn't exist), so it
	// is a 500, not a client-facing auth failure.
	client, err := h.deps.ClientStore.Get(ctx, h.cfg.ClientID)
	if err != nil || client == nil {
		h.logger.Error("kerberos: minting client not found", "client_id", h.cfg.ClientID, "error", errOrNil(err))
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}
	if !client.Active {
		// An inactive client must not mint — same disposition as /auth/login.
		h.logger.Error("kerberos: minting client inactive", "client_id", h.cfg.ClientID)
		writeError(w, http.StatusForbidden, "invalid_client")
		return
	}

	// Build the validated identity. ExternalID is the FULLY-QUALIFIED principal
	// (principal@REALM) so two principals with the same local name in different
	// realms never collide on the identity model; the local user id is the same
	// qualified string (stable, durable). AMR ["krb5"] lets a resource server
	// branch on the auth method. Attributes carry ONLY the two derived,
	// server-controlled values (realm + groups) — a Kerberos ticket can never
	// smuggle an arbitrary claim onto the token.
	qualified := principal + "@" + realm
	attrs := map[string]string{
		h.cfg.realmAttr(): realm,
	}
	if len(groups) > 0 {
		attrs[h.cfg.groupsAttr()] = strings.Join(groups, ",")
	}

	// Upsert the user onto the one identity model (mirrors the SAML ACS +
	// finishLogin). A store failure fails closed (500) — we never mint a token
	// for a user we couldn't persist.
	if err := h.deps.UserProvider.CreateOrUpdate(ctx, &sso.User{
		ID:         qualified,
		ExternalID: qualified,
		Provider:   h.cfg.Name,
		Attributes: attrs,
	}); err != nil {
		h.logger.Error("kerberos: upsert user failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}

	// Create the session through the SessionManager (not a raw store) so it
	// lands with the same lifecycle as every other login.
	session, err := h.deps.SessionManager.Create(ctx, qualified)
	if err != nil {
		h.logger.Error("kerberos: session create failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}

	// Mint the access (+ id) token. A signing/issuance failure fails closed.
	result, err := h.issueTokens(ctx, client, qualified, session.ID, attrs)
	if err != nil {
		h.logger.Error("kerberos: token issuance failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, sso.ErrInternal)
		return
	}

	// Audit a login_success on the SAME recorder the rest of the server uses
	// (provider = Config.Name). Realm rides Metadata via SetMeta (NEVER
	// e.Metadata = map{} — that clobbers geo/tenant enrichment, AGENTS.md §2).
	h.recordLogin(ctx, client.ID, qualified, session.ID, realm)

	writeJSON(w, http.StatusOK, result)
}

// kerberosIssueResult is the JSON the handler returns on success. It mirrors
// the WebAuthn finish-login response shape so client integration is consistent
// across SSO surfaces. Status + SessionID echo the SAML ACS contract.
type kerberosIssueResult struct {
	Principal   string `json:"principal"`
	SessionID   string `json:"session_id"`
	Status      string `json:"status"`
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
}

// issueTokens mints the access token (and, when the client requests the openid
// scope AND an id_token issuer resolves, an id_token) for the validated
// principal. It mirrors issueWebAuthnToken: per-tenant access-token issuer
// selection (so the token is signed with the tenant's key), the full
// AllowedScopes routed through the shared GrantedScopes gate, AMR ["krb5"],
// AuthTime = now. A refresh token is deliberately NOT minted here — desktop
// SSO re-runs the (silent) Negotiate handshake to re-authenticate, so a
// long-lived refresh token would only widen the blast radius of an exfiltrated
// token without a usability win.
func (h *negotiateHandler) issueTokens(ctx context.Context, client *sso.Client, userID, sessionID string, attrs map[string]string) (*kerberosIssueResult, error) {
	// Per-tenant access-token issuer (tenant -> client strategy -> default).
	_, issuer, err := h.deps.IssuerForClient(client)
	if err != nil {
		return nil, err
	}

	scopes, err := oauth.GrantedScopes(client.AllowedScopes, client)
	if err != nil {
		return nil, err
	}

	authTime := time.Now()
	subject := &sso.Subject{
		ID:       userID,
		Provider: h.cfg.Name,
		ClientID: client.ID, // RFC 9068 §2.2 REQUIRED
		AuthTime: authTime,
		AMR:      []string{"krb5"},
		SID:      sessionID,
		Claims:   attrs, // realm/groups surface as token claims via the issuer
	}
	token, err := issuer.Issue(ctx, subject, scopes)
	if err != nil {
		return nil, err
	}

	result := &kerberosIssueResult{
		Principal:   userID,
		SessionID:   sessionID,
		Status:      sso.StatusAuthenticated,
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresIn:   token.ExpiresIn,
		Scope:       token.Scope,
	}

	// id_token: gated on openid scope AND a resolvable per-tenant id_token
	// issuer (when the hook is wired). emit=false ⇒ the tenant strategy can't
	// mint id_tokens (opaque session tokens) ⇒ omit, never sign with the shared
	// key. A resolver error fails CLOSED (the whole mint fails) so a
	// misconfigured tenant issuer never silently downgrades.
	if h.deps.IDTokenIssuerForClient != nil && slices.Contains(scopes, sso.ScopeOpenID) {
		idIssuer, emit, resErr := h.deps.IDTokenIssuerForClient(client)
		if resErr != nil {
			return nil, resErr
		}
		if emit {
			idToken, err := idIssuer.IssueIDToken(ctx, &oidc.IDTokenRequest{
				Subject:       userID,
				Audience:      client.ID,
				AuthTime:      authTime,
				AMR:           []string{"krb5"},
				SID:           sessionID,
				Claims:        attrs,
				AccessToken:   token.AccessToken,
				GrantedScopes: scopes,
			})
			if err != nil {
				return nil, err
			}
			// Fail-closed encryption: a client that registered
			// id_token_encrypted_response_alg gets a JWE; if encryption was
			// requested but failed, omit the id_token (no cleartext leak).
			if h.deps.EncryptIDToken != nil {
				if enc, ok := h.deps.EncryptIDToken(ctx, client, idToken); ok {
					result.IDToken = enc
				}
			} else {
				result.IDToken = idToken
			}
		}
	}

	return result, nil
}

// recordLogin emits a login_success audit event (provider = Config.Name). Realm
// rides Metadata via SetMeta. Nil recorder = no-op.
func (h *negotiateHandler) recordLogin(ctx context.Context, clientID, userID, sessionID, realm string) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventLogin,
		Outcome:   audit.OutcomeSuccess,
		Provider:  h.cfg.Name,
		ClientID:  clientID,
		ActorID:   userID,
		SessionID: sessionID,
	}
	audit.SetMeta(e, "krb5_realm", realm)
	h.deps.AuditRecorder.Record(ctx, e)
}

// recordLoginFailure emits a login_failure audit event (the EXISTING
// audit.EventLoginFailure vocabulary — NOT a new wire contract) on a validation
// or realm-gate rejection, so brute-force / replay attempts against the
// Negotiate endpoint surface in the audit pipeline + anomaly detectors. It is
// the SECRET-BEARING server-side side channel that pairs with the oracle-safe
// wire response (the SAML/MFA *_failure pattern, AGENTS.md §2): the WIRE stays a
// byte-identical generic 401, the detail rides only this server-side event.
//
// Carries ONLY a secret-free reason (Metadata "reason"=reasonValidate|
// reasonRealmMismatch, "provider"=Config.Name) — NEVER the ticket, keytab, or
// any gokrb5 internal. principal/realm are attached ONLY when keytab-validated
// (the realm-mismatch case, where the KDC asserted them); on a validation
// failure they are empty (no validated identity exists to attribute, and the
// client-asserted name from an unvalidated token MUST NOT be trusted/logged as
// an identity). Nil recorder = no-op. Metadata rides SetMeta (NEVER e.Metadata =
// map{}, which clobbers geo/tenant enrichment, AGENTS.md §2).
func (h *negotiateHandler) recordLoginFailure(ctx context.Context, reason, validatedRealm, validatedPrincipal string) {
	if h.deps.AuditRecorder == nil {
		return
	}
	e := &audit.Event{
		Type:     audit.EventLoginFailure,
		Outcome:  audit.OutcomeFailure,
		Provider: h.cfg.Name,
		ClientID: h.cfg.ClientID,
		Reason:   reason,
	}
	// ActorID + realm only when keytab-validated (realm-mismatch path). On a
	// validation failure both stay empty — there is no proven identity.
	if validatedPrincipal != "" {
		e.ActorID = validatedPrincipal + "@" + validatedRealm
	}
	audit.SetMeta(e, "reason", reason)
	audit.SetMeta(e, "provider", h.cfg.Name)
	if validatedRealm != "" {
		audit.SetMeta(e, "krb5_realm", validatedRealm)
	}
	h.deps.AuditRecorder.Record(ctx, e)
}

// challenge writes the SPNEGO 401 handshake: `WWW-Authenticate: Negotiate` +
// (optionally) the oracle-safe error envelope. An empty code is the
// missing-credentials first leg (no error= per RFC 6750 §3.1); errInvalidToken
// is a validation failure. Either way the Negotiate challenge lets the client
// (re)send a ticket. no-store is already set by serve.
func (h *negotiateHandler) challenge(w http.ResponseWriter, status int, code string) {
	w.Header().Set(headerWWWAuthenticate, negotiateScheme)
	if code == "" {
		// No body — the bare Negotiate challenge (initial handshake leg).
		w.WriteHeader(status)
		return
	}
	writeError(w, status, code)
}

// negotiateToken pulls the base64 token out of an `Authorization: Negotiate
// <b64>` header value, case-insensitively on the scheme. Returns ("", false)
// when the header is absent or not a Negotiate header (-> the handshake
// challenge). A present-but-empty token also returns false (treated as the
// initial challenge leg rather than a malformed credential).
func negotiateToken(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], negotiateScheme) {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// noStore stamps the RFC 6749 §5.1 credential-endpoint cache headers.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{sso.KeyError: code})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set(sso.HeaderContentType, sso.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errOrNil(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
