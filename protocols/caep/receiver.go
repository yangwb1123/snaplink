package caep

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"net/http"
	"sync"
	"time"
)

// The CAEP/SSF RECEIVER — the inbound half of OpenID Shared Signals.
//   - subject mapping PRECISION (the other crux): the SET's subject is
//     mapped to a LOCAL user via an explicit, configured strategy. A
//     subject that does NOT map to a KNOWN local user is a NO-OP (acked,
//     never acted on) — revoking a guessed / partial-match subject would
//     be wrongful revocation, i.e. a targeted denial-of-service against
//     whoever the attacker can make the subject string resolve to.
//
// Once a SET is FULLY validated AND its subject maps to a local user, the
// action is fail-TOWARD-revoking: revoking local access is the safe
// direction, so a downstream store error during the revoke is surfaced
// (the caller decides) but the validated intent stands. Validation itself
// is strictly fail-CLOSED: any failure → no action.
//
// # Acknowledgement semantics (RFC 8935)
//
// A VALID SET is ACKED (the transmitter did its job) even when it maps to
// no local subject or carries only unknown event types — the receiver
// simply has nothing to do. Only a MALFORMED / UNSIGNED / UNTRUSTED-iss /
// WRONG-aud / EXPIRED / REPLAYED SET is an error. The error is oracle-safe:
// it does not reveal WHICH check failed beyond the SSF-standard codes.
//
// # Dependency-free
//
// The Receiver reuses security.VerifyCompactJWS (signature), the existing
// security.JTIReplayStore (replay), and the existing revocation seams
// (SubjectRevoker over SessionManager + RefreshTokenSubjectIndex). No new
// dependency; the package import graph stays core + audit + security.
// SubjectMapMode selects how a SET's subject identifier is mapped onto a
// LOCAL user id. The mapping is the security crux of the receiver: it MUST
// be precise (a mismatch is wrongful revocation), so the strategy is an
// EXPLICIT operator choice per trusted transmitter, never a guess.
type SubjectMapMode int

const (
	// SubjectMapOpaque treats the SET's `sub_id` opaque `id` as the LOCAL
	// user id directly. This is the symmetric inverse of THIS project's
	// own Transmitter, which emits {format:"opaque", id:<local subject>}
	// (security_event_token.go). It maps ONLY when a local user with that
	// EXACT id exists; an unknown id is a no-op. Use it for a peer SSO that
	// shares this server's subject namespace (or itself federates from the
	// same IdP, so the `sub` is already the shared subject).
	SubjectMapOpaque SubjectMapMode = iota
	// SubjectMapIssSub treats the SET's `sub_id` as the RFC 9493 `iss_sub`
	// format {format:"iss_sub", iss:<upstream-iss>, sub:<upstream-sub>} and
	// resolves it through the federation link:
	// UserProvider.GetByExternalID(provider, sub). The provider name is the
	// per-transmitter Provider, which is REQUIRED (operator-pinned, never
	// derived from the SET's attacker-controlled sub_id.iss), so a local user
	// federated from that upstream (User.Provider == provider, User.ExternalID
	// == upstream sub) is matched EXACTLY. A subject with no such federation
	// link — or one whose sub_id.iss names a FOREIGN provider — is a no-op.
	// Use it for a PARTIALLY-trusted upstream IdP whose subject namespace
	// differs from this server's: a transmitter in this mode can only revoke
	// subjects under ITS configured provider, never another upstream's.
	SubjectMapIssSub
)

// Subject-identifier `format` values (RFC 9493 §3) the receiver
// understands. A SET whose sub_id uses an unrecognised format maps to no
// subject (no-op + ack) rather than being guessed.
const (
	subjectFormatOpaque = "opaque"
	subjectFormatIssSub = "iss_sub"
)

// DefaultReceiverMaxClockSkew bounds SET iat/exp freshness validation.
// SETs are short-lived (the Transmitter defaults to a 2-minute TTL); a
// small skew tolerates clock drift between the upstream transmitter and
// this server without meaningfully widening the replay window.
const DefaultReceiverMaxClockSkew = 60 * time.Second

// EventSSFEventReceived is the internal audit event recorded when a
// validated SET is processed (whether or not it found a local subject to
// act on). It carries the transmitter iss + the event type + the mapped
// local subject via SetMeta — NEVER the raw SET (which is a signed bearer
// artefact). Operator-facing signal, not a wire code.
const EventSSFEventReceived audit.EventType = "ssf_event_received"

// EventSSFRevocation is the internal audit event recorded when a validated
// SET caused a LOCAL revocation (sessions + refresh tokens killed for the
// mapped subject). Distinct from ssf_event_received so an operator can
// alert specifically on receiver-driven revocations.
const EventSSFRevocation audit.EventType = "ssf_revocation"

// Receiver-side metric outcome labels for sso_ssf_sets_received_total.
// Bounded cardinality by construction.
const (
	// ReceiverOutcomeRevoked — a validated SET mapped to a local subject
	// and a revocation was performed.
	ReceiverOutcomeRevoked = "revoked"
	// ReceiverOutcomeNoop — a validated SET was acked but did nothing
	// (unmapped subject or only unknown events).
	ReceiverOutcomeNoop = "noop"
	// ReceiverOutcomeRejected — the SET failed validation (bad sig /
	// untrusted iss / wrong aud / expired / replayed / malformed).
	ReceiverOutcomeRejected = "rejected"
)

// SubjectRevoker performs the local "revoke ALL of this subject's access"
// action once a SET is fully validated and its subject is mapped. It is a
// narrow seam (one method) so the receiver depends on a behavior, not on a
// concrete store wiring — StoreRevoker (revoker.go) is the default
// implementation composing the existing SessionManager +
// RefreshTokenSubjectIndex seams (the same ones /token/revoke-all and the
// compliance Eraser drive).
type SubjectRevoker interface {
	// RevokeAllForSubject revokes every refresh token and destroys every
	// session for the LOCAL user id. It returns counts for audit. It MUST be
	// idempotent (a second call finds nothing) and best-effort across the
	// two stores (a failure in one is reported, not a reason to skip the
	// other) — revoking is the safe direction.
	RevokeAllForSubject(ctx context.Context, localUserID string) (RevocationResult, error)
}

// RevocationResult reports what a RevokeAllForSubject did (for audit).
type RevocationResult struct {
	RefreshTokensRevoked int
	SessionsDestroyed    int
	// TrustedDevicesRevoked counts "remember this device" MFA-skip grants
	// killed by the optional fourth leg (WithTrustedDeviceRevocation). Zero
	// when that leg isn't wired — distinct from "wired but nothing to
	// revoke", which the receiver's audit trail doesn't need to tell apart.
	TrustedDevicesRevoked int
}

// SubjectResolver maps a SET subject identifier to a LOCAL user id. The
// default resolver (userProviderResolver) uses core.UserProvider; the seam
// is exported so an operator with a bespoke external-id store can plug a
// custom precise mapping. The crux invariant: return ("", false) — NOT a
// guessed id — for any subject that does not map to a KNOWN local user.
type SubjectResolver interface {
	// ResolveLocalSubject maps the SET subject to a local user id. ok=false
	// means "no known local user" — the caller MUST treat that as a no-op
	// (ack, no revocation). An error is a transient lookup failure (the
	// caller fails closed: no action, and the delivery is NOT acked so the
	// transmitter may retry).
	ResolveLocalSubject(ctx context.Context, mode SubjectMapMode, provider string, sub setSubjectID) (localUserID string, ok bool, err error)
}

// setSubjectID is the RFC 9493 Subject Identifier carried in a SET's
// `sub_id`. The receiver parses the two formats it acts on (opaque,
// iss_sub) plus the bare `sub` string fallback (some transmitters carry
// the subject as a top-level `sub` claim instead of sub_id).
type setSubjectID struct {
	Format string `json:"format"`
	ID     string `json:"id"`  // opaque
	Iss    string `json:"iss"` // iss_sub
	Sub    string `json:"sub"` // iss_sub
}

// inboundSETClaims is the SET payload subset the receiver validates +
// acts on. `aud` is string-or-array per RFC 7519 §4.1.3 (setAudClaim,
// jws.go).
type inboundSETClaims struct {
	Iss    string                     `json:"iss"`
	Jti    string                     `json:"jti"`
	Iat    int64                      `json:"iat"`
	Exp    int64                      `json:"exp"`
	Aud    setAudClaim                `json:"aud"`
	SubID  *setSubjectID              `json:"sub_id"`
	Sub    string                     `json:"sub"` // top-level subject fallback
	Events map[string]json.RawMessage `json:"events"`
}

// ReceiverResult is the outcome of processing one inbound SET, returned so
// the HTTP handler can choose the ack status + audit shape WITHOUT the
// receiver knowing about HTTP.
type ReceiverResult struct {
	// Acked is true when the SET was valid SSF and the transmitter's
	// delivery is complete (202) — including the valid-but-no-op cases
	// (unmapped subject / unknown event). False only on a validation
	// failure (the caller returns an SSF error).
	Acked bool
	// Acted is true when a revocation was actually performed.
	Acted bool
	// Issuer / EventTypes / LocalSubject are populated for audit on a valid
	// SET (Acked). They are SAFE to audit (no token bytes).
	Issuer       string
	EventTypes   []string
	LocalSubject string
	// Revocation carries the counts when Acted.
	Revocation RevocationResult
	// RejectCode is the SSF-standard error code when !Acked. One of the
	// ErrReceiver* / SSF codes below; the handler maps it to a 400. It does
	// NOT distinguish which internal check failed beyond the standard codes
	// (oracle-safe).
	RejectCode string
}

// SSF / RFC 8935 receiver error codes (the `err` field of the SSF error
// response). Deliberately COARSE so the receiver never leaks which precise
// validation gate failed (signature vs aud vs replay vs expiry) — an
// attacker probing the endpoint learns only the SSF-standard category.
const (
	// ErrReceiverInvalidRequest — the body is not a parseable compact-JWS
	// SET (RFC 8935 "invalid_request"). The ONLY shape error distinct from
	// the trust failures below.
	ErrReceiverInvalidRequest = "invalid_request"
	// ErrReceiverInvalidKey — the SET could not be authenticated: bad
	// signature, untrusted/unknown `iss`, wrong `aud`, expired, replayed,
	// or otherwise not from a trusted transmitter addressed to this
	// receiver. RFC 8935 §2.4 uses "invalid_key" for an authentication
	// failure of the SET; ALL trust failures collapse to it (oracle-safe).
	ErrReceiverInvalidKey = "invalid_key"
)

// SSFConfiguration describes this server's SSF transmitter capabilities.
// Served at /.well-known/ssf-configuration per OpenID SSF §4.
type SSFConfiguration struct {
	// Issuer is the SSF transmitter's issuer URL (same as the OIDC issuer).
	Issuer string `json:"issuer"`
	// JWKSURI is where the transmitter's signing public keys are published.
	JWKSURI string `json:"jwks_uri"`
	// DeliveryMethods are the supported SET delivery methods.
	DeliveryMethods []string `json:"delivery_methods_supported"`
	// ConfigurationEndpoint is the Stream Management API endpoint.
	ConfigurationEndpoint string `json:"configuration_endpoint,omitempty"`
	// StatusEndpoint is the poll-based status endpoint for RFC 8936.
	StatusEndpoint string `json:"status_endpoint,omitempty"`
	// SupportedEvents lists the SSF event types this transmitter can emit.
	SupportedEvents []string `json:"supported_events,omitempty"`
}

// SSFConfigDeps is what HandleSSFConfiguration needs from the host server.
type SSFConfigDeps interface {
	// ResolveIssuer resolves the issuer URL for the current request.
	ResolveIssuer(ctx core.HandlerContext) string
}

// DefaultSSFSupportedEvents is the set of SSF/CAEP events the transmitter
// currently maps from internal audit events. Aligned with event_mapper.go.
var DefaultSSFSupportedEvents = []string{
	"https://schemas.openid.net/secevent/caep/event-type/token-revocation",
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"https://schemas.openid.net/secevent/caep/event-type/credential-change",
	"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
}

// HandleSSFConfiguration serves GET /.well-known/ssf-configuration — returns
// the SSF transmitter metadata a receiver needs to configure SET delivery.
func HandleSSFConfiguration(d SSFConfigDeps, ctx core.HandlerContext) {
	iss := d.ResolveIssuer(ctx)
	cfg := SSFConfiguration{
		Issuer:          iss,
		JWKSURI:         iss + "/.well-known/jwks.json",
		DeliveryMethods: []string{"https://schemas.openid.net/secevent/ssf/delivery-method/push"},
		SupportedEvents: DefaultSSFSupportedEvents,
	}
	// Advertise the Stream Management API endpoint when available.
	if core.PathSSFConfig != "" {
		cfg.ConfigurationEndpoint = iss + "/ssf/streams"
	}
	ctx.JSON(http.StatusOK, cfg)
}

// Stream represents an SSF event stream (RFC 8935 §2). A stream is a
// delivery channel for Security Event Tokens (SETs) pushed to a receiver.
type Stream struct {
	// ID is a unique identifier for this stream.
	ID string `json:"id"`
	// Issuer is the SSF transmitter's issuer URL.
	Issuer string `json:"issuer"`
	// Subject is the entity this stream delivers events about.
	Subject string `json:"subject,omitempty"`
	// Events is the set of event types this stream delivers.
	Events []string `json:"events,omitempty"`
	// Delivery contains the push delivery configuration.
	Delivery *StreamDelivery `json:"delivery,omitempty"`
	// CreatedAt is when the stream was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the stream was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// StreamDelivery configures how SETs are delivered for a stream.
type StreamDelivery struct {
	// Method is the delivery method URI.
	Method string `json:"method"`
	// Endpoint is the receiver's SET endpoint URL (for push delivery).
	Endpoint string `json:"endpoint,omitempty"`
	// Authorization is the bearer token the transmitter includes.
	Authorization string `json:"authorization,omitempty"`
}

// StreamStore persists SSF event streams.
type StreamStore interface {
	// Create inserts a new stream. Returns ErrStreamExists if the ID is taken.
	Create(ctx context.Context, s *Stream) error
	// Get returns a stream by ID, or ErrStreamNotFound.
	Get(ctx context.Context, id string) (*Stream, error)
	// Update replaces an existing stream.
	Update(ctx context.Context, s *Stream) error
	// Delete removes a stream by ID. Idempotent.
	Delete(ctx context.Context, id string) error
	// List returns every stream (optionally filtered by subject).
	List(ctx context.Context, subject string) ([]*Stream, error)
}

// Sentinel errors.
var (
	ErrStreamNotFound = errors.New("caep: stream not found")
	ErrStreamExists   = errors.New("caep: stream already exists")
)

// MemoryStreamStore is an in-memory StreamStore implementation.
type MemoryStreamStore struct {
	mu      sync.RWMutex
	streams map[string]*Stream
}

func NewMemoryStreamStore() *MemoryStreamStore {
	return &MemoryStreamStore{
		streams: make(map[string]*Stream),
	}
}
func (m *MemoryStreamStore) Create(_ context.Context, s *Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.streams[s.ID]; exists {
		return ErrStreamExists
	}
	if s.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		s.ID = "strm_" + hex.EncodeToString(b)
	}
	now := time.Now()
	s.CreatedAt = now
	s.UpdatedAt = now
	cp := *s
	m.streams[cp.ID] = &cp
	return nil
}
func (m *MemoryStreamStore) Get(_ context.Context, id string) (*Stream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.streams[id]
	if !ok {
		return nil, ErrStreamNotFound
	}
	cp := *s
	return &cp, nil
}
func (m *MemoryStreamStore) Update(_ context.Context, s *Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.streams[s.ID]; !exists {
		return ErrStreamNotFound
	}
	cp := *s
	cp.UpdatedAt = time.Now()
	m.streams[cp.ID] = &cp
	return nil
}
func (m *MemoryStreamStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, id)
	return nil
}
func (m *MemoryStreamStore) List(_ context.Context, subject string) ([]*Stream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Stream
	for _, s := range m.streams {
		if subject == "" || s.Subject == subject {
			cp := *s
			out = append(out, &cp)
		}
	}
	if out == nil {
		out = []*Stream{}
	}
	return out, nil
}

// StreamAPIHandler holds the stream management HTTP handlers.
// StreamAPIDeps is what the stream management handlers need.
type StreamAPIDeps interface {
	StreamStore() StreamStore
	ErrorBody(code string) map[string]any
	ErrorBodyDesc(code, desc string) map[string]any
}

// HandleCreateStream serves POST /ssf/streams — creates a new event stream.
func HandleCreateStream(d StreamAPIDeps, ctx core.HandlerContext) {
	store := d.StreamStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	var s Stream
	if err := ctx.Bind(&s); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody("invalid_request"))
		return
	}
	if err := store.Create(ctx.Request().Context(), &s); err != nil {
		if err == ErrStreamExists {
			ctx.JSON(http.StatusConflict, d.ErrorBody("already_exists"))
			return
		}
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody("internal_error"))
		return
	}
	ctx.JSON(http.StatusCreated, s)
}

// HandleGetStream serves GET /ssf/streams/:id
func HandleGetStream(d StreamAPIDeps, ctx core.HandlerContext) {
	store := d.StreamStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	id := ctx.Param("id")
	s, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	ctx.JSON(http.StatusOK, s)
}

// HandleListStreams serves GET /ssf/streams — lists all streams.
func HandleListStreams(d StreamAPIDeps, ctx core.HandlerContext) {
	store := d.StreamStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	streams, err := store.List(ctx.Request().Context(), ctx.Query("subject"))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody("internal_error"))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"streams": streams})
}

// HandleDeleteStream serves DELETE /ssf/streams/:id
func HandleDeleteStream(d StreamAPIDeps, ctx core.HandlerContext) {
	store := d.StreamStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	id := ctx.Param("id")
	if err := store.Delete(ctx.Request().Context(), id); err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody("internal_error"))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// HandleUpdateStream serves PUT /ssf/streams/:id — updates a stream.
func HandleUpdateStream(d StreamAPIDeps, ctx core.HandlerContext) {
	store := d.StreamStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	id := ctx.Param("id")
	s, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
		return
	}
	if err := ctx.Bind(&s); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody("invalid_request"))
		return
	}
	s.ID = id // path param wins
	if err := store.Update(ctx.Request().Context(), s); err != nil {
		if err == ErrStreamNotFound {
			ctx.JSON(http.StatusNotFound, d.ErrorBody("not_found"))
			return
		}
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody("internal_error"))
		return
	}
	ctx.JSON(http.StatusOK, s)
}
