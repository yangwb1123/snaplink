package kerberosauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// ErrValidate is the SINGLE error every validation failure collapses to. The
// handler maps it (and any other validator error) to ONE generic 401 — a
// forged, malformed, expired, wrong-realm, or keytab-mismatched SPNEGO token
// is indistinguishable on the wire (oracle-safe, AGENTS.md §2). The cause is
// NEVER surfaced to the client; it rides only the wrapped error for the
// operator's log.
var ErrValidate = errors.New("kerberos: SPNEGO validation failed")

// SPNEGOValidator is the MINIMAL seam the Negotiate handler depends on to turn
// a raw SPNEGO/Negotiate token into an authenticated client principal. It is
// the trust boundary: a returned (principal, realm, groups, nil) means the
// token was cryptographically validated against the server's keytab; any
// non-nil error means it was NOT and MUST NOT authenticate.
//
// Declaring our OWN narrow interface (rather than coupling the handler to
// gokrb5's *spnego.SPNEGO) keeps the seam test-injectable: handler_test.go
// drives a FAKE validator (no real KDC, no real keytab, no network), mirroring
// kms/awskms's KMSAPI + ldap's conn/dialer seams. The prod gokrb5Validator is
// the only thing that touches gokrb5.
type SPNEGOValidator interface {
	// Validate verifies negotiateToken (the raw, already-base64-DECODED bytes
	// of the `Authorization: Negotiate <b64>` value) against the keytab and
	// returns the authenticated client principal (its name + realm) plus any
	// PAC group SIDs. It MUST FAIL CLOSED: a forged/expired/replayed/
	// wrong-realm/unparseable token returns a non-nil error and NO usable
	// principal. principal is the bare client name (e.g. "alice"); realm is the
	// Kerberos realm (e.g. "EXAMPLE.COM"); groups are the PAC group SIDs (nil
	// when no PAC / PAC decoding disabled).
	Validate(ctx context.Context, negotiateToken []byte) (principal, realm string, groups []string, err error)
}

// gokrb5Validator is the production SPNEGOValidator. It wraps a gokrb5
// SPNEGOService built ONCE over the loaded keytab + service principal, and
// validates each token via the GSS-API AcceptSecContext path (the same path
// gokrb5's own SPNEGOKRB5Authenticate HTTP middleware uses internally —
// service.VerifyAPREQ under the hood, which is where the keytab signature
// check, ticket-lifetime check, and gokrb5's replay cache live).
//
// The keytab is held inside the gokrb5 settings; this struct stores no copy of
// the raw bytes and never logs them.
type gokrb5Validator struct {
	// svc carries the keytab + KeytabPrincipal(serviceName) + PAC + skew
	// settings. SPNEGOService is cheap and stateless-per-call for verification
	// (AcceptSecContext builds the per-request context), so one shared instance
	// is reused across goroutines — gokrb5's replay cache (jcmturner/rpc) is
	// process-global and concurrency-safe, so sharing the service is correct
	// and actually NECESSARY for the replay cache to see every request.
	svc *spnego.SPNEGO
}

// NewGokrb5Validator builds the production validator from a Config. It LOADS
// the keytab (from KeytabPath or KeytabBytes) ONCE here — a missing file or
// malformed keytab fails CONSTRUCTION (the operator's boot), never a request.
// Construction does NO network I/O (no KDC contact), so a down KDC does not
// block startup; only the keytab (a local secret) is read.
//
// SECURITY: the keytab is the trust anchor. On any load error this returns a
// generic "load keytab" error WITHOUT echoing the keytab bytes; the path is
// included only because it is operator-supplied config, not a secret value.
func NewGokrb5Validator(cfg Config) (*gokrb5Validator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	kt, err := loadKeytab(cfg)
	if err != nil {
		// Do NOT wrap the keytab BYTES into the error — only a generic reason.
		return nil, fmt.Errorf("kerberos: load keytab: %w", err)
	}

	return &gokrb5Validator{
		svc: spnego.SPNEGOService(kt, serviceOpts(cfg)...),
	}, nil
}

// serviceOpts assembles the gokrb5 SPNEGOService settings options from the
// Config. Extracted so a test can apply it to a fresh service.Settings and read
// the resulting MaxClockSkew back (the SPNEGO struct's settings field is
// unexported), proving the optional skew knob plumbs through.
func serviceOpts(cfg Config) []func(*service.Settings) {
	opts := []func(*service.Settings){
		// KeytabPrincipal pins WHICH key in the keytab validates the AP-REQ.
		// A service keytab commonly holds several principals/enctypes (the AD
		// default); without this gokrb5 would try to infer it. Pinning it makes
		// validation deterministic against the configured SPN.
		service.KeytabPrincipal(cfg.ServicePrincipal),
		// Decode the AD PAC unless the operator turned it off — that is where
		// the principal's group SIDs come from.
		service.DecodePAC(!cfg.DisablePAC),
	}
	// Plumb the optional skew override ONLY when set. A zero value is left out
	// entirely so the opts slice is byte-identical to before — gokrb5 then
	// applies its own 5-minute default. (Config.Validate already rejected a
	// negative value.) This governs the ticket-validity, authenticator-skew,
	// and replay-cache-retention window alike.
	if cfg.MaxClockSkew > 0 {
		opts = append(opts, service.MaxClockSkew(cfg.MaxClockSkew))
	}
	return opts
}

// loadKeytab reads the keytab from whichever source the (already-validated)
// Config specifies. Exactly one of KeytabPath / KeytabBytes is set.
func loadKeytab(cfg Config) (*keytab.Keytab, error) {
	if len(cfg.KeytabBytes) > 0 {
		kt := keytab.New()
		if err := kt.Unmarshal(cfg.KeytabBytes); err != nil {
			return nil, errors.New("malformed keytab bytes")
		}
		return kt, nil
	}
	// keytab.Load reads the file + unmarshals; a missing/unreadable file or
	// malformed content surfaces here. We return its error (a path/IO reason),
	// which carries no secret.
	return keytab.Load(cfg.KeytabPath)
}

// Validate implements SPNEGOValidator over gokrb5. It unmarshals the raw token
// into an SPNEGO context token, runs AcceptSecContext (the keytab-backed
// signature + freshness + replay validation), and on success extracts the
// authenticated principal + realm + PAC groups from the returned context.
//
// FAIL-CLOSED at every step: a token that doesn't parse, doesn't validate, or
// validates but yields no credentials returns ErrValidate (wrapping the gokrb5
// status/reason for the log). The returned principal is used ONLY after this
// function returns nil — the handler never trusts a client-asserted identity
// without this keytab validation.
func (v *gokrb5Validator) Validate(_ context.Context, negotiateToken []byte) (string, string, []string, error) {
	if len(negotiateToken) == 0 {
		return "", "", nil, fmt.Errorf("%w: empty token", ErrValidate)
	}

	// Unmarshal the raw GSS-API/SPNEGO token. A malformed/forged blob fails
	// here and collapses to ErrValidate (no detail leaked to the caller).
	var st spnego.SPNEGOToken
	if err := st.Unmarshal(negotiateToken); err != nil {
		return "", "", nil, fmt.Errorf("%w: %v", ErrValidate, err)
	}

	// AcceptSecContext is the trust gate: it runs service.VerifyAPREQ against
	// the keytab (signature + ticket lifetime), consults gokrb5's process-wide
	// replay cache (so a captured ticket replayed within its lifetime is
	// rejected), and on success returns a context carrying the validated
	// credentials. We treat ANYTHING other than an authenticated, COMPLETE
	// status as a failure.
	authed, ctx, status := v.svc.AcceptSecContext(&st)
	if !authed || status.Code != gssapi.StatusComplete {
		// Includes StatusContinueNeeded (a multi-leg handshake we don't drive),
		// every defective-token/credential code, and any KRB error — all one
		// oracle-safe failure. The GSS status string is logged by the handler
		// via the wrapped error, never returned to the client.
		return "", "", nil, fmt.Errorf("%w: %s", ErrValidate, gssStatusReason(authed, status))
	}

	// Pull the validated credentials out of the returned context. gokrb5 stores
	// them under an UNEXPORTED string key (set in spnego/krb5Token.go); since a
	// context key compares by value and it is a plain string, we read it back
	// with the SAME literal — exactly as gokrb5's own SPNEGOKRB5Authenticate
	// does internally (spnego/http.go). There is no exported accessor on the
	// returned context for the low-level AcceptSecContext path.
	creds, ok := ctx.Value(ctxKeyCredentials).(*credentials.Credentials)
	if !ok || creds == nil {
		// Validated but no credentials object — defensive fail-closed (should
		// not happen for a COMPLETE status, but we never authenticate without a
		// concrete principal).
		return "", "", nil, fmt.Errorf("%w: no credentials in validated context", ErrValidate)
	}

	// UserName is KDC-asserted, not attacker-controllable: when a PAC is decoded
	// (the AD default), gokrb5 OVERWRITES UserName with the PAC's EffectiveName
	// (spnego/krb5Token.go), so the qualified principal we build below is the
	// KDC's signed EffectiveName, NOT the raw authenticator CName a client could
	// influence — and the PAC itself is keytab-validated. Domain() / the realm
	// is NOT PAC-overwritten (it comes from the validated ticket's realm), so
	// the realm gate in the handler is unaffected by PAC decoding.
	principal := creds.UserName()
	realm := creds.Domain()
	if principal == "" || realm == "" {
		return "", "", nil, fmt.Errorf("%w: empty principal or realm", ErrValidate)
	}

	return principal, realm, extractGroups(creds), nil
}

// ctxKeyCredentials mirrors gokrb5's unexported context key
// (github.com/jcmturner/gokrb5/v8/ctxCredentials, set in spnego/krb5Token.go's
// KRB5Token.Verify). gokrb5 does NOT export it and offers no accessor on the
// raw AcceptSecContext context, so we reproduce the literal. It is load-bearing:
// if a gokrb5 upgrade changes the string the type assertion fails CLOSED (no
// credentials ⇒ ErrValidate ⇒ 401), never a silent auth bypass. The
// happy-path test (real gokrb5 fixtures) catches such a drift immediately.
const ctxKeyCredentials = "github.com/jcmturner/gokrb5/v8/ctxCredentials"

// extractGroups returns the PAC group SIDs from the validated credentials, or
// nil when no PAC was present / PAC decoding was disabled. gokrb5 decodes the
// AD PAC into a value-typed credentials.ADCredentials stored under the standard
// attribute key and exposed via the typed GetADCredentials accessor; that is
// the ONLY representation gokrb5 produces. (An earlier JSON-string fallback
// here was dead code — gokrb5 never stashes the ADCredentials as a string — so
// it was removed.) Groups are enrichment, never an auth gate: no PAC ⇒ nil, and
// the principal + realm still authenticate.
func extractGroups(creds *credentials.Credentials) []string {
	ad := creds.GetADCredentials()
	if len(ad.GroupMembershipSIDs) > 0 {
		return append([]string(nil), ad.GroupMembershipSIDs...)
	}
	return nil
}

// gssStatusReason renders a SHORT, secret-free reason string for the operator
// log (carried on the wrapped ErrValidate, never returned to the client).
func gssStatusReason(authed bool, status gssapi.Status) string {
	if !authed {
		return "not authenticated"
	}
	return status.Error()
}

// Interface guard.
var _ SPNEGOValidator = (*gokrb5Validator)(nil)
