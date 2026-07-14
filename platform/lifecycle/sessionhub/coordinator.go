package sessionhub

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/spi"
)

// CoreSessionTerminator is the narrow capability Coordinator needs from the
// core session store: destroy one session by id. core.SessionManager already
// has this exact method, so a *Server's wired SessionManager satisfies this
// interface structurally with no adapter.
type CoreSessionTerminator interface {
	Destroy(ctx context.Context, sessionID string) error
}

// OIDCLogoutTrigger is the narrow capability Coordinator needs from the OIDC
// Back-Channel Logout 1.0 fan-out (protocols/oidc + interfaces/sso's
// fanOutBackchannelLogout): notify every relying party linked to subject that
// session sid has ended. Declared here (not imported from protocols/oidc) so
// this package never imports protocols/ — the composition root (interfaces/sso)
// supplies a value that satisfies it structurally.
type OIDCLogoutTrigger interface {
	TriggerBackchannelLogout(ctx context.Context, subject, sid string)
}

// SAMLLogoutTrigger is the narrow capability Coordinator needs from the SAML
// IdP-initiated Single Logout fan-out (infrastructure/saml/idp.Handlers.Fanout,
// a SEPARATE Go module). Its method shape is declared here, structurally
// matching Handlers.Fanout exactly, so that type satisfies this interface with
// zero changes to the saml module and zero import of it from this package —
// domains/ MUST NOT import infrastructure/.
type SAMLLogoutTrigger interface {
	// Fanout pushes a signed SAML LogoutRequest to every OTHER SP subject has
	// an active SAML session with, excluding excludeSPEntityID (pass "" to
	// notify all). Async + best-effort by the implementation's own contract;
	// this method itself does not return an error.
	Fanout(ctx context.Context, subject, excludeSPEntityID string)
}

// Coordinator orchestrates unified logout across every protocol a single
// login fanned out into. It holds ONLY narrow SPI references (never a
// concrete protocols/oidc or infrastructure/saml import), composing their
// already-existing logout mechanisms rather than reimplementing them.
type Coordinator struct {
	links  LinkStore
	core   CoreSessionTerminator
	oidc   OIDCLogoutTrigger
	logger spi.Logger

	// saml is set post-construction via SetSAMLTrigger: the concrete SAML IdP
	// handlers live in a separate Go module built FROM the already-constructed
	// *sso.Server (they need its IssuerForClient/SessionManager), so they
	// cannot be supplied as a constructor argument without a wiring cycle. A
	// mutex guards it since it may be set once at boot from a different
	// goroutine than the one handling the first request.
	mu   sync.RWMutex
	saml SAMLLogoutTrigger

	// inflightMu + inflight are the RE-ENTRANCY GUARD for Logout: the set of
	// global_sids currently mid-propagation. Logout composes the OIDC BCL
	// fan-out and the SAML SLO fan-out, each of which notifies EXTERNAL
	// parties (relying parties / service providers) today — but this
	// Coordinator is an intentionally general, reusable entry point (see
	// package doc), and a future receiver on either protocol side (e.g. an
	// operator wiring the SAML SP-side SLO receiver, or an OIDC back-channel
	// logout receiver, to ALSO call Coordinator.Logout for the same
	// global_sid instead of just destroying its own local session) would
	// close a cycle back into THIS Coordinator. Without a guard, that bounce
	// would re-run the full fan-out again — which itself fires the bounce a
	// second time — recursing without bound. The guard is keyed on gsid (not
	// global) so an unrelated concurrent Logout for a DIFFERENT global_sid is
	// never blocked; only a re-entrant call for the SAME global_sid,
	// already-in-flight, is turned into a safe no-op. See enterPropagation.
	inflightMu sync.Mutex
	inflight   map[GlobalSID]struct{}
}

// NewCoordinator builds a Coordinator. A nil links falls back to a fresh
// [NewMemoryLinkStore]; a nil logger falls back to [spi.NopLogger]. core and
// oidc may be nil — the corresponding leg is then a no-op in Logout, exactly
// as the un-wired mechanism already behaves today (fail-open, never a panic).
func NewCoordinator(links LinkStore, core CoreSessionTerminator, oidc OIDCLogoutTrigger, logger spi.Logger) *Coordinator {
	if links == nil {
		links = NewMemoryLinkStore(0)
	}
	if logger == nil {
		logger = spi.NopLogger{}
	}
	return &Coordinator{links: links, core: core, oidc: oidc, logger: logger, inflight: make(map[GlobalSID]struct{})}
}

// SetSAMLTrigger wires (or clears, with nil) the SAML SLO fan-out mechanism.
// Intended to be called once at boot, after both the *sso.Server (which owns
// this Coordinator) and the infrastructure/saml BuildResult (which owns the
// Fanout-capable IdP handlers) exist — see infrastructure/saml's Deps.SessionHub.
func (c *Coordinator) SetSAMLTrigger(t SAMLLogoutTrigger) {
	c.mu.Lock()
	c.saml = t
	c.mu.Unlock()
}

// HasSAMLTrigger reports whether SetSAMLTrigger has wired a SAML SLO fan-out
// mechanism. Exported so composition-root/integration code (and tests) can
// confirm the wiring completed without needing white-box access to the
// unexported saml field.
func (c *Coordinator) HasSAMLTrigger() bool {
	return c.samlTrigger() != nil
}

func (c *Coordinator) samlTrigger() SAMLLogoutTrigger {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.saml
}

// Link records one leg of gsid's fan-out — e.g. the core session leg at
// login, or (from infrastructure/saml's ACS handler) the SAML leg when the
// login went through SAML federation. Best-effort from the caller's
// perspective: a LinkStore error just means that leg won't be found later,
// never a login-blocking failure.
func (c *Coordinator) Link(ctx context.Context, gsid GlobalSID, protocol Protocol, externalRef, subject string) error {
	if gsid == "" {
		return ErrEmptyGlobalSID
	}
	return c.links.Link(ctx, LinkRecord{
		GlobalSID:   gsid,
		Protocol:    protocol,
		ExternalRef: externalRef,
		Subject:     subject,
	})
}

// ListBySubject returns every LinkRecord (both protocol legs, across every
// login) recorded for subject — the read side of the admin-facing
// cross-protocol session query (interfaces/admin's HandleLinkedSessions).
// Delegates straight to the wired LinkStore; Coordinator adds no grouping of
// its own, keeping this method's contract identical to
// LinkStore.ListBySubject's flat, creation-ordered shape.
func (c *Coordinator) ListBySubject(ctx context.Context, subject string) ([]LinkRecord, error) {
	return c.links.ListBySubject(ctx, subject)
}

// enterPropagation marks gsid as currently being propagated by Logout,
// returning false when it already is in flight (a bounced-back re-trigger —
// see the inflight field's doc comment). Cleared by exitPropagation once the
// owning Logout call's body completes, success or failure.
func (c *Coordinator) enterPropagation(gsid GlobalSID) bool {
	c.inflightMu.Lock()
	defer c.inflightMu.Unlock()
	if _, ok := c.inflight[gsid]; ok {
		return false
	}
	c.inflight[gsid] = struct{}{}
	return true
}

// exitPropagation clears gsid's in-flight marker (see enterPropagation).
func (c *Coordinator) exitPropagation(gsid GlobalSID) {
	c.inflightMu.Lock()
	delete(c.inflight, gsid)
	c.inflightMu.Unlock()
}

// Logout terminates every protocol leg linked to gsid:
//  1. destroys the core Session leg(s) via CoreSessionTerminator.Destroy;
//  2. triggers the OIDC Back-Channel Logout fan-out for the login's subject
//     (unconditional — every login on this server is, at minimum, an OIDC
//     login, and the fan-out is itself a no-op when the RP index isn't
//     wired or the subject has no other RPs);
//  3. triggers the SAML SLO fan-out for the subject, ONLY when a SAML leg
//     was recorded for THIS gsid ("where applicable") AND a trigger is
//     wired (SetSAMLTrigger).
//
// A gsid with no recorded legs (never linked, already logged out, or
// LRU-evicted) returns ErrUnknownGlobalSID — a clean, oracle-irrelevant
// signal since this is an internal orchestration API, not a public endpoint.
// Every per-leg failure is logged and does NOT stop the remaining legs from
// being attempted (fail-open, matching the composed mechanisms' own
// best-effort posture) — Logout only returns a non-nil error for a bad
// gsid, never a partial-failure aggregate.
func (c *Coordinator) Logout(ctx context.Context, gsid GlobalSID) error {
	if gsid == "" {
		return ErrEmptyGlobalSID
	}
	if !c.enterPropagation(gsid) {
		// gsid's fan-out is already in flight on THIS Coordinator — a
		// bounced-back re-trigger (see the inflight field's doc comment).
		// Safe no-op: the in-flight call owns completing the propagation;
		// recursing into the same fan-out again would either repeat it or,
		// if the bounce is synchronous, recurse without bound.
		c.logger.Info("sessionhub: Logout re-entered for an in-flight global_sid, ignoring", "global_sid", string(gsid))
		return ErrLogoutInProgress
	}
	defer c.exitPropagation(gsid)

	links, err := c.links.List(ctx, gsid)
	if err != nil {
		return err
	}
	if len(links) == 0 {
		return ErrUnknownGlobalSID
	}

	subject, coreSID, sawSAML := c.terminateLegs(ctx, links)

	if c.oidc != nil && subject != "" {
		c.oidc.TriggerBackchannelLogout(ctx, subject, coreSID)
	}
	if saml := c.samlTrigger(); saml != nil && sawSAML && subject != "" {
		saml.Fanout(ctx, subject, "")
	}

	if err := c.links.DeleteAll(ctx, gsid); err != nil {
		c.logger.Error("sessionhub: cleanup link records failed", "error", err, "global_sid", string(gsid))
	}
	return nil
}

// terminateLegs destroys every ProtocolCore leg found in links and reports
// back what Logout needs to drive the subject-keyed OIDC/SAML fan-outs: the
// subject (denormalized identically onto every record for one gsid), the
// core session id (used as the OIDC logout_token's sid claim), and whether a
// SAML leg was present at all.
func (c *Coordinator) terminateLegs(ctx context.Context, links []LinkRecord) (subject, coreSID string, sawSAML bool) {
	for _, l := range links {
		if l.Subject != "" {
			subject = l.Subject
		}
		switch l.Protocol {
		case ProtocolCore:
			coreSID = l.ExternalRef
			if c.core != nil {
				if err := c.core.Destroy(ctx, l.ExternalRef); err != nil {
					c.logger.Error("sessionhub: destroy core session failed", "error", err, "session_id", l.ExternalRef)
				}
			}
		case ProtocolSAML:
			sawSAML = true
		}
	}
	return subject, coreSID, sawSAML
}
