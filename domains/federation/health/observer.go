package health

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"time"

	"github.com/snaplink/sso/domains/federation"
)

// observingFetcher decorates a federation.EntityStatementFetcher, recording
// EVERY fetch attempt's outcome (success/failure) plus the peer's observed TLS
// leaf-certificate expiry into a ConnectionHealth store. It is a PURE
// OBSERVER: it never alters the wrapped fetcher's returned bytes or error, so
// trust-chain validation and its fail-closed semantics (AGENTS.md:
// "Trust-chain FAIL-CLOSED; anchor keys NEVER fetched") are completely
// unaffected — health tracking wraps the fetch path, it is never a new gate.
//
// The certificate is captured via net/http/httptrace on the SAME round trip
// the wrapped fetcher performs (httptrace.ClientTrace.TLSHandshakeDone fires
// for any TLS handshake the transport that Do()es the request completes,
// regardless of who constructed the *http.Client) — there is no supplementary
// network call, so this adds no new outbound request nor any new failure
// mode. A reused keep-alive connection performs no fresh handshake, so the
// trace simply does not fire that call; RecordSuccess's zero-value handling
// then preserves whatever expiry a past success last observed.
type observingFetcher struct {
	base   federation.EntityStatementFetcher
	health ConnectionHealth
	now    func() time.Time
}

var _ federation.EntityStatementFetcher = (*observingFetcher)(nil)

// NewObservingFetcher wraps base so every fetch's outcome and observed TLS
// certificate expiry is recorded into health. Returns base UNCHANGED when
// health or base is nil (default-off, byte-identical — AGENTS.md "OFF by
// default ... no-op if not configured"), so a caller may unconditionally wrap
// without an extra nil check at each call site.
func NewObservingFetcher(base federation.EntityStatementFetcher, health ConnectionHealth) federation.EntityStatementFetcher {
	if base == nil || health == nil {
		return base
	}
	return &observingFetcher{base: base, health: health, now: time.Now}
}

// FetchEntityConfiguration implements federation.EntityStatementFetcher.
// Keyed by entityID: the leaf/superior IS the peer being observed.
func (o *observingFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	return o.observe(ctx, entityID, func(tctx context.Context) ([]byte, error) {
		return o.base.FetchEntityConfiguration(tctx, entityID)
	})
}

// FetchSubordinateStatement implements federation.EntityStatementFetcher.
// Keyed by issuer (the federation PEER this fetch endpoint belongs to), not
// the endpoint URL — an operator recognizes a peer by its entity id, and a
// superior's federation_fetch_endpoint is an implementation detail of it.
func (o *observingFetcher) FetchSubordinateStatement(ctx context.Context, fetchEndpoint, issuer, subject string) ([]byte, error) {
	return o.observe(ctx, issuer, func(tctx context.Context) ([]byte, error) {
		return o.base.FetchSubordinateStatement(tctx, fetchEndpoint, issuer, subject)
	})
}

// observe runs do with an httptrace-instrumented context (capturing the
// peer's TLS leaf certificate, if any fresh handshake occurs) and records the
// outcome against peerID. The trace is READ-ONLY instrumentation — it cannot
// alter the request, so it changes nothing about the wrapped fetcher's own
// SSRF/scheme/redirect/size hardening or its returned result.
func (o *observingFetcher) observe(ctx context.Context, peerID string, do func(context.Context) ([]byte, error)) ([]byte, error) {
	var leaf *tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				captured := state
				leaf = &captured
			}
		},
	}
	body, err := do(httptrace.WithClientTrace(ctx, trace))
	now := o.now()
	if err != nil {
		o.health.RecordFailure(peerID, now, err.Error())
		return body, err
	}
	o.health.RecordSuccess(peerID, now, leafCertExpiry(leaf))
	return body, nil
}

// leafCertExpiry returns the peer's leaf certificate's NotAfter, or the zero
// Time when no handshake was observed (state nil — e.g. a reused connection,
// or a test fetcher that performs no real TLS) or the chain is empty. The
// LEAF (first certificate) is the peer's own cert; chain[1:] are
// intermediates, whose expiry is not what an operator renews.
func leafCertExpiry(state *tls.ConnectionState) time.Time {
	if state == nil || len(state.PeerCertificates) == 0 {
		return time.Time{}
	}
	return state.PeerCertificates[0].NotAfter
}
