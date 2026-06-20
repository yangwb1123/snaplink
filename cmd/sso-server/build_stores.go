package main

import (
	"log/slog"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"
)

// buildApp is pure server-assembly wiring: it reads config and constructs the
// Server with every WithXxx option, store, subsystem, and background worker.
// The work is delegated to ordered wireXxx sub-builders on appBuilder (defined
// across build_app*.go), grouped into three phases (foundation -> domains ->
// edge) whose Option-application order is identical to the original monolith
// (option order can decide which security feature wins), as is every
// conditional, error-wrap, defer/cleanup, and background-worker handoff.
func buildApp(cfg *config.Config, logger spi.Logger) (builtApp *app, retErr error) {
	b := &appBuilder{cfg: cfg, logger: logger}
	if err := b.wireFoundation(); err != nil {
		return nil, err
	}
	// If buildApp fails downstream, stop the classifier's watch loop so its
	// goroutine + context don't leak; on success the app owns netCancel and
	// calls it at shutdown. Registered here (after wireFoundation populates
	// netCancel, before the later phases) so the LIFO cleanup fires for any
	// later error, exactly as the original defer did.
	if b.netCancel != nil {
		defer func() {
			if retErr != nil {
				b.netCancel()
			}
		}()
	}
	if err := b.wireDomains(); err != nil {
		return nil, err
	}
	if err := b.wireEdge(); err != nil {
		return nil, err
	}
	return b.finalize()
}

// wireFoundation runs the kernel sub-builders (identity/signing, audit,
// permissions, network) that the later phases depend on. wireNetwork populates
// b.netCancel, so buildApp registers the on-failure cancel defer immediately
// after this phase returns.
func (b *appBuilder) wireFoundation() error {
	if err := b.wireIdentitySigning(); err != nil {
		return err
	}
	if err := b.wireAudit(); err != nil {
		return err
	}
	if err := b.wirePermissions(); err != nil {
		return err
	}
	return b.wireNetwork()
}

// wireDomains runs the business-domain sub-builders, in the same order the
// original monolith applied their Options.
func (b *appBuilder) wireDomains() error {
	if err := b.wireSelfServicePassword(); err != nil {
		return err
	}
	if err := b.wireGeoRegionRisk(); err != nil {
		return err
	}
	if err := b.wireWebAuthnMFA(); err != nil {
		return err
	}
	if err := b.wireAnomaly(); err != nil {
		return err
	}
	if err := b.wireTenant(); err != nil {
		return err
	}
	if err := b.wireConnectionsAndCache(); err != nil {
		return err
	}
	if err := b.wireDPoP(); err != nil {
		return err
	}
	return b.wireOAuthGrantStores()
}

// wireEdge runs the delivery-edge sub-builders (response encryption, DCR/
// backchannel, CAEP transmitter, federation, profiles/metadata, metrics, body/
// rate-limit, JTI-replay/SPIFFE, CAEP receiver/mesh, mTLS/lockout/proxies/CORS),
// in the original Option-application order. wireCAEPTransmitter and
// wireMetricsCollector return no error and keep their original positions.
func (b *appBuilder) wireEdge() error {
	if err := b.wireResponseEncryption(); err != nil {
		return err
	}
	if err := b.wireDCRBackchannel(); err != nil {
		return err
	}
	b.wireCAEPTransmitter()
	if err := b.wireFederation(); err != nil {
		return err
	}
	if err := b.wireProfilesAndMetadata(); err != nil {
		return err
	}
	b.wireMetricsCollector()
	if err := b.wireBodyAndRateLimit(); err != nil {
		return err
	}
	if err := b.wireJTIReplaySPIFFE(); err != nil {
		return err
	}
	if err := b.wireCAEPReceiverMesh(); err != nil {
		return err
	}
	return b.wireMTLSLockoutProxiesCORS()
}

// --- helpers ---

// slogLogger adapts log/slog to the spi.Logger interface so the SDK can hand
// off to whatever sink the operator wants (stdout, journald, file...).
type slogLogger struct{ inner *slog.Logger }
