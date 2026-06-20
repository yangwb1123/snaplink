package main

import (
	"log/slog"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"
)

// buildApp is pure server-assembly wiring: it reads config and constructs the
// Server with every WithXxx option, store, subsystem, and background worker.
// The work is delegated to ordered wireXxx sub-builders on appBuilder (defined
// across build_app*.go); the Option-application order across them is identical
// to the original monolith (option order can decide which security feature
// wins), as is every conditional, error-wrap, defer/cleanup, and
// background-worker handoff.
func buildApp(cfg *config.Config, logger spi.Logger) (builtApp *app, retErr error) {
	b := &appBuilder{cfg: cfg, logger: logger}
	if err := b.wireIdentitySigning(); err != nil {
		return nil, err
	}
	if err := b.wireAudit(); err != nil {
		return nil, err
	}
	if err := b.wirePermissions(); err != nil {
		return nil, err
	}
	if err := b.wireNetwork(); err != nil {
		return nil, err
	}
	// If buildApp fails downstream, stop the classifier's watch loop so its
	// goroutine + context don't leak; on success the app owns netCancel and
	// calls it at shutdown. Registered here (buildApp scope) so the LIFO
	// cleanup fires for any later error, exactly as the original defer did.
	if b.netCancel != nil {
		defer func() {
			if retErr != nil {
				b.netCancel()
			}
		}()
	}
	if err := b.wireSelfServicePassword(); err != nil {
		return nil, err
	}
	if err := b.wireGeoRegionRisk(); err != nil {
		return nil, err
	}
	if err := b.wireWebAuthnMFA(); err != nil {
		return nil, err
	}
	if err := b.wireAnomaly(); err != nil {
		return nil, err
	}
	if err := b.wireTenant(); err != nil {
		return nil, err
	}
	if err := b.wireConnectionsAndCache(); err != nil {
		return nil, err
	}
	if err := b.wireDPoP(); err != nil {
		return nil, err
	}
	if err := b.wireOAuthGrantStores(); err != nil {
		return nil, err
	}
	if err := b.wireResponseEncryption(); err != nil {
		return nil, err
	}
	if err := b.wireDCRBackchannel(); err != nil {
		return nil, err
	}
	b.wireCAEPTransmitter()
	if err := b.wireFederation(); err != nil {
		return nil, err
	}
	if err := b.wireProfilesAndMetadata(); err != nil {
		return nil, err
	}
	b.wireMetricsCollector()
	if err := b.wireBodyAndRateLimit(); err != nil {
		return nil, err
	}
	if err := b.wireJTIReplaySPIFFE(); err != nil {
		return nil, err
	}
	if err := b.wireCAEPReceiverMesh(); err != nil {
		return nil, err
	}
	if err := b.wireMTLSLockoutProxiesCORS(); err != nil {
		return nil, err
	}
	return b.finalize()
}

// --- helpers ---

// slogLogger adapts log/slog to the spi.Logger interface so the SDK can hand
// off to whatever sink the operator wants (stdout, journald, file...).
type slogLogger struct{ inner *slog.Logger }
