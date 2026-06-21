package serverbuildstore

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/webauthn"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
)

// BuildMFA materializes the MFA orchestration triple: provider, store,
// per-challenge TTL. Returns (nil, nil, 0, "", nil) when MFA is
// disabled so cmd skips WithMFAProvider / WithMFAChallengeStore entirely
// — RequireMFA then decays to Allow (back-compat).
//
// totpAuth is the *authenticators.TOTPAuthenticator instance built in
// serverbuildauthn.BuildAuthenticators; webauthnHelper is the *webauthn.Helper built
// earlier in the assembly path. Passing the same instances here means
// each factor's secret/credential store + policy is single-source
// between primary auth and MFA step-up — one enrollment, two
// consumer roles.
//
// The returned mode string is a short backend identifier emitted in
// the startup log + suitable for /readyz wiring suffixes.
func BuildMFA(cfg config.MFAConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger spi.Logger) (spi.MFAProvider, spi.MFAChallengeStore, time.Duration, string, *sqlitestores.PushApprovalStore, func(string), error) {
	if !cfg.Enabled {
		return nil, nil, 0, "", nil, nil, nil
	}

	// Provider: "totp" and "webauthn" carry YAML toggles. "multi"
	// composes several leaf kinds via MultiMFAProvider. Other factors
	// (push, IdP redirect, hardware OTP) ship in the SDK and embedders
	// wire them via WithMFAProvider directly, so this switch
	// intentionally stays narrow.
	kind := strings.ToLower(strings.TrimSpace(cfg.Provider.Kind))
	if kind == "" {
		kind = "totp"
	}
	capture := &pushStoreCapture{}
	provider, err := buildMFAProviderByKind(kind, cfg.Provider.Kinds, cfg.Provider.Push, totpAuth, webauthnHelper, logger, capture)
	if err != nil {
		return nil, nil, 0, "", nil, nil, err
	}

	store, storeKind, err := buildMFAChallengeStore(cfg.Challenge)
	if err != nil {
		return nil, nil, 0, "", nil, nil, err
	}

	logger.Info("mfa orchestration enabled",
		"provider", kind,
		"methods", provider.SupportedMethods(),
		"store", storeKind,
		"ttl", cfg.Challenge.TTL)

	return provider, store, cfg.Challenge.TTL, storeKind, capture.store, capture.notify, nil
}

// buildMFAProviderByKind constructs the MFA provider tree for the
// requested kind. Recursive for kind=multi (one level only — nested
// multi is rejected to keep the operator surface flat). Leaf kinds
// (totp, webauthn, push) fail loud when their underlying
// dependency is nil / misconfigured.
//
// outerKinds is the cfg.Provider.Kinds slice — used only when
// kind=multi to list the inner leaf kinds. Empty or single-entry
// Kinds when kind=multi → error (a multi with zero or one inner
// provider is a misconfiguration; use the leaf kind directly).
// pushStoreCapture is buildMFAProviderByKind's side-channel for
// surfacing push-factor handles through the recursive multi-build.
// cmd's BuildMFA inspects store to register a /readyz check + launch
// the PruneExpired loop, and notify to wire the channel-notify wakeup
// into the reference approval callback. Both stay nil for
// memory-backed push, absent push, or (notify) channel_notify=false.
type pushStoreCapture struct {
	store  *sqlitestores.PushApprovalStore
	notify func(approvalID string)
}

func buildMFAProviderByKind(kind string, outerKinds []string, pushCfg config.MFAPushConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger spi.Logger, capture *pushStoreCapture) (spi.MFAProvider, error) {
	switch kind {
	case "totp":
		if totpAuth == nil {
			return nil, errors.New("mfa.provider.kind=totp requires authenticators.totp.enabled=true")
		}
		return authenticators.NewTOTPMFAProvider(totpAuth), nil
	case "webauthn":
		if webauthnHelper == nil {
			return nil, errors.New("mfa.provider.kind=webauthn requires webauthn.enabled=true")
		}
		p, err := webauthn.NewWebAuthnMFAProvider(webauthnHelper)
		if err != nil {
			return nil, fmt.Errorf("mfa.provider.kind=webauthn: %w", err)
		}
		return p, nil
	case "push":
		return buildPushMFAProviderWithCapture(pushCfg, logger, capture)
	case "multi":
		return buildMultiMFAProvider(outerKinds, pushCfg, totpAuth, webauthnHelper, logger, capture)
	default:
		return nil, fmt.Errorf("unknown mfa.provider.kind %q (supported: totp, webauthn, push, multi)", kind)
	}
}

// buildPushMFAProviderWithCapture builds the push factor and surfaces its
// store + (opt-in) channel-notify handle through capture for the caller's
// /readyz wiring + reference approval callback.
func buildPushMFAProviderWithCapture(pushCfg config.MFAPushConfig, logger spi.Logger, capture *pushStoreCapture) (spi.MFAProvider, error) {
	provider, sqliteStore, err := buildPushMFAProvider(pushCfg, logger)
	if err != nil {
		return nil, err
	}
	if capture != nil {
		capture.store = sqliteStore
		// Surface Notify only when channel-notify is opted in — the
		// reference callback then wakes a blocked Verify directly.
		// The concrete type is always *PushMFAProvider here (this
		// case constructs it); the assertion just narrows from the
		// spi.MFAProvider return.
		if pushCfg.ChannelNotify {
			if pp, ok := provider.(*defaultimpl.PushMFAProvider); ok {
				capture.notify = pp.Notify
			}
		}
	}
	return provider, nil
}

// buildMultiMFAProvider composes the leaf kinds named in mfa.provider.kinds
// into a MultiMFAProvider. Rejects fewer than two inner kinds, empty/duplicate
// entries, and nested multi.
func buildMultiMFAProvider(outerKinds []string, pushCfg config.MFAPushConfig, totpAuth *authenticators.TOTPAuthenticator, webauthnHelper *webauthn.Helper, logger spi.Logger, capture *pushStoreCapture) (spi.MFAProvider, error) {
	if len(outerKinds) < 2 {
		return nil, errors.New("mfa.provider.kind=multi requires at least two entries in mfa.provider.kinds")
	}
	seen := make(map[string]struct{}, len(outerKinds))
	innerProviders := make([]spi.MFAProvider, 0, len(outerKinds))
	for _, inner := range outerKinds {
		innerKind := strings.ToLower(strings.TrimSpace(inner))
		if innerKind == "" {
			return nil, errors.New("mfa.provider.kinds contains an empty entry")
		}
		if innerKind == "multi" {
			return nil, errors.New("mfa.provider.kinds cannot contain 'multi' (no nesting)")
		}
		if _, dup := seen[innerKind]; dup {
			return nil, fmt.Errorf("mfa.provider.kinds duplicate entry %q", innerKind)
		}
		seen[innerKind] = struct{}{}
		p, err := buildMFAProviderByKind(innerKind, nil, pushCfg, totpAuth, webauthnHelper, logger, capture)
		if err != nil {
			return nil, fmt.Errorf("mfa.provider.kinds[%s]: %w", innerKind, err)
		}
		innerProviders = append(innerProviders, p)
	}
	return defaultimpl.NewMultiMFAProvider(innerProviders...)
}

// buildPushMFAProvider wires the reference push MFA factor —
// PushApprovalStore backend + PushTransport selection + pollInterval
// + maxWait. Today the only ship-included transport is the
// log-only stub (mirrors the cmd SMS/email "stub" pattern); operators
// fork cmd to drop in FCM/APNs/webhook. The reference impl is
// useful for development + smoke-test deployments.
//
// Returns the provider plus the SQLite store handle (or nil if
// backend=memory). cmd uses the typed handle for /readyz wiring +
// the optional PruneExpired loop. Error path: nil/nil/<err> when
// backend / transport / SQLite validation fails — kind=push is a
// misconfig if any of those components are absent.
// BuildPushWebhookTransport validates the webhook config + returns
// the constructed transport. URL is required; everything else is
// optional + defaults apply. Operators wiring transport=webhook
// without a URL see a boot-time error rather than runtime delivery
// failures.
func BuildPushWebhookTransport(cfg config.MFAPushWebhookConfig) (defaultimpl.PushTransport, error) {
	if cfg.URL == "" {
		return nil, errors.New("mfa.provider.push.webhook.url required when transport=webhook")
	}
	opts := []defaultimpl.PushWebhookOption{}
	if cfg.BearerToken != "" {
		opts = append(opts, defaultimpl.WithPushWebhookBearerToken(cfg.BearerToken))
	}
	for k, v := range cfg.Headers {
		opts = append(opts, defaultimpl.WithPushWebhookHeader(k, v))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, defaultimpl.WithPushWebhookClient(&http.Client{Timeout: cfg.Timeout}))
	}
	if cfg.RetryMaxAttempts > 0 || cfg.RetryInitialBackoff > 0 || cfg.RetryMaxBackoff > 0 {
		opts = append(opts, defaultimpl.WithPushWebhookRetry(
			cfg.RetryMaxAttempts,
			cfg.RetryInitialBackoff,
			cfg.RetryMaxBackoff,
		))
	}
	return defaultimpl.NewHTTPWebhookPushTransport(cfg.URL, opts...)
}

func buildPushMFAProvider(cfg config.MFAPushConfig, logger spi.Logger) (spi.MFAProvider, *sqlitestores.PushApprovalStore, error) {
	store, sqliteStore, err := buildPushApprovalStore(cfg)
	if err != nil {
		return nil, nil, err
	}
	pushTransport, err := buildPushTransport(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	provider, err := defaultimpl.NewPushMFAProvider(store, pushTransport, pushMFAOptions(cfg)...)
	if err != nil {
		return nil, nil, err
	}
	return provider, sqliteStore, nil
}
