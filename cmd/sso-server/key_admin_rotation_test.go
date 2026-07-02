package main

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	clustermemory "github.com/snaplink/sso/platform/cluster/memory"
	"github.com/snaplink/sso/platform/metrics"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestBuildKeyAdminService_RuntimeRotateReusesHook is the end-to-end cmd proof
// that the on-demand admin rotate path produces the SAME side effects as the
// scheduled loop: it drives the injected closure through makeRotateHook and
// observes (1) the coordinated-cutover broadcast on the cluster bus, (2) the
// scheduler's EventSigningKeyRotated (from the shared hook), AND (3) the
// admin-namespaced EventAdminSigningKeyRotated (from the RPC). Reusing
// makeRotateHook — not forking it — is what makes on-demand == scheduled.
func TestBuildKeyAdminService_RuntimeRotateReusesHook(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
		sso.WithInvalidationBus(bus),
		sso.WithCoordinatedKeyRotation(),
	)
	sink := audit.NewMemorySink(10)
	b := &appBuilder{
		cfg:             &config.Config{},
		logger:          quietLogger(),
		recorder:        audit.New(sink),
		metricsRegistry: metrics.New(),
		jwtIssuer:       iss,
		tokenIssuers:    map[string]sso.TokenIssuer{"jwt": iss},
	}

	ka := b.buildKeyAdminService(srv)
	oldKID := iss.KeyID()
	resp, err := ka.RotateSigningKey(ctx, &adminv1.RotateSigningKeyRequest{GraceSeconds: 90})
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	if resp.OldKid != oldKID || resp.NewKid == "" || resp.NewKid == oldKID {
		t.Fatalf("bad kids: old=%q new=%q (pre-rotate active=%q)", resp.OldKid, resp.NewKid, oldKID)
	}

	// (1) The coordinated-cutover broadcast rode the bus (hook → PublishSigningKeyRotation).
	// The hook also busts the discovery cache, which publishes its own event first,
	// so scan until the rotation event arrives (its presence proves the hook ran).
	deadline := time.After(2 * time.Second)
	for {
		select {
		case evt := <-events:
			if evt.Kind != cluster.KindSigningKeyRotation {
				continue
			}
			if evt.Payload[cluster.MetaOldKid] != resp.OldKid || evt.Payload[cluster.MetaNewKid] != resp.NewKid {
				t.Fatalf("broadcast kids mismatch: %+v", evt.Payload)
			}
		case <-deadline:
			t.Fatal("no coordinated-rotation broadcast observed on the bus")
		}
		break
	}

	// (2)+(3) Both the shared-hook event and the admin-namespaced event recorded.
	assertCmdAudit(t, sink, audit.EventSigningKeyRotated)
	assertCmdAudit(t, sink, audit.EventAdminSigningKeyRotated)
}

// TestBuildKeyAdminService_ExternalSignerRefused proves the KMS/HSM guard: with
// keys.signing.external set, the RPC refuses (FailedPrecondition) rather than
// mint a key the backend never sees — even though the issuer itself is rotatable.
func TestBuildKeyAdminService_ExternalSignerRefused(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	cfg := &config.Config{}
	cfg.Keys.Signing.External = "awskms"
	b := &appBuilder{
		cfg:          cfg,
		logger:       quietLogger(),
		jwtIssuer:    iss,
		tokenIssuers: map[string]sso.TokenIssuer{"jwt": iss},
	}
	ka := b.buildKeyAdminService(sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
	))
	if _, err := ka.RotateSigningKey(context.Background(), &adminv1.RotateSigningKeyRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("external signer want FailedPrecondition, got %v", err)
	}
}

func assertCmdAudit(t *testing.T, sink *audit.MemorySink, want audit.EventType) {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	for _, e := range evts {
		if e.Type == want {
			return
		}
	}
	t.Fatalf("audit event %q not recorded", want)
}
