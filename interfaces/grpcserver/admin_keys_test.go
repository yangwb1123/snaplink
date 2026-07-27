package grpcserver_test

import (
	"context"
	"net"
	"testing"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startKeyAdminGRPC stands up a bufconn KeyAdminService over the supplied config.
func startKeyAdminGRPC(t *testing.T, cfg grpcserver.KeyAdminConfig) adminv1.KeyAdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterKeyAdminServiceServer(srv, grpcserver.NewKeyAdminService(cfg))
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); srv.Stop(); _ = lis.Close() })
	return adminv1.NewKeyAdminServiceClient(conn)
}

// rotateSeam builds a rotate closure over a real Ed25519 issuer that mirrors the
// cmd orchestration: promote a fresh key, then arrange the grace-delayed local
// retire. Returned issuer is shared so the test can watch its verify-set.
func rotateSeam(iss *defaultimpl.Ed25519JWTIssuer) func(context.Context, time.Duration) (string, string, error) {
	return func(_ context.Context, grace time.Duration) (string, string, error) {
		old := iss.KeyID()
		nw, err := iss.RotateNow()
		if err != nil {
			return old, "", err
		}
		iss.ScheduleRetire(old, grace)
		return old, nw, nil
	}
}

func jwksHas(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer, kid string) bool {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// TestKeyAdmin_Rotate_OverlapAndAudit proves the RPC rotates the primary issuer,
// returns distinct kids, records the admin audit event, and (short default
// grace) keeps the old kid verify-only during the window then drops it after.
func TestKeyAdmin_Rotate_OverlapAndAudit(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	c := startKeyAdminGRPC(t, grpcserver.KeyAdminConfig{
		Rotate:       rotateSeam(iss),
		DefaultGrace: 40 * time.Millisecond, // short so the retire fires within the test
		Issuers:      map[string]sso.TokenIssuer{"jwt": iss},
		Recorder:     rec,
	})
	ctx := context.Background()

	// A token minted before rotation, to prove the overlap window.
	oldTok, err := iss.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	resp, err := c.RotateSigningKey(ctx, &adminv1.RotateSigningKeyRequest{})
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	if resp.OldKid == "" || resp.NewKid == "" || resp.OldKid == resp.NewKid {
		t.Fatalf("rotate returned bad kids: %+v", resp)
	}
	if iss.KeyID() != resp.NewKid {
		t.Errorf("active kid = %q, want new %q", iss.KeyID(), resp.NewKid)
	}
	// During the grace window: old token still verifies, both kids in JWKS.
	if _, err := iss.Validate(ctx, oldTok.AccessToken); err != nil {
		t.Errorf("old token should verify during grace: %v", err)
	}
	if !jwksHas(t, iss, resp.OldKid) {
		t.Error("old kid dropped before grace elapsed")
	}
	// Audit event recorded (admin-namespaced, actor-attributed).
	assertAuditRecorded(t, sink, audit.EventAdminSigningKeyRotated)

	// After grace: the old kid is retired from JWKS.
	deadline := time.Now().Add(2 * time.Second)
	for jwksHas(t, iss, resp.OldKid) {
		if time.Now().After(deadline) {
			t.Fatal("old kid never retired after grace")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The new kid still validates a freshly-minted token.
	newTok, _ := iss.Issue(ctx, &sso.Subject{ID: "u", ClientID: "c"}, nil)
	if _, err := iss.Validate(ctx, newTok.AccessToken); err != nil {
		t.Errorf("new token should validate: %v", err)
	}
}

func TestKeyAdmin_Rotate_GraceTooSmall(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	c := startKeyAdminGRPC(t, grpcserver.KeyAdminConfig{Rotate: rotateSeam(iss), DefaultGrace: time.Hour})
	_, err := c.RotateSigningKey(context.Background(), &adminv1.RotateSigningKeyRequest{GraceSeconds: 30})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("grace<60 want InvalidArgument, got %v", err)
	}
}

func TestKeyAdmin_Rotate_ExternalSignerFailedPrecondition(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer()
	// External signer: even though a rotate closure exists, the guard wins.
	c := startKeyAdminGRPC(t, grpcserver.KeyAdminConfig{
		Rotate:          rotateSeam(iss),
		ExternalManaged: true,
		Issuers:         map[string]sso.TokenIssuer{"jwt": iss},
	})
	_, err := c.RotateSigningKey(context.Background(), &adminv1.RotateSigningKeyRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("external signer want FailedPrecondition, got %v", err)
	}
}

func TestKeyAdmin_Rotate_NoSeamUnimplemented(t *testing.T) {
	t.Parallel()
	// Custom issuer without runtime-rotation support: no rotate closure wired.
	c := startKeyAdminGRPC(t, grpcserver.KeyAdminConfig{})
	_, err := c.RotateSigningKey(context.Background(), &adminv1.RotateSigningKeyRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("no seam want Unimplemented, got %v", err)
	}
}

// TestKeyAdmin_List_AcrossIssuers proves ListSigningKeys enumerates every wired
// JWKSProvider issuer, marks exactly the active kid, and returns only public
// metadata (kid/alg/state) — never private material.
func TestKeyAdmin_List_AcrossIssuers(t *testing.T) {
	t.Parallel()
	issA := defaultimpl.NewEd25519JWTIssuer()
	issB := defaultimpl.NewECDSAJWTIssuer()
	// Demote a key on A so it publishes an active + a verify-only kid.
	demoted := issA.KeyID()
	activeA, _ := issA.RotateNow()

	c := startKeyAdminGRPC(t, grpcserver.KeyAdminConfig{
		Issuers: map[string]sso.TokenIssuer{"a": issA, "b": issB},
	})
	resp, err := c.ListSigningKeys(context.Background(), &adminv1.ListSigningKeysRequest{})
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	states := make(map[string]string, len(resp.Keys))
	for _, k := range resp.Keys {
		states[k.Kid] = k.State
		if k.Alg == "" {
			t.Errorf("kid %q missing alg", k.Kid)
		}
	}
	if states[activeA] != "active" {
		t.Errorf("A active kid %q state = %q, want active", activeA, states[activeA])
	}
	if states[demoted] != "verify_only" {
		t.Errorf("A demoted kid %q state = %q, want verify_only", demoted, states[demoted])
	}
	if states[issB.KeyID()] != "active" {
		t.Errorf("B active kid state = %q, want active", states[issB.KeyID()])
	}
}

func assertAuditRecorded(t *testing.T, sink *audit.MemorySink, want audit.EventType) {
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
	t.Fatalf("audit event %q not recorded (have %d events)", want, len(evts))
}
