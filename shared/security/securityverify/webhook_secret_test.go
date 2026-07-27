package securityverify

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

func TestRotatingWebhookSecret_GeneratesWhenNoInitial(t *testing.T) {
	t.Parallel()
	rws, err := NewRotatingWebhookSecret(nil)
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	if len(rws.Current()) != WebhookSecretBytes {
		t.Fatalf("generated secret length = %d, want %d", len(rws.Current()), WebhookSecretBytes)
	}
	meta := rws.Meta()
	if meta.Version != 1 || meta.Type != corecredential.CredentialTypeWebhookHMAC || meta.Status != corecredential.CredentialStatusActive {
		t.Fatalf("initial Meta() = %+v", meta)
	}
}

func TestRotatingWebhookSecret_SeedsFromInitial(t *testing.T) {
	t.Parallel()
	initial := []byte("operator-supplied-static-secret!")
	rws, err := NewRotatingWebhookSecret(initial)
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	if !bytes.Equal(rws.Current(), initial) {
		t.Fatalf("Current() = %x, want the supplied initial secret", rws.Current())
	}
}

// TestRotatingWebhookSecret_OverlapWindowDualAccept is the core rotation
// contract this credential class exists to prove: during the overlap window
// a receiver's Verify accepts EITHER the just-demoted secret or the new one
// (in-flight/redelivered signatures from before the rotation still
// authenticate), and once the window closes only the new secret works.
func TestRotatingWebhookSecret_OverlapWindowDualAccept(t *testing.T) {
	t.Parallel()
	initial := []byte("initial-secret-before-rotation!!")
	rws, err := NewRotatingWebhookSecret(initial)
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	body := []byte(`{"event":"payment.succeeded"}`)
	now := time.Unix(1_700_000_000, 0)
	hdrOld := SignWebhookPayload(initial, now, body)

	overlap := 10 * time.Minute
	rotateAt := now.Add(time.Hour)
	meta, err := rws.Rotate(rotateAt, overlap)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("post-rotate Meta.Version = %d, want 2", meta.Version)
	}
	newSecret := rws.Current()
	if bytes.Equal(newSecret, initial) {
		t.Fatal("Rotate did not change the current secret")
	}
	hdrNew := SignWebhookPayload(newSecret, rotateAt, body)

	// tolerance=0 disables the SIGNATURE timestamp-freshness check so this
	// test isolates the OVERLAP-WINDOW behavior from that unrelated check.
	insideWindow := rotateAt.Add(overlap - time.Minute)
	if err := rws.Verify(hdrOld, body, insideWindow, 0); err != nil {
		t.Fatalf("old secret inside the overlap window: %v, want accepted", err)
	}
	if err := rws.Verify(hdrNew, body, insideWindow, 0); err != nil {
		t.Fatalf("new secret inside the overlap window: %v, want accepted", err)
	}

	afterWindow := rotateAt.Add(overlap + time.Minute)
	if err := rws.Verify(hdrOld, body, afterWindow, 0); err == nil {
		t.Fatal("old secret after the overlap window closed: want rejected, got accepted")
	}
	if err := rws.Verify(hdrNew, body, afterWindow, 0); err != nil {
		t.Fatalf("new secret after the overlap window closed: %v, want accepted", err)
	}
}

// TestRotatingWebhookSecret_ZeroOverlapDropsImmediately proves overlap<=0
// drops the demoted secret right away (no grace window at all).
func TestRotatingWebhookSecret_ZeroOverlapDropsImmediately(t *testing.T) {
	t.Parallel()
	initial := []byte("initial-secret-zero-overlap-case")
	rws, err := NewRotatingWebhookSecret(initial)
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	body := []byte(`{}`)
	now := time.Unix(1_700_000_000, 0)
	hdrOld := SignWebhookPayload(initial, now, body)

	if _, err := rws.Rotate(now, 0); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := rws.Verify(hdrOld, body, now, 0); err == nil {
		t.Fatal("old secret with overlap<=0: want rejected immediately, got accepted")
	}
}

// TestRotatingWebhookSecret_VerifyUnseededIsNoActiveCredential covers the
// "wiring mistake" guard: a never-seeded holder must fail closed rather than
// accept everything (an empty secret would make hmac.Equal meaningless).
func TestRotatingWebhookSecret_VerifyUnseededIsNoActiveCredential(t *testing.T) {
	t.Parallel()
	var empty RotatingWebhookSecret
	err := empty.Verify("t=1700000000,v1=00", []byte("x"), time.Unix(1_700_000_000, 0), 0)
	if !errors.Is(err, corecredential.ErrNoActiveCredential) {
		t.Fatalf("Verify on unseeded holder = %v, want ErrNoActiveCredential", err)
	}
}

func TestWebhookSecretRotator_ConformsToCredentialRotator(t *testing.T) {
	t.Parallel()
	rws, err := NewRotatingWebhookSecret(nil)
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	rotator := NewWebhookSecretRotator(rws, 5*time.Minute)

	if rotator.Type() != corecredential.CredentialTypeWebhookHMAC {
		t.Fatalf("Type() = %q", rotator.Type())
	}
	if rotator.OverlapWindow() != 5*time.Minute {
		t.Fatalf("OverlapWindow() = %v, want 5m", rotator.OverlapWindow())
	}
	seed := rotator.CurrentMeta()
	if seed.Version != 1 {
		t.Fatalf("CurrentMeta() before any Rotate = %+v, want version 1", seed)
	}

	meta, err := rotator.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("Rotate() meta.Version = %d, want 2", meta.Version)
	}
	if got := rotator.CurrentMeta().Version; got != 2 {
		t.Fatalf("CurrentMeta() after Rotate = version %d, want 2 (must reflect the live installed secret)", got)
	}
}
