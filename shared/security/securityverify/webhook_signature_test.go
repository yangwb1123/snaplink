package securityverify

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignature_RoundTripTamperExpiry(t *testing.T) {
	t.Parallel()
	secret, body := []byte("s3cret"), []byte(`{"a":1}`)
	now := time.Unix(1760000000, 0)
	hdr := SignWebhookPayload(secret, now, body)
	if !strings.HasPrefix(hdr, "t=1760000000,v1=") {
		t.Fatalf("header shape: %q", hdr)
	}
	if err := VerifyWebhookSignature(secret, hdr, body, now.Add(2*time.Minute), DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("fresh verify: %v", err)
	}
	if err := VerifyWebhookSignature(secret, hdr, append(body, 'x'), now, DefaultWebhookSignatureTolerance); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Fatalf("tampered body: %v, want ErrWebhookSignatureMismatch", err)
	}
	if err := VerifyWebhookSignature(secret, hdr, body, now.Add(10*time.Minute), DefaultWebhookSignatureTolerance); !errors.Is(err, ErrWebhookSignatureExpired) {
		t.Fatalf("stale: %v, want ErrWebhookSignatureExpired", err)
	}
	if err := VerifyWebhookSignature(secret, "garbage", body, now, 0); !errors.Is(err, ErrWebhookSignatureMalformed) {
		t.Fatalf("malformed: %v, want ErrWebhookSignatureMalformed", err)
	}
	if err := VerifyWebhookSignature([]byte("wrong"), hdr, body, now, 0); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Fatalf("wrong secret: %v, want ErrWebhookSignatureMismatch", err)
	}
}
