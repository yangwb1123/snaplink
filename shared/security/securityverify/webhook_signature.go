package securityverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// WebhookSignatureHeader carries the outbound webhook payload signature
// (Stripe/Svix style: "t=<unix>,v1=<hex hmac-sha256>").
const WebhookSignatureHeader = "X-Signature"

// DefaultWebhookSignatureTolerance bounds receiver-side clock skew plus
// retry/redelivery delay when checking the signed timestamp.
const DefaultWebhookSignatureTolerance = 5 * time.Minute

var (
	ErrWebhookSignatureMalformed = errors.New("webhook signature: malformed header")
	ErrWebhookSignatureMismatch  = errors.New("webhook signature: mismatch")
	ErrWebhookSignatureExpired   = errors.New("webhook signature: timestamp outside tolerance")
)

// SignWebhookPayload returns the WebhookSignatureHeader value for body:
// t=<unix>,v1=hex(hmac-sha256(secret, "<unix>." + body)). The timestamp is
// folded into the MAC so a captured signature cannot be replayed later.
func SignWebhookPayload(secret []byte, ts time.Time, body []byte) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	return "t=" + t + ",v1=" + webhookHMACHex(secret, t, body)
}

func webhookHMACHex(secret []byte, t string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(t))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature is the receiver-side check: recomputes the MAC over
// the received body and compares in constant time (hmac.Equal). tolerance <= 0
// skips the freshness check (the timestamp is still authenticated by the MAC).
func VerifyWebhookSignature(secret []byte, header string, body []byte, now time.Time, tolerance time.Duration) error {
	t, v1, err := parseWebhookSignature(header)
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(v1)
	if err != nil {
		return ErrWebhookSignatureMalformed
	}
	got, _ := hex.DecodeString(webhookHMACHex(secret, t, body))
	if !hmac.Equal(got, want) {
		return ErrWebhookSignatureMismatch
	}
	if tolerance > 0 {
		sec, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return ErrWebhookSignatureMalformed
		}
		if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
			return ErrWebhookSignatureExpired
		}
	}
	return nil
}

func parseWebhookSignature(header string) (t, v1 string, err error) {
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return "", "", ErrWebhookSignatureMalformed
		}
		switch k {
		case "t":
			t = v
		case "v1":
			v1 = v
		}
	}
	if t == "" || v1 == "" {
		return "", "", ErrWebhookSignatureMalformed
	}
	return t, v1, nil
}
