package audit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/snaplink/sso/audit"
)

func TestRedactor_ActorIDHashWithSalt(t *testing.T) {
	r := audit.RedactActorIDHash("secret-salt")
	e := &audit.Event{ActorID: "alice@example.com"}
	r.Redact(e)
	if e.ActorID == "alice@example.com" {
		t.Fatal("ActorID was not transformed")
	}
	if !strings.HasPrefix(e.ActorID, "h:") {
		t.Errorf("expected leading 'h:' prefix, got %q", e.ActorID)
	}
	// Same input + salt = same output (deterministic — required
	// for SIEM pivot-on-pseudonym workflows).
	e2 := &audit.Event{ActorID: "alice@example.com"}
	r.Redact(e2)
	if e.ActorID != e2.ActorID {
		t.Errorf("hash not deterministic: %q vs %q", e.ActorID, e2.ActorID)
	}
}

func TestRedactor_ActorIDHashDifferentSalts(t *testing.T) {
	a := audit.RedactActorIDHash("salt-a")
	b := audit.RedactActorIDHash("salt-b")
	e1 := &audit.Event{ActorID: "alice"}
	e2 := &audit.Event{ActorID: "alice"}
	a.Redact(e1)
	b.Redact(e2)
	if e1.ActorID == e2.ActorID {
		t.Errorf("different salts must produce different hashes: %q", e1.ActorID)
	}
}

func TestRedactor_ActorIDHashEmptyActorIDPassthrough(t *testing.T) {
	r := audit.RedactActorIDHash("salt")
	e := &audit.Event{} // empty ActorID
	r.Redact(e)
	if e.ActorID != "" {
		t.Errorf("empty ActorID must stay empty, got %q", e.ActorID)
	}
}

func TestRedactor_IPTruncateIPv4(t *testing.T) {
	r := audit.RedactIPTruncate()
	cases := []struct {
		in, want string
	}{
		{"192.168.1.42", "192.168.1.0/24"},
		{"10.0.0.255", "10.0.0.0/24"},
		{"203.0.113.5", "203.0.113.0/24"},
	}
	for _, c := range cases {
		e := &audit.Event{ActorIP: c.in}
		r.Redact(e)
		if e.ActorIP != c.want {
			t.Errorf("ActorIP %q → %q want %q", c.in, e.ActorIP, c.want)
		}
	}
}

func TestRedactor_IPTruncateIPv6(t *testing.T) {
	r := audit.RedactIPTruncate()
	e := &audit.Event{ActorIP: "2001:db8:abcd:1234::1"}
	r.Redact(e)
	// /48 preserves only the first 3 hextets.
	if !strings.HasSuffix(e.ActorIP, "/48") {
		t.Errorf("IPv6 not truncated to /48: %q", e.ActorIP)
	}
	if !strings.HasPrefix(e.ActorIP, "2001:db8:abcd:") {
		t.Errorf("first 3 hextets should be preserved: %q", e.ActorIP)
	}
}

func TestRedactor_IPTruncatePassesThroughInvalid(t *testing.T) {
	r := audit.RedactIPTruncate()
	e := &audit.Event{ActorIP: "not-an-ip"}
	r.Redact(e)
	if e.ActorIP != "not-an-ip" {
		t.Errorf("invalid IP should pass through unchanged: %q", e.ActorIP)
	}
}

func TestRedactor_UserAgentCleared(t *testing.T) {
	r := audit.RedactUserAgent()
	e := &audit.Event{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."}
	r.Redact(e)
	if e.UserAgent != "" {
		t.Errorf("UserAgent not cleared: %q", e.UserAgent)
	}
}

func TestRedactor_MetadataKeysDeleted(t *testing.T) {
	r := audit.RedactMetadataKeys("email", "phone")
	e := &audit.Event{
		Metadata: map[string]string{
			"email":         "a@b.com",
			"phone":         "+15551234567",
			"geo.country":   "US",
			"keep_this_key": "kept",
		},
	}
	r.Redact(e)
	if _, ok := e.Metadata["email"]; ok {
		t.Errorf("email should be removed")
	}
	if _, ok := e.Metadata["phone"]; ok {
		t.Errorf("phone should be removed")
	}
	if e.Metadata["geo.country"] != "US" {
		t.Errorf("non-listed keys must survive")
	}
	if e.Metadata["keep_this_key"] != "kept" {
		t.Errorf("non-listed keys must survive")
	}
}

func TestRedactor_MetadataKeyPrefixesDeleted(t *testing.T) {
	r := audit.RedactMetadataKeyPrefixes("pii.", "internal.")
	e := &audit.Event{
		Metadata: map[string]string{
			"pii.email":      "x",
			"pii.phone":      "y",
			"internal.token": "z",
			"geo.country":    "US",
		},
	}
	r.Redact(e)
	for _, k := range []string{"pii.email", "pii.phone", "internal.token"} {
		if _, ok := e.Metadata[k]; ok {
			t.Errorf("%s should be removed by prefix match", k)
		}
	}
	if e.Metadata["geo.country"] != "US" {
		t.Errorf("non-prefixed key must survive: %v", e.Metadata)
	}
}

func TestRedactor_ComposeRunsAllInOrder(t *testing.T) {
	a := audit.RedactorFunc(func(e *audit.Event) { e.ActorID = "a" })
	b := audit.RedactorFunc(func(e *audit.Event) { e.ActorID += "b" })
	c := audit.RedactorFunc(func(e *audit.Event) { e.ActorID += "c" })
	r := audit.Compose(a, b, c)
	e := &audit.Event{ActorID: "original"}
	r.Redact(e)
	if e.ActorID != "abc" {
		t.Errorf("ActorID = %q want %q (in-order composition)", e.ActorID, "abc")
	}
}

func TestRedactor_ComposeEmptyIsNoop(t *testing.T) {
	r := audit.Compose()
	e := &audit.Event{ActorID: "alice"}
	r.Redact(e)
	if e.ActorID != "alice" {
		t.Errorf("empty Compose must be no-op, got %q", e.ActorID)
	}
}

func TestRedactor_DefaultPIIRedactor(t *testing.T) {
	r := audit.DefaultPIIRedactor("salt")
	e := &audit.Event{
		ActorID:   "alice@example.com",
		ActorIP:   "192.168.1.42",
		UserAgent: "Mozilla/5.0",
	}
	r.Redact(e)
	if !strings.HasPrefix(e.ActorID, "h:") {
		t.Errorf("ActorID not hashed: %q", e.ActorID)
	}
	if e.ActorIP != "192.168.1.0/24" {
		t.Errorf("ActorIP not truncated: %q", e.ActorIP)
	}
	if e.UserAgent != "" {
		t.Errorf("UserAgent not cleared: %q", e.UserAgent)
	}
}

// Recorder wire-up: redaction runs BEFORE the sink AND BEFORE
// the hash chainer, so a downstream verifier of the chain sees
// the redacted form.

func TestRecorder_WithRedactor_AppliesBeforeSink(t *testing.T) {
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink, audit.WithRedactor(audit.RedactActorIDHash("salt")))

	rec.Record(context.Background(), &audit.Event{
		Type:    audit.EventLogin,
		ActorID: "alice",
	})
	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ActorID == "alice" {
		t.Errorf("ActorID arrived at sink un-redacted: %q", events[0].ActorID)
	}
	if !strings.HasPrefix(events[0].ActorID, "h:") {
		t.Errorf("expected hashed ActorID at sink, got %q", events[0].ActorID)
	}
}

func TestRecorder_RedactorRunsBeforeHashChain(t *testing.T) {
	sink := audit.NewMemorySink(10)
	rec := audit.New(
		sink,
		audit.WithRedactor(audit.RedactActorIDHash("salt")),
		audit.WithHashChain(),
	)
	rec.Record(context.Background(), &audit.Event{
		Type:    audit.EventLogin,
		ActorID: "alice",
	})
	rec.Record(context.Background(), &audit.Event{
		Type:    audit.EventLogout,
		ActorID: "alice",
	})

	events, _ := sink.Query(context.Background(), audit.Query{})
	// Sink returns newest-first; reverse for chain verification.
	rev := make([]*audit.Event, len(events))
	for i := range events {
		rev[i] = events[len(events)-1-i]
	}
	if err := audit.VerifyChain(rev); err != nil {
		t.Fatalf("chain validation failed over redacted events: %v", err)
	}
	for _, e := range events {
		if e.ActorID == "alice" {
			t.Errorf("expected hashed ActorID in chain-stamped event, got %q", e.ActorID)
		}
	}
}
