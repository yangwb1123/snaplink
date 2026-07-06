package kafkaaudit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"github.com/snaplink/sso/platform/audit/auditsink"
	"github.com/snaplink/sso/platform/audit/auditspi"
)

// fakeProducer is an in-process stand-in for *kafka.Writer — no real broker,
// no mocking framework, mirroring infrastructure/ldap's fakeDirectory and
// infrastructure/kms's fakeKMS. It records every published message so tests
// can assert on topic/value without a network round-trip.
type fakeProducer struct {
	mu       sync.Mutex
	messages []kafkago.Message
	closed   bool
	writeErr error
	closeErr error
	// closeDelay lets a test exercise Sink.Close's ctx-deadline path.
	closeDelay time.Duration
}

func (f *fakeProducer) WriteMessages(_ context.Context, msgs ...kafkago.Message) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, msgs...)
	return nil
}

func (f *fakeProducer) Close() error {
	if f.closeDelay > 0 {
		time.Sleep(f.closeDelay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func (f *fakeProducer) snapshot() []kafkago.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]kafkago.Message(nil), f.messages...)
}

func TestSink_RecordPublishesOneMessagePerEvent(t *testing.T) {
	t.Parallel()
	fp := &fakeProducer{}
	s := newWithProducer(fp, "audit-events")

	e := &auditspi.Event{Type: auditspi.EventLogin, ActorID: "u1", Outcome: auditspi.OutcomeSuccess}
	if err := s.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	msgs := fp.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	if msgs[0].Topic != "audit-events" {
		t.Fatalf("topic = %q, want audit-events", msgs[0].Topic)
	}
	// No trailing newline — the transport is message-framed, unlike a
	// shared file/stdout target (producerWriter trims WriterSink's
	// uniform '\n').
	if n := len(msgs[0].Value); n > 0 && msgs[0].Value[n-1] == '\n' {
		t.Fatal("kafka message value must not carry WriterSink's trailing newline")
	}
}

func TestSink_DefaultFormatIsJSONWithSchemaVersion(t *testing.T) {
	t.Parallel()
	fp := &fakeProducer{}
	s := newWithProducer(fp, "audit-events")

	if err := s.Record(context.Background(), &auditspi.Event{Type: auditspi.EventLogin, ActorID: "u1"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(fp.snapshot()[0].Value, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := got["schema_version"].(float64); !ok || int(v) != schemaVersion {
		t.Fatalf("schema_version = %v, want %d", got["schema_version"], schemaVersion)
	}
	if got["type"] != string(auditspi.EventLogin) {
		t.Fatalf("type = %v, want %s", got["type"], auditspi.EventLogin)
	}
	if got["actor_id"] != "u1" {
		t.Fatalf("actor_id = %v, want u1", got["actor_id"])
	}
}

func TestSink_WithFormatOverridesToCEF(t *testing.T) {
	t.Parallel()
	fp := &fakeProducer{}
	s := newWithProducer(fp, "audit-events", WithFormat(auditsink.FormatCEF("Vendor", "Product", "1.0")))

	if err := s.Record(context.Background(), &auditspi.Event{Type: auditspi.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	val := string(fp.snapshot()[0].Value)
	if val[:5] != "CEF:0" {
		t.Fatalf("value = %q, want CEF:0 header", val)
	}
}

func TestSink_RecordPropagatesProducerError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("broker unreachable")
	fp := &fakeProducer{writeErr: wantErr}
	s := newWithProducer(fp, "audit-events")

	err := s.Record(context.Background(), &auditspi.Event{Type: auditspi.EventLogin})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Record err = %v, want %v", err, wantErr)
	}
}

func TestSink_GetAndQueryAreWriteOnly(t *testing.T) {
	t.Parallel()
	s := newWithProducer(&fakeProducer{}, "audit-events")

	if _, err := s.Get(context.Background(), "any"); !errors.Is(err, auditsink.ErrSinkWriteOnly) {
		t.Fatalf("Get err = %v, want ErrSinkWriteOnly", err)
	}
	if _, err := s.Query(context.Background(), auditspi.Query{}); !errors.Is(err, auditsink.ErrSinkWriteOnly) {
		t.Fatalf("Query err = %v, want ErrSinkWriteOnly", err)
	}
}

func TestSink_CloseClosesProducer(t *testing.T) {
	t.Parallel()
	fp := &fakeProducer{}
	s := newWithProducer(fp, "audit-events")

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fp.mu.Lock()
	closed := fp.closed
	fp.mu.Unlock()
	if !closed {
		t.Fatal("producer.Close was not called")
	}
}

func TestSink_CloseRespectsContextDeadline(t *testing.T) {
	t.Parallel()
	fp := &fakeProducer{closeDelay: 200 * time.Millisecond}
	s := newWithProducer(fp, "audit-events")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); err == nil {
		t.Fatal("expected deadline-exceeded error, got nil")
	}
}

func TestNew_RequiresBrokersAndTopic(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{Topic: "t"}); err == nil {
		t.Fatal("expected error when brokers is empty")
	}
	if _, err := New(Config{Brokers: []string{"localhost:9092"}}); err == nil {
		t.Fatal("expected error when topic is empty")
	}
}

func TestNew_RejectsInvalidRequiredAcks(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Brokers: []string{"localhost:9092"}, Topic: "t", RequiredAcks: "bogus"})
	if err == nil {
		t.Fatal("expected error for invalid required_acks")
	}
}

func TestNew_BuildsRealSinkWithoutDialing(t *testing.T) {
	t.Parallel()
	// New must not perform any network I/O — constructing a *kafka.Writer
	// is lazy (it dials lazily on the first WriteMessages call), so this
	// must succeed even though localhost:9 refuses connections.
	s, err := New(Config{Brokers: []string{"127.0.0.1:9"}, Topic: "t", RequiredAcks: "one"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil sink")
	}
}

func TestParseRequiredAcks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want kafkago.RequiredAcks
	}{
		{"", kafkago.RequireAll},
		{"all", kafkago.RequireAll},
		{"ALL", kafkago.RequireAll},
		{"one", kafkago.RequireOne},
		{"none", kafkago.RequireNone},
	}
	for _, c := range cases {
		got, err := parseRequiredAcks(c.in)
		if err != nil {
			t.Fatalf("parseRequiredAcks(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseRequiredAcks(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
