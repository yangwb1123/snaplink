package caep_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/core"
)

// fakeMQTTPublisher is a real, hand-rolled test double (not a mock
// framework) satisfying caep.MQTTPublisher — the same "recording stub"
// shape as setReceiver for the HTTPS channel (transmitter_test.go).
type fakeMQTTPublisher struct {
	mu        sync.Mutex
	published []fakeMQTTPublish
	failErr   error
}

type fakeMQTTPublish struct {
	topic   string
	payload string
}

func (f *fakeMQTTPublisher) Publish(_ context.Context, topic string, payload []byte) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, fakeMQTTPublish{topic: topic, payload: string(payload)})
	return nil
}

func (f *fakeMQTTPublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published)
}

func (f *fakeMQTTPublisher) snapshot() []fakeMQTTPublish {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMQTTPublish(nil), f.published...)
}

func TestTransmitter_MQTTChannel_DeliversSignedSET(t *testing.T) {
	t.Parallel()
	pub := &fakeMQTTPublisher{}
	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "mqtt-rp", Active: true,
		Attributes: map[string]string{caep.AttrReceiverMQTTTopic: "caep/receivers/mqtt-rp/events"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	tx := caep.NewTransmitter(iss, store, caep.WithIssuer("https://idp.test"), caep.WithMQTTPublisher(pub))
	_ = tx.Record(ctx, tenantTokensRevokedForClient("mqtt-rp"))

	waitFor(t, func() bool { return pub.count() == 1 }, "MQTT receiver gets a published SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	got := pub.snapshot()[0]
	if got.topic != "caep/receivers/mqtt-rp/events" {
		t.Errorf("topic = %q, want caep/receivers/mqtt-rp/events", got.topic)
	}
	v := verifySET(t, got.payload, iss.PublicKey())
	if len(v.aud) != 1 || v.aud[0] != "mqtt-rp" {
		t.Errorf("aud = %v, want [mqtt-rp]", v.aud)
	}
}

func TestTransmitter_MQTTChannel_NoPublisherWired_TopicIgnored(t *testing.T) {
	t.Parallel()
	// AttrReceiverMQTTTopic set but WithMQTTPublisher never wired, and no
	// HTTPS endpoint either -- the client has NO usable receiver, so
	// Record must not panic or hang; it just has nowhere to deliver.
	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "mqtt-only-no-publisher", Active: true,
		Attributes: map[string]string{caep.AttrReceiverMQTTTopic: "caep/receivers/x/events"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	tx := caep.NewTransmitter(iss, store, caep.WithIssuer("https://idp.test"))
	_ = tx.Record(ctx, tenantTokensRevokedForClient("mqtt-only-no-publisher"))
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Nothing to assert beyond "did not panic/hang" -- there is no
	// receiver to check delivery against.
}

func TestTransmitter_MQTTChannel_PublishFailure_RecordsBroadcastFailedAudit(t *testing.T) {
	t.Parallel()
	pub := &fakeMQTTPublisher{failErr: errors.New("broker unreachable")}
	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "mqtt-rp-down", Active: true,
		Attributes: map[string]string{caep.AttrReceiverMQTTTopic: "caep/receivers/mqtt-rp-down/events"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)
	tx := caep.NewTransmitter(iss, store,
		caep.WithIssuer("https://idp.test"),
		caep.WithMQTTPublisher(pub),
		caep.WithFailureRecorder(rec))
	_ = tx.Record(ctx, tenantTokensRevokedForClient("mqtt-rp-down"))

	waitFor(t, func() bool {
		evs, _ := sink.Query(ctx, audit.Query{})
		for _, e := range evs {
			if e.Type == caep.EventCAEPBroadcastFailed {
				return true
			}
		}
		return false
	}, "a caep_broadcast_failed audit event is recorded")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if pub.count() != 0 {
		t.Errorf("published count = %d, want 0 (publish always failed)", pub.count())
	}

	evs, _ := sink.Query(ctx, audit.Query{})
	for _, e := range evs {
		if e.Type == caep.EventCAEPBroadcastFailed {
			if e.ClientID != "mqtt-rp-down" {
				t.Errorf("failure audit ClientID = %q, want mqtt-rp-down", e.ClientID)
			}
			if got := e.Metadata["receiver"]; got != "mqtt:caep/receivers/mqtt-rp-down/events" {
				t.Errorf("failure audit receiver metadata = %q, want mqtt:caep/receivers/mqtt-rp-down/events", got)
			}
		}
	}
}

// tenantTokensRevokedForClient builds a client-scoped mapped event
// (admin_token_revoked, the same event kind TestTransmitter_
// AdminTokenRevoked_DeliversToAffectedClient uses) targeting clientID.
func tenantTokensRevokedForClient(clientID string) *audit.Event {
	e := &audit.Event{Type: audit.EventAdminTokenRevoked, Outcome: audit.OutcomeSuccess, ClientID: "some-admin-console"}
	audit.SetMeta(e, caep.MetaAffectedClient, clientID)
	return e
}
