package sse

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit/auditsink"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// TestSink_RecordPublishesRedactedSummary proves the sink never forwards
// anything beyond the documented Summary whitelist — in particular, that
// raw fields the audit Event carries (metadata, actor IP, user agent,
// session/token ids, request/trace ids, hash-chain fields) never reach a
// subscriber even when the recorded Event is populated with all of them.
func TestSink_RecordPublishesRedactedSummary(t *testing.T) {
	b := NewBroker(Options{})
	sub, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	sink := NewSink(b)
	ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	e := &auditspi.Event{
		ID:            "evt-1",
		Type:          auditspi.EventLogin,
		Outcome:       auditspi.OutcomeSuccess,
		Timestamp:     ts,
		RequestID:     "req-secret",
		TraceID:       "trace-secret",
		SpanID:        "span-secret",
		ActorID:       "user-1",
		ActorIP:       "203.0.113.9",
		UserAgent:     "Mozilla/5.0 fingerprint",
		ClientID:      "client-1",
		TenantID:      "acme",
		SessionID:     "sess-secret",
		TokenID:       "tok-secret",
		Reason:        "target=client-1",
		Metadata:      map[string]string{"raw_password": "hunter2"},
		PrevHash:      "prevhash",
		Hash:          "hash",
		ServerVersion: "1.2.3",
	}
	if err := sink.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}

	ev, ok := drain(t, sub, time.Second)
	if !ok {
		t.Fatal("subscriber channel closed unexpectedly")
	}
	if ev.Type != string(auditspi.EventLogin) || ev.TenantID != "acme" {
		t.Fatalf("broker Event routing fields wrong: %+v", ev)
	}

	var raw map[string]any
	if err := json.Unmarshal(ev.Data, &raw); err != nil {
		t.Fatalf("unmarshal published data: %v", err)
	}
	forbidden := []string{
		"request_id", "trace_id", "span_id", "parent_span_id",
		"actor_ip", "user_agent", "session_id", "token_id",
		"metadata", "prev_hash", "hash", "server_version",
	}
	for _, key := range forbidden {
		if _, present := raw[key]; present {
			t.Errorf("published summary leaked field %q: %v", key, raw)
		}
	}

	var sum Summary
	if err := json.Unmarshal(ev.Data, &sum); err != nil {
		t.Fatalf("unmarshal into Summary: %v", err)
	}
	if sum.ID != "evt-1" || sum.Type != string(auditspi.EventLogin) ||
		sum.Outcome != string(auditspi.OutcomeSuccess) || sum.ActorID != "user-1" ||
		sum.TenantID != "acme" || sum.ClientID != "client-1" || sum.Resource != "target=client-1" ||
		!sum.Timestamp.Equal(ts) {
		t.Fatalf("summary fields mismatch: %+v", sum)
	}
}

func TestSink_QueryAndGetAreWriteOnly(t *testing.T) {
	sink := NewSink(NewBroker(Options{}))
	if _, err := sink.Query(context.Background(), auditspi.Query{}); !errors.Is(err, auditsink.ErrSinkWriteOnly) {
		t.Errorf("Query error = %v, want ErrSinkWriteOnly", err)
	}
	if _, err := sink.Get(context.Background(), "evt-1"); !errors.Is(err, auditsink.ErrSinkWriteOnly) {
		t.Errorf("Get error = %v, want ErrSinkWriteOnly", err)
	}
}
