package serverbuildauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestBuildManagedWebhookRuntimeAuditsGenerationTransitions(t *testing.T) {
	sink := audit.NewMemorySink(32)
	recorder := audit.New(sink)
	runtime, err := BuildManagedWebhookRuntime(config.WebhooksConfig{Enabled: true}, recorder, spi.NopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(context.Background()) }()

	updated := config.WebhooksConfig{Enabled: true, DeliveryTimeout: time.Second}
	if err := runtime.Activate(context.Background(), mustJSON(t, updated)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, queryErr := sink.Query(context.Background(), audit.Query{Type: audit.EventWebhookLifecycleTransition})
		if queryErr == nil && len(events) > 0 {
			for _, event := range events {
				if event.Metadata["generation"] == "2" {
					return
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	allEvents, _ := sink.Query(context.Background(), audit.Query{})
	summaries := make([]string, 0, len(allEvents))
	for _, event := range allEvents {
		summaries = append(summaries, fmt.Sprintf("type=%q reason=%q metadata=%v", event.Type, event.Reason, event.Metadata))
	}
	t.Fatalf("transition audit event not observed; events=%v status=%+v observer=%+v", summaries, runtime.Status(), runtime.ObserverStatus())
}

func TestBuildManagedWebhookRuntimeRequiresEnabledPolicy(t *testing.T) {
	if _, err := BuildManagedWebhookRuntime(config.WebhooksConfig{}, nil, spi.NopLogger{}); err == nil {
		t.Fatal("disabled policy unexpectedly built a managed runtime")
	}
}

func mustJSON(t *testing.T, value config.WebhooksConfig) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
