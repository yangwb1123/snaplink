package main

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/config"
	configreload "github.com/yangwb1123/snaplink/config/reload"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestWireWebhookReloadReplacesGenerationAndPreservesStores(t *testing.T) {
	recorder := audit.New(audit.NewMemorySink(32))
	runtime, err := serverbuildauthn.BuildManagedWebhookRuntime(
		config.WebhooksConfig{Enabled: true}, recorder, spi.NopLogger{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(context.Background()) }()
	if _, err := runtime.Subscriptions().Create(context.Background(), webhookSubscriptionForTest()); err != nil {
		t.Fatal(err)
	}
	srv := sso.NewServer(sso.WithAuditRecorder(recorder), sso.WithWebhookRuntime(runtime))
	initial := &config.Config{Webhooks: config.WebhooksConfig{Enabled: true}}
	next := &config.Config{Webhooks: config.WebhooksConfig{
		Enabled: true, DeliveryTimeout: 2 * time.Second,
	}}
	reloader := configreload.New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	wireWebhookReload(reloader, srv)
	result, err := reloader.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) != 1 || result.Applied[0] != "webhooks: delivery policy generation replaced" {
		t.Fatalf("reload result = %+v", result)
	}
	if got := runtime.Status()[0].Generation; got != 2 {
		t.Fatalf("generation = %d, want 2", got)
	}
	if list, err := runtime.Subscriptions().List(context.Background()); err != nil || len(list) != 1 {
		t.Fatalf("subscriptions after reload = %d, err=%v", len(list), err)
	}
}

func webhookSubscriptionForTest() webhook.EventSubscription {
	return webhook.EventSubscription{
		URL: "https://receiver.example.test/events", EventTypes: []audit.EventType{audit.EventLogin}, Secret: "secret",
	}
}
