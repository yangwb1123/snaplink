package mqttbus

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eclipse/paho.golang/paho"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// Publish opens a one-shot connection (see Bus's doc for why Publish
// never reuses Subscribe's persistent ClientID), publishes evt at
// Config.QoS with retain=false, and disconnects. A real network round
// trip every call, same as etcd.go's Publish (Grant+Put) — Publish is
// not this Bus's hot path (see platform/cluster/bus.go's doc: triggered
// by admin mutations, not per-request traffic).
func (b *Bus) Publish(ctx context.Context, evt cluster.Event) error {
	ctx, span := tracing.StartSpan(ctx, "cluster.bus.publish")
	defer span.End()
	span.SetAttributes(
		attribute.String("cluster.bus.backend", "mqtt"),
		attribute.String("cluster.bus.kind", string(evt.Kind)),
	)

	if b.isClosed() {
		tracing.SetError(span, ErrClosed)
		return ErrClosed
	}

	body, err := json.Marshal(evt)
	if err != nil {
		err = fmt.Errorf("mqttbus: marshal event: %w", err)
		tracing.SetError(span, err)
		return err
	}

	clientID := b.cfg.ClientID + "-pub-" + randomSuffix()
	client, _, err := dialConnect(ctx, b.cfg, clientID, true, nil)
	if err != nil {
		tracing.SetError(span, err)
		return err
	}
	defer func() { _ = client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()

	if _, err := client.Publish(ctx, &paho.Publish{
		Topic:   b.cfg.Prefix,
		QoS:     *b.cfg.QoS,
		Retain:  false,
		Payload: body,
	}); err != nil {
		err = fmt.Errorf("mqttbus: publish: %w", err)
		tracing.SetError(span, err)
		return err
	}
	return nil
}
