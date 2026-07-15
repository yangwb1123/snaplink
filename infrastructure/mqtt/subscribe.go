package mqttbus

import (
	"context"
	"fmt"

	"github.com/eclipse/paho.golang/paho"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// subscribeChannelBuffer matches etcd.go's and the memory peer's buffer
// size — generous enough that a burst of Events doesn't trip the
// slow-consumer drop under ordinary load.
const subscribeChannelBuffer = 16

// Subscribe opens ONE persistent-session connection (cfg.ClientID,
// CleanStart=false) and subscribes to Config.Prefix at Config.QoS. The
// returned channel closes when ctx is cancelled OR the underlying MQTT
// session is lost — see doc.go's "Reconnection" section for why this Bus
// deliberately does not retry internally; the caller (typically
// interfaces/sso's runInvalidationBus) owns backoff + resubscribe.
func (b *Bus) Subscribe(ctx context.Context) (<-chan cluster.Event, error) {
	_, span := tracing.StartSpan(ctx, "cluster.bus.subscribe")
	defer span.End()
	span.SetAttributes(attribute.String("cluster.bus.backend", "mqtt"))

	if b.isClosed() {
		tracing.SetError(span, ErrClosed)
		return nil, ErrClosed
	}

	out := make(chan cluster.Event, subscribeChannelBuffer)
	client, err := b.subscribeClient(ctx, out)
	if err != nil {
		tracing.SetError(span, err)
		return nil, err
	}

	go func() {
		defer close(out)
		defer func() { _ = client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()
		select {
		case <-ctx.Done():
		case <-client.Done():
			// Underlying session lost (transport error, server-initiated
			// disconnect, or a clean Disconnect racing this select) —
			// either way, closing `out` here is what lets the generic
			// self-heal wrapper (runInvalidationBus) notice and retry.
		}
	}()
	return out, nil
}

// subscribeClient dials the persistent-session connection, wiring the
// inbound-message handler IN THE CONNECT CALL (via dialConnect's
// onPublishReceived parameter) rather than registering it afterward, then
// issues the MQTT SUBSCRIBE — but ONLY when the broker did not already
// report an existing session (Session Present). Split out of Subscribe for
// the function-length budget.
//
// The handler must be bound before dialConnect returns — see dialConnect's
// doc for why registering it after Connect (e.g. via a post-hoc
// client.AddOnPublishReceived call) would race a resumed session's
// immediately-flushed, queued QoS-1 messages and silently, permanently
// lose them (auto-acked with zero handlers bound).
//
// Skipping the re-SUBSCRIBE on a resumed session (see dialConnect's doc on
// its returned bool) is not just an optimization: reissuing it right as the
// broker is flushing that same session's queued backlog has been observed,
// against a real broker, to fail the SUBSCRIBE outright (a PacketID
// collision with the broker's own in-flight redelivery bookkeeping) —
// which would disconnect and discard the connection, losing the very
// message this persistent session exists to redeliver.
func (b *Bus) subscribeClient(ctx context.Context, out chan<- cluster.Event) (*paho.Client, error) {
	onPublish := func(pr paho.PublishReceived) (bool, error) {
		evt, ok := decodeEvent(pr.Packet.Payload)
		if !ok {
			return true, nil
		}
		select {
		case out <- evt:
		default:
			// Slow consumer — drop rather than block paho's internal read
			// loop (which also services PINGRESP/acks): the invalidation
			// bus's TTL fallback is the safety net, exactly as the memory
			// peer's own documented drop behavior (platform/cluster/memory/bus.go).
		}
		return true, nil
	}
	client, sessionPresent, err := dialConnect(ctx, b.cfg, b.cfg.ClientID, false, onPublish)
	if err != nil {
		return nil, err
	}
	if sessionPresent {
		return client, nil
	}

	if _, err := client.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: b.cfg.Prefix, QoS: *b.cfg.QoS}},
	}); err != nil {
		_ = client.Disconnect(&paho.Disconnect{ReasonCode: 0})
		return nil, fmt.Errorf("mqttbus: subscribe: %w", err)
	}
	return client, nil
}
