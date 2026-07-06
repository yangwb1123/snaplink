// Package mqttbus implements [cluster.Bus] against an MQTT v5 broker, as a
// SEPARATE nested Go module — the cross-replica coordination bus's answer
// to a fleet that already runs an MQTT broker (IoT/edge gateways, an
// existing EMQX/HiveMQ deployment) instead of etcd.
//
// # Why a separate module
//
// The github.com/eclipse/paho.golang dependency lives ONLY in this
// module's go.mod (github.com/snaplink/sso/mqtt). The core sso module's
// go.mod stays byte-free of it — the same firm zero-external-SDK-in-core
// invariant that isolates kms/awskms, ldap, saml, and kafka (see those
// packages' own doc.go). paho.golang is pure Go (no cgo), so this module
// builds and races-tests in CI with the default toolchain.
//
// # How it reaches the server (fork-only wiring, no config-driven factory)
//
// Unlike infrastructure/kafka's audit sink — whose every connection
// parameter already has a home in config.AuditKafkaConfig, making a
// drop-in Factory registration possible — cluster.Bus has no
// config-driven backend-selection point beyond "memory" and "etcd"
// (cmd/sso-server/serverbuildplatform.BuildInvalidationBus hardcodes that
// two-way switch, and go.etcd.io/etcd/client/v3 is — unusually — a ROOT
// module dependency, unlike every other external-broker integration).
// Adding a config.yaml-driven "mqtt" backend selection would need a new
// core-side extension point (a RegisterClusterBusFactory hook mirroring
// kafkaaudit's Factory pattern) — deliberately NOT done here, since it is
// its own separate, small follow-up touching core files, orthogonal to
// "does an MQTT Bus implementation exist and work." Until that follow-up
// lands, an operator wires this Bus the same way any fork constructs a
// custom cluster.Bus today:
//
//	package main
//
//	import (
//		"github.com/snaplink/sso/interfaces/sso"
//		mqttbus "github.com/snaplink/sso/mqtt"
//	)
//
//	func buildBus() (*mqttbus.Bus, error) {
//		return mqttbus.New(mqttbus.Config{
//			BrokerAddr: "mqtt-broker.internal:1883",
//			ClientID:   "sso-replica-" + os.Getenv("HOSTNAME"),
//		})
//	}
//
//	// ... then: opts = append(opts, sso.WithInvalidationBus(bus))
//
// # Wire format
//
// A single flat topic under Config.Prefix (default
// "snaplink/cluster/bus/events") carries every cluster.EventKind — there is
// no per-kind topic tree. cluster.Bus.Subscribe has no concept of partial
// (kind-filtered) subscription, so a wildcard topic tree would only add
// complexity without buying any functional capability; kind-dispatch stays
// entirely in the JSON payload + the subscriber-side switch
// (interfaces/sso/server_invalidation.go's applyInvalidation), exactly as
// it already works for the etcd and memory peers.
//
// # Delivery semantics
//
//   - QoS 1 (at-least-once) for both publish and subscribe. QoS 0 risks
//     silently losing exactly the Events this Bus exists to deliver; QoS 2
//     buys deduplication this Bus doesn't need — every EventKind's apply
//     arm is documented as idempotent/additive/fail-safe (see
//     platform/cluster/bus.go), so a QoS-1 duplicate delivery is a
//     documented no-op.
//   - retain=false always. A retained message would hand a late-joining
//     subscriber exactly one stale historical Event, contradicting the
//     cross-backend expectation (etcd's own doc: "a subscriber never
//     replays Events published before it joined").
//   - A persistent session per Bus instance (MQTT v5 CleanStart=false +
//     a stable ClientID + Config.SessionExpiryInterval) — STRICTLY BETTER
//     than etcd's own guarantee: a brief disconnect shorter than
//     SessionExpiryInterval lets the broker queue QoS-1 messages published
//     during the gap and deliver them on reconnect, where etcd's watch
//     never replays anything published during a gap at all. Do not assume
//     behavioral parity with the etcd/memory peers on this point — it is a
//     genuine (documented) improvement, not a bug.
//
// # Reconnection: deliberately NOT handled inside this Bus
//
// paho.golang's low-level Client does its own dialing/session management
// but does not itself retry a lost connection — by design, matching this
// package's choice to keep ALL retry/backoff/degraded-readiness/audit
// logic in the ONE place the rest of this codebase already trusts for it:
// interfaces/sso/server_invalidation.go's runInvalidationBus (a generic
// wrapper around ANY cluster.Bus, already mirrored by
// platform/netpolicy/classifier_selfheal.go and the signing-key
// aggregation loop). Subscribe's returned channel closes the instant the
// underlying MQTT session is lost while ctx is still live — mirroring
// etcd.go's contract exactly — so the SAME generic self-heal wrapper
// (backoff, "invalidation_bus_degraded" audit event, /readyz gate) keeps
// working unmodified for this backend. This Bus intentionally does NOT
// use paho's autopaho auto-reconnect wrapper: autopaho's automatic
// reconnect resubscribes silently at the SESSION level but (on a
// paho.golang client without careful handling) can leave a connection
// "transport-healthy but broker-deaf" — connected, yet with no live
// subscription — which would be WORSE than etcd's original watch-death
// bug because it would never even trip the degraded flag. Subscribe here
// takes the simpler, safer path: one connect+subscribe attempt per call,
// no silent retry, so a dropped subscription is ALWAYS visible as a
// closed channel.
package mqttbus
