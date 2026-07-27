// Package kafkaaudit publishes snaplink/sso audit events to a Kafka topic,
// as a SEPARATE nested Go module: every recorded [auditspi.Event] is
// produced as one Kafka message, letting an operator fan the audit stream
// into a SIEM/log-analytics pipeline (Splunk, Elastic, Datadog, a
// Kafka-Streams job) without adding a network hop through the audit.webhook
// HTTP sink.
//
// # Why a separate module
//
// The github.com/segmentio/kafka-go dependency (and its transitive
// compression codecs) lives ONLY in this module's go.mod
// (github.com/snaplink/sso/kafka). The core sso module's go.mod stays
// byte-free of it — the same firm zero-external-SDK-in-core invariant that
// isolates kms/awskms (aws-sdk-go-v2), ldap (go-ldap), and saml
// (crewjam/saml). segmentio/kafka-go is pure Go (no cgo, matching this
// SDK's "no CGO" bias — see AGENTS.md system overview) so the module builds
// and races-tests in CI with the default toolchain, no C compiler needed
// (unlike kms/pkcs11).
//
// # How it reaches the server
//
// A separate module's package CANNOT import cmd's package main, so this
// module references no cmd type. It exposes an importable constructor
// (New) returning a *Sink that implements the root platform/audit
// auditspi.Sink interface, PLUS a ready-made [Factory] function matching the
// AuditKafkaSinkFactory signature the composition registry expects — unlike
// the KMS/LDAP integration points (which need per-vendor operator glue
// because vendor credentials aren't representable in the core config
// schema), every Kafka connection parameter this Sink needs already has a
// home in config.AuditKafkaConfig, so Factory is a complete, drop-in
// registration.
//
// # Cold-profile wiring
//
// Build the supported profile from the root repository:
//
//	python cli.py configure --profile standard-kafka --build
//
// The generated cold-profile registrar imports this module and explicitly
// registers [Factory] before configuration is loaded. It uses neither a
// blank import nor init-time side effects. With that profile,
// audit.kafka.enabled plus audit.kafka.{brokers,topic} in config.yaml (see
// docs/config-reference.md) is all an operator needs. Leaving
// audit.kafka.enabled true in the ordinary standard binary fails boot CLOSED,
// so a missing compiled module is found at startup rather than through
// silently dropped audit events.
//
// # Wire format
//
// Format defaults to a JSON envelope carrying an explicit "schema_version"
// field (see FormatJSON) — unlike the audit.webhook HTTP sink (whose
// receiver can content-negotiate), a Kafka consumer has no per-message
// negotiation, so the version travels IN the payload. Format may instead
// select one of the SDK's existing SIEM formatters — "cef" | "ocsf" |
// "syslog" (platform/audit/auditsink) — the exact same pure
// Event-to-bytes encoders the CEF/OCSF/syslog file sinks use, reused
// UNCHANGED over this transport (see auditsink.Formatter's doc comment).
//
// # Delivery semantics
//
// RequiredAcks defaults to "all" (full ISR acknowledgement) — audit events
// are a compliance record, so this Sink favors durability over latency,
// the opposite of kafka-go's own library default ("none"). Record is
// synchronous by default (cfg.Async=false): the call blocks until the
// broker acks, so Record's error return is a real signal for the audit
// Recorder's fail-open policy / ErrorHandler. Pair with audit.async
// (platform/audit AsyncSink) to move that wait off the request hot path
// rather than flipping cfg.Async, which drops WriteMessages's error
// entirely (see kafka-go's Writer.Async doc).
package kafkaaudit
