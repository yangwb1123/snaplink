package kafkaaudit

import (
	"encoding/json"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// schemaVersion is the wire schema of the JSON envelope FormatJSON emits.
// Bump it — and keep the OLD number's shape documented here — on any
// breaking change, so a downstream Kafka consumer can branch on
// schema_version instead of guessing from field presence:
//
//	1: {"schema_version":1, ...auditspi.Event fields inlined at top level}
const schemaVersion = 1

// jsonEnvelope wraps auditspi.Event with an explicit schema_version.
// Unlike the audit.webhook HTTP sink (whose receiver can content-negotiate
// or version the endpoint URL), a Kafka consumer reads an undifferentiated
// byte stream with no per-message negotiation, so the version has to travel
// IN the payload. The embedded *auditspi.Event inlines its fields at the
// envelope's top level (Go's struct-embedding JSON behavior), so existing
// consumers written against the bare Event JSON only need to start
// tolerating one extra field, not a nested wrapper.
type jsonEnvelope struct {
	SchemaVersion int `json:"schema_version"`
	*auditspi.Event
}

// FormatJSON is the default Kafka wire formatter: the JSON encoding of
// jsonEnvelope. Exported so an operator composing their own WriterSink
// (bypassing New) can reuse it directly, and so Factory can select it by
// name from config.AuditKafkaConfig.Format.
func FormatJSON(e *auditspi.Event) ([]byte, error) {
	return json.Marshal(jsonEnvelope{SchemaVersion: schemaVersion, Event: e})
}
