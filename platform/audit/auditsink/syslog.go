package auditsink

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// syslogStructuredDataID is the SD-ID used for the one STRUCTURED-DATA
// element this formatter emits. It deliberately carries no enterprise-number
// suffix ("audit@<PEN>") — this is an internal-only element (not intended
// for cross-vendor SD-ID registration), and RFC 5424 permits a bare name for
// that case.
const syslogStructuredDataID = "audit"

// sdParamNameEscape sanitizes an SD-PARAM name: RFC 5424 excludes '=', SP,
// ']', and '"' from PARAM-NAME outright (they are not merely escapable, as
// they are in PARAM-VALUE), so a pathological Metadata key is replaced
// rather than escaped.
func sdParamNameEscape(k string) string {
	return strings.NewReplacer("=", "_", " ", "_", "]", "_", `"`, "_").Replace(k)
}

// sdParamValueEscape escapes an SD-PARAM value per RFC 5424 section 6.3.3:
// '"', '\', and ']' are backslash-escaped.
func sdParamValueEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

// syslogStructuredData renders meta as one SD-ELEMENT, one SD-PARAM per
// entry (sorted by key for deterministic output), or the RFC 5424 NILVALUE
// "-" when meta is empty. Per the SIEM-formats decision, structured-data
// carries ONLY Event.Metadata — identity fields (actor, tenant, ids, ...)
// live in MSG via the wrapped inner Formatter instead of being duplicated
// here.
func syslogStructuredData(meta map[string]string) string {
	if len(meta) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(syslogStructuredDataID)
	for _, k := range keys {
		b.WriteString(" ")
		b.WriteString(sdParamNameEscape(k))
		b.WriteString(`="`)
		b.WriteString(sdParamValueEscape(meta[k]))
		b.WriteString(`"`)
	}
	b.WriteString("]")
	return b.String()
}

// syslogMsgID uses the event type as RFC 5424's MSGID (identifies "the type
// of message") — a natural fit, and lets a receiver filter/route on MSGID
// without parsing MSG. Truncated to the RFC's 32-character MSGID limit
// (no current EventType is anywhere near that long); "-" (NILVALUE) when t
// is empty.
func syslogMsgID(t auditspi.EventType) string {
	s := string(t)
	if s == "" {
		return "-"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

// FormatSyslog wraps inner's rendered payload in an RFC 5424 header
// (`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`).
// facility/hostname/appName are static per-deployment fields; inner renders
// the MSG part — nil defaults to the plain JSONL formatter, so config-driven
// callers that don't need CEF-over-syslog can omit it (an operator CAN
// compose FormatSyslog(..., FormatCEF(...)) programmatically for that). RFC
// 3164 (legacy BSD syslog, no structured-data) is NOT supported — see the
// SIEM-formats task decision. The returned closure is a pure,
// transport-independent []byte encoder — roadmap item 19 (Kafka/NATS)
// reuses it unchanged over a different transport.
func FormatSyslog(facility int, hostname, appName string, inner Formatter) Formatter {
	if inner == nil {
		inner = defaultJSONFormatter
	}
	if hostname == "" {
		hostname = "-"
	}
	if appName == "" {
		appName = "-"
	}
	procID := strconv.Itoa(os.Getpid())
	return func(e *auditspi.Event) ([]byte, error) {
		msg, err := inner(e)
		if err != nil {
			return nil, err
		}
		pri := facility*8 + toSyslogSeverity(eventSeverity(e))
		ts := e.Timestamp.UTC().Format(time.RFC3339Nano)
		header := fmt.Sprintf("<%d>1 %s %s %s %s %s %s ",
			pri, ts, hostname, appName, procID, syslogMsgID(e.Type), syslogStructuredData(e.Metadata))
		return append([]byte(header), msg...), nil
	}
}

// NewSyslogSink is a thin WriterSink constructor pairing FormatSyslog with a
// concrete output target.
func NewSyslogSink(w io.Writer, facility int, hostname, appName string, inner Formatter) *WriterSink {
	return NewWriterSink(w, WithWriterFormat(FormatSyslog(facility, hostname, appName, inner)))
}
