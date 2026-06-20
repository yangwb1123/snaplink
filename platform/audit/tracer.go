package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// W3C Trace Context constants (https://www.w3.org/TR/trace-context/).
const (
	// TraceVersion is the only currently-defined traceparent version.
	TraceVersion = "00"

	// TraceIDBytes / SpanIDBytes are the wire sizes (raw bytes before hex).
	TraceIDBytes = 16
	SpanIDBytes  = 8

	// TraceparentHeader is the standard header name for cross-service propagation.
	TraceparentHeader = "Traceparent"

	// FlagSampled is the only standardized flag bit (per the spec, version 00).
	FlagSampled byte = 0x01
)

// ErrInvalidTraceparent is returned by ParseTraceparent for any malformed input.
var ErrInvalidTraceparent = errors.New("audit: invalid traceparent")

// TraceContext is one node in a distributed trace. ParentSpanID is empty for
// trace roots; SpanID identifies the current operation; TraceID is constant
// across the entire call chain.
type TraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Flags        byte
}

// IsValid reports whether the trace and span IDs are non-empty and the right
// length. Useful for testing whether middleware actually populated a context.
func (tc TraceContext) IsValid() bool {
	return len(tc.TraceID) == TraceIDBytes*2 && len(tc.SpanID) == SpanIDBytes*2
}

// IsSampled reports whether the sampled flag bit is set.
func (tc TraceContext) IsSampled() bool {
	return tc.Flags&FlagSampled != 0
}

// Tracer is a tiny set of stateless helpers around the W3C Trace Context
// wire format. It is intentionally not an interface — the spec is fixed and
// abstraction adds nothing here. Callers in other systems can use this as a
// library without depending on sso or HTTP.
type Tracer struct{}

func NewTracer() *Tracer { return &Tracer{} }

// NewTraceID returns a fresh 128-bit hex trace ID (32 chars). The all-zero
// trace ID is invalid per the spec and is retried on the astronomically
// improbable chance crypto/rand produces it.
func (Tracer) NewTraceID() string { return randHex(TraceIDBytes, true) }

// NewSpanID returns a fresh 64-bit hex span ID (16 chars).
func (Tracer) NewSpanID() string { return randHex(SpanIDBytes, true) }

// FormatTraceparent renders tc into the wire format:
//
//	"00-<trace_id>-<span_id>-<flags>"
func (Tracer) FormatTraceparent(tc TraceContext) string {
	flags := strconv.FormatUint(uint64(tc.Flags), 16)
	if len(flags) == 1 {
		flags = "0" + flags
	}
	return TraceVersion + "-" + tc.TraceID + "-" + tc.SpanID + "-" + flags
}

// ParseTraceparent decodes a W3C traceparent header. The returned context has
// the incoming span as SpanID (not ParentSpanID) — callers typically pass it
// to StartChild to derive the local span.
func (Tracer) ParseTraceparent(s string) (TraceContext, error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 4 {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if parts[0] != TraceVersion {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if !isHexOfLen(parts[1], TraceIDBytes*2) || allZero(parts[1]) {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if !isHexOfLen(parts[2], SpanIDBytes*2) || allZero(parts[2]) {
		return TraceContext{}, ErrInvalidTraceparent
	}
	flagsU, err := strconv.ParseUint(parts[3], 16, 8)
	if err != nil || len(parts[3]) != 2 {
		return TraceContext{}, ErrInvalidTraceparent
	}
	return TraceContext{
		TraceID: parts[1],
		SpanID:  parts[2],
		Flags:   byte(flagsU),
	}, nil
}

// StartChild produces a new TraceContext that shares parent's TraceID and
// records parent's SpanID as the parent. A fresh SpanID is generated.
// If parent is zero (no incoming trace), a brand-new trace is started.
func (t Tracer) StartChild(parent TraceContext) TraceContext {
	if !parent.IsValid() {
		return TraceContext{
			TraceID: t.NewTraceID(),
			SpanID:  t.NewSpanID(),
			Flags:   FlagSampled,
		}
	}
	return TraceContext{
		TraceID:      parent.TraceID,
		SpanID:       t.NewSpanID(),
		ParentSpanID: parent.SpanID,
		Flags:        parent.Flags,
	}
}

// randHex returns hex of n random bytes; if requireNonZero is true, retries
// until the result has at least one non-zero byte (the spec forbids all-zero
// trace/span IDs).
func randHex(n int, requireNonZero bool) string {
	b := make([]byte, n)
	for {
		if _, err := rand.Read(b); err != nil {
			// crypto/rand never returns an error on Linux; if it does,
			// returning a hex of zeros is worse than panicking.
			panic("audit: crypto/rand failed: " + err.Error())
		}
		if !requireNonZero {
			return hex.EncodeToString(b)
		}
		for _, x := range b {
			if x != 0 {
				return hex.EncodeToString(b)
			}
		}
		// All zero — loop and try again. Probability < 2^-128.
	}
}

func isHexOfLen(s string, want int) bool {
	if len(s) != want {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for _, r := range s {
		if r != '0' {
			return false
		}
	}
	return true
}
