package core

import (
	"context"
	"testing"
)

func TestErrorBodyWithTrace(t *testing.T) {
	t.Run("with trace ID", func(t *testing.T) {
		body := ErrorBodyWithTrace("invalid_request", "trace-123")
		if body[KeyError] != "invalid_request" {
			t.Errorf("expected 'invalid_request', got %q", body[KeyError])
		}
		if body[KeyTraceID] != "trace-123" {
			t.Errorf("expected 'trace-123', got %q", body[KeyTraceID])
		}
	})

	t.Run("without trace ID", func(t *testing.T) {
		body := ErrorBodyWithTrace("access_denied", "")
		if body[KeyError] != "access_denied" {
			t.Errorf("expected 'access_denied', got %q", body[KeyError])
		}
		if _, ok := body[KeyTraceID]; ok {
			t.Error("expected no trace_id key")
		}
	})
}

func TestBreakGlassActorFromContext(t *testing.T) {
	t.Run("no actor in context", func(t *testing.T) {
		_, ok := BreakGlassActorFromContext(context.Background())
		if ok {
			t.Error("expected false for empty context")
		}
	})

	t.Run("with actor in context", func(t *testing.T) {
		actor := BreakGlassActor{AdminID: "admin-1", AdminSessionID: "session-1"}
		ctx := context.WithValue(context.Background(), breakGlassActorKey{}, actor)
		got, ok := BreakGlassActorFromContext(ctx)
		if !ok {
			t.Fatal("expected true")
		}
		if got.AdminID != "admin-1" {
			t.Errorf("expected 'admin-1', got %q", got.AdminID)
		}
		if got.AdminSessionID != "session-1" {
			t.Errorf("expected 'session-1', got %q", got.AdminSessionID)
		}
	})
}

func TestErrorBodyWithLocalizedDesc(t *testing.T) {
	t.Run("empty desc returns original", func(t *testing.T) {
		original := map[string]string{KeyError: "invalid_request"}
		result := ErrorBodyWithLocalizedDesc(original, "")
		if result[KeyError] != "invalid_request" {
			t.Errorf("expected 'invalid_request', got %q", result[KeyError])
		}
	})

	t.Run("with localized desc", func(t *testing.T) {
		original := map[string]string{KeyError: "invalid_request"}
		result := ErrorBodyWithLocalizedDesc(original, "zh-CN: 无效请求")
		if result[KeyError] != "invalid_request" {
			t.Errorf("expected 'invalid_request', got %q", result[KeyError])
		}
		if result[KeyErrorDescriptionLocalized] != "zh-CN: 无效请求" {
			t.Errorf("expected localized desc, got %q", result[KeyErrorDescriptionLocalized])
		}
	})
}
