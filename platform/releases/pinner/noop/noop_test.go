package noop_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/pinner/noop"
)

func TestPinForwardAndRollbackReturnNil(t *testing.T) {
	p := noop.Pinner{}
	r := &releases.Release{ID: "rel-1"}
	if err := p.PinForward(context.Background(), r); err != nil {
		t.Errorf("PinForward: %v", err)
	}
	if err := p.PinRollback(context.Background(), r); err != nil {
		t.Errorf("PinRollback: %v", err)
	}
}

func TestLoggerInvokedWithMode(t *testing.T) {
	var got []string
	p := noop.Pinner{Logger: func(msg string, kv ...any) {
		// kv = ["mode", "forward", "release_id", "rel-1"]
		for i := 0; i < len(kv)-1; i += 2 {
			if k, ok := kv[i].(string); ok && k == "mode" {
				if v, ok := kv[i+1].(string); ok {
					got = append(got, v)
				}
			}
		}
	}}
	r := &releases.Release{ID: "rel-1"}
	_ = p.PinForward(context.Background(), r)
	_ = p.PinRollback(context.Background(), r)
	if len(got) != 2 || got[0] != "forward" || got[1] != "rollback" {
		t.Errorf("logger captured = %v", got)
	}
}
