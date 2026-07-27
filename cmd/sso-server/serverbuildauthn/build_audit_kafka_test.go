package serverbuildauthn

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// fakeAuditSink is a minimal audit.Sink stand-in — no real Kafka broker, no
// mocking framework, mirroring registerExternalSignerForTest's staticSigner
// one file over.
type fakeAuditSink struct{ recorded []*auditspi.Event }

func (f *fakeAuditSink) Record(_ context.Context, e *auditspi.Event) error {
	f.recorded = append(f.recorded, e)
	return nil
}
func (*fakeAuditSink) Get(context.Context, string) (*auditspi.Event, error) { return nil, nil }
func (*fakeAuditSink) Query(context.Context, auditspi.Query) ([]*auditspi.Event, error) {
	return nil, nil
}

// registerAuditKafkaSinkFactoryForTest registers f and unregisters it when the
// test ends, keeping the package-global single-slot registry clean across
// subtests and -count>1 runs — RegisterAuditKafkaSinkFactory panics on a
// second registration by design (a production wiring guard), same posture as
// registerExternalSignerForTest in external_signer_test.go.
func registerAuditKafkaSinkFactoryForTest(t *testing.T, f AuditKafkaSinkFactory) {
	t.Helper()
	RegisterAuditKafkaSinkFactory(f)
	t.Cleanup(func() {
		auditKafkaFactory.mu.Lock()
		defer auditKafkaFactory.mu.Unlock()
		auditKafkaFactory.f = nil
	})
}

func TestRegisterAuditKafkaSinkFactory_PanicsOnNil(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil factory")
		}
	}()
	RegisterAuditKafkaSinkFactory(nil)
}

func TestRegisterAuditKafkaSinkFactory_PanicsOnDuplicate(t *testing.T) {
	registerAuditKafkaSinkFactoryForTest(t, func(config.AuditKafkaConfig, spi.Logger) (audit.Sink, error) {
		return &fakeAuditSink{}, nil
	})
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	RegisterAuditKafkaSinkFactory(func(config.AuditKafkaConfig, spi.Logger) (audit.Sink, error) {
		return &fakeAuditSink{}, nil
	})
}

func TestBuildAuditKafkaSink_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	sink, err := BuildAuditKafkaSink(config.AuditKafkaConfig{Enabled: false}, spi.NopLogger{})
	if err != nil {
		t.Fatalf("BuildAuditKafkaSink: %v", err)
	}
	if sink != nil {
		t.Fatal("expected nil sink when disabled")
	}
}

func TestBuildAuditKafkaSink_RequiresBrokersAndTopic(t *testing.T) {
	t.Parallel()
	if _, err := BuildAuditKafkaSink(config.AuditKafkaConfig{Enabled: true, Topic: "t"}, spi.NopLogger{}); err == nil {
		t.Fatal("expected error when brokers is empty")
	}
	if _, err := BuildAuditKafkaSink(config.AuditKafkaConfig{Enabled: true, Brokers: []string{"b:9092"}}, spi.NopLogger{}); err == nil {
		t.Fatal("expected error when topic is empty")
	}
}

func TestBuildAuditKafkaSink_FailsClosedWhenNotRegistered(t *testing.T) {
	// No registerAuditKafkaSinkFactoryForTest call — the package-global slot
	// must be empty (no other test in this file leaves it registered, since
	// every registration is t.Cleanup'd).
	_, err := BuildAuditKafkaSink(config.AuditKafkaConfig{
		Enabled: true, Brokers: []string{"b:9092"}, Topic: "t",
	}, spi.NopLogger{})
	if err == nil {
		t.Fatal("expected error when no factory is registered")
	}
}

func TestBuildAuditKafkaSink_UsesRegisteredFactory(t *testing.T) {
	fake := &fakeAuditSink{}
	var gotCfg config.AuditKafkaConfig
	registerAuditKafkaSinkFactoryForTest(t, func(cfg config.AuditKafkaConfig, _ spi.Logger) (audit.Sink, error) {
		gotCfg = cfg
		return fake, nil
	})

	cfg := config.AuditKafkaConfig{Enabled: true, Brokers: []string{"b:9092"}, Topic: "audit-events"}
	sink, err := BuildAuditKafkaSink(cfg, spi.NopLogger{})
	if err != nil {
		t.Fatalf("BuildAuditKafkaSink: %v", err)
	}
	if sink != fake {
		t.Fatal("BuildAuditKafkaSink did not return the registered factory's sink")
	}
	if gotCfg.Topic != "audit-events" {
		t.Fatalf("factory received topic %q, want audit-events", gotCfg.Topic)
	}
}

func TestBuildAuditKafkaSink_PropagatesFactoryError(t *testing.T) {
	wantErr := errors.New("dial failed")
	registerAuditKafkaSinkFactoryForTest(t, func(config.AuditKafkaConfig, spi.Logger) (audit.Sink, error) {
		return nil, wantErr
	})

	_, err := BuildAuditKafkaSink(config.AuditKafkaConfig{
		Enabled: true, Brokers: []string{"b:9092"}, Topic: "t",
	}, spi.NopLogger{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wrapping %v", err, wantErr)
	}
}

func TestBuildAuditKafkaSink_RejectsNilSinkFromFactory(t *testing.T) {
	registerAuditKafkaSinkFactoryForTest(t, func(config.AuditKafkaConfig, spi.Logger) (audit.Sink, error) {
		return nil, nil
	})

	_, err := BuildAuditKafkaSink(config.AuditKafkaConfig{
		Enabled: true, Brokers: []string{"b:9092"}, Topic: "t",
	}, spi.NopLogger{})
	if err == nil {
		t.Fatal("expected error when factory returns a nil sink")
	}
}
