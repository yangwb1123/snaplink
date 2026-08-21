package serverbuildauthn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestBuildExternalAuditRuntimeDisabled(t *testing.T) {
	runtime, err := BuildExternalAuditRuntime(config.ExternalAuditWorkerConfig{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatal("disabled external worker returned a runtime")
	}
}

func TestBuildExternalWorkerSpecPinsHostProfile(t *testing.T) {
	_, err := buildExternalWorkerSpec(config.ExternalAuditWorkerConfig{BuildProfile: "different-profile"})
	if err == nil || !strings.Contains(err.Error(), "does not match host profile") {
		t.Fatalf("profile mismatch error = %v", err)
	}
}

func TestDecodeExternalWorkerKeySupportsHexAndBase64(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"hex":    hex.EncodeToString(public),
		"base64": base64.StdEncoding.EncodeToString(public),
		"raw":    base64.RawStdEncoding.EncodeToString(public),
	} {
		got, err := decodeExternalWorkerKey(encoded, "test")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != string(public) {
			t.Fatalf("%s: decoded key differs", name)
		}
	}
	if _, err := decodeExternalWorkerKey("not-a-key", "test"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestExternalWorkerObserverRecordsBoundedTransition(t *testing.T) {
	sink := audit.NewMemorySink(8)
	recorder := audit.New(sink)
	observer := externalWorkerObserver(recorder, spi.NopLogger{})
	err := observer.Observe(context.Background(), modules.TransitionEvent{
		Type: modules.TransitionActivated, ModuleID: "worker", Generation: 3,
		RelatedGeneration: 2, OccurredAt: time.Unix(10, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventExternalWorkerLifecycleTransition})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	if events[0].Metadata["module_id"] != "worker" || events[0].Metadata["generation"] != "3" {
		t.Fatalf("unexpected metadata: %v", events[0].Metadata)
	}
}

func TestExternalAuditRuntimeFailOpenAndReadiness(t *testing.T) {
	runtime, instance := newTestExternalAuditRuntime(t, errors.New("worker unavailable"))
	if err := runtime.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record returned worker error: %v", err)
	}
	if instance.records.Load() != 1 {
		t.Fatalf("records=%d, want 1", instance.records.Load())
	}
	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
}

func TestExternalAuditRuntimeReadyRejectsClosedManager(t *testing.T) {
	runtime, _ := newTestExternalAuditRuntime(t, nil)
	runtime.manager = nil
	if err := runtime.Ready(context.Background()); !errors.Is(err, modules.ErrManagerClosed) {
		t.Fatalf("Ready error=%v, want manager closed", err)
	}
}

type externalAuditRuntimeTestInstance struct {
	recordErr error
	readyErr  error
	records   atomic.Int32
}

func (i *externalAuditRuntimeTestInstance) Start(context.Context) error   { return nil }
func (i *externalAuditRuntimeTestInstance) Quiesce(context.Context) error { return nil }
func (i *externalAuditRuntimeTestInstance) Stop(context.Context) error    { return nil }
func (i *externalAuditRuntimeTestInstance) Ready(context.Context) error   { return i.readyErr }
func (i *externalAuditRuntimeTestInstance) Record(context.Context, *audit.Event) error {
	i.records.Add(1)
	return i.recordErr
}
func (*externalAuditRuntimeTestInstance) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}
func (*externalAuditRuntimeTestInstance) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

func newTestExternalAuditRuntime(t *testing.T, recordErr error) (*ExternalAuditRuntime, *externalAuditRuntimeTestInstance) {
	t.Helper()
	instance := &externalAuditRuntimeTestInstance{recordErr: recordErr}
	manager, err := modules.New([]modules.Definition{{
		ID: "test-worker", Factory: modules.FactoryFunc(func(context.Context, modules.PrepareRequest) (modules.Instance, error) {
			return instance, nil
		}),
	}}, modules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), "test-worker", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.WaitObserver(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime := &ExternalAuditRuntime{manager: manager, moduleID: "test-worker", logger: spi.NopLogger{}}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime, instance
}
