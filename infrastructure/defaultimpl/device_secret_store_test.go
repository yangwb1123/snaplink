package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
)

// deviceSecretStoreSuite runs the shared contract against any
// core.DeviceSecretStore so memory + sqlite stay behaviorally identical.
func deviceSecretStoreSuite(t *testing.T, mk func(t *testing.T) core.DeviceSecretStore) {
	ctx := context.Background()

	t.Run("issue then consume returns the binding", func(t *testing.T) {
		s := mk(t)
		ds := &core.DeviceSecret{Secret: "sec-1", Subject: "u1", SID: "sid1", ClientID: "app-a", ExpiresAt: time.Now().Add(time.Minute)}
		if err := s.Issue(ctx, ds); err != nil {
			t.Fatalf("issue: %v", err)
		}
		got, err := s.Consume(ctx, "sec-1")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got.Subject != "u1" || got.SID != "sid1" || got.ClientID != "app-a" {
			t.Errorf("binding = %+v", got)
		}
	})

	t.Run("consume missing returns ErrDeviceSecretNotFound", func(t *testing.T) {
		s := mk(t)
		if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
			t.Errorf("err = %v, want ErrDeviceSecretNotFound", err)
		}
	})

	t.Run("consume is single-use", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.DeviceSecret{Secret: "sec-2", Subject: "u", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})
		if _, err := s.Consume(ctx, "sec-2"); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if _, err := s.Consume(ctx, "sec-2"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
			t.Errorf("second consume err = %v, want ErrDeviceSecretNotFound", err)
		}
	})

	t.Run("expired secret is not returned", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.DeviceSecret{Secret: "sec-3", Subject: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)})
		if _, err := s.Consume(ctx, "sec-3"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
			t.Errorf("expired consume err = %v, want ErrDeviceSecretNotFound", err)
		}
	})
}

func TestMemoryDeviceSecretStore(t *testing.T) {
	deviceSecretStoreSuite(t, func(t *testing.T) core.DeviceSecretStore {
		return defaultimpl.NewMemoryDeviceSecretStore()
	})
}
