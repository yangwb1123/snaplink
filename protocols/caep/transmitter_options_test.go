package caep

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

type mockSigner struct{}

func (m *mockSigner) SignJWT(_ context.Context, typ string, claims any) (string, error) {
	return "signed.jwt.token", nil
}

type mockClientStore struct{}

func (m *mockClientStore) Get(_ context.Context, id string) (*core.Client, error) {
	return &core.Client{ID: id, Active: true}, nil
}
func (m *mockClientStore) ValidateSecret(_ context.Context, id, secret string) error { return nil }
func (m *mockClientStore) List(_ context.Context) ([]*core.Client, error) { return nil, nil }
func (m *mockClientStore) Add(_ context.Context, c *core.Client) error { return nil }
func (m *mockClientStore) Update(_ context.Context, c *core.Client) error { return nil }
func (m *mockClientStore) Delete(_ context.Context, id string) error { return nil }
func (m *mockClientStore) RotateSecret(_ context.Context, id string) (string, error) { return "new-secret", nil }

func TestWithIssuer(t *testing.T) {
	tx := &Transmitter{}
	WithIssuer("https://sso.test")(tx)
	if tx.issuer != "https://sso.test" {
		t.Errorf("expected 'https://sso.test', got %q", tx.issuer)
	}
}

func TestWithHTTPClient(t *testing.T) {
	tx := &Transmitter{}
	client := &http.Client{Timeout: 10 * time.Second}
	WithHTTPClient(client)(tx)
	if tx.httpClient == nil {
		t.Fatal("expected non-nil client")
	}
	if tx.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", tx.httpClient.Timeout)
	}
}

func TestWithReceiverTimeout(t *testing.T) {
	tx := &Transmitter{}
	WithReceiverTimeout(5 * time.Second)(tx)
	if tx.timeout != 5*time.Second {
		t.Errorf("expected 5s, got %v", tx.timeout)
	}
}

func TestWithSETTTL(t *testing.T) {
	tx := &Transmitter{}
	WithSETTTL(30 * time.Minute)(tx)
	if tx.setTTL != 30*time.Minute {
		t.Errorf("expected 30m, got %v", tx.setTTL)
	}
}

func TestNewTransmitter_NilSigner(t *testing.T) {
	tx := NewTransmitter(nil, nil)
	// Transmitter does not validate nil arguments at construction
	_ = tx
}

func TestNewTransmitter_Valid(t *testing.T) {
	signer := &mockSigner{}
	clientStore := &mockClientStore{}
	tx := NewTransmitter(signer, clientStore)
	if tx == nil {
		t.Fatal("expected non-nil transmitter")
	}
}

func TestWithMetric(t *testing.T) {
	called := false
	fn := func(outcome string) { called = true }
	tx := &Transmitter{}
	WithMetric(fn)(tx)
	tx.metric("ok")
	if !called {
		t.Error("expected metric function to be called")
	}
}
