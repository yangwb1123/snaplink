package authenticators

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestAsyncCodeSenderReturnsAfterEnqueueAndDrains(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	q := NewAsyncCodeSender(func(context.Context, string, string) error {
		close(started)
		<-release
		return nil
	}, AsyncCodeSenderConfig{Workers: 1}, nil)
	if err := q.Send(context.Background(), "target", "secret"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	<-started
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestAsyncCodeSenderRetries(t *testing.T) {
	var attempts atomic.Int32
	q := NewAsyncCodeSender(func(context.Context, string, string) error {
		if attempts.Add(1) < 3 {
			return errors.New("temporary")
		}
		return nil
	}, AsyncCodeSenderConfig{Workers: 1, Attempts: 3, RetryBackoff: time.Millisecond}, nil)
	if err := q.Send(context.Background(), "target", "secret"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestAsyncEmailFailureInvalidatesCode(t *testing.T) {
	deliveredCode := make(chan string, 1)
	q := NewAsyncCodeSender(func(_ context.Context, _, code string) error {
		deliveredCode <- code
		return errors.New("provider down")
	}, AsyncCodeSenderConfig{Workers: 1, Attempts: 1}, nil)
	store := NewMemoryCodeStoreWithCooldown(0)
	authenticator := NewEmailAuthenticator(store, q)
	if err := authenticator.SendCode(context.Background(), "a@example.com"); err != nil {
		t.Fatalf("SendCode should report accepted queue job: %v", err)
	}
	code := <-deliveredCode
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := authenticator.CloseCodeDelivery(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err := authenticator.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"email": "a@example.com", "code": code},
	})
	if !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Authenticate error = %v, want invalidated code", err)
	}
}

func TestAsyncCodeSenderRejectsFullQueue(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	q := NewAsyncCodeSender(func(context.Context, string, string) error {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return nil
	}, AsyncCodeSenderConfig{Workers: 1, QueueSize: 1}, nil)
	if err := q.Send(context.Background(), "one", "secret"); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := q.Send(context.Background(), "two", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := q.Send(context.Background(), "three", "secret"); !errors.Is(err, ErrCodeDeliveryQueueFull) {
		t.Fatalf("third enqueue error = %v", err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
