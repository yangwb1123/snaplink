package authenticators

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sso "github.com/yangwb1123/snaplink/interfaces/sso"
	"golang.org/x/crypto/bcrypt"
)

// ---- helpers ----

// fixedVerifier always succeeds for the given user, ignoring the password.
// It simulates an underlying verifier that already accepted the credentials
// (e.g. a multi-hash verifier that handled argon2id comparison).
func fixedVerifier(subjectID string) PasswordVerifier {
	return PasswordVerifierFunc(func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
		return &sso.AuthResult{UserID: subjectID}, nil
	})
}

// ---- TestLazyRehashVerifier_RehashesOnFirstLogin ----

// TestLazyRehashVerifier_RehashesOnFirstLogin checks that when NeedsRehash
// returns true, Updater is eventually called with a valid bcrypt hash.
func TestLazyRehashVerifier_RehashesOnFirstLogin(t *testing.T) {
	t.Parallel()
	var (
		mu          sync.Mutex
		updatedUser string
		updatedHash string
		updateDone  = make(chan struct{})
	)

	v := &LazyRehashVerifier{
		Underlying: fixedVerifier("user-1"),
		NeedsRehash: func(_ context.Context, username string) (bool, error) {
			return true, nil
		},
		Updater: func(_ context.Context, username, newBcryptHash string) error {
			mu.Lock()
			updatedUser = username
			updatedHash = newBcryptHash
			mu.Unlock()
			close(updateDone)
			return nil
		},
	}

	result, err := v.Verify(context.Background(), "alice", "plaintext")
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", result.UserID)
	}

	// Wait for the goroutine to call Updater.
	<-updateDone

	mu.Lock()
	defer mu.Unlock()
	if updatedUser != "alice" {
		t.Errorf("Updater username = %q, want alice", updatedUser)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte("plaintext")); err != nil {
		t.Errorf("Updater hash is not a valid bcrypt hash for the plaintext: %v", err)
	}
}

// ---- TestLazyRehashVerifier_NoRehashForBcrypt ----

// TestLazyRehashVerifier_NoRehashForBcrypt verifies that when NeedsRehash
// returns false (e.g. for a user whose hash is already bcrypt), Updater is
// never called.
func TestLazyRehashVerifier_NoRehashForBcrypt(t *testing.T) {
	t.Parallel()
	updaterCalled := false

	v := &LazyRehashVerifier{
		Underlying: fixedVerifier("user-2"),
		NeedsRehash: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
		Updater: func(_ context.Context, _, _ string) error {
			updaterCalled = true
			return nil
		},
	}

	if _, err := v.Verify(context.Background(), "bob", "secret"); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	// Give a moment for any stray goroutine to run (there should be none).
	// We don't block here since no goroutine should be spawned.
	if updaterCalled {
		t.Error("Updater was called even though NeedsRehash returned false")
	}
}

// ---- TestLazyRehashVerifier_FailOpenOnRehashError ----

// TestLazyRehashVerifier_FailOpenOnRehashError verifies that when Updater
// returns an error, authentication still succeeds (fail-open contract).
func TestLazyRehashVerifier_FailOpenOnRehashError(t *testing.T) {
	t.Parallel()
	// logErrCh receives exactly one value: the logged message on Updater
	// error. Using a channel rather than a shared variable avoids a data
	// race between the goroutine write and the test-goroutine read.
	logErrCh := make(chan string, 1)
	// updaterDone signals that the goroutine has finished executing Updater.
	updaterDone := make(chan struct{})

	v := &LazyRehashVerifier{
		Underlying: fixedVerifier("user-3"),
		NeedsRehash: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		Updater: func(_ context.Context, _, _ string) error {
			defer close(updaterDone)
			return errors.New("db write failed")
		},
		Logger: &captureLogger{onError: func(msg string, args ...any) {
			select {
			case logErrCh <- msg:
			default:
			}
		}},
	}

	result, err := v.Verify(context.Background(), "carol", "pw")
	if err != nil {
		t.Fatalf("Verify must succeed even when Updater will fail, got: %v", err)
	}
	if result.UserID != "user-3" {
		t.Errorf("UserID = %q, want user-3", result.UserID)
	}

	// Wait for the goroutine to run Updater. Logger.Error is called AFTER Updater
	// returns (see LazyRehashVerifier.Verify), so updaterDone unblocking does NOT
	// imply the log send has happened — block on logErrCh with a timeout rather
	// than a non-blocking check that would race the goroutine under load.
	<-updaterDone

	select {
	case msg := <-logErrCh:
		if msg == "" {
			t.Error("Logger.Error called with empty message")
		}
	case <-time.After(2 * time.Second):
		t.Error("expected Logger.Error to be called on Updater failure")
	}
}

// ---- TestLazyRehashVerifier_NilUpdaterIsNoop ----

func TestLazyRehashVerifier_NilUpdaterIsNoop(t *testing.T) {
	t.Parallel()
	// When Updater is nil, verification should still work without panicking.
	v := &LazyRehashVerifier{
		Underlying:  fixedVerifier("user-4"),
		NeedsRehash: nil, // not called when Updater is nil
		Updater:     nil,
	}
	result, err := v.Verify(context.Background(), "dave", "pw")
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.UserID != "user-4" {
		t.Errorf("UserID = %q, want user-4", result.UserID)
	}
}

// ---- TestLazyRehashVerifier_NeedsRehashErrorIsFailOpen ----

func TestLazyRehashVerifier_NeedsRehashErrorIsFailOpen(t *testing.T) {
	t.Parallel()
	updaterCalled := false
	v := &LazyRehashVerifier{
		Underlying: fixedVerifier("user-5"),
		NeedsRehash: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("store unavailable")
		},
		Updater: func(_ context.Context, _, _ string) error {
			updaterCalled = true
			return nil
		},
	}
	result, err := v.Verify(context.Background(), "eve", "pw")
	if err != nil {
		t.Fatalf("Verify must succeed even when NeedsRehash errors, got: %v", err)
	}
	if result.UserID != "user-5" {
		t.Errorf("UserID = %q, want user-5", result.UserID)
	}
	if updaterCalled {
		t.Error("Updater should not be called when NeedsRehash returned an error")
	}
}

// ---- TestLazyRehashVerifier_UpdaterPanicIsRecovered ----

// TestLazyRehashVerifier_UpdaterPanicIsRecovered proves the fire-and-forget
// rehash goroutine recovers a panic from the operator-supplied Updater
// instead of letting it escape the bare `go func()` and crash the whole
// process. Updater is arbitrary persistence code (per the LazyRehashVerifier
// doc comment) — a nil map write, a bad type assertion, anything — and this
// goroutine has no caller to observe or recover a panic on its behalf.
func TestLazyRehashVerifier_UpdaterPanicIsRecovered(t *testing.T) {
	t.Parallel()
	logErrCh := make(chan string, 1)
	panicked := make(chan struct{})

	v := &LazyRehashVerifier{
		Underlying: fixedVerifier("user-6"),
		NeedsRehash: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		Updater: func(_ context.Context, _, _ string) error {
			defer close(panicked)
			panic("simulated updater panic")
		},
		Logger: &captureLogger{onError: func(msg string, args ...any) {
			select {
			case logErrCh <- msg:
			default:
			}
		}},
	}

	// Verify itself must return normally (the panic happens in the detached
	// goroutine, after Verify has already returned).
	result, err := v.Verify(context.Background(), "frank", "pw")
	if err != nil {
		t.Fatalf("Verify must succeed even though Updater will panic, got: %v", err)
	}
	if result.UserID != "user-6" {
		t.Errorf("UserID = %q, want user-6", result.UserID)
	}

	<-panicked

	// Reaching this point at all proves the panic did not escape the
	// goroutine: an unrecovered panic in ANY goroutine is process-fatal in
	// Go, so this whole test binary would have crashed (not failed a single
	// assertion) before ever reaching this select.
	select {
	case msg := <-logErrCh:
		if msg == "" {
			t.Error("Logger.Error called with empty message on Updater panic")
		}
	case <-time.After(2 * time.Second):
		t.Error("expected Logger.Error to be called after Updater panic is recovered")
	}
}

// captureLogger captures Logger.Error calls for test assertions.
type captureLogger struct {
	onError func(string, ...any)
}

func (l *captureLogger) Error(msg string, args ...any) {
	if l.onError != nil {
		l.onError(msg, args...)
	}
}
