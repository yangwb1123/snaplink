package emailsmtp

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestNotificationSenderResolvesRecipientAndReturnsTransportError(t *testing.T) {
	wantErr := errors.New("smtp unavailable")
	calls := 0
	sender, err := New(Config{Host: "smtp.example", Port: 25, From: "security@example.com"}, nil,
		WithSendFunc(func(_ string, _ smtp.Auth, _ string, to []string, message []byte) error {
			calls++
			if len(to) != 1 || to[0] != "alice@example.com" {
				t.Fatalf("to=%v", to)
			}
			if !strings.Contains(string(message), "Account locked") || !strings.Contains(string(message), "Review activity") {
				t.Fatalf("message=%s", message)
			}
			return wantErr
		}))
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewNotificationSender(sender, func(_ context.Context, subjectID string) (string, error) {
		if subjectID != "alice" {
			t.Fatalf("subject=%q", subjectID)
		}
		return "alice@example.com", nil
	})
	err = adapter.SendNotification(context.Background(), &core.NotificationEvent{SubjectID: "alice",
		Title: "Account locked", Body: "Review activity"})
	if !errors.Is(err, wantErr) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

// captured is one delivery observed by captureSend.
type captured struct {
	addr, from string
	to         []string
	msg        string
}

// captureSend returns a sendFunc plus the channel it publishes deliveries to
// — the injectable transport seam (WithSendFunc) that lets these tests
// exercise the real render+dispatch path without a live SMTP server.
func captureSend() (sendFunc, chan captured) {
	ch := make(chan captured, 4)
	fn := func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		ch <- captured{addr: addr, from: from, to: to, msg: string(msg)}
		return nil
	}
	return fn, ch
}

func testConfig() Config {
	return Config{
		Enabled:     true,
		Host:        "mail.example.internal",
		Port:        25,
		From:        "no-reply@example.com",
		LinkBaseURL: "https://sso.example.com/reset",
	}
}

// awaitDelivery reads one delivery off ch, failing the test if dispatch
// (which runs on a background goroutine) never fires within the window.
func awaitDelivery(t *testing.T, ch chan captured) captured {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery dispatched")
		return captured{}
	}
}

func TestSender_SendResetToken(t *testing.T) {
	fn, ch := captureSend()
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendResetToken(context.Background(), "alice@ex.com", "tok-123"); err != nil {
		t.Fatalf("SendResetToken returned %v, want nil (fire-and-forget)", err)
	}
	got := awaitDelivery(t, ch)
	if len(got.to) != 1 || got.to[0] != "alice@ex.com" {
		t.Fatalf("to = %v, want [alice@ex.com]", got.to)
	}
	if !strings.Contains(got.msg, "tok-123") {
		t.Fatal("token missing from rendered message")
	}
	if !strings.Contains(got.msg, "Subject:") {
		t.Fatal("no Subject header in rendered message")
	}
	if !strings.Contains(got.msg, "flow=reset_password&amp;token=tok-123") {
		t.Fatalf("reset action URL is not explicit or escaped: %q", got.msg)
	}
}

func TestSender_SendEmailVerificationToken(t *testing.T) {
	fn, ch := captureSend()
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendEmailVerificationToken(context.Background(), "bob@ex.com", "verify-tok"); err != nil {
		t.Fatalf("returned %v, want nil", err)
	}
	got := awaitDelivery(t, ch)
	if len(got.to) != 1 || got.to[0] != "bob@ex.com" {
		t.Fatalf("to = %v, want [bob@ex.com]", got.to)
	}
	if !strings.Contains(got.msg, "verify-tok") {
		t.Fatal("token missing from rendered message")
	}
	if !strings.Contains(got.msg, "flow=verify_email&amp;token=verify-tok") {
		t.Fatalf("verification action URL is not explicit: %q", got.msg)
	}
}

func TestSender_SendEmailChangeToken(t *testing.T) {
	fn, ch := captureSend()
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendEmailChangeToken(context.Background(), "new@ex.com", "change-tok"); err != nil {
		t.Fatalf("returned %v, want nil", err)
	}
	got := awaitDelivery(t, ch)
	// Delivery target MUST be the new address (proves control of it), per
	// spi.EmailChangeSender's doc comment.
	if len(got.to) != 1 || got.to[0] != "new@ex.com" {
		t.Fatalf("to = %v, want [new@ex.com]", got.to)
	}
	if !strings.Contains(got.msg, "change-tok") {
		t.Fatal("token missing from rendered message")
	}
	if !strings.Contains(got.msg, "flow=change_email&amp;token=change-tok") {
		t.Fatalf("email-change action URL is not explicit: %q", got.msg)
	}
}

func TestSender_SendInvitation(t *testing.T) {
	fn, ch := captureSend()
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendInvitation(context.Background(), "invitee@ex.com", "tenant-42", "admin", "invite-tok"); err != nil {
		t.Fatalf("returned %v, want nil", err)
	}
	got := awaitDelivery(t, ch)
	if len(got.to) != 1 || got.to[0] != "invitee@ex.com" {
		t.Fatalf("to = %v, want [invitee@ex.com]", got.to)
	}
	if !strings.Contains(got.msg, "invite-tok") {
		t.Fatal("token missing from rendered message")
	}
	if !strings.Contains(got.msg, "tenant-42") || !strings.Contains(got.msg, "admin") {
		t.Fatal("tenant/role missing from rendered message")
	}
	if !strings.Contains(got.msg, "flow=invitation&amp;token=invite-tok") {
		t.Fatalf("invitation action URL is not explicit: %q", got.msg)
	}
}

func TestSender_Send_OTP(t *testing.T) {
	fn, ch := captureSend()
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), "otp@ex.com", "482913"); err != nil {
		t.Fatalf("returned %v, want nil", err)
	}
	got := awaitDelivery(t, ch)
	if len(got.to) != 1 || got.to[0] != "otp@ex.com" {
		t.Fatalf("to = %v, want [otp@ex.com]", got.to)
	}
	if !strings.Contains(got.msg, "482913") {
		t.Fatal("code missing from rendered message")
	}
}

// TestSender_DeliverDoesNotBlock is the anti-enumeration assertion: even when
// the injected send blocks indefinitely, SendResetToken must still return
// nil promptly — dispatch runs on its own goroutine and never makes the
// caller wait, so /auth/forgot-password stays constant-time regardless of
// SMTP latency.
func TestSender_DeliverDoesNotBlock(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	fn := func(string, smtp.Auth, string, []string, []byte) error {
		<-block
		return nil
	}
	s, err := New(testConfig(), nil, WithSendFunc(fn))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.SendResetToken(context.Background(), "slow@ex.com", "tok") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendResetToken returned %v, want nil", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendResetToken blocked on a slow transport — fire-and-forget contract broken")
	}
}
