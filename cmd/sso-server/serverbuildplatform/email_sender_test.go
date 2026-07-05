package serverbuildplatform

import (
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/shared/spi"
)

func TestBuildEmailSender_DisabledReturnsNil(t *testing.T) {
	sender, err := BuildEmailSender(config.SMTPConfig{Enabled: false, Host: "mail.example.com"}, spi.NopLogger{})
	if err != nil {
		t.Fatalf("BuildEmailSender returned error: %v", err)
	}
	if sender != nil {
		t.Fatal("expected nil sender when smtp.enabled=false")
	}
}

func TestBuildEmailSender_EnabledNoHostReturnsNil(t *testing.T) {
	sender, err := BuildEmailSender(config.SMTPConfig{Enabled: true, Host: ""}, spi.NopLogger{})
	if err != nil {
		t.Fatalf("BuildEmailSender returned error: %v", err)
	}
	if sender != nil {
		t.Fatal("expected nil sender when smtp.host is empty")
	}
}

func TestBuildEmailSender_EnabledWithHostReturnsSender(t *testing.T) {
	sender, err := BuildEmailSender(config.SMTPConfig{
		Enabled: true,
		Host:    "mail.example.com",
		Port:    587,
		From:    "no-reply@example.com",
	}, spi.NopLogger{})
	if err != nil {
		t.Fatalf("BuildEmailSender returned error: %v", err)
	}
	if sender == nil {
		t.Fatal("expected non-nil sender when smtp.enabled=true and host set")
	}
}
