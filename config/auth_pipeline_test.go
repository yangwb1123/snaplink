package config

import (
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestAuthPipelineConfigValidationAndOptions(t *testing.T) {
	config := &Config{
		Server:  ServerConfig{Issuer: "https://issuer.example"},
		Logging: LoggingConfig{Level: "info"},
		AuthPipeline: AuthPipelineConfig{
			IPSkipMFACIDRs:            []string{"10.0.0.0/8"},
			RequiredProfileAttributes: []string{" email "},
		},
	}
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	if config.AuthPipeline.RequiredProfileAttributes[0] != "email" {
		t.Fatalf("attribute not normalized: %#v", config.AuthPipeline.RequiredProfileAttributes)
	}
	options := config.ServerOptions()
	if len(options) != 3 {
		t.Fatalf("options=%d, want issuer plus two auth hooks", len(options))
	}
	_ = sso.NewServer(options...)
}

func TestAuthPipelineConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		config AuthPipelineConfig
		want   string
	}{
		{name: "cidr", config: AuthPipelineConfig{IPSkipMFACIDRs: []string{"bad"}}, want: "ip_skip_mfa_cidrs"},
		{name: "empty attribute", config: AuthPipelineConfig{RequiredProfileAttributes: []string{" "}}, want: "must not be empty"},
		{name: "duplicate", config: AuthPipelineConfig{RequiredProfileAttributes: []string{"email", "email"}}, want: "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{Server: ServerConfig{Issuer: "https://issuer.example"}, Logging: LoggingConfig{Level: "info"}, AuthPipeline: test.config}
			err := config.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want substring %q", err, test.want)
			}
		})
	}
}
