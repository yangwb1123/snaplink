package config

import (
	"strings"
	"testing"
)

func TestValidateConfiguredClientsLoginPageURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{name: "unset"},
		{name: "https", uri: "https://login.example.test/authorize"},
		{name: "loopback http", uri: "http://127.0.0.1:8081/login/"},
		{name: "public http", uri: "http://login.example.test/authorize", wantErr: true},
		{name: "userinfo", uri: "https://operator@login.example.test/authorize", wantErr: true},
		{name: "relative", uri: "/authorize", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfiguredClients([]ClientConfig{{ID: "portal", LoginPageURI: test.uri}})
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "login_page_uri") {
					t.Fatalf("err=%v, want login_page_uri validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateConfiguredClients() error = %v", err)
			}
		})
	}
}
