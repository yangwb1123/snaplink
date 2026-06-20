package oauth

import (
	"net/http"
	"testing"
)

func TestBasicClientCreds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		header     string
		wantID     string
		wantSecret string
		wantOK     bool
	}{
		{name: "valid basic auth", header: "Basic Y2xpZW50MTpzZWNyZXQx", wantID: "client1", wantSecret: "secret1", wantOK: true},
		{name: "no header", header: "", wantOK: false},
		{name: "wrong scheme", header: "Bearer token123", wantOK: false},
		{name: "malformed base64", header: "Basic !!invalid!!", wantOK: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &http.Request{Header: http.Header{}}
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			id, secret, ok := BasicClientCreds(r)
			if ok != tc.wantOK {
				t.Errorf("BasicClientCreds() ok = %v, want %v", ok, tc.wantOK)
			}
			if id != tc.wantID {
				t.Errorf("BasicClientCreds() id = %q, want %q", id, tc.wantID)
			}
			if secret != tc.wantSecret {
				t.Errorf("BasicClientCreds() secret = %q, want %q", secret, tc.wantSecret)
			}
		})
	}
}

func TestBasicClientCredsNilRequest(t *testing.T) {
	t.Parallel()

	id, secret, ok := BasicClientCreds(nil)
	if ok {
		t.Error("BasicClientCreds(nil) returned ok=true")
	}
	if id != "" {
		t.Errorf("BasicClientCreds(nil) id = %q, want empty", id)
	}
	if secret != "" {
		t.Errorf("BasicClientCreds(nil) secret = %q, want empty", secret)
	}
}
