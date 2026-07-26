package oauthwire

import (
	"testing"
)

func FuzzBearerToken(f *testing.F) {
	seeds := []string{
		"Bearer my-token",
		"Basic dXNlcjpwYXNz",
		"",
		"Bearer",
		"bearer token",
		"Bearer  ",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, auth string) {
		r := newRequest("GET", "/", nil)
		r.Header.Set("Authorization", auth)
		token := BearerToken(r)
		// Must not panic. JWTs can be up to ~10KB.
		if token != "" && len(token) > 10240 {
			t.Errorf("unexpectedly long token: %d chars", len(token))
		}
	})
}

func FuzzBasicClientCreds(f *testing.F) {
	seeds := []string{
		"Basic Y2xpZW50OnNlY3JldA==",
		"Bearer token",
		"",
		"Basic ",
		"Basic !!!",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, auth string) {
		r := newRequest("GET", "/", nil)
		r.Header.Set("Authorization", auth)
		_, _, ok := BasicClientCreds(r)
		// Must not panic. ok can be true or false.
		_ = ok
	})
}
