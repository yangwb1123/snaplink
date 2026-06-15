package oauth

import (
	"net/http"
	"testing"
)

func TestBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "valid bearer", header: "Bearer mytoken123", want: "mytoken123"},
		{name: "lowercase bearer", header: "bearer mytoken123", want: ""},
		{name: "no header", header: "", want: ""},
		{name: "wrong scheme", header: "Basic dXNlcjpwYXNz", want: ""},
		{name: "empty bearer", header: "Bearer ", want: ""},
		{name: "bearer with extra spaces", header: "Bearer  mytoken123", want: " mytoken123"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &http.Request{Header: http.Header{}}
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got := BearerToken(r)
			if got != tc.want {
				t.Errorf("BearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}
