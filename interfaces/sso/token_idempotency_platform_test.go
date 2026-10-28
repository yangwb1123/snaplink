package sso_test

import "testing"

func TestClientCredentialsIdempotencyProcessPlatformSupport(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want bool
	}{
		{goos: "windows", want: false},
		{goos: "linux", want: true},
		{goos: "darwin", want: true},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			if got := cc04ProcessPlatformSupported(tc.goos); got != tc.want {
				t.Fatalf("process platform support for %s = %t, want %t", tc.goos, got, tc.want)
			}
		})
	}
}
