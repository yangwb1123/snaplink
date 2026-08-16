package config

import (
	"strings"
	"testing"
)

// TestValidateIDTokenAlgs covers the boot gate for the additional per-client
// id_token signing keys (keys.id_token_algs): each entry must name a
// supported JWS algorithm that DIFFERS from the primary keys.signing.alg and
// must not repeat another entry. This mirrors the DCR-side rule that a client
// may only register an alg the AS can actually produce — the additional keys
// are exactly what widens that set (design docs/design/per-client-id-token-alg.md
// Decision 1 + 2, config-facing form).
func TestValidateIDTokenAlgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		primary string // keys.signing.alg
		algs    []IDTokenAlgConfig
		wantErr bool
		errText string
	}{
		{name: "empty list ok", primary: "es256"},
		{name: "one additional alg ok", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "rs256"}}},
		{name: "eddsa alongside es256 ok", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "eddsa"}}},
		{name: "ps256 alongside es256 ok", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "ps256"}}},
		{name: "primary default eddsa + rs256 ok", primary: "", algs: []IDTokenAlgConfig{{Alg: "rs256"}}},
		{name: "alg alias accepted", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "rsa"}}},
		{name: "empty alg rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: ""}}, wantErr: true, errText: "alg is required"},
		{name: "duplicate of primary rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "es256"}}, wantErr: true, errText: "duplicates the primary"},
		{name: "duplicate primary via alias rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "ecdsa"}}, wantErr: true, errText: "duplicates the primary"},
		{name: "duplicate among entries rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "rs256"}, {Alg: "rs256"}}, wantErr: true, errText: "duplicate alg"},
		{name: "alg none rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "none"}}, wantErr: true, errText: "unsupported"},
		{name: "unknown alg rejected", primary: "es256", algs: []IDTokenAlgConfig{{Alg: "hs256"}}, wantErr: true, errText: "unsupported"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateIDTokenAlgs(&Config{
				Keys: KeysConfig{Signing: SigningConfig{Alg: tc.primary}, IDTokenAlgs: tc.algs},
			})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("err=%v, want error containing %q", err, tc.errText)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateIDTokenAlgs() error = %v", err)
			}
		})
	}
}
