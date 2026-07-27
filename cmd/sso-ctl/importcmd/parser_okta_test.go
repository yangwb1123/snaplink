package importcmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"golang.org/x/crypto/bcrypt"
)

// oktaBcryptFixture generates a REAL bcrypt hash and splits it the way Okta's
// export does — cost into workFactor, then the trailing 53 radix-64 chars into
// a 22-char salt and 31-char value — so the reconstruction test proves the
// concatenation yields the exact original modular-crypt string.
func oktaBcryptFixture(t *testing.T, password string) (workFactor int, salt, value, full string) {
	t.Helper()
	enc, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt generate: %v", err)
	}
	full = string(enc) // "$2a$04$" + 22-char salt + 31-char hash
	const prefixLen = len("$2a$04$")
	if len(full) != prefixLen+22+31 {
		t.Fatalf("unexpected bcrypt encoding length %d: %q", len(full), full)
	}
	return bcrypt.MinCost, full[prefixLen : prefixLen+22], full[prefixLen+22:], full
}

// TestParseOkta covers the array framing end-to-end: bcrypt reconstruction
// from split fields, profile mapping (login/email/firstName/lastName), the
// missing-credentials password-less path, and empty-row skipping.
func TestParseOkta(t *testing.T) {
	wf, salt, value, full := oktaBcryptFixture(t, "hunter2")
	in := fmt.Sprintf(`[
		{"id":"00u1","status":"ACTIVE",
		 "profile":{"login":"al@x.z","email":"al@x.z","firstName":"Al","lastName":"Ice"},
		 "credentials":{"password":{"hash":{"algorithm":"BCRYPT","workFactor":%d,"salt":"%s","value":"%s"}}}},
		{"id":"00u2","profile":{"login":"bob@x.z","email":"bob@x.z"}},
		{"id":"","profile":{"login":"","email":""}}
	]`, wf, salt, value)
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users; want 2 (empty row skipped)", len(users))
	}
	u := users[0]
	if u.Hash != full || u.HashFormat != "bcrypt" {
		t.Errorf("bcrypt reconstruction: hash=%q fmt=%q; want %q / bcrypt", u.Hash, u.HashFormat, full)
	}
	if u.ID != "okta:00u1" || u.ExternalID != "00u1" || u.Provider != "okta" {
		t.Errorf("identity fields wrong: %+v", u)
	}
	if u.Email != "al@x.z" || u.Name != "Al Ice" {
		t.Errorf("profile mapping wrong: %+v", u)
	}
	if users[1].Hash != "" || users[1].HashFormat != "" {
		t.Errorf("user without credentials should be password-less; got %+v", users[1])
	}
}

// TestParseOkta_BcryptRoundTrip drives the whole seam: parse → toSSOUser →
// real SQLite store → the SAME StoredHashVerifier the server wires for
// imported hashes, proving a reconstructed Okta bcrypt hash authenticates.
func TestParseOkta_BcryptRoundTrip(t *testing.T) {
	const password = "correct-horse-battery"
	wf, salt, value, full := oktaBcryptFixture(t, password)
	in := fmt.Sprintf(`[{"id":"00u9","profile":{"login":"rt@x.z","email":"rt@x.z"},`+
		`"credentials":{"password":{"hash":{"algorithm":"BCRYPT","workFactor":%d,"salt":"%s","value":"%s"}}}}]`,
		wf, salt, value)
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta: %v", err)
	}

	// Attribute shape is the contract StoredHashVerifier reads (its Attr* keys).
	su := toSSOUser(users[0])
	if su.Attributes[authenticators.AttrPasswordHash] != full ||
		su.Attributes[authenticators.AttrPasswordHashFormat] != authenticators.HashFormatBcrypt {
		t.Fatalf("attribute seam wrong: %+v", su.Attributes)
	}

	ctx := context.Background()
	p := newTestProvider(t)
	if err := runImport(ctx, p, users, 100); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	// MinCost dummy keeps the miss-path precompute fast in tests.
	v := authenticators.NewStoredHashVerifier(p, authenticators.WithStoredHashDummyCost(bcrypt.MinCost))
	res, err := v.Verify(ctx, "okta:00u9", password)
	if err != nil {
		t.Fatalf("imported okta bcrypt user failed to authenticate: %v", err)
	}
	if res.UserID != "okta:00u9" {
		t.Errorf("UserID = %q; want okta:00u9", res.UserID)
	}
	if _, err := v.Verify(ctx, "okta:00u9", "wrong-password"); err == nil {
		t.Error("wrong password must not verify")
	}
}

// TestParseOkta_BcryptPassthrough — some exports carry the complete
// modular-crypt string in value; it must pass through unmodified.
func TestParseOkta_BcryptPassthrough(t *testing.T) {
	const full = "$2b$10$abcdefghijklmnopqrstuvabcdefghijklmnopqrstuvabcdefghi"
	in := `[{"id":"00u3","profile":{"login":"p@x.z"},` +
		`"credentials":{"password":{"hash":{"algorithm":"BCRYPT","value":"` + full + `"}}}}]`
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta: %v", err)
	}
	if users[0].Hash != full || users[0].HashFormat != "bcrypt" {
		t.Errorf("passthrough hash=%q fmt=%q; want unmodified bcrypt", users[0].Hash, users[0].HashFormat)
	}
}

// TestParseOkta_BcryptBadMaterial — malformed split fields cannot produce a
// verifiable hash and must fail the parse, not import a locked-out user.
func TestParseOkta_BcryptBadMaterial(t *testing.T) {
	cases := []struct {
		name, hashJSON, wantSub string
	}{
		{"short-salt", `{"algorithm":"BCRYPT","workFactor":10,"salt":"tooshort","value":"abcdefghijklmnopqrstuvwxyz01234"}`, "radix-64 salt"},
		{"short-value", `{"algorithm":"BCRYPT","workFactor":10,"salt":"abcdefghijklmnopqrstuv","value":"short"}`, "radix-64 salt"},
		{"bad-cost", `{"algorithm":"BCRYPT","workFactor":99,"salt":"abcdefghijklmnopqrstuv","value":"abcdefghijklmnopqrstuvwxyz01234"}`, "workFactor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := `[{"id":"00u4","profile":{"login":"bad@x.z"},"credentials":{"password":{"hash":` + tc.hashJSON + `}}}]`
			_, err := parseInput("okta", strings.NewReader(in))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) || !strings.Contains(err.Error(), "bad@x.z") {
				t.Errorf("want error naming %q and the login; got %v", tc.wantSub, err)
			}
		})
	}
}

// TestParseOkta_PBKDF2SHA256RoundTrip — the reconstructed encoding must be
// byte-identical to what EncodePBKDF2SHA256 emits (the exact serialization
// the verifier's parsePBKDF2 reads) and must verify the original plaintext.
func TestParseOkta_PBKDF2SHA256RoundTrip(t *testing.T) {
	const password = "s3cret-pw"
	encoded, err := authenticators.EncodePBKDF2SHA256(password, 1000)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	parts := strings.Split(encoded, "$") // pbkdf2_sha256 $ iter $ salt $ hash
	if len(parts) != 4 {
		t.Fatalf("unexpected fixture shape: %q", encoded)
	}
	in := fmt.Sprintf(`[{"id":"00u5","profile":{"login":"pb@x.z","email":"pb@x.z"},`+
		`"credentials":{"password":{"hash":{"algorithm":"PBKDF2","digestAlgorithm":"SHA256_HMAC",`+
		`"iterationCount":%s,"keySize":32,"salt":"%s","value":"%s"}}}}]`, parts[1], parts[2], parts[3])
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta: %v", err)
	}
	if users[0].Hash != encoded || users[0].HashFormat != "pbkdf2-sha256" {
		t.Fatalf("hash=%q fmt=%q; want %q / pbkdf2-sha256", users[0].Hash, users[0].HashFormat, encoded)
	}
	su := toSSOUser(users[0])
	ph := authenticators.PasswordHash{
		Format: su.Attributes[authenticators.AttrPasswordHashFormat],
		Hash:   su.Attributes[authenticators.AttrPasswordHash],
	}
	if err := authenticators.VerifyHash(context.Background(), ph, password); err != nil {
		t.Errorf("imported pbkdf2 hash failed to verify: %v", err)
	}
	if err := authenticators.VerifyHash(context.Background(), ph, "wrong"); err == nil {
		t.Error("wrong password must not verify")
	}
}

// TestParseOkta_PBKDF2SHA512Shape — SHA512 maps to the pbkdf2_sha512 prefix
// and requires a 64-byte derived key. Digest spelling variants are accepted.
func TestParseOkta_PBKDF2SHA512Shape(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString(make([]byte, 16))
	value := base64.StdEncoding.EncodeToString(make([]byte, 64))
	for _, digest := range []string{"SHA512_HMAC", "SHA512", "SHA-512"} {
		in := fmt.Sprintf(`[{"id":"00u6","profile":{"login":"pb512@x.z"},`+
			`"credentials":{"password":{"hash":{"algorithm":"PBKDF2","digestAlgorithm":"%s",`+
			`"iterationCount":5000,"keySize":64,"salt":"%s","value":"%s"}}}}]`, digest, salt, value)
		users, err := parseInput("okta", strings.NewReader(in))
		if err != nil {
			t.Fatalf("digest %q: %v", digest, err)
		}
		want := "pbkdf2_sha512$5000$" + salt + "$" + value
		if users[0].Hash != want || users[0].HashFormat != "pbkdf2-sha512" {
			t.Errorf("digest %q: hash=%q fmt=%q; want %q / pbkdf2-sha512",
				digest, users[0].Hash, users[0].HashFormat, want)
		}
	}
}

// TestParseOkta_PBKDF2BadMaterial — parameters the verifier can never match
// (wrong key size, bad base64, unknown digest, bad iterations) fail loudly.
func TestParseOkta_PBKDF2BadMaterial(t *testing.T) {
	salt16 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	key16 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name, hashJSON, wantSub string
	}{
		{"wrong-key-size",
			`{"algorithm":"PBKDF2","digestAlgorithm":"SHA256_HMAC","iterationCount":1000,"keySize":16,"salt":"` + salt16 + `","value":"` + key16 + `"}`,
			"derived key is 16 bytes"},
		{"bad-digest",
			`{"algorithm":"PBKDF2","digestAlgorithm":"SHA1","iterationCount":1000,"keySize":32,"salt":"` + salt16 + `","value":"` + key32 + `"}`,
			"digestAlgorithm"},
		{"bad-iterations",
			`{"algorithm":"PBKDF2","digestAlgorithm":"SHA256","iterationCount":0,"keySize":32,"salt":"` + salt16 + `","value":"` + key32 + `"}`,
			"iterationCount"},
		{"bad-salt-b64",
			`{"algorithm":"PBKDF2","digestAlgorithm":"SHA256","iterationCount":1000,"keySize":32,"salt":"!!!","value":"` + key32 + `"}`,
			"salt is not base64"},
		{"bad-value-b64",
			`{"algorithm":"PBKDF2","digestAlgorithm":"SHA256","iterationCount":1000,"keySize":32,"salt":"` + salt16 + `","value":"!!!"}`,
			"value is not base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := `[{"id":"00u7","profile":{"login":"pbbad@x.z"},"credentials":{"password":{"hash":` + tc.hashJSON + `}}}]`
			_, err := parseInput("okta", strings.NewReader(in))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("want error containing %q; got %v", tc.wantSub, err)
			}
		})
	}
}

// TestParseOkta_UnsupportedAlgorithmRejected — the verifier matrix has no
// salted-digest support, so these must abort the import naming the algorithm
// and the record, never import a silently unusable hash.
func TestParseOkta_UnsupportedAlgorithmRejected(t *testing.T) {
	for _, alg := range []string{"SHA-256", "SHA-512", "SHA-1", "MD5", "scrypt"} {
		t.Run(alg, func(t *testing.T) {
			in := fmt.Sprintf(`[{"id":"00u8","profile":{"login":"legacy@x.z"},`+
				`"credentials":{"password":{"hash":{"algorithm":"%s","salt":"c2FsdA==","saltOrder":"PREFIX","value":"aGFzaA=="}}}}]`, alg)
			_, err := parseInput("okta", strings.NewReader(in))
			if err == nil {
				t.Fatalf("algorithm %s must be rejected", alg)
			}
			if !strings.Contains(err.Error(), alg) || !strings.Contains(err.Error(), "legacy@x.z") {
				t.Errorf("error must name the algorithm and the user; got %v", err)
			}
		})
	}
}

// TestParseOkta_NDJSON — newline-delimited user objects (streaming export
// framing). The FIRST object carries nested credentials to prove the
// token-stream rebuild path preserves the hash object.
func TestParseOkta_NDJSON(t *testing.T) {
	wf, salt, value, full := oktaBcryptFixture(t, "ndjson-pw")
	in := fmt.Sprintf(`{"id":"00un1","profile":{"login":"n1@x.z","email":"n1@x.z","firstName":"En","lastName":"One"},"credentials":{"password":{"hash":{"algorithm":"BCRYPT","workFactor":%d,"salt":"%s","value":"%s"}}}}
{"id":"00un2","profile":{"login":"n2@x.z","email":"n2@x.z"}}
`, wf, salt, value)
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta ndjson: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users; want 2: %+v", len(users), users)
	}
	if users[0].Hash != full || users[0].HashFormat != "bcrypt" || users[0].Name != "En One" {
		t.Errorf("first ndjson user lost fields through the rebuild: %+v", users[0])
	}
	if users[1].ID != "okta:00un2" || users[1].Hash != "" {
		t.Errorf("second ndjson user wrong: %+v", users[1])
	}
}

// TestParseOkta_LoginFallbackID — no top-level id falls back to login for
// ExternalID / ID derivation (Advanced Server Access exports omit id).
func TestParseOkta_LoginFallbackID(t *testing.T) {
	in := `[{"profile":{"login":"only-login@x.z"}}]`
	users, err := parseInput("okta", strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseOkta: %v", err)
	}
	if users[0].ID != "okta:only-login@x.z" || users[0].ExternalID != "only-login@x.z" {
		t.Errorf("login fallback wrong: %+v", users[0])
	}
}

func TestParseOkta_BadInput(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"garbage":          "not json",
		"top-level-scalar": `"a string"`,
		"bad-array-elem":   `[{"id":"x"}, 42]`,
		"truncated-object": `{"id":"x","profile":`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInput("okta", strings.NewReader(in)); err == nil {
				t.Fatalf("input %q must fail to parse", in)
			}
		})
	}
}

// TestParseInput_UnknownFormatNamesOkta — the format enumeration in the
// error message must advertise the okta format.
func TestParseInput_UnknownFormatNamesOkta(t *testing.T) {
	_, err := parseInput("ldif", strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "okta") {
		t.Errorf("unknown-format error should enumerate okta; got %v", err)
	}
}
