package authenticators

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ---- VerifyHash: bcrypt ----

func TestVerifyHash_Bcrypt(t *testing.T) {
	t.Parallel()
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate bcrypt: %v", err)
	}
	h := PasswordHash{Format: HashFormatBcrypt, Hash: string(hash)}

	if err := VerifyHash(context.Background(), h, "hunter2"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyHash(context.Background(), h, "wrong"); err == nil {
		t.Error("wrong password should be rejected")
	}
}

func TestVerifyHash_Bcrypt_MalformedHash(t *testing.T) {
	t.Parallel()
	h := PasswordHash{Format: HashFormatBcrypt, Hash: "not-a-bcrypt-hash"}
	if err := VerifyHash(context.Background(), h, "anything"); err == nil {
		t.Error("malformed bcrypt hash should return error")
	}
}

// ---- VerifyHash: argon2id ----

func TestVerifyHash_Argon2id(t *testing.T) {
	t.Parallel()
	encoded, err := EncodeArgon2id("secr3t", 65536, 3, 4, 32)
	if err != nil {
		t.Fatalf("EncodeArgon2id: %v", err)
	}
	h := PasswordHash{Format: HashFormatArgon2id, Hash: encoded}

	if err := VerifyHash(context.Background(), h, "secr3t"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyHash(context.Background(), h, "wrong"); err == nil {
		t.Error("wrong password should be rejected")
	}
}

func TestVerifyHash_Argon2id_MalformedHash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"wrong_algo", "$argon2i$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA"},
		{"bad_version", "$argon2id$v=18$m=65536,t=3,p=4$dGVzdA$dGVzdA"},
		{"zero_m", "$argon2id$v=19$m=0,t=3,p=4$dGVzdA$dGVzdA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := PasswordHash{Format: HashFormatArgon2id, Hash: tc.hash}
			if err := VerifyHash(context.Background(), h, "any"); err == nil {
				t.Errorf("expected error for hash %q, got nil", tc.hash)
			}
		})
	}
}

// ---- VerifyHash: PBKDF2-SHA256 ----

func TestVerifyHash_PBKDF2SHA256(t *testing.T) {
	t.Parallel()
	encoded, err := EncodePBKDF2SHA256("p@ssw0rd", 260000)
	if err != nil {
		t.Fatalf("EncodePBKDF2SHA256: %v", err)
	}
	h := PasswordHash{Format: HashFormatPBKDF2SHA256, Hash: encoded}

	if err := VerifyHash(context.Background(), h, "p@ssw0rd"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := VerifyHash(context.Background(), h, "wrong"); err == nil {
		t.Error("wrong password should be rejected")
	}
}

// TestVerifyHash_PBKDF2SHA256_RoundTrip verifies that EncodePBKDF2SHA256
// produces a hash that VerifyHash can check, exercising the full encode/verify
// path including the Django-style "pbkdf2_sha256$iter$salt$hash" encoding.
func TestVerifyHash_PBKDF2SHA256_RoundTrip(t *testing.T) {
	t.Parallel()
	enc, err := EncodePBKDF2SHA256("testpassword", 10000)
	if err != nil {
		t.Fatalf("EncodePBKDF2SHA256: %v", err)
	}
	h := PasswordHash{Format: HashFormatPBKDF2SHA256, Hash: enc}
	if err := VerifyHash(context.Background(), h, "testpassword"); err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
	if err := VerifyHash(context.Background(), h, "wrongpassword"); err == nil {
		t.Error("wrong password should be rejected in round-trip")
	}
}

// ---- VerifyHash: unknown format ----

func TestVerifyHash_UnknownFormat(t *testing.T) {
	t.Parallel()
	h := PasswordHash{Format: "md5", Hash: "5f4dcc3b5aa765d61d8327deb882cf99"}
	err := VerifyHash(context.Background(), h, "password")
	if err == nil {
		t.Fatal("unknown format should return error")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention 'unsupported format', got: %v", err)
	}
}

func TestVerifyHash_EmptyFormat(t *testing.T) {
	t.Parallel()
	h := PasswordHash{Format: "", Hash: ""}
	if err := VerifyHash(context.Background(), h, "anything"); err == nil {
		t.Error("empty format should return error")
	}
}

// ---- IsBcrypt ----

func TestPasswordHash_IsBcrypt(t *testing.T) {
	t.Parallel()
	if !(PasswordHash{Format: HashFormatBcrypt}).IsBcrypt() {
		t.Error("bcrypt hash should report IsBcrypt=true")
	}
	if (PasswordHash{Format: HashFormatArgon2id}).IsBcrypt() {
		t.Error("argon2id hash should report IsBcrypt=false")
	}
}
