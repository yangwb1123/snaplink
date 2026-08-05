package passwordhash

import (
	"testing"
)

func TestHashAndVerify_RoundTrip(t *testing.T) {
	h, err := Hash("hunter2", DefaultCost)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !IsBcrypt(h) {
		t.Fatalf("hash %q not recognized as bcrypt", h)
	}
	if !Verify(h, "hunter2") {
		t.Error("correct plaintext rejected")
	}
	if Verify(h, "hunter3") {
		t.Error("wrong plaintext accepted")
	}
}

func TestVerify_RejectsUnknownFormats(t *testing.T) {
	// Plaintext stored masquerading as a hash must never verify (import
	// boundaries reject it too; this is the second line of defense).
	if Verify("hunter2", "hunter2") {
		t.Error("plaintext stored value verified as a hash")
	}
	if Verify("$argon2id$v=19$m=65536", "anything") {
		t.Error("unknown algorithm prefix verified")
	}
	if Verify("", "") {
		t.Error("empty stored hash verified")
	}
}

func TestCost_RecognizesBcryptOnly(t *testing.T) {
	h, _ := Hash("x", 10)
	if c, ok := Cost(h); !ok || c != 10 {
		t.Errorf("Cost(bcrypt) = (%d, %v), want (10, true)", c, ok)
	}
	if _, ok := Cost("plain"); ok {
		t.Error("Cost(plain) reported ok")
	}
}

func TestNeedsRehash_Policy(t *testing.T) {
	low, _ := Hash("x", MinCost)
	high, _ := Hash("x", DefaultCost)
	if !NeedsRehash(low, DefaultCost) {
		t.Error("cost-below-target hash not flagged for rehash")
	}
	if NeedsRehash(high, DefaultCost) {
		t.Error("at-target hash flagged for rehash")
	}
	if !NeedsRehash("unrecognized-format", DefaultCost) {
		t.Error("unrecognized format not flagged for rehash")
	}
	if !NeedsRehash("", DefaultCost) {
		// empty stored hash: cannot verify under any policy — flagging it
		// drives the login upgrade path to mint a real hash.
		t.Error("empty stored hash not flagged")
	}
}

func TestDummyHash_ConsistentAndCosted(t *testing.T) {
	d1, err := DummyHash(DefaultCost)
	if err != nil {
		t.Fatalf("DummyHash: %v", err)
	}
	d2, _ := DummyHash(DefaultCost)
	// Salt makes the two dumps differ; what must hold is identical cost and
	// verifiability against DummyPassword.
	if string(d1) == string(d2) {
		t.Error("two dumps identical (missing salt)")
	}
	if !Verify(string(d1), DummyPassword) || !Verify(string(d2), DummyPassword) {
		t.Error("dummy does not verify against DummyPassword")
	}
	for _, d := range [][]byte{d1, d2} {
		if c, ok := Cost(string(d)); !ok || c != DefaultCost {
			t.Errorf("dummy cost = (%d, %v), want (%d, true)", c, ok, DefaultCost)
		}
	}
}
