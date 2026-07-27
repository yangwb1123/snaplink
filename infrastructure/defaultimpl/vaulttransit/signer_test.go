package vaulttransit_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/cryptosigner"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/vaulttransit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// fakeVault is an httptest-backed stand-in for a Vault transit engine. It is a
// fake EXTERNAL SERVICE (the awskms/azure local-key-fake pattern), NOT a
// storage mock: it holds a real in-process private key and answers the two
// transit REST operations this signer uses (GET keys/:name read-key, POST
// sign/:name) in Vault's exact wire format — so the crypto path is exercised
// end to end with no real Vault.
type fakeVault struct {
	t           *testing.T
	transitType string // "ecdsa-p256" | "rsa-2048" | "ed25519" | ...
	ec          *ecdsa.PrivateKey
	rsaKey      *rsa.PrivateKey
	edPub       ed25519.PublicKey
	edPriv      ed25519.PrivateKey

	server *httptest.Server

	// observed request facts, for assertions.
	mu              sync.Mutex
	lastToken       string
	lastNamespace   string
	lastSignBody    map[string]any
	keyReads        int32
	wantToken       string // if set, 403 when X-Vault-Token mismatches (re-auth path)
	forceStatus     int    // if non-zero, every request returns this status
	forceSignStatus int    // if non-zero, sign requests return this status
	corruptSig      bool   // if true, return a malformed/empty signature wrapper
	corruptKind     string // "no-prefix" | "empty" | "bad-b64" | "bad-version"
}

func newFakeVault(t *testing.T, transitType string) *fakeVault {
	t.Helper()
	fv := &fakeVault{t: t, transitType: transitType}
	switch transitType {
	case "ecdsa-p256":
		fv.ec = mustGenECDSA(t, elliptic.P256())
	case "ecdsa-p384":
		fv.ec = mustGenECDSA(t, elliptic.P384())
	case "ecdsa-p521":
		fv.ec = mustGenECDSA(t, elliptic.P521())
	case "rsa-2048":
		fv.rsaKey = mustGenRSA(t, 2048)
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("gen ed25519: %v", err)
		}
		fv.edPub, fv.edPriv = pub, priv
	default:
		t.Fatalf("unsupported fake transit type %q", transitType)
	}
	fv.server = httptest.NewTLSServer(http.HandlerFunc(fv.handle))
	t.Cleanup(fv.server.Close)
	return fv
}

func mustGenECDSA(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("gen ecdsa: %v", err)
	}
	return k
}

func mustGenRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	return k
}

// addr returns the fake Vault's https base URL.
func (fv *fakeVault) addr() string { return fv.server.URL }

// client returns the httptest server's client, which trusts its self-signed
// TLS cert. (A real operator would supply a client trusting their Vault CA;
// the DEFAULT client would correctly REFUSE this self-signed cert — proving
// the default verifies TLS, which a separate test asserts.)
func (fv *fakeVault) client() *http.Client { return fv.server.Client() }

func (fv *fakeVault) publicKey() crypto.PublicKey {
	switch {
	case fv.ec != nil:
		return &fv.ec.PublicKey
	case fv.rsaKey != nil:
		return &fv.rsaKey.PublicKey
	default:
		return fv.edPub
	}
}

func (fv *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	fv.mu.Lock()
	fv.lastToken = r.Header.Get("X-Vault-Token")
	fv.lastNamespace = r.Header.Get("X-Vault-Namespace")
	wantToken := fv.wantToken
	forceStatus := fv.forceStatus
	forceSignStatus := fv.forceSignStatus
	fv.mu.Unlock()

	if forceStatus != 0 {
		http.Error(w, `{"errors":["forced failure"]}`, forceStatus)
		return
	}
	if wantToken != "" && r.Header.Get("X-Vault-Token") != wantToken {
		// Emulate Vault's 403 on a stale/wrong token (the re-auth trigger).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
		return
	}

	switch {
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/keys/"):
		fv.handleReadKey(w, r)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/sign/"):
		if forceSignStatus != 0 {
			http.Error(w, `{"errors":["sign refused"]}`, forceSignStatus)
			return
		}
		fv.handleSign(w, r)
	default:
		http.Error(w, `{"errors":["no handler"]}`, http.StatusNotFound)
	}
}

func (fv *fakeVault) handleReadKey(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&fv.keyReads, 1)
	der, err := x509.MarshalPKIXPublicKey(fv.publicKey())
	if err != nil {
		fv.t.Fatalf("marshal pkix: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	resp := map[string]any{
		"data": map[string]any{
			"type":           fv.transitType,
			"latest_version": 1,
			"keys": map[string]any{
				"1": map[string]any{
					"public_key": string(pemBytes),
				},
			},
		},
	}
	writeJSON(w, resp)
}

func (fv *fakeVault) handleSign(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"errors":["bad body"]}`, http.StatusBadRequest)
		return
	}
	fv.mu.Lock()
	fv.lastSignBody = body
	corrupt := fv.corruptSig
	corruptKind := fv.corruptKind
	fv.mu.Unlock()

	inputB64, _ := body["input"].(string)
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		http.Error(w, `{"errors":["bad input b64"]}`, http.StatusBadRequest)
		return
	}

	var rawSig []byte
	switch {
	case fv.ec != nil:
		// EC/RSA arrive prehashed; transit signs the supplied digest. With
		// marshaling_algorithm=asn1, transit returns ASN.1 DER — produced here
		// by ecdsa.SignASN1, which is exactly Vault's asn1 marshaling.
		marshaling, _ := body["marshaling_algorithm"].(string)
		if marshaling != "asn1" {
			fv.t.Errorf("ECDSA sign marshaling_algorithm = %q, want asn1", marshaling)
		}
		if prehashed, _ := body["prehashed"].(bool); !prehashed {
			fv.t.Error("ECDSA sign missing prehashed=true")
		}
		der, serr := ecdsa.SignASN1(rand.Reader, fv.ec, input)
		if serr != nil {
			fv.t.Fatalf("ec sign: %v", serr)
		}
		rawSig = der
	case fv.rsaKey != nil:
		if prehashed, _ := body["prehashed"].(bool); !prehashed {
			fv.t.Error("RSA sign missing prehashed=true")
		}
		sigAlg, _ := body["signature_algorithm"].(string)
		var serr error
		switch sigAlg {
		case "pss":
			rawSig, serr = rsa.SignPSS(rand.Reader, fv.rsaKey, crypto.SHA256, input, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		case "pkcs1v15":
			rawSig, serr = rsa.SignPKCS1v15(rand.Reader, fv.rsaKey, crypto.SHA256, input)
		default:
			fv.t.Errorf("RSA sign signature_algorithm = %q, want pss/pkcs1v15", sigAlg)
			http.Error(w, `{"errors":["bad sig alg"]}`, http.StatusBadRequest)
			return
		}
		if serr != nil {
			fv.t.Fatalf("rsa sign: %v", serr)
		}
	default:
		// Ed25519: transit signs the RAW message (NOT prehashed). Assert the
		// request carries the full message and no prehash / hash_algorithm.
		if _, ok := body["prehashed"]; ok {
			if ph, _ := body["prehashed"].(bool); ph {
				fv.t.Error("Ed25519 sign must not set prehashed=true")
			}
		}
		if _, ok := body["hash_algorithm"]; ok {
			fv.t.Errorf("Ed25519 sign must not carry hash_algorithm, got %v", body["hash_algorithm"])
		}
		rawSig = ed25519.Sign(fv.edPriv, input)
	}

	if corrupt {
		switch corruptKind {
		case "no-prefix":
			writeJSON(w, map[string]any{"data": map[string]any{"signature": base64.StdEncoding.EncodeToString(rawSig)}})
		case "empty":
			writeJSON(w, map[string]any{"data": map[string]any{"signature": "vault:v1:"}})
		case "bad-b64":
			writeJSON(w, map[string]any{"data": map[string]any{"signature": "vault:v1:@@not-base64@@"}})
		case "bad-version":
			writeJSON(w, map[string]any{"data": map[string]any{"signature": "vault:x:" + base64.StdEncoding.EncodeToString(rawSig)}})
		default:
			fv.t.Fatalf("unknown corruptKind %q", corruptKind)
		}
		return
	}

	writeJSON(w, map[string]any{
		"data": map[string]any{
			"key_version": 1,
			"signature":   "vault:v1:" + base64.StdEncoding.EncodeToString(rawSig),
		},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// staticToken is a TokenSource closure that returns a fixed token and counts
// calls, to assert the per-request contract.
func staticToken(token string, counter *int32) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		atomic.AddInt32(counter, 1)
		return token, nil
	}
}

func newSigner(t *testing.T, fv *fakeVault, mutate func(*vaulttransit.Config)) *vaulttransit.Signer {
	t.Helper()
	var count int32
	cfg := vaulttransit.Config{
		VaultAddr:   fv.addr(),
		KeyName:     "sso-signing",
		TokenSource: staticToken("s.test-token", &count),
		HTTPClient:  fv.client(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	sgn, err := vaulttransit.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return sgn
}

// --- THE critical test: full crypto.Signer -> cryptosigner bridge -> real
// issuer -> JWS -> Validate round-trip, per algorithm. This is the only
// assertion that proves the signature format, the bridge wiring, AND the JWKS
// public key all agree (it catches the ECDSA asn1=DER -> R||S conversion and
// the Ed25519-message vs digest distinction being wrong).

func TestEndToEnd_ECDSA_P256(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	sgn := newSigner(t, fv, nil)

	bridge, pub, err := cryptosigner.ECDSA(sgn)
	if err != nil {
		t.Fatalf("cryptosigner.ECDSA: %v", err)
	}
	if !pub.Equal(&fv.ec.PublicKey) {
		t.Fatal("bridge public key != transit key")
	}
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(bridge, pub, "vault-es256"),
	)
	assertIssueValidate(t, iss, iss)

	// Direct ecdsa.VerifyASN1 against Public(): the signer is a faithful
	// crypto.Signer (asn1/DER round-trips the stdlib verifier).
	msg := []byte("direct ecdsa message")
	dgst := sha256.Sum256(msg)
	der, err := sgn.Sign(rand.Reader, dgst[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("direct Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&fv.ec.PublicKey, dgst[:], der) {
		t.Fatal("ecdsa.VerifyASN1 rejected the transit DER signature")
	}
}

func TestEndToEnd_RSA(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{cryptosigner.AlgRS256, cryptosigner.AlgPS256} {
		t.Run(alg, func(t *testing.T) {
			fv := newFakeVault(t, "rsa-2048")
			sgn := newSigner(t, fv, nil)

			bridge, pub, err := cryptosigner.RSA(sgn, alg)
			if err != nil {
				t.Fatalf("cryptosigner.RSA: %v", err)
			}
			if !pub.Equal(&fv.rsaKey.PublicKey) {
				t.Fatal("bridge public key != transit key")
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(alg),
				defaultimpl.WithRSAExternalSigner(bridge, pub, "vault-"+alg),
			)
			assertIssueValidate(t, iss, iss)

			// Direct rsa.Verify against Public().
			msg := []byte("direct rsa message")
			dgst := sha256.Sum256(msg)
			var opts crypto.SignerOpts = crypto.SHA256
			if alg == cryptosigner.AlgPS256 {
				opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
			}
			sig, err := sgn.Sign(rand.Reader, dgst[:], opts)
			if err != nil {
				t.Fatalf("direct Sign: %v", err)
			}
			if alg == cryptosigner.AlgPS256 {
				if err := rsa.VerifyPSS(&fv.rsaKey.PublicKey, crypto.SHA256, dgst[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err != nil {
					t.Fatalf("rsa.VerifyPSS rejected: %v", err)
				}
			} else {
				if err := rsa.VerifyPKCS1v15(&fv.rsaKey.PublicKey, crypto.SHA256, dgst[:], sig); err != nil {
					t.Fatalf("rsa.VerifyPKCS1v15 rejected: %v", err)
				}
			}
		})
	}
}

func TestEndToEnd_Ed25519(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ed25519")
	sgn := newSigner(t, fv, nil)

	bridge, pub, err := cryptosigner.Ed25519(sgn)
	if err != nil {
		t.Fatalf("cryptosigner.Ed25519: %v", err)
	}
	if !pub.Equal(fv.edPub) {
		t.Fatal("bridge public key != transit key")
	}
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(bridge, pub, "vault-ed25519"),
	)
	assertIssueValidate(t, iss, iss)

	// Ed25519 signs the MESSAGE, not a digest: assert the fake received the
	// full message as input, and verify directly.
	msg := []byte("ed25519 raw message that is not a digest")
	sig, err := sgn.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("direct Sign: %v", err)
	}
	if !ed25519.Verify(fv.edPub, msg, sig) {
		t.Fatal("ed25519.Verify rejected the transit signature")
	}
	fv.mu.Lock()
	gotInputB64, _ := fv.lastSignBody["input"].(string)
	fv.mu.Unlock()
	gotInput, _ := base64.StdEncoding.DecodeString(gotInputB64)
	if string(gotInput) != string(msg) {
		t.Fatalf("Ed25519 transit input = %q, want the raw message %q", gotInput, msg)
	}
}

// Higher curves end-to-end via the direct stdlib verifier (the cryptosigner
// bridge's ECDSA path is P-256 only, so the issuer round-trip covers P-256;
// these prove the signer's curve<->hash pairing + DER round-trip for P-384/521).
func TestEndToEnd_ECDSA_HigherCurves(t *testing.T) {
	t.Parallel()
	cases := []struct {
		transitType string
		hash        crypto.Hash
		sum         func([]byte) []byte
	}{
		{"ecdsa-p384", crypto.SHA384, func(b []byte) []byte { h := crypto.SHA384.New(); h.Write(b); return h.Sum(nil) }},
		{"ecdsa-p521", crypto.SHA512, func(b []byte) []byte { h := crypto.SHA512.New(); h.Write(b); return h.Sum(nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.transitType, func(t *testing.T) {
			fv := newFakeVault(t, tc.transitType)
			sgn := newSigner(t, fv, nil)
			if pub := sgn.Public().(*ecdsa.PublicKey); !pub.Equal(&fv.ec.PublicKey) {
				t.Fatal("Public() != transit key")
			}
			dgst := tc.sum([]byte("higher curve message"))
			der, err := sgn.Sign(rand.Reader, dgst, tc.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ecdsa.VerifyASN1(&fv.ec.PublicKey, dgst, der) {
				t.Fatalf("%s: VerifyASN1 rejected the transit DER signature", tc.transitType)
			}
		})
	}
}

// --- hash<->curve mismatch must fail closed with NO HTTP call.

func TestHashCurveMismatch_FailsClosed_NoHTTPCall(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	var tokenCalls int32
	sgn := newSigner(t, fv, func(c *vaulttransit.Config) {
		c.TokenSource = staticToken("s.tok", &tokenCalls)
	})
	// Prime the public key (one read-key GET, which calls the token source).
	if _, err := sgn.PublicKey(context.Background()); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	readsBefore := atomic.LoadInt32(&fv.keyReads)
	tokenBefore := atomic.LoadInt32(&tokenCalls)

	// P-256 key + SHA-384 digest: must reject before any sign round-trip.
	dgst := make([]byte, 48)
	if _, err := sgn.Sign(rand.Reader, dgst, crypto.SHA384); err == nil {
		t.Fatal("P-256 + SHA-384 did not fail closed")
	}
	// hash==0 (Ed25519-shaped) on an EC key must also fail closed.
	if _, err := sgn.Sign(rand.Reader, dgst, crypto.Hash(0)); err == nil {
		t.Fatal("P-256 + hash==0 did not fail closed")
	}

	fv.mu.Lock()
	signBody := fv.lastSignBody
	fv.mu.Unlock()
	if signBody != nil {
		t.Error("a sign request reached Vault despite the hash<->curve mismatch")
	}
	// No new read-key and no new token-source call should have occurred for the
	// rejected signs (the public key was already cached; the rejection is local).
	if got := atomic.LoadInt32(&fv.keyReads); got != readsBefore {
		t.Errorf("read-key count changed on mismatch: before %d after %d", readsBefore, got)
	}
	if got := atomic.LoadInt32(&tokenCalls); got != tokenBefore {
		t.Errorf("token source called on a locally-rejected sign: before %d after %d", tokenBefore, got)
	}
}

// --- Vault failure modes fail closed, and the token never leaks.

func TestVaultErrorFailsClosed(t *testing.T) {
	t.Parallel()
	t.Run("read-key 5xx", func(t *testing.T) {
		fv := newFakeVault(t, "ecdsa-p256")
		fv.mu.Lock()
		fv.forceStatus = http.StatusInternalServerError
		fv.mu.Unlock()
		sgn := newSigner(t, fv, nil)
		_, err := sgn.PublicKey(context.Background())
		if err == nil {
			t.Fatal("read-key 500 did not fail closed")
		}
		assertNoToken(t, err)
	})

	t.Run("sign 403", func(t *testing.T) {
		fv := newFakeVault(t, "ecdsa-p256")
		sgn := newSigner(t, fv, nil)
		// Public OK, then force sign to 403.
		if _, err := sgn.PublicKey(context.Background()); err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		fv.mu.Lock()
		fv.forceSignStatus = http.StatusForbidden
		fv.mu.Unlock()
		dgst := sha256.Sum256([]byte("m"))
		_, err := sgn.Sign(rand.Reader, dgst[:], crypto.SHA256)
		if err == nil {
			t.Fatal("sign 403 did not fail closed")
		}
		assertNoToken(t, err)
	})
}

func TestMalformedSignature_FailsClosed(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"no-prefix", "empty", "bad-b64", "bad-version"} {
		t.Run(kind, func(t *testing.T) {
			fv := newFakeVault(t, "ecdsa-p256")
			fv.mu.Lock()
			fv.corruptSig = true
			fv.corruptKind = kind
			fv.mu.Unlock()
			sgn := newSigner(t, fv, nil)
			dgst := sha256.Sum256([]byte("m"))
			if _, err := sgn.Sign(rand.Reader, dgst[:], crypto.SHA256); err == nil {
				t.Fatalf("corrupt signature (%s) did not fail closed", kind)
			}
		})
	}
}

// assertNoToken fails if the secret token string ever appears in an error.
func assertNoToken(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "s.test-token") || strings.Contains(err.Error(), "s.tok") {
		t.Fatalf("Vault token leaked into error: %v", err)
	}
}

// --- TokenSource is called PER request; the namespace header is set.

func TestTokenSourceCalledPerRequest(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	var calls int32
	sgn := newSigner(t, fv, func(c *vaulttransit.Config) {
		c.TokenSource = staticToken("s.per-req", &calls)
		c.Namespace = "team-x"
	})
	if _, err := sgn.PublicKey(context.Background()); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	afterRead := atomic.LoadInt32(&calls)
	if afterRead < 1 {
		t.Fatalf("token source not called for read-key (got %d)", afterRead)
	}
	dgst := sha256.Sum256([]byte("m"))
	for i := 0; i < 3; i++ {
		if _, err := sgn.Sign(rand.Reader, dgst[:], crypto.SHA256); err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
	}
	// 3 signs => at least 3 more token-source calls (public key is cached, so
	// no more read-key calls; each sign still fetches a fresh token).
	if got := atomic.LoadInt32(&calls); got < afterRead+3 {
		t.Errorf("token source calls = %d, want >= %d (per-request)", got, afterRead+3)
	}
	fv.mu.Lock()
	gotNS := fv.lastNamespace
	fv.mu.Unlock()
	if gotNS != "team-x" {
		t.Errorf("X-Vault-Namespace = %q, want team-x", gotNS)
	}
}

// A renewing token source: the fake demands a specific token; a stale token
// 403s, then the source rotates to the accepted token and the sign succeeds.
// Proves the operator owns token lifecycle (re-auth happens outside the signer).
func TestTokenSource_Renewal(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ed25519")
	fv.mu.Lock()
	fv.wantToken = "s.good"
	fv.mu.Unlock()

	var current atomic.Value
	current.Store("s.stale")
	cfg := vaulttransit.Config{
		VaultAddr:  fv.addr(),
		KeyName:    "sso-signing",
		HTTPClient: fv.client(),
		TokenSource: func(context.Context) (string, error) {
			return current.Load().(string), nil
		},
	}
	sgn, err := vaulttransit.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	// Stale token => 403 fail-closed.
	if _, err := sgn.PublicKey(context.Background()); err == nil {
		t.Fatal("stale token did not fail closed")
	} else {
		assertNoToken(t, err)
	}
	// Operator renews; the next call (fresh token per request) succeeds.
	current.Store("s.good")
	if _, err := sgn.PublicKey(context.Background()); err != nil {
		t.Fatalf("after renewal PublicKey: %v", err)
	}
}

// --- Public-key cache: one read-key GET for N signs; a fetch error is retried.

func TestPublicKeyCached_OneReadForManySigns(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "rsa-2048")
	sgn := newSigner(t, fv, nil)
	dgst := sha256.Sum256([]byte("m"))
	for i := 0; i < 5; i++ {
		if _, err := sgn.Sign(rand.Reader, dgst[:], crypto.SHA256); err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&fv.keyReads); got != 1 {
		t.Errorf("read-key fetched %d times for 5 signs, want exactly 1 (cache)", got)
	}
}

func TestPublicKeyFetchError_NotCached_Retried(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	fv.mu.Lock()
	fv.forceStatus = http.StatusServiceUnavailable
	fv.mu.Unlock()
	sgn := newSigner(t, fv, nil)

	// First fetch fails (transient outage) — must NOT be cached.
	if _, err := sgn.PublicKey(context.Background()); err == nil {
		t.Fatal("expected first PublicKey to fail")
	}
	// Vault recovers; the next call must RE-ATTEMPT (a poisoned cache would
	// keep failing forever — the awskms 6bda097 lesson).
	fv.mu.Lock()
	fv.forceStatus = 0
	fv.mu.Unlock()
	pub, err := sgn.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey after recovery: %v", err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(&fv.ec.PublicKey) {
		t.Fatal("recovered public key mismatch")
	}
}

// Concurrent signs while the public key is fetched: race-detector coverage for
// the cache mutex (run under -race -count=10).
func TestConcurrentSigns(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ed25519")
	sgn := newSigner(t, fv, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("msg-%d", n))
			sig, err := sgn.Sign(rand.Reader, msg, crypto.Hash(0))
			if err != nil {
				errs <- err
				return
			}
			if !ed25519.Verify(fv.edPub, msg, sig) {
				errs <- fmt.Errorf("verify failed for %d", n)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := atomic.LoadInt32(&fv.keyReads); got != 1 {
		t.Errorf("concurrent signs caused %d read-key fetches, want 1", got)
	}
}

// --- Config validation.

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	good := func() vaulttransit.Config {
		return vaulttransit.Config{
			VaultAddr:   "https://vault.example:8200",
			KeyName:     "k",
			TokenSource: func(context.Context) (string, error) { return "t", nil },
		}
	}
	cases := []struct {
		name   string
		mutate func(*vaulttransit.Config)
		wantOK bool
	}{
		{"valid", func(*vaulttransit.Config) {}, true},
		{"http rejected", func(c *vaulttransit.Config) { c.VaultAddr = "http://vault.example:8200" }, false},
		{"empty addr", func(c *vaulttransit.Config) { c.VaultAddr = "" }, false},
		{"no scheme", func(c *vaulttransit.Config) { c.VaultAddr = "vault.example:8200" }, false},
		{"empty key", func(c *vaulttransit.Config) { c.KeyName = "" }, false},
		{"nil token source", func(c *vaulttransit.Config) { c.TokenSource = nil }, false},
		{"negative version", func(c *vaulttransit.Config) { c.KeyVersion = -1 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good()
			tc.mutate(&cfg)
			_, err := vaulttransit.NewSigner(cfg)
			if tc.wantOK && err != nil {
				t.Errorf("expected ok, got %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// The DEFAULT client (no HTTPClient supplied) must VERIFY TLS — it must REFUSE
// the fake's self-signed cert. This proves the default is not InsecureSkipVerify.
func TestDefaultClientVerifiesTLS(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	cfg := vaulttransit.Config{
		VaultAddr:   fv.addr(), // httptest self-signed cert
		KeyName:     "sso-signing",
		TokenSource: func(context.Context) (string, error) { return "t", nil },
		// HTTPClient deliberately nil -> default verifying client.
	}
	sgn, err := vaulttransit.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	_, err = sgn.PublicKey(context.Background())
	if err == nil {
		t.Fatal("default client accepted a self-signed cert (TLS verification is OFF)")
	}
	// And the cert error must not carry the token.
	if strings.Contains(err.Error(), "\"t\"") {
		t.Errorf("token leaked into TLS error: %v", err)
	}
}

// Unsupported transit key type is rejected at read-key (defense against a
// transit key whose type this signer cannot bridge).
func TestUnsupportedKeyType(t *testing.T) {
	t.Parallel()
	fv := newFakeVault(t, "ecdsa-p256")
	// Lie about the type so the parsed EC key disagrees with a claimed aes type.
	fv.transitType = "aes256-gcm96"
	sgn := newSigner(t, fv, nil)
	if _, err := sgn.PublicKey(context.Background()); err == nil {
		t.Fatal("unsupported transit key type was accepted")
	}
}

// assertIssueValidate issues a token through the real issuer and validates it,
// proving the bridged transit signature is byte-compatible with the issuer's
// own verifier + the JWKS public key. Mirrors the cryptosigner test helper.
func assertIssueValidate(t *testing.T, iss tokenIssuer, val tokenValidator) {
	t.Helper()
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u1", ClientID: "c1"}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := val.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v (transit-bridged signature rejected by the issuer's own verifier)", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("subject = %q, want u1", claims.Subject)
	}
}

type tokenIssuer interface {
	Issue(context.Context, *sso.Subject, []string) (*sso.Token, error)
}
type tokenValidator interface {
	Validate(context.Context, string) (*sso.TokenClaims, error)
}
