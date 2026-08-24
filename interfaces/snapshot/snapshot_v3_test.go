package snapshot_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	aesgcm "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionaesgcm"
	none "github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionnone"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// ---- software authenticator (compact peer of assertion_regression_test.go) ----

// v3Authenticator is a minimal in-test FIDO2 authenticator that can mint
// VALID, signed assertion responses the real go-webauthn VerifyLogin path
// accepts — the only faithful way to prove a snapshot-restored credential
// still verifies at login. It mirrors the harness in
// domains/authenticators/webauthn/assertion_regression_test.go.
type v3Authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newV3Authenticator(t *testing.T) *v3Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("random cred id: %v", err)
	}
	return &v3Authenticator{key: key, credID: id}
}

func (a *v3Authenticator) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	pub := a.key.PublicKey
	pubBytes, err := pub.Bytes()
	if err != nil {
		t.Fatalf("ecdsa public key bytes: %v", err)
	}
	cose := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: pubBytes[1:33],
		YCoord: pubBytes[33:65],
	}
	b, err := webauthncbor.Marshal(cose)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return b
}

// credential builds the stored gw.Credential with the given starting
// signature counter — the exact shape the snapshot projection carries.
func (a *v3Authenticator) credential(t *testing.T, startCounter uint32) *gw.Credential {
	t.Helper()
	return &gw.Credential{
		ID:        a.credID,
		PublicKey: a.cosePublicKey(t),
		Authenticator: gw.Authenticator{
			SignCount: startCounter,
		},
	}
}

// assertJSON produces a valid, signed assertion response for the given
// challenge, asserting signCount and the user-verified bit.
func (a *v3Authenticator) assertJSON(t *testing.T, rpID, origin, challenge string, signCount uint32, userVerified bool) string {
	t.Helper()
	clientData, err := json.Marshal(map[string]string{
		"type":      string(protocol.AssertCeremony),
		"challenge": challenge,
		"origin":    origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	authData := v3AuthData(t, rpID, signCount, userVerified)
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	resp := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(a.credID),
		"rawId": base64.RawURLEncoding.EncodeToString(a.credID),
		"type":  string(protocol.PublicKeyCredentialType),
		"response": map[string]string{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return string(b)
}

// v3AuthData lays out the 37-byte assertion authenticator data: SHA256(rpID)
// [32] | flags[1] | signCount[4]. UP is always set; UV per userVerified.
func v3AuthData(t *testing.T, rpID string, signCount uint32, userVerified bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	flags := byte(protocol.FlagUserPresent)
	if userVerified {
		flags |= byte(protocol.FlagUserVerified)
	}
	out := make([]byte, 0, 37)
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], signCount)
	out = append(out, counter[:]...)
	return out
}

// ---- webauthn portability ----

const (
	v3RPID   = "example.com"
	v3Origin = "https://sso.example.com"
)

// TestSnapshotV3_WebAuthnRoundTrip proves Decision 2 end to end: export a
// passkey from the source store, round-trip the artifact through the v3
// codec, restore into a fresh store, and complete a REAL login ceremony
// against the restored credential. The exported record is public-key
// material only (the Attestation blob never travels); the handle survives
// (HandlePreservingUserCreator), so the restored store resolves the same
// user by handle.
func TestSnapshotV3_WebAuthnRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auth := newV3Authenticator(t)
	const userName = "alice@example.com"

	src := webauthn.NewMemoryUserStore()
	if _, err := src.CreateUser(ctx, userName, "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cred := auth.credential(t, 5)
	if err := src.AddCredential(ctx, userName, cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	// SDK-captured extension metadata must ride the record too.
	discoverable := true
	if err := src.SetCredentialExtensions(ctx, userName, cred.ID, webauthn.CredentialExtensions{Discoverable: &discoverable}); err != nil {
		t.Fatalf("SetCredentialExtensions: %v", err)
	}

	srcUsers := defaultimpl.NewMemoryUserProvider()
	if err := srcUsers.CreateOrUpdate(ctx, &sso.User{ID: userName}); err != nil {
		t.Fatalf("seed sso user: %v", err)
	}
	exported, err := (&snapshot.Snapshotter{
		WebAuthn: src, Users: srcUsers, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !exported.IncludesCategory(snapshot.CategoryWebAuthn) {
		t.Fatal("webauthn_credentials category missing from v3 export")
	}
	rec := exported.Resources.WebAuthnCredentials[0]
	if len(rec.Credential.Attestation.Object) != 0 || len(rec.Credential.Attestation.ClientDataJSON) != 0 {
		t.Error("exported credential carries the attestation blob")
	}
	if len(rec.Credential.PublicKey) == 0 || rec.Credential.Authenticator.SignCount != 5 {
		t.Fatalf("verification-relevant projection damaged: %+v", rec.Credential)
	}

	// The artifact must round-trip through the v3 codec losslessly.
	decoded := mustCodecSnapshot(t, exported)
	if got := decoded.Resources.WebAuthnCredentials[0].Credential.Authenticator.SignCount; got != 5 {
		t.Fatalf("codec round-trip lost SignCount: %d", got)
	}

	// Restore onto a fresh node.
	dst := webauthn.NewMemoryUserStore()
	rep, err := (&snapshot.Restorer{WebAuthn: dst}).Restore(ctx, decoded, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	counts := rep.Items[snapshot.CategoryWebAuthn]
	if counts.Inserted != 1 {
		t.Fatalf("webauthn inserted=%d want 1 (%+v)", counts.Inserted, counts)
	}

	// Handle preservation: the restored store resolves the user by the
	// ORIGINAL handle (discoverable/conditional login depends on it).
	restoredUser, err := dst.GetByName(ctx, userName)
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if !bytesEqualTest(restoredUser.Handle, rec.Handle) {
		t.Error("restored handle differs from the exported handle")
	}
	if _, err := dst.GetByHandle(ctx, rec.Handle); err != nil {
		t.Errorf("GetByHandle with the exported handle: %v", err)
	}
	// Extension metadata replayed.
	if restoredUser.CredentialExtensions == nil ||
		restoredUser.CredentialExtensions[base64.RawURLEncoding.EncodeToString(cred.ID)].Discoverable == nil ||
		!*restoredUser.CredentialExtensions[base64.RawURLEncoding.EncodeToString(cred.ID)].Discoverable {
		t.Error("credProps Discoverable metadata not replayed onto the restored credential")
	}

	// REAL login against the restored credential: a valid, counter-advancing
	// assertion must verify through the actual go-webauthn path.
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID: v3RPID, RPDisplayName: "Example AS", RPOrigins: []string{v3Origin},
	}, dst, webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	assertion, sessionID, err := h.BeginLogin(ctx, userName)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body := auth.assertJSON(t, v3RPID, v3Origin, assertion.Response.Challenge.String(), 6, true)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	user, cred2, err := h.FinishLogin(ctx, sessionID, req)
	if err != nil {
		t.Fatalf("FinishLogin against restored credential: %v", err)
	}
	if user.Name != userName {
		t.Fatalf("user = %q, want %q", user.Name, userName)
	}
	if cred2.Authenticator.SignCount != 6 {
		t.Fatalf("SignCount = %d, want 6 (advanced)", cred2.Authenticator.SignCount)
	}
	if cred2.Authenticator.CloneWarning {
		t.Fatal("CloneWarning set on a valid advancing-counter assertion")
	}
}

// TestSnapshotV3_WebAuthnCounterRegression_Skips proves the fail-closed
// counter rule: a live credential that is NEWER than the snapshot's is
// skipped + counted, and the live counter is never written backwards.
func TestSnapshotV3_WebAuthnCounterRegression_Skips(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auth := newV3Authenticator(t)
	const userName = "bob@example.com"

	// Destination is the authority: its credential has a NEWER counter.
	dst := webauthn.NewMemoryUserStore()
	if _, err := dst.CreateUser(ctx, userName, "Bob"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := dst.AddCredential(ctx, userName, auth.credential(t, 7)); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	snap := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-regress",
		SourceNamespace: "test",
		Categories:      []snapshot.ResourceCategory{snapshot.CategoryUsers, snapshot.CategoryWebAuthn},
		Resources: snapshot.Resources{
			Users: []*sso.User{{ID: userName}},
			WebAuthnCredentials: []webauthn.UserCredentialRecord{{
				UserName:    userName,
				Handle:      []byte("handle"),
				DisplayName: "Bob",
				Credential:  *auth.credential(t, 5),
			}},
		},
	})

	rep, err := (&snapshot.Restorer{WebAuthn: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	counts := rep.Items[snapshot.CategoryWebAuthn]
	if counts.Skipped != 1 || counts.Updated != 0 {
		t.Fatalf("webauthn counts = %+v, want Skipped=1 (counter regression)", counts)
	}
	user, err := dst.GetByName(ctx, userName)
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if user.Credentials[0].Authenticator.SignCount != 7 {
		t.Fatalf("live SignCount = %d, want 7 (never written backwards)", user.Credentials[0].Authenticator.SignCount)
	}
}

// TestSnapshotV3_WebAuthnExporterLessStore_OmitsCategory proves the
// optional-store pattern: a wired webauthn store WITHOUT CredentialLister
// silently omits the category — the absent category IS the observability
// marker.
func TestSnapshotV3_WebAuthnExporterLessStore_OmitsCategory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	exported, err := (&snapshot.Snapshotter{
		WebAuthn: noListerStore{}, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if exported.IncludesCategory(snapshot.CategoryWebAuthn) {
		t.Fatal("webauthn category present despite exporter-less store")
	}
	if len(exported.Resources.WebAuthnCredentials) != 0 {
		t.Fatal("webauthn credentials present despite exporter-less store")
	}
}

// noListerStore satisfies webauthn.UserStore but NOT
// webauthn.CredentialLister — the exporter-less backend.
type noListerStore struct{}

func (noListerStore) GetByName(context.Context, string) (*webauthn.User, error) {
	return nil, webauthn.ErrUserUnknown
}
func (noListerStore) CreateUser(context.Context, string, string) (*webauthn.User, error) {
	return nil, errors.New("not implemented")
}
func (noListerStore) AddCredential(context.Context, string, *gw.Credential) error {
	return errors.New("not implemented")
}
func (noListerStore) UpdateCredential(context.Context, string, *gw.Credential) error {
	return errors.New("not implemented")
}
func (noListerStore) RemoveCredential(context.Context, string, []byte) error {
	return errors.New("not implemented")
}

// TestSnapshotV3_WebAuthnOrphanRecord_Skipped proves identity ownership: a
// credential whose user is absent from the snapshot's users category is an
// orphan and is skipped + counted (the users category owns identity).
func TestSnapshotV3_WebAuthnOrphanRecord_Skipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auth := newV3Authenticator(t)

	snap := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap-orphan",
		SourceNamespace: "test",
		Categories:      []snapshot.ResourceCategory{snapshot.CategoryUsers, snapshot.CategoryWebAuthn},
		Resources: snapshot.Resources{
			// users category carries carol only; the record is for dan.
			Users: []*sso.User{{ID: "carol"}},
			WebAuthnCredentials: []webauthn.UserCredentialRecord{{
				UserName: "dan", Handle: []byte("h"), Credential: *auth.credential(t, 1),
			}},
		},
	})

	dst := webauthn.NewMemoryUserStore()
	rep, err := (&snapshot.Restorer{WebAuthn: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	counts := rep.Items[snapshot.CategoryWebAuthn]
	if counts.Skipped != 1 || counts.Inserted != 0 {
		t.Fatalf("webauthn counts = %+v, want Skipped=1 (orphan)", counts)
	}
	if _, err := dst.GetByName(ctx, "dan"); !errors.Is(err, webauthn.ErrUserUnknown) {
		t.Fatalf("orphan user was created: %v", err)
	}
}

// ---- TOTP seed portability ----

func v3Sealer(t *testing.T) *aesgcm.Sealer {
	t.Helper()
	key := make([]byte, aesgcm.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random key: %v", err)
	}
	s, err := aesgcm.New(key)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	return s
}

// knownSeed is a fixed, searchable seed: the sealed-payload substring scan
// must NOT find it anywhere in the artifact (fail-closed proof that seed
// plaintext never touches the wire).
var knownSeed = []byte("V3SEED-PLAINTEXT-MUST-NOT-APPEAR-0123456789")

// TestSnapshotV3_TotpSeedsRoundTrip_SealedEnvelope proves Decision 3 end to
// end: with the explicit flag + an encryption sealer, seeds ride inside the
// purpose-separated envelope; the artifact's bytes contain the seed
// NOWHERE; and an opted-in restore imports them byte-identically so the
// existing TOTP verification passes unchanged.
func TestSnapshotV3_TotpSeedsRoundTrip_SealedEnvelope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := authenticators.NewMemoryTOTPStore()
	src.Set("alice", knownSeed)
	src.Set("bob", []byte("bob-secret-2"))
	sealer := v3Sealer(t)

	exported, err := (&snapshot.Snapshotter{
		TOTP: src, Sealer: sealer, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !exported.IncludesCategory(snapshot.CategoryTotpSeeds) {
		t.Fatal("totp_seeds category missing from opted-in v3 export")
	}
	env := exported.Resources.SeedEnvelope
	if env == nil || env.Algorithm != snapshot.EncryptionAESGCM || len(env.Cipher) == 0 {
		t.Fatalf("seed envelope malformed: %+v", env)
	}

	// FAIL-CLOSED PROOF: scan the full artifact bytes (the codec output —
	// everything that would be sealed as the snapshot body) and the sealed
	// envelope bytes for the known seed plaintext. Neither may contain it.
	artifact, err := snapshot.NewJSONCodec().Marshal(exported)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	for _, probe := range [][]byte{artifact, env.Cipher} {
		if strings.Contains(string(probe), string(knownSeed)) {
			t.Fatal("seed plaintext found in the artifact or sealed payload")
		}
	}

	// Round-trip through the codec, then restore opted-in onto a fresh store.
	decoded := mustCodecSnapshot(t, exported)
	dst := authenticators.NewMemoryTOTPStore()
	rep, err := (&snapshot.Restorer{TOTP: dst, Sealer: sealer}).Restore(ctx, decoded, snapshot.RestoreOptions{
		Mode:                   snapshot.ModeMerge,
		RestoreCredentialSeeds: true,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryTotpSeeds].Inserted; got != 2 {
		t.Fatalf("totp inserted=%d want 2", got)
	}
	if len(rep.MFAReenrollmentRequired) != 0 {
		t.Fatalf("opted-in restore flagged users: %+v", rep.MFAReenrollmentRequired)
	}

	// Byte-identical import: the restored secret equals the source seed.
	got, err := dst.GetSecret(ctx, "alice")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(knownSeed) {
		t.Fatalf("restored seed = %q, want %q", got, knownSeed)
	}
	// And existing TOTP verification passes (hotp is a pure function of
	// (secret, step) — a byte-identical seed yields identical codes).
	totp := authenticators.NewTOTPAuthenticator(dst)
	res, err := totp.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{
			"username": "alice",
			"code":     validTOTPCode(t, knownSeed),
		},
	})
	if err != nil {
		t.Fatalf("TOTP verification against restored seed: %v", err)
	}
	if res.UserID != "alice" {
		t.Fatalf("authenticated user = %q", res.UserID)
	}
}

// validTOTPCode derives the current-step code for seed via an independent
// RFC 4226 reimplementation, then proves the real authenticator accepts it.
func validTOTPCode(t *testing.T, secret []byte) string {
	t.Helper()
	code := hotpForTest(secret, time.Now().Unix()/30)
	if !authenticators.NewTOTPAuthenticator(nil).VerifyCode(secret, code) {
		t.Fatalf("self-derived code %q did not verify (harness broken)", code)
	}
	return code
}

// hotpForTest is a minimal RFC 4226 HMAC-SHA1 dynamic-truncation
// implementation, independent of the authenticator's own primitive.
func hotpForTest(secret []byte, counter int64) string {
	mac := hmacSHA1(secret, counter)
	offset := mac[len(mac)-1] & 0x0f
	binCode := (uint32(mac[offset])&0x7f)<<24 |
		(uint32(mac[offset+1])&0xff)<<16 |
		(uint32(mac[offset+2])&0xff)<<8 |
		uint32(mac[offset+3])
	return fmt.Sprintf("%06d", binCode%1000000)
}

func hmacSHA1(secret []byte, counter int64) []byte {
	mac := hmac.New(sha1.New, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac.Write(buf[:])
	return mac.Sum(nil)
}

// TestSnapshotV3_TotpSeedsOptOut_FlagsReenrollment proves the opt-out
// default: every other category restores, the envelope's users land on
// MFAReenrollmentRequired, the category counts them as Skipped, and the
// destination store is untouched — lockouts are discovered from the
// report, not by users.
func TestSnapshotV3_TotpSeedsOptOut_FlagsReenrollment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := authenticators.NewMemoryTOTPStore()
	src.Set("alice", knownSeed)
	sealer := v3Sealer(t)
	exported, err := (&snapshot.Snapshotter{
		TOTP: src, Sealer: sealer, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := authenticators.NewMemoryTOTPStore()
	rep, err := (&snapshot.Restorer{TOTP: dst, Sealer: sealer}).Restore(ctx, exported, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryTotpSeeds].Skipped; got != 1 {
		t.Fatalf("totp skipped=%d want 1", got)
	}
	if len(rep.MFAReenrollmentRequired) != 1 || rep.MFAReenrollmentRequired[0] != "alice" {
		t.Fatalf("mfa_reenrollment_required = %+v, want [alice]", rep.MFAReenrollmentRequired)
	}
	if _, err := dst.GetSecret(ctx, "alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Fatalf("opt-out restore imported a seed: %v", err)
	}
}

// TestSnapshotV3_TotpSeedsExportGates proves the fail-closed gate matrix:
// once the operator sets IncludeCredentialSeeds, every missing gate is a
// HARD error (never silent absence), and redaction XOR seeds refuses.
func TestSnapshotV3_TotpSeedsExportGates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := authenticators.NewMemoryTOTPStore()
	store.Set("alice", knownSeed)
	sealer := v3Sealer(t)

	t.Run("flag without sealer", func(t *testing.T) {
		_, err := (&snapshot.Snapshotter{TOTP: store, Namespace: "test"}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
		if !errors.Is(err, snapshot.ErrSnapshotSeedsRequireEncryption) {
			t.Fatalf("err = %v, want ErrSnapshotSeedsRequireEncryption", err)
		}
	})
	t.Run("flag with none sealer (no PurposeSealer)", func(t *testing.T) {
		_, err := (&snapshot.Snapshotter{TOTP: store, Sealer: none.New(), Namespace: "test"}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
		if !errors.Is(err, snapshot.ErrSnapshotSeedsRequireEncryption) {
			t.Fatalf("err = %v, want ErrSnapshotSeedsRequireEncryption", err)
		}
	})
	t.Run("flag with store lacking SeedExporter", func(t *testing.T) {
		_, err := (&snapshot.Snapshotter{TOTP: noExporterStore{}, Sealer: sealer, Namespace: "test"}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
		if !errors.Is(err, snapshot.ErrSnapshotSeedsRequireEncryption) {
			t.Fatalf("err = %v, want ErrSnapshotSeedsRequireEncryption", err)
		}
	})
	t.Run("flag unset is silent absence", func(t *testing.T) {
		exported, err := (&snapshot.Snapshotter{TOTP: store, Sealer: sealer, Namespace: "test"}).Export(ctx, snapshot.ExportOptions{})
		if err != nil {
			t.Fatalf("default export must succeed: %v", err)
		}
		if exported.IncludesCategory(snapshot.CategoryTotpSeeds) || exported.Resources.SeedEnvelope != nil {
			t.Fatal("default export carries the seed category")
		}
	})
	t.Run("redaction XOR seeds", func(t *testing.T) {
		_, err := (&snapshot.Snapshotter{
			TOTP: store, Sealer: sealer, Namespace: "test",
			DefaultExportRedactor: snapshot.SnapshotRedactSecrets(),
		}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
		if !errors.Is(err, snapshot.ErrSnapshotSeedsWithRedaction) {
			t.Fatalf("err = %v, want ErrSnapshotSeedsWithRedaction", err)
		}
	})
}

// noExporterStore satisfies authenticators.TOTPStore but NOT SeedExporter.
type noExporterStore struct{}

func (noExporterStore) GetSecret(context.Context, string) ([]byte, error) {
	return nil, authenticators.ErrTOTPNoSecret
}

// TestSnapshotV3_TotpSeedsWrongKey_RestoreFailsClosed proves the wrong-key
// restore: the category aborts with an error AND every snapshot user is
// conservatively flagged for re-enrollment (over-flagging beats silent
// lockout).
func TestSnapshotV3_TotpSeedsWrongKey_RestoreFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := authenticators.NewMemoryTOTPStore()
	src.Set("alice", knownSeed)
	exported, err := (&snapshot.Snapshotter{
		TOTP: src, Sealer: v3Sealer(t), Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Users category must be present for the conservative flag-all.
	exported.Resources.Users = []*sso.User{{ID: "alice"}, {ID: "carol"}}
	exported.Categories = append(exported.Categories, snapshot.CategoryUsers)

	wrongKey := make([]byte, aesgcm.KeySize)
	for i := range wrongKey {
		wrongKey[i] = 0xAB
	}
	wrongSealer, err := aesgcm.New(wrongKey)
	if err != nil {
		t.Fatalf("new wrong sealer: %v", err)
	}

	dst := authenticators.NewMemoryTOTPStore()
	rep, err := (&snapshot.Restorer{TOTP: dst, Sealer: wrongSealer}).Restore(ctx, exported, snapshot.RestoreOptions{
		Mode:                   snapshot.ModeMerge,
		RestoreCredentialSeeds: true,
	})
	if err == nil {
		t.Fatal("wrong-key restore succeeded")
	}
	if !errors.Is(err, snapshot.ErrSnapshotSeedsRequireEncryption) {
		t.Fatalf("err = %v, want ErrSnapshotSeedsRequireEncryption", err)
	}
	// Conservative all-users flag.
	flagged := map[string]bool{}
	for _, u := range rep.MFAReenrollmentRequired {
		flagged[u] = true
	}
	if !flagged["alice"] || !flagged["carol"] {
		t.Fatalf("mfa_reenrollment_required = %+v, want both alice and carol", rep.MFAReenrollmentRequired)
	}
	if len(rep.Errors) == 0 {
		t.Fatal("category error not recorded in Report.Errors")
	}
}

// TestSnapshotV3_TotpSeedsDryRun_PredictsWithoutImport proves TOTP dry-run
// honesty: an opted-in dry run reports the same counts the real run applies
// without importing a single seed.
func TestSnapshotV3_TotpSeedsDryRun_PredictsWithoutImport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := authenticators.NewMemoryTOTPStore()
	src.Set("alice", knownSeed)
	sealer := v3Sealer(t)
	exported, err := (&snapshot.Snapshotter{
		TOTP: src, Sealer: sealer, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{IncludeCredentialSeeds: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := authenticators.NewMemoryTOTPStore()
	rep, err := (&snapshot.Restorer{TOTP: dst, Sealer: sealer}).Restore(ctx, exported, snapshot.RestoreOptions{
		Mode: snapshot.ModeMerge, DryRun: true, RestoreCredentialSeeds: true,
	})
	if err != nil {
		t.Fatalf("dry-run restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryTotpSeeds].Inserted; got != 1 {
		t.Fatalf("dry-run totp inserted=%d want 1", got)
	}
	if _, err := dst.GetSecret(ctx, "alice"); !errors.Is(err, authenticators.ErrTOTPNoSecret) {
		t.Fatal("dry-run imported a seed")
	}
}

// ---- schema v3 wire compatibility ----

// v2Snapshot mirrors the v2-era envelope shape (no webauthn/totp fields) —
// what a ≤v2 binary's DisallowUnknownFields codec would decode into.
type v2Snapshot struct {
	SchemaVersion   string `json:"schema_version"`
	SnapshotID      string `json:"snapshot_id"`
	TakenAtUnix     int64  `json:"taken_at_unix"`
	SourceNamespace string `json:"source_namespace"`
	SourceNodeID    string `json:"source_node_id,omitempty"`
	BootstrapState  struct {
		Namespace      string `json:"namespace"`
		AppliedVersion int    `json:"applied_version"`
	} `json:"bootstrap_state"`
	Categories []string `json:"categories"`
	Resources  struct {
		Clients []*sso.Client `json:"clients,omitempty"`
	} `json:"resources"`
}

// TestSnapshotV3_RefusedByV2ShapedCodec pins the F5-documented refusal
// shape: in a ≤v2 binary the JSON decode (DisallowUnknownFields) runs
// BEFORE the version check, so a v3 artifact carrying the new fields fails
// as an unknown-field error, and only a new-field-free v3 artifact reaches
// ErrUnknownSchemaVersion. Both fail; the messages differ.
func TestSnapshotV3_RefusedByV2ShapedCodec(t *testing.T) {
	t.Parallel()
	decoder := func(data []byte) error {
		var out v2Snapshot
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil {
			return err
		}
		if out.SchemaVersion != "1" && out.SchemaVersion != "2" {
			return snapshot.ErrUnknownSchemaVersion
		}
		return nil
	}

	// v3 artifact WITH new fields: unknown-field JSON error.
	withFields := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, SnapshotID: "s1", SourceNamespace: "test",
		Resources: snapshot.Resources{WebAuthnCredentials: []webauthn.UserCredentialRecord{{UserName: "x"}}},
	})
	raw, err := snapshot.NewJSONCodec().Marshal(withFields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := decoder(raw); err == nil || strings.Contains(err.Error(), "unknown field") == false {
		t.Fatalf("v2-shaped decode of field-carrying v3 artifact = %v, want unknown-field error", err)
	}

	// v3 artifact WITHOUT new fields: decodes, then the version sentinel.
	noFields := mustCodecSnapshot(t, &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, SnapshotID: "s2", SourceNamespace: "test",
		Resources: snapshot.Resources{Clients: []*sso.Client{{ID: "web"}}},
	})
	raw2, err := snapshot.NewJSONCodec().Marshal(noFields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := decoder(raw2); !errors.Is(err, snapshot.ErrUnknownSchemaVersion) {
		t.Fatalf("v2-shaped decode of field-free v3 artifact = %v, want ErrUnknownSchemaVersion", err)
	}
}

// TestSnapshotV3_V1V2ArtifactsRemainReadable proves v1 and v2 artifacts
// still round-trip through the v3 build's codec and restore path unchanged.
func TestSnapshotV3_V1V2ArtifactsRemainReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			snap := mustCodecSnapshot(t, &snapshot.Snapshot{
				SchemaVersion: version, SnapshotID: "legacy-" + version, SourceNamespace: "test",
				Resources: snapshot.Resources{Clients: []*sso.Client{{ID: "legacy-client", Name: "Legacy"}}},
			})
			dst := defaultimpl.NewMemoryClientStore()
			if _, err := (&snapshot.Restorer{Clients: dst}).Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge}); err != nil {
				t.Fatalf("v%s restore: %v", version, err)
			}
			if _, err := dst.Get(ctx, "legacy-client"); err != nil {
				t.Fatalf("v%s client missing: %v", version, err)
			}
		})
	}
}

// bytesEqualTest compares two byte slices.
func bytesEqualTest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
