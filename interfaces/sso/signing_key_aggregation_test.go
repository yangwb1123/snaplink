package sso_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/signingkeys"
	signingkeysmemory "github.com/snaplink/sso/platform/signingkeys/memory"
	"github.com/snaplink/sso/shared/core"
)

// serverJWKS collects the union of every wired issuer's JWKS the way the
// /jwks.json handler does — used to assert peer keys do (or don't) surface.
func serverJWKS(t *testing.T, s *sso.Server) []core.JWK {
	t.Helper()
	var out []core.JWK
	for _, ti := range s.TokenIssuers() {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(context.Background())
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		out = append(out, jwks...)
	}
	return out
}

func jwksHasKidSrv(jwks []core.JWK, kid string) bool {
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// newAggServer builds a minimal Server with a single Ed25519 JWT issuer,
// wired into the shared signing-key registry under replicaID.
func newAggServer(t *testing.T, replicaID string, reg *signingkeysmemory.Registry) (*sso.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithSharedSigningKeyRegistry(reg),
		sso.WithSigningKeyReplicaID(replicaID),
	)
	return srv, iss
}

// TestSigningKeyAggregation_CrossReplicaVerify is the end-to-end property:
// two Servers each holding their own Ed25519 key, sharing one in-memory
// registry. After aggregation settles, a token minted by A validates on B
// and A's kid appears in B's JWKS union (and vice versa).
func TestSigningKeyAggregation_CrossReplicaVerify(t *testing.T) {
	reg := signingkeysmemory.New()
	defer func() { _ = reg.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvA, issA := newAggServer(t, "replica-a", reg)
	srvB, issB := newAggServer(t, "replica-b", reg)

	doneA, err := srvA.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start A: %v", err)
	}
	doneB, err := srvB.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start B: %v", err)
	}

	// A token minted by A.
	tokA, err := issA.Issue(ctx, &sso.Subject{ID: "user-a", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("A Issue: %v", err)
	}

	// Eventual consistency: the registry fan-out + initial List run
	// synchronously inside StartSigningKeyAggregation, but the goroutine
	// that consumes the subscription stream is async. Poll briefly.
	if !waitFor(2*time.Second, func() bool {
		_, vErr := srvB.ValidateToken(ctx, tokA.AccessToken)
		return vErr == nil && jwksHasKidSrv(serverJWKS(t, srvB), issA.KeyID())
	}) {
		t.Fatalf("B never adopted A's key (kid=%s)", issA.KeyID())
	}

	// Symmetric: a token minted by B validates on A.
	tokB, err := issB.Issue(ctx, &sso.Subject{ID: "user-b", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("B Issue: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		_, vErr := srvA.ValidateToken(ctx, tokB.AccessToken)
		return vErr == nil && jwksHasKidSrv(serverJWKS(t, srvA), issB.KeyID())
	}) {
		t.Fatalf("A never adopted B's key (kid=%s)", issB.KeyID())
	}

	// A must NOT adopt its OWN key as a peer key (no duplicate kid).
	jwksA := serverJWKS(t, srvA)
	count := 0
	for _, k := range jwksA {
		if k.Kid == issA.KeyID() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("A's own kid appears %d times in its JWKS, want 1", count)
	}

	cancel()
	_ = reg.Close()
	<-doneA
	<-doneB
}

// TestSigningKeyAggregation_OptInByteIdentity is the single most important
// property: with NO registry wired the JWKS is byte-identical to a Server
// built without the option, and no peer keys are ever adopted (zero
// regression). StartSigningKeyAggregation is a no-op (already-closed chan,
// nil error).
func TestSigningKeyAggregation_OptInByteIdentity(t *testing.T) {
	// Same key on both so JWKS is comparable: byte-identity is about the
	// option not perturbing output, not about key material.
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))

	withoutOpt := sso.NewServer(sso.WithTokenIssuer(sso.TokenStrategyJWT, iss))
	withOptNoReg := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		// Wired but nil-default: the option is present, the registry is not.
		sso.WithSigningKeyReplicaID("replica-x"),
		sso.WithSigningKeyLeaseTTL(time.Minute),
	)

	// StartSigningKeyAggregation must be a pure no-op without a registry.
	done, err := withOptNoReg.StartSigningKeyAggregation(context.Background())
	if err != nil {
		t.Fatalf("StartSigningKeyAggregation no-op returned error: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("StartSigningKeyAggregation returned an un-closed channel without a registry")
	}

	a := serverJWKS(t, withoutOpt)
	b := serverJWKS(t, withOptNoReg)
	if len(a) != len(b) {
		t.Fatalf("JWKS length differs: without=%d withOpt=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("JWKS entry %d differs:\n without=%+v\n withOpt=%+v", i, a[i], b[i])
		}
	}

	// And the issuer's own JWKS carries exactly its one signing key — no
	// stray peer entries snuck in.
	own, _ := iss.JWKS(context.Background())
	if len(own) != 1 {
		t.Fatalf("issuer JWKS has %d keys without a registry, want 1 (peerVerifyKeys must be empty)", len(own))
	}
}

// TestSigningKeyAggregation_RequiresReplicaID locks FIX A: a wired registry
// with an empty replicaID must fail LOUD at StartSigningKeyAggregation rather
// than start silent one-directional aggregation (this replica would adopt
// peers but its own announcement — rejected by the registry for an empty
// ReplicaID — would never land, so peers could not verify its tokens).
func TestSigningKeyAggregation_RequiresReplicaID(t *testing.T) {
	reg := signingkeysmemory.New()
	defer func() { _ = reg.Close() }()

	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithSharedSigningKeyRegistry(reg),
		// Deliberately NO WithSigningKeyReplicaID.
	)

	done, err := srv.StartSigningKeyAggregation(context.Background())
	if err == nil {
		t.Fatal("StartSigningKeyAggregation must error when a registry is wired but replicaID is empty")
	}
	// The done channel must be closed so a caller that still drains it does
	// not block.
	select {
	case <-done:
	default:
		t.Fatal("StartSigningKeyAggregation returned an un-closed channel alongside its error")
	}
}

// newEventServer builds a Server with one Ed25519 issuer and a fixed
// replicaID but NO registry, so a test feeds it crafted events directly via
// ApplySigningKeyEventForTest. Returns the local issuer to assert on.
func newEventServer(t *testing.T, replicaID string) (*sso.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(sso.WithTokenIssuer(sso.TokenStrategyJWT, iss))
	srv.SetReplicaIDForTest(replicaID)
	return srv, iss
}

// peerIssuerJWK returns a peer issuer's primary signing JWK so an
// announcement can carry a real, decodable Ed25519 verify key.
func peerIssuerJWK(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer) core.JWK {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("peer JWKS: %v", err)
	}
	if len(jwks) == 0 {
		t.Fatal("peer issuer has no JWK")
	}
	return jwks[0]
}

func issuerHasKid(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer, kid string) bool {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// TestSigningKeyAggregation_DropPath is FIX D: an EventKeysRemoved for a
// replica whose key was previously adopted via EventKeysUpserted must remove
// the adopted kid from the issuer's JWKS AND make a token signed by that
// peer's key fail Validate (unknown kid).
func TestSigningKeyAggregation_DropPath(t *testing.T) {
	srv, localIss := newEventServer(t, "replica-local")
	_, peerIss := newEventServer(t, "replica-peer")
	peerKid := peerIss.KeyID()

	tok, err := peerIss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("peer Issue: %v", err)
	}
	if _, err := localIss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("local issuer validated peer token before adoption")
	}

	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type: signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{
			ReplicaID: "replica-peer",
			Keys:      []core.JWK{peerIssuerJWK(t, peerIss)},
		},
	})
	if !issuerHasKid(t, localIss, peerKid) {
		t.Fatalf("peer kid %s not in JWKS after adoption", peerKid)
	}
	if _, err := localIss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("peer token must validate after adoption: %v", err)
	}

	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysRemoved,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-peer"},
	})
	if issuerHasKid(t, localIss, peerKid) {
		t.Fatalf("peer kid %s still in JWKS after EventKeysRemoved", peerKid)
	}
	if _, err := localIss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("peer token must FAIL validation after its key was dropped (unknown kid)")
	}
}

// TestSigningKeyAggregation_SharedKidRefcount is FIX C: when two distinct
// replicas announce the SAME kid (fingerprint collision / shared key /
// misconfig), removing ONE must NOT evict the kid the other live replica
// still announces — the kid stays in JWKS and tokens signed by it still
// validate. Only when BOTH are gone does the refcount reach 0 and the kid
// drop.
func TestSigningKeyAggregation_SharedKidRefcount(t *testing.T) {
	srv, localIss := newEventServer(t, "replica-local")

	// One peer issuer; both announcements carry ITS key, simulating two
	// replicas that happen to announce the same kid.
	_, peerIss := newEventServer(t, "replica-shared")
	sharedKid := peerIss.KeyID()
	jwk := peerIssuerJWK(t, peerIss)

	tok, err := peerIss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("peer Issue: %v", err)
	}

	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-1", Keys: []core.JWK{jwk}},
	})
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-2", Keys: []core.JWK{jwk}},
	})
	if !issuerHasKid(t, localIss, sharedKid) {
		t.Fatalf("shared kid %s not in JWKS after both announcements", sharedKid)
	}

	// Drop replica-1: the kid must SURVIVE because replica-2 still holds it.
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysRemoved,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-1"},
	})
	if !issuerHasKid(t, localIss, sharedKid) {
		t.Fatalf("shared kid %s evicted by dropping replica-1 — refcount broken (FIX C)", sharedKid)
	}
	if _, err := localIss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("token must still validate while replica-2 announces the kid: %v", err)
	}

	// Drop replica-2 too: refcount reaches 0 and the kid is gone.
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysRemoved,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-2"},
	})
	if issuerHasKid(t, localIss, sharedKid) {
		t.Fatalf("shared kid %s still in JWKS after BOTH replicas dropped", sharedKid)
	}
	if _, err := localIss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("token must fail validation once no replica announces the kid")
	}
}

// TestSigningKeyAggregation_CrossAlgRoutingGate is FIX E: an announced key
// whose Alg is NOT the Server's issuer alg (ES256 to an EdDSA-only Server)
// must be silently skipped — it must not appear in the EdDSA issuer's JWKS
// and must not change Validate behavior. This proves the alg-match routing
// gate at adoption time.
func TestSigningKeyAggregation_CrossAlgRoutingGate(t *testing.T) {
	srv, localIss := newEventServer(t, "replica-local")

	before, err := localIss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	// Real Ed25519 key material, but tagged with a non-EdDSA alg. The alg
	// gate must reject it before any decode/adopt, so it never lands in the
	// EdDSA issuer.
	peerEd := peerIssuerJWK(t, defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://peer.example")))
	crossAlg := peerEd
	crossAlg.Alg = "ES256"
	crossAlg.Kid = "es256-peer-kid"

	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "replica-es256", Keys: []core.JWK{crossAlg}},
	})

	if issuerHasKid(t, localIss, crossAlg.Kid) {
		t.Fatalf("cross-alg kid %s leaked into the EdDSA issuer's JWKS", crossAlg.Kid)
	}
	after, err := localIss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("JWKS size changed after a cross-alg announcement: before=%d after=%d", len(before), len(after))
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// jwkForAlg pulls a peer issuer's primary signing JWK as a core.JWK, the
// material a real replica announces. ti must be a JWKSProvider (every default
// JWT issuer is).
func jwkForAlg(t *testing.T, ti core.JWKSProvider) core.JWK {
	t.Helper()
	jwks, err := ti.JWKS(context.Background())
	if err != nil {
		t.Fatalf("peer JWKS: %v", err)
	}
	if len(jwks) == 0 {
		t.Fatal("peer issuer has no JWK")
	}
	return jwks[0]
}

// newMultiAlgEventServer builds a Server with one issuer of EACH alg (EdDSA,
// ES256, RS256) and a fixed replicaID but NO registry, so a test feeds it
// crafted events via ApplySigningKeyEventForTest and asserts each announced key
// routes to the correct-alg issuer.
func newMultiAlgEventServer(t *testing.T, replicaID string) (*sso.Server, *defaultimpl.Ed25519JWTIssuer, *defaultimpl.ECDSAJWTIssuer, *defaultimpl.RSAJWTIssuer) {
	t.Helper()
	ed := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	ec := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAIssuer("https://sso.example"),
		defaultimpl.WithECDSATokenTTL(5*time.Minute),
	)
	rs := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://sso.example"),
		defaultimpl.WithRSAAlg("RS256"),
		defaultimpl.WithRSATokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt-eddsa", ed),
		sso.WithTokenIssuer("jwt-es256", ec),
		sso.WithTokenIssuer("jwt-rs256", rs),
	)
	srv.SetReplicaIDForTest(replicaID)
	return srv, ed, ec, rs
}

// issuerHasKidEC / issuerHasKidRSA are the EC/RSA analogues of issuerHasKid.
func issuerHasKidEC(t *testing.T, iss *defaultimpl.ECDSAJWTIssuer, kid string) bool {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

func issuerHasKidRSA(t *testing.T, iss *defaultimpl.RSAJWTIssuer, kid string) bool {
	t.Helper()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	for _, k := range jwks {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// TestSigningKeyAggregation_MultiAlgRouting is the cross-alg integration
// property: a Server wired with one issuer of each alg (EdDSA + ES256 + RS256)
// receives peer announcements of all three algs, and each key routes to the
// CORRECT-alg issuer — appears in that issuer's JWKS, validates a token signed
// by the matching peer, and does NOT appear in any other-alg issuer.
func TestSigningKeyAggregation_MultiAlgRouting(t *testing.T) {
	srv, edLocal, ecLocal, rsLocal := newMultiAlgEventServer(t, "replica-local")

	// Three peers, one per alg, each minting a token + announcing its key.
	edPeer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://peer.example"))
	ecPeer := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("https://peer.example"))
	rsPeer := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://peer.example"),
		defaultimpl.WithRSAAlg("RS256"),
	)

	edTok, err := edPeer.Issue(context.Background(), &sso.Subject{ID: "u-ed", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("ed peer Issue: %v", err)
	}
	ecTok, err := ecPeer.Issue(context.Background(), &sso.Subject{ID: "u-ec", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("ec peer Issue: %v", err)
	}
	rsTok, err := rsPeer.Issue(context.Background(), &sso.Subject{ID: "u-rs", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("rs peer Issue: %v", err)
	}

	// Announce all three keys from three distinct peer replicas.
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-ed", Keys: []core.JWK{jwkForAlg(t, edPeer)}},
	})
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-ec", Keys: []core.JWK{jwkForAlg(t, ecPeer)}},
	})
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-rs", Keys: []core.JWK{jwkForAlg(t, rsPeer)}},
	})

	// Each peer kid lands in ITS alg's issuer.
	if !issuerHasKid(t, edLocal, edPeer.KeyID()) {
		t.Fatalf("EdDSA peer kid %s not adopted by the EdDSA issuer", edPeer.KeyID())
	}
	if !issuerHasKidEC(t, ecLocal, ecPeer.KeyID()) {
		t.Fatalf("ES256 peer kid %s not adopted by the ECDSA issuer", ecPeer.KeyID())
	}
	if !issuerHasKidRSA(t, rsLocal, rsPeer.KeyID()) {
		t.Fatalf("RS256 peer kid %s not adopted by the RSA issuer", rsPeer.KeyID())
	}

	// And each peer kid is NOT cross-adopted into a wrong-alg issuer.
	if issuerHasKidEC(t, ecLocal, edPeer.KeyID()) || issuerHasKidRSA(t, rsLocal, edPeer.KeyID()) {
		t.Fatal("EdDSA peer kid leaked into a non-EdDSA issuer")
	}
	if issuerHasKid(t, edLocal, ecPeer.KeyID()) || issuerHasKidRSA(t, rsLocal, ecPeer.KeyID()) {
		t.Fatal("ES256 peer kid leaked into a non-ES256 issuer")
	}
	if issuerHasKid(t, edLocal, rsPeer.KeyID()) || issuerHasKidEC(t, ecLocal, rsPeer.KeyID()) {
		t.Fatal("RS256 peer kid leaked into a non-RS256 issuer")
	}

	// The Server's union ValidateToken accepts a token from each peer alg.
	for name, tok := range map[string]string{
		"eddsa": edTok.AccessToken,
		"es256": ecTok.AccessToken,
		"rs256": rsTok.AccessToken,
	} {
		if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
			t.Fatalf("%s peer token failed Server validation after adoption: %v", name, err)
		}
	}
}

// TestSigningKeyAggregation_RS256VsPS256Routing locks strict RS256/PS256
// routing at the Server level: a Server with ONLY an RS256 issuer must NOT
// adopt a PS256-announced key (and a PS256-only Server must NOT adopt an
// RS256-announced key). Alg-match is by the exact alg string, so RS256 != PS256.
func TestSigningKeyAggregation_RS256VsPS256Routing(t *testing.T) {
	// RS256-only Server; announce a PS256 key.
	rsIss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://sso.example"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	rsSrv := sso.NewServer(sso.WithTokenIssuer("jwt-rs256", rsIss))
	rsSrv.SetReplicaIDForTest("rs-replica")

	psPeer := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://peer.example"),
		defaultimpl.WithRSAAlg("PS256"),
	)
	rsSrv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-ps", Keys: []core.JWK{jwkForAlg(t, psPeer)}},
	})
	if issuerHasKidRSA(t, rsIss, psPeer.KeyID()) {
		t.Fatalf("RS256 issuer adopted a PS256-announced key (kid=%s) — RS256/PS256 routing breached", psPeer.KeyID())
	}

	// PS256-only Server; announce an RS256 key.
	psIss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://sso.example"),
		defaultimpl.WithRSAAlg("PS256"),
	)
	psSrv := sso.NewServer(sso.WithTokenIssuer("jwt-ps256", psIss))
	psSrv.SetReplicaIDForTest("ps-replica")

	rsPeer := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://peer.example"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	psSrv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-rs", Keys: []core.JWK{jwkForAlg(t, rsPeer)}},
	})
	if issuerHasKidRSA(t, psIss, rsPeer.KeyID()) {
		t.Fatalf("PS256 issuer adopted an RS256-announced key (kid=%s) — RS256/PS256 routing breached", rsPeer.KeyID())
	}
}

// TestSigningKeyAggregation_MalformedECKeySkipped proves a malformed/off-curve
// EC peer key is logged + skipped (fail-open), never adopted, and the
// subscriber path keeps going. An EC JWK whose x/y do not lie on P-256 must not
// land in the ES256 issuer.
func TestSigningKeyAggregation_MalformedECKeySkipped(t *testing.T) {
	ecIss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("https://sso.example"))
	srv := sso.NewServer(sso.WithTokenIssuer("jwt-es256", ecIss))
	srv.SetReplicaIDForTest("local")

	// Start from a real EC JWK, then corrupt Y so the point is off-curve.
	good := jwkForAlg(t, defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("https://peer.example")))
	bad := good
	bad.Kid = "off-curve-kid"
	bad.Y = "AAAA" // wrong length / off-curve

	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-bad", Keys: []core.JWK{bad}},
	})
	if issuerHasKidEC(t, ecIss, bad.Kid) {
		t.Fatalf("malformed EC peer key %s was adopted — must be skipped", bad.Kid)
	}
}

// TestSigningKeyAggregation_DegenerateRSAExponentSkipped proves the registry
// adoption path rejects an RSA peer key whose public exponent is degenerate.
// e=1 makes RSA verification the identity (sig^1 mod N == sig) so anyone could
// forge a "signature" with no private key; an even e is non-invertible modulo
// the (odd) totient. Go's rsa.Verify* reject neither, so decodeRSAJWK must —
// the key must never enter the RS256 issuer's verify-set.
func TestSigningKeyAggregation_DegenerateRSAExponentSkipped(t *testing.T) {
	rsIss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://sso.example"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	srv := sso.NewServer(sso.WithTokenIssuer("jwt-rs256", rsIss))
	srv.SetReplicaIDForTest("local")

	// Start from a real 2048-bit RSA peer JWK (valid modulus) and forge a
	// degenerate exponent: "AQ" = 0x01 (e=1), "Ag" = 0x02 (e=2, even).
	good := jwkForAlg(t, defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://peer.example"),
		defaultimpl.WithRSAAlg("RS256"),
	))
	for name, badE := range map[string]string{"e1": "AQ", "e2_even": "Ag"} {
		bad := good
		bad.Kid = "degenerate-" + name
		bad.E = badE
		srv.ApplySigningKeyEventForTest(signingkeys.Event{
			Type:         signingkeys.EventKeysUpserted,
			Announcement: signingkeys.Announcement{ReplicaID: "peer-" + name, Keys: []core.JWK{bad}},
		})
		if issuerHasKidRSA(t, rsIss, bad.Kid) {
			t.Fatalf("%s: degenerate-exponent RSA peer key %s was adopted — must be skipped", name, bad.Kid)
		}
	}
}

// TestSigningKeyAggregation_WeakRSAModulusSkipped proves a sub-2048-bit RSA
// peer key is rejected at the aggregation decode path, symmetric with the
// malformed-EC skip test (decodeRSAJWK modulus floor).
func TestSigningKeyAggregation_WeakRSAModulusSkipped(t *testing.T) {
	rsIss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("https://sso.example"),
		defaultimpl.WithRSAAlg("RS256"),
	)
	srv := sso.NewServer(sso.WithTokenIssuer("jwt-rs256", rsIss))
	srv.SetReplicaIDForTest("local")

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak key: %v", err)
	}
	jwk := core.JWK{
		Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "weak-1024",
		N: base64.RawURLEncoding.EncodeToString(weak.N.Bytes()),
		E: "AQAB", // 65537 — exponent is fine; the 1024-bit modulus is the defect
	}
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-weak", Keys: []core.JWK{jwk}},
	})
	if issuerHasKidRSA(t, rsIss, jwk.Kid) {
		t.Fatalf("sub-2048 RSA peer key %s was adopted — must be skipped", jwk.Kid)
	}
}
