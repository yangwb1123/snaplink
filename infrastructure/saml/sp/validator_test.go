package sp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

const (
	tIDPEntity = "https://idp.example.com"
	tSPEntity  = "https://sp.example.com/saml/metadata"
	tACSURL    = "https://sp.example.com/auth/saml/callback"
)

// assertInvalid asserts that err is EXACTLY the single oracle-safe
// assertion-invalid error: non-nil, matches the exported sentinel, and its wire
// string is sso.ErrSAMLAssertionInvalid. This is the crux of the oracle-safety
// contract — every distinct validation failure must be indistinguishable here.
func assertInvalid(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want %s", label, sso.ErrSAMLAssertionInvalid)
	}
	if !errors.Is(err, ErrAssertionInvalid) {
		t.Fatalf("%s: error %v does not match ErrAssertionInvalid sentinel", label, err)
	}
	if err.Error() != sso.ErrSAMLAssertionInvalid {
		t.Fatalf("%s: error string = %q, want %q (oracle leak)", label, err.Error(), sso.ErrSAMLAssertionInvalid)
	}
}

// TestOracleSafety_AllFailuresCollapseToOneCode enumerates every distinct
// assertion-validation failure and asserts each returns the IDENTICAL
// oracle-safe error — no probe can tell a bad signature from a wrong audience
// from a replay. This is the §2 oracle-leak-hardening contract for the SP gate.
func TestOracleSafety_AllFailuresCollapseToOneCode(t *testing.T) {
	t.Parallel()
	now := time.Now()

	t.Run("bad_signature_attacker_cert", func(t *testing.T) {
		idp := newIDPKeypair(t)
		attacker := newIDPKeypair(t) // different key — signs a forged assertion
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		// Sign the assertion with the ATTACKER's key; the SP pins the IdP's.
		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		el := signAssertionEl(t, buildAssertion(p), attacker)
		resp := responseFrom(p.idpEntityID, tACSURL, p.inResponseTo, el)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "attacker-signed", err)
	})

	t.Run("unsigned_assertion", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		// Wrap an UNSIGNED assertion element — no Signature at all.
		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		el := buildAssertion(p).Element()
		resp := responseFrom(p.idpEntityID, tACSURL, p.inResponseTo, el)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "unsigned", err)
	})

	t.Run("wrong_audience", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		p.spEntityID = "https://attacker.example.com/metadata" // audience for a DIFFERENT SP
		resp := mintValidResponse(t, p, idp, tACSURL)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "wrong-audience", err)
	})

	t.Run("wrong_recipient", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		p.recipient = "https://attacker.example.com/acs" // recipient != SP ACS URL
		// Destination must still match for crewjam; only the SubjectConfirmation
		// Recipient is tampered, which is the realistic recipient-confusion attack.
		resp := mintValidResponse(t, p, idp, tACSURL)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "wrong-recipient", err)
	})

	t.Run("expired", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		// Far in the past, beyond crewjam's MaxClockSkew (180s) and ours.
		p.notBefore = now.Add(-2 * time.Hour)
		p.notOnOrAfter = now.Add(-1 * time.Hour)
		resp := mintValidResponse(t, p, idp, tACSURL)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "expired", err)
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		// Conditions NotBefore far in the future.
		p.notBefore = now.Add(1 * time.Hour)
		p.notOnOrAfter = now.Add(2 * time.Hour)
		resp := mintValidResponse(t, p, idp, tACSURL)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "not-yet-valid", err)
	})

	t.Run("wrong_idp_issuer", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
		p.idpEntityID = "https://rogue-idp.example.com" // signed by pinned key but claims a different issuer
		resp := mintValidResponse(t, p, idp, tACSURL)

		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "wrong-issuer", err)
	})

	t.Run("malformed_base64", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		_, err := a.ProcessAssertion(context.Background(), "!!!not base64!!!", "")
		assertInvalid(t, "malformed-base64", err)
	})

	t.Run("replayed", func(t *testing.T) {
		idp := newIDPKeypair(t)
		a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

		resp := mintValidResponse(t, defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL), idp, tACSURL)

		// First presentation succeeds.
		if _, err := a.ProcessAssertion(context.Background(), resp, ""); err != nil {
			t.Fatalf("first presentation: %v, want success", err)
		}
		// Second presentation of the SAME assertion (same ID) is a replay.
		_, err := a.ProcessAssertion(context.Background(), resp, "")
		assertInvalid(t, "replayed", err)
	})
}

// TestXSW_AttackerCertRejected proves an assertion signed by a cert OTHER than
// the pinned IdP cert is rejected (the signature gate's core property).
func TestXSW_AttackerCertRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	attacker := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	el := signAssertionEl(t, buildAssertion(p), attacker)
	resp := responseFrom(p.idpEntityID, tACSURL, p.inResponseTo, el)

	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("attacker-signed assertion ACCEPTED — signature gate broken")
	} else {
		assertInvalid(t, "xsw-attacker-cert", err)
	}
}

// TestXSW_EmbeddedCertNotTrusted proves the validator does NOT trust a cert
// embedded in the assertion's own Signature/KeyInfo. The attacker self-signs an
// assertion with their own keypair AND embeds their cert in the KeyInfo (the
// classic "bring your own cert" attack). Because the SP pins the IdP cert via
// metadata and we never set IDPCertificateFingerprint, crewjam verifies against
// the pinned cert, not the embedded one — so it must be rejected.
func TestXSW_EmbeddedCertNotTrusted(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	attacker := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	// goxmldsig's SignEnveloped (via NewSigningContext with the attacker cert
	// chain) embeds the attacker's X509Certificate in the Signature KeyInfo.
	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	el := signAssertionEl(t, buildAssertion(p), attacker)

	// Sanity: the signed element really does carry an embedded cert in KeyInfo.
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		t.Fatal("test setup: expected an embedded X509Certificate in the signature")
	}

	resp := responseFrom(p.idpEntityID, tACSURL, p.inResponseTo, el)
	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("assertion with attacker-embedded cert ACCEPTED — embedded cert was trusted (XSW hole)")
	} else {
		assertInvalid(t, "xsw-embedded-cert", err)
	}
}

// TestXSW_MultiAssertionRejected proves a response carrying more than one
// assertion is rejected outright — even if one assertion is legitimately signed
// by the pinned IdP, the presence of a second (attacker-appended) assertion
// must fail the whole response, defeating signature-wrapping by assertion
// injection. crewjam alone would silently return the first; our count gate
// rejects it.
func TestXSW_MultiAssertionRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	attacker := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	// One legitimately-signed assertion...
	pGood := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	good := signAssertionEl(t, buildAssertion(pGood), idp)

	// ...plus a SECOND assertion (attacker-signed, forged subject) appended.
	pEvil := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	pEvil.nameID = "attacker@evil.example.com"
	evil := signAssertionEl(t, buildAssertion(pEvil), attacker)

	resp := responseFrom(pGood.idpEntityID, tACSURL, pGood.inResponseTo, good, evil)

	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("multi-assertion response ACCEPTED — assertion-injection gate broken")
	} else {
		assertInvalid(t, "multi-assertion", err)
	}
}

// TestXSW_ZeroAssertionsRejected proves a response with NO assertion is rejected
// (the count gate requires exactly one).
func TestXSW_ZeroAssertionsRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	resp := responseFrom(tIDPEntity, tACSURL, "id-req-x") // no assertion children
	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("zero-assertion response ACCEPTED")
	} else {
		assertInvalid(t, "zero-assertion", err)
	}
}

// TestHappyPath_MapsNameIDAttributesAndAMR proves a valid assertion yields an
// AuthResult with the NameID as ExternalID, the mapped attributes, the provider
// name, and the SAML AMR.
func TestHappyPath_MapsNameIDAttributesAndAMR(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)

	// SP with an attribute mapping: SAML "email" -> local "mail".
	a, err := NewSPAuthenticator(SPConfig{
		Name:        "corp-idp",
		EntityID:    tSPEntity,
		ACSURL:      tACSURL,
		IDPCert:     idp.certPEM(),
		IDPEntityID: tIDPEntity,
		AttributeMapping: map[string]string{
			"email": "mail",
		},
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	a.now = func() time.Time { return now }

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	p.nameID = "bob@corp.example.com"
	p.attrs = map[string]string{"email": "bob@corp.example.com", "role": "engineer"}
	resp := mintValidResponse(t, p, idp, tACSURL)

	res, err := a.ProcessAssertion(context.Background(), resp, "")
	if err != nil {
		t.Fatalf("ProcessAssertion(valid) = %v, want success", err)
	}
	if res.ExternalID != "bob@corp.example.com" {
		t.Errorf("ExternalID = %q, want bob@corp.example.com", res.ExternalID)
	}
	if res.UserID != "bob@corp.example.com" {
		t.Errorf("UserID = %q, want bob@corp.example.com", res.UserID)
	}
	if res.Provider != "corp-idp" {
		t.Errorf("Provider = %q, want corp-idp", res.Provider)
	}
	// Mapped key "mail" present; unmapped "role" passes through under its name.
	if res.Attributes["mail"] != "bob@corp.example.com" {
		t.Errorf("Attributes[mail] = %q, want bob@corp.example.com (mapping not applied)", res.Attributes["mail"])
	}
	if res.Attributes["role"] != "engineer" {
		t.Errorf("Attributes[role] = %q, want engineer (passthrough)", res.Attributes["role"])
	}
	// The SAML attribute name "email" must NOT survive — it was remapped to "mail".
	if _, ok := res.Attributes["email"]; ok {
		t.Errorf("Attributes still has unmapped key 'email'; remap to 'mail' failed")
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != core.AMRSaml {
		t.Errorf("AuthMethods = %v, want [%s]", res.AuthMethods, core.AMRSaml)
	}
}

// TestSPInitiated_RejectsUnsolicited proves the default (AllowIDPInitiated=false)
// posture rejects a response with an empty InResponseTo (unsolicited), while a
// solicited one (non-empty InResponseTo) is accepted.
func TestSPInitiated_RejectsUnsolicited(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now) // AllowIDPInitiated=false

	// Unsolicited: empty InResponseTo.
	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	p.inResponseTo = ""
	resp := mintValidResponse(t, p, idp, tACSURL)
	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("unsolicited response ACCEPTED under SP-initiated-only posture")
	} else {
		assertInvalid(t, "unsolicited", err)
	}

	// Solicited: non-empty InResponseTo accepted.
	p2 := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	resp2 := mintValidResponse(t, p2, idp, tACSURL)
	if _, err := a.ProcessAssertion(context.Background(), resp2, ""); err != nil {
		t.Fatalf("solicited response rejected: %v", err)
	}
}

// TestIDPInitiated_AcceptsUnsolicited proves AllowIDPInitiated=true accepts a
// response with an empty InResponseTo.
func TestIDPInitiated_AcceptsUnsolicited(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name:              "idp-initiated",
		EntityID:          tSPEntity,
		ACSURL:            tACSURL,
		IDPCert:           idp.certPEM(),
		IDPEntityID:       tIDPEntity,
		AllowIDPInitiated: true,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	a.now = func() time.Time { return now }

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	p.inResponseTo = "" // unsolicited
	resp := mintValidResponse(t, p, idp, tACSURL)
	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err != nil {
		t.Fatalf("IdP-initiated unsolicited response rejected: %v", err)
	}
}

// TestProcessAssertion_NoAudienceRestrictionRejected proves an assertion with NO
// AudienceRestriction is rejected (we require an explicit audience; an
// unrestricted assertion must not authenticate at a specific SP).
func TestProcessAssertion_NoAudienceRestrictionRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	assertion := buildAssertion(p)
	assertion.Conditions.AudienceRestrictions = nil // strip audience
	el := signAssertionEl(t, assertion, idp)
	resp := responseFrom(p.idpEntityID, tACSURL, p.inResponseTo, el)

	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err == nil {
		t.Fatal("assertion with no AudienceRestriction ACCEPTED")
	} else {
		assertInvalid(t, "no-audience", err)
	}
}
