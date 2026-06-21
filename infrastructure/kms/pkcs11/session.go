package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 EdDSA constants. miekg/pkcs11 v1.1.1 predates v3.0 and does
// NOT export these, so they are pinned here from the standard's published
// numeric values (these are fixed by the spec and identical across every
// conformant token / provider, exactly like the CKM_* values miekg does
// export). Defining them locally keeps the Ed25519 / CKM_EDDSA seam working
// without forcing a dependency-version bump on the rest of the module. A
// later miekg that exports CKM_EDDSA / CKK_EC_EDWARDS will carry these same
// values.
const (
	ckmEDDSA     uint = 0x00001057 // CKM_EDDSA
	ckkECEdwards uint = 0x00000040 // CKK_EC_EDWARDS
)

// Config parameters the production [New] constructor: where the PKCS#11
// module is, which token + key to use, and how to authenticate.
type Config struct {
	// ModulePath is the filesystem path to the PKCS#11 provider shared object
	// (e.g. /usr/lib/softhsm/libsofthsm2.so, the vendor's libCryptoki2.so).
	ModulePath string

	// TokenLabel selects the slot whose token has this CKA_LABEL. Preferred
	// over a raw slot number (slot ids are not stable across reboots).
	TokenLabel string

	// PIN is the user (CKU_USER) PIN. An empty PIN skips C_Login — valid only
	// for tokens with public/no-login signing objects (rare); production keys
	// almost always require a PIN. Source it from a secret store, never YAML.
	PIN string

	// KeyLabel locates the signing key objects (private + public) by their
	// shared CKA_LABEL. Set this OR KeyID (or both, AND-ed together). The
	// private object provides the signing handle; the matching public object
	// provides the public key (unless PublicKey is supplied below).
	KeyLabel string

	// KeyID locates the signing key objects by their shared CKA_ID (raw
	// bytes). Optional; combined with KeyLabel when both are set.
	KeyID []byte

	// PublicKey, when non-nil, is the known public half of the signing key
	// (e.g. parsed from a certificate). Supplying it skips the token
	// public-key-object lookup + attribute read entirely; the signer then
	// needs only the private object handle.
	PublicKey crypto.PublicKey
}

// realSession is the miekg/pkcs11-backed [Session]. It owns the *pkcs11.Ctx,
// the open session handle, and the public-key object handle (for the lazy
// attribute read). A mutex serializes Sign because PKCS#11 permits only one
// signing operation in flight per session (C_SignInit/C_Sign are stateful).
type realSession struct {
	ctx       *pkcs11.Ctx
	session   pkcs11.SessionHandle
	pubHandle pkcs11.ObjectHandle // CKO_PUBLIC_KEY; 0 when PublicKey was supplied
	keyType   uint                // CKK_EC | CKK_RSA | CKK_EC_EDWARDS

	mu sync.Mutex // serializes SignInit+Sign (one op per session)
}

// New opens the PKCS#11 token described by cfg and returns a [Signer] over
// the located signing key. It performs C_Initialize, finds the slot by token
// label, opens a serial read-only session, C_Login (when a PIN is set),
// locates the private (and, unless cfg.PublicKey is set, the public) key
// objects by label/id, and reads the public key's type so Sign can pick the
// mechanism.
//
// New requires cgo + a C toolchain (miekg/pkcs11 is a cgo binding) and a
// reachable token. Call [Signer.PublicKey] once after New to fail loud if the
// public key cannot be read. Call [Signer.Close] on shutdown to C_Logout +
// C_CloseSession + C_Finalize.
func New(cfg Config) (*Signer, error) {
	if cfg.ModulePath == "" {
		return nil, errors.New("pkcs11: empty ModulePath")
	}
	if cfg.KeyLabel == "" && len(cfg.KeyID) == 0 {
		return nil, errors.New("pkcs11: one of KeyLabel or KeyID is required")
	}

	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: load module %q failed", cfg.ModulePath)
	}
	// From here a failure must Destroy the ctx so the cgo handle is freed.
	ok := false
	defer func() {
		if !ok {
			ctx.Destroy()
		}
	}()

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: C_Initialize: %w", err)
	}
	// On any failure after Initialize, also Finalize.
	defer func() {
		if !ok {
			_ = ctx.Finalize()
		}
	}()

	slot, err := findSlot(ctx, cfg.TokenLabel)
	if err != nil {
		return nil, err
	}

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: C_OpenSession: %w", err)
	}
	defer func() {
		if !ok {
			_ = ctx.CloseSession(session)
		}
	}()

	if cfg.PIN != "" {
		if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
			return nil, fmt.Errorf("pkcs11: C_Login: %w", err)
		}
	}
	defer func() {
		if !ok && cfg.PIN != "" {
			_ = ctx.Logout(session)
		}
	}()

	privHandle, err := findKeyObject(ctx, session, pkcs11.CKO_PRIVATE_KEY, cfg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: locate private key: %w", err)
	}

	rs := &realSession{ctx: ctx, session: session}

	// Determine the key type from the private object so Sign maps mechanisms.
	kt, err := keyTypeOf(ctx, session, privHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read private key type: %w", err)
	}
	rs.keyType = kt

	if cfg.PublicKey == nil {
		pubHandle, err := findKeyObject(ctx, session, pkcs11.CKO_PUBLIC_KEY, cfg)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: locate public key (supply Config.PublicKey to skip): %w", err)
		}
		rs.pubHandle = pubHandle
	}

	signer, err := NewSigner(rs, uint(privHandle), cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	ok = true
	return signer, nil
}

// findSlot returns the slot whose token CKA_LABEL matches label. An empty
// label takes the first slot with a token present (single-token deployments).
func findSlot(ctx *pkcs11.Ctx, label string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: C_GetSlotList: %w", err)
	}
	if len(slots) == 0 {
		return 0, errors.New("pkcs11: no token present in any slot")
	}
	if label == "" {
		return slots[0], nil
	}
	for _, slot := range slots {
		ti, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if trimPadded(ti.Label) == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token with label %q", label)
}

// findKeyObject finds exactly the key object of the given class matching the
// configured label/id. It errors if none match (a misconfiguration that must
// fail loud, not sign with the wrong key).
func findKeyObject(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, cfg Config) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	if cfg.KeyLabel != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.KeyLabel))
	}
	if len(cfg.KeyID) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, cfg.KeyID))
	}
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	handles, _, err := ctx.FindObjects(session, 2)
	finalErr := ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("C_FindObjects: %w", err)
	}
	if finalErr != nil {
		return 0, fmt.Errorf("C_FindObjectsFinal: %w", finalErr)
	}
	if len(handles) == 0 {
		return 0, errors.New("no matching key object")
	}
	// More than one match means the label/id is ambiguous — refuse rather
	// than guess which key signs.
	if len(handles) > 1 {
		return 0, errors.New("multiple key objects match the label/id (ambiguous)")
	}
	return handles[0], nil
}

// keyTypeOf reads CKA_KEY_TYPE (CKK_EC / CKK_RSA / CKK_EC_EDWARDS) off an object.
func keyTypeOf(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (uint, error) {
	attrs, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return 0, err
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return 0, errors.New("empty CKA_KEY_TYPE")
	}
	return uintFromCKBytes(attrs[0].Value), nil
}

// Sign implements [Session]. It maps the package Mechanism to the miekg
// pkcs11.Mechanism (attaching PSS params for MechRSAPSS), runs C_SignInit +
// C_Sign under the session mutex, and returns the token's raw signature.
func (rs *realSession) Sign(mech Mechanism, keyHandle uint, data []byte) ([]byte, error) {
	m, err := toPKCS11Mechanism(mech)
	if err != nil {
		return nil, err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err := rs.ctx.SignInit(rs.session, m, pkcs11.ObjectHandle(keyHandle)); err != nil {
		return nil, fmt.Errorf("C_SignInit(%s): %w", mech, err)
	}
	sig, err := rs.ctx.Sign(rs.session, data)
	if err != nil {
		return nil, fmt.Errorf("C_Sign(%s): %w", mech, err)
	}
	return sig, nil
}

// toPKCS11Mechanism maps the package enum to the concrete miekg mechanism.
// CKM_RSA_PKCS_PSS carries CK_RSA_PKCS_PSS_PARAMS (SHA-256 + MGF1-SHA-256 +
// salt length = 32) as its parameter blob — the JWS PS256 profile go-jose
// verifies with PSSSaltLengthAuto / what AWS KMS RSASSA_PSS_SHA_256 produces.
func toPKCS11Mechanism(mech Mechanism) ([]*pkcs11.Mechanism, error) {
	switch mech {
	case MechECDSA:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, nil
	case MechRSAPKCS1v15:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, nil
	case MechRSAPSS:
		params := pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32)
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}, nil
	case MechEdDSA:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}, nil
	default:
		return nil, fmt.Errorf("pkcs11: %w: mechanism %s", ErrUnsupportedKey, mech)
	}
}

// PublicKeyDER implements [Session]: it reads the public-key object's
// attributes and assembles a DER SubjectPublicKeyInfo so [Signer] can parse
// it with x509.ParsePKIXPublicKey. EC: CKA_EC_PARAMS (named-curve OID) +
// CKA_EC_POINT (the point, DER-wrapped in an OCTET STRING). RSA: CKA_MODULUS +
// CKA_PUBLIC_EXPONENT. Ed25519 (CKK_EC_EDWARDS): CKA_EC_POINT (the raw 32-byte
// public key, OCTET-STRING-wrapped).
func (rs *realSession) PublicKeyDER() ([]byte, error) {
	switch rs.keyType {
	case pkcs11.CKK_EC:
		return rs.ecPublicKeyDER()
	case pkcs11.CKK_RSA:
		return rs.rsaPublicKeyDER()
	case ckkECEdwards:
		return rs.ed25519PublicKeyDER()
	default:
		return nil, fmt.Errorf("pkcs11: %w: CKA_KEY_TYPE %d", ErrUnsupportedKey, rs.keyType)
	}
}

func (rs *realSession) getAttrs(types ...uint) (map[uint][]byte, error) {
	tmpl := make([]*pkcs11.Attribute, 0, len(types))
	for _, t := range types {
		tmpl = append(tmpl, pkcs11.NewAttribute(t, nil))
	}
	rs.mu.Lock()
	attrs, err := rs.ctx.GetAttributeValue(rs.session, rs.pubHandle, tmpl)
	rs.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("C_GetAttributeValue: %w", err)
	}
	out := make(map[uint][]byte, len(attrs))
	for _, a := range attrs {
		out[a.Type] = a.Value
	}
	return out, nil
}

func (rs *realSession) ecPublicKeyDER() ([]byte, error) {
	attrs, err := rs.getAttrs(pkcs11.CKA_EC_PARAMS, pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, err
	}
	curve, err := curveFromECParams(attrs[pkcs11.CKA_EC_PARAMS])
	if err != nil {
		return nil, err
	}
	point, err := unwrapECPoint(attrs[pkcs11.CKA_EC_POINT])
	if err != nil {
		return nil, err
	}
	// ParseUncompressedPublicKey (Go 1.25+) parses the uncompressed SEC1 point
	// and validates it is on-curve, replacing the deprecated elliptic.Unmarshal
	// + manual *ecdsa.PublicKey assembly.
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: CKA_EC_POINT is not a valid uncompressed point: %w", err)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func (rs *realSession) rsaPublicKeyDER() ([]byte, error) {
	attrs, err := rs.getAttrs(pkcs11.CKA_MODULUS, pkcs11.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, err
	}
	modBytes := attrs[pkcs11.CKA_MODULUS]
	expBytes := attrs[pkcs11.CKA_PUBLIC_EXPONENT]
	if len(modBytes) == 0 || len(expBytes) == 0 {
		return nil, errors.New("pkcs11: empty CKA_MODULUS / CKA_PUBLIC_EXPONENT")
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modBytes),
		E: int(new(big.Int).SetBytes(expBytes).Int64()),
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// ed25519PublicKeyDER assembles the Ed25519 SPKI by hand: x509.MarshalPKIX-
// PublicKey accepts an ed25519.PublicKey, so we extract the raw 32-byte key
// from CKA_EC_POINT (PKCS#11 v3.0 stores the EdDSA public key there, OCTET-
// STRING-wrapped) and hand it to the stdlib marshaller.
func (rs *realSession) ed25519PublicKeyDER() ([]byte, error) {
	attrs, err := rs.getAttrs(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, err
	}
	point, err := unwrapECPoint(attrs[pkcs11.CKA_EC_POINT])
	if err != nil {
		return nil, err
	}
	if len(point) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pkcs11: Ed25519 CKA_EC_POINT length %d, want %d", len(point), ed25519.PublicKeySize)
	}
	return x509.MarshalPKIXPublicKey(ed25519.PublicKey(point))
}

// unwrapECPoint strips the DER OCTET STRING wrapper most tokens put around the
// raw EC point in CKA_EC_POINT (PKCS#11 v2.40 §A: "the octet string value of
// the DER-encoding"). Some legacy tokens return the bare point — if the bytes
// don't parse as an OCTET STRING, they are returned as-is.
func unwrapECPoint(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("pkcs11: empty CKA_EC_POINT")
	}
	var inner []byte
	rest, err := asn1.Unmarshal(raw, &inner)
	if err == nil && len(rest) == 0 {
		return inner, nil
	}
	// Not OCTET-STRING-wrapped (legacy token): use the bytes directly.
	return raw, nil
}

// namedCurveOIDs maps the DER-encoded ECParameters (a named-curve OID) to the
// stdlib curve. CKA_EC_PARAMS is the DER of the curve OID for the prime
// curves SoftHSM and HSMs use for ES256/384/512.
var namedCurveOIDs = []struct {
	oid   asn1.ObjectIdentifier
	curve elliptic.Curve
}{
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, elliptic.P256()}, // prime256v1 / secp256r1
	{asn1.ObjectIdentifier{1, 3, 132, 0, 34}, elliptic.P384()},          // secp384r1
	{asn1.ObjectIdentifier{1, 3, 132, 0, 35}, elliptic.P521()},          // secp521r1
}

// curveFromECParams decodes CKA_EC_PARAMS (a DER named-curve OID) to the
// matching stdlib curve.
func curveFromECParams(params []byte) (elliptic.Curve, error) {
	if len(params) == 0 {
		return nil, errors.New("pkcs11: empty CKA_EC_PARAMS")
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("pkcs11: parse CKA_EC_PARAMS OID: %w", err)
	}
	for _, c := range namedCurveOIDs {
		if oid.Equal(c.oid) {
			return c.curve, nil
		}
	}
	return nil, fmt.Errorf("pkcs11: %w: EC curve OID %v", ErrUnsupportedKey, oid)
}

// Close logs out, closes the session, and finalizes the module, releasing the
// cgo handle. Safe to call once on shutdown; idempotent-ish (a second call is
// a no-op against an already-finalized ctx, which miekg tolerates).
func (s *Signer) Close() error {
	rs, ok := s.sess.(*realSession)
	if !ok {
		return nil // a fake/non-token session has nothing to close
	}
	var firstErr error
	// Best-effort, in reverse order of New's acquisition. A Logout error on a
	// public (no-login) session is benign, so it is not surfaced first.
	_ = rs.ctx.Logout(rs.session)
	if err := rs.ctx.CloseSession(rs.session); err != nil {
		firstErr = err
	}
	if err := rs.ctx.Finalize(); err != nil && firstErr == nil {
		firstErr = err
	}
	rs.ctx.Destroy()
	return firstErr
}

// trimPadded trims the trailing spaces PKCS#11 pads fixed-width string fields
// (like CK_TOKEN_INFO.label, 32 bytes space-padded) with.
func trimPadded(s string) string {
	end := len(s)
	for end > 0 && s[end-1] == ' ' {
		end--
	}
	return s[:end]
}

// uintFromCKBytes decodes a CK_ULONG attribute value (native-endian bytes, as
// miekg returns it) into a uint. CKA_KEY_TYPE / CKA_CLASS come back this way.
func uintFromCKBytes(b []byte) uint {
	var v uint
	// miekg returns CK_ULONG attribute values in the platform byte order; on
	// the little-endian targets this module builds for, the low byte is first.
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint(b[i])
	}
	return v
}

// _ keeps pkix imported even if a future refactor drops the only current use
// (defensive: x509.MarshalPKIXPublicKey already pulls the SPKI machinery, but
// referencing pkix documents the SPKI/AlgorithmIdentifier intent).
var _ = pkix.AlgorithmIdentifier{}
