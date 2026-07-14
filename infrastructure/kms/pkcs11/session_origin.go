//go:build !no_pkcs11

package pkcs11

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// KeyOriginAttrs implements [Session]. It reads CKA_LOCAL and
// CKA_NEVER_EXTRACTABLE off the private-key object at keyHandle -- the
// standard PKCS#11 attributes keyOriginFromAttrs (origin.go) classifies
// into a core.KeyOrigin. Some tokens do not support CKA_NEVER_EXTRACTABLE
// on every key, or restrict attribute reads on the private object; either
// error surfaces here and the caller (Signer.KeyOrigin) fails open to
// core.OriginUnknown rather than guessing. Locking mirrors getAttrs in
// session.go: rs.mu serializes this read against a concurrent Sign (one
// PKCS#11 operation in flight per session).
func (rs *realSession) KeyOriginAttrs(keyHandle uint) (KeyOriginAttrs, error) {
	rs.mu.Lock()
	attrs, err := rs.ctx.GetAttributeValue(rs.session, pkcs11.ObjectHandle(keyHandle), []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LOCAL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, nil),
	})
	rs.mu.Unlock()
	if err != nil {
		return KeyOriginAttrs{}, fmt.Errorf("pkcs11: C_GetAttributeValue(CKA_LOCAL/CKA_NEVER_EXTRACTABLE): %w", err)
	}
	var out KeyOriginAttrs
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_LOCAL:
			out.Local = ckBoolTrue(a.Value)
		case pkcs11.CKA_NEVER_EXTRACTABLE:
			out.NeverExtractable = ckBoolTrue(a.Value)
		}
	}
	return out, nil
}

// ckBoolTrue decodes a CK_BBOOL attribute value (a single byte: CK_FALSE =
// 0x00, CK_TRUE = 0x01 per PKCS#11 v2.40 §3.2), tolerating any nonzero byte
// as true -- the same defensive style session.go's uintFromCKBytes uses for
// CK_ULONG values.
func ckBoolTrue(v []byte) bool {
	return len(v) > 0 && v[0] != 0
}
