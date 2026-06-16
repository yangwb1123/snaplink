package defaultimpl_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
)

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestMultiJWEDecrypter_SupportedAlgsAndEncs(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaDec, _ := defaultimpl.NewRSAJWEDecrypter(rsaPriv, "rsa-1")
	ecDec, _ := defaultimpl.NewECDHJWEDecrypter(ecPriv, "ec-1")
	multi := defaultimpl.NewMultiJWEDecrypter(rsaDec, ecDec)

	algs := multi.SupportedAlgs()
	if !contains(algs, "RSA-OAEP-256") || !contains(algs, "ECDH-ES") {
		t.Errorf("SupportedAlgs = %v, want union of RSA-OAEP-256 + ECDH-ES", algs)
	}
	encs := multi.SupportedEncs()
	if !contains(encs, "A256GCM") {
		t.Errorf("SupportedEncs = %v, want A256GCM", encs)
	}
}

func TestMultiJWEResponseEncrypter_SupportedAlgsAndEncs(t *testing.T) {
	multi := defaultimpl.NewMultiJWEResponseEncrypter(
		defaultimpl.NewRSAJWEResponseEncrypter(),
		defaultimpl.NewECDHJWEResponseEncrypter(),
	)
	algs := multi.SupportedAlgs()
	if !contains(algs, "RSA-OAEP-256") || !contains(algs, "ECDH-ES") {
		t.Errorf("SupportedAlgs = %v, want union", algs)
	}
	encs := multi.SupportedEncs()
	if !contains(encs, "A256GCM") {
		t.Errorf("SupportedEncs = %v, want A256GCM", encs)
	}
}
