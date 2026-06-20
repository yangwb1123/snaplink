// Package vaulttransit provides a DEPENDENCY-FREE [crypto.Signer] backed by a
// HashiCorp Vault transit secrets engine key, for cloud-agnostic / multi-cloud
// / Vault-standardized deployments. It targets a different operator segment
// than the AWS/GCP/Azure cloud-KMS peers in kms/: a shop that has standardized
// on Vault as its single secrets/crypto control plane across (or independent
// of) any cloud.
//
// # Why this lives in the core module (no nested module)
//
// Vault transit's sign + read-key operations are a plain JSON REST API over
// HTTPS, so this client is implemented BY HAND with ONLY the standard library
// (net/http, encoding/json, crypto/x509, encoding/pem, encoding/base64,
// crypto/{ecdsa,rsa,ed25519,elliptic}). It imports NO third-party package, so
// the root go.mod stays byte-unchanged and it ships IN the core module —
// unlike kms/awskms, kms/gcpkms, kms/azurekeyvault, which each pull a heavy
// vendor SDK and therefore live in a SEPARATE nested module to keep that SDK
// out of the core go.mod.
//
// This is the HIBP precedent: a runtime HTTPS call to an external service is
// NOT a go.mod dependency. The repo already calls out dep-free over net/http
// in several places (the geo/JAR-fetch/oidc_federation/CAEP paths, and
// defaultimpl's HIBPPasswordHealthChecker) — a hand-rolled REST client for a
// stable, simple API is the same pattern, and it avoids forcing every operator
// who wants Vault-backed signing to vendor the full github.com/hashicorp/vault
// API module.
//
// # Security properties
//
//   - The private key NEVER leaves Vault. The process holds only the public
//     half (read once from transit/keys) and a (mount, key, version) reference;
//     every Sign is a transit/sign HTTPS round-trip. This is the cloud-agnostic
//     analogue of the FIPS/PCI/SOC2 "key never leaves the HSM" compliance gate
//     the cloud-KMS peers provide.
//   - Fail-closed: any Vault error, non-2xx, malformed "vault:vN:" wrapper, or
//     empty signature aborts the sign — token issuance fails rather than
//     emitting an unsigned or partially-signed token. (This signs the
//     JWKS-published JWTs, so a silent wrong/empty signature would be
//     catastrophic.)
//   - TLS is the operator's http.Client's responsibility. VaultAddr is
//     https-only (rejected at construction otherwise); the DEFAULT client uses
//     the stdlib's verifying TLS config and is NEVER constructed with
//     InsecureSkipVerify. An operator needing a private CA supplies their own
//     *http.Client whose tls.Config carries the CA in RootCAs (the correct,
//     verifying way) — and the same seam threads mTLS client certs.
//   - The Vault token is a secret. It is produced by Config.TokenSource PER
//     request (so the operator owns lifecycle/renewal — AppRole, Kubernetes
//     auth, an agent sidecar's token sink), set only as the X-Vault-Token
//     request header, and NEVER logged or placed in an error.
//
// # crypto.Signer contract / cryptosigner bridge
//
// Like the cloud-KMS peers, the Signer is a stdlib [crypto.Signer] wired into
// the SSO JWT issuers through the defaultimpl/cryptosigner bridge, NOT directly.
// The bridge's per-algorithm expectations are honored exactly:
//
//   - ECDSA: transit is asked for marshaling_algorithm=asn1, so it returns
//     ASN.1 DER (SEQUENCE{r,s}) — the stdlib ECDSA crypto.Signer contract. The
//     cryptosigner bridge then re-splits that DER into the fixed-width JWS R||S
//     form (RFC 7518 §3.4). The digest is sent prehashed; the curve<->hash
//     pairing (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512) is enforced
//     fail-closed before any Vault call.
//   - RSA: transit is asked for signature_algorithm=pss (when opts is
//     *rsa.PSSOptions) or pkcs1v15, over a prehashed SHA-256 digest; the raw
//     signature is returned (already the JWS form). PSS salt length = hash
//     length, matching go-jose's PSSSaltLengthAuto verify.
//   - Ed25519: the digest argument is the RAW message (opts.HashFunc()==0 —
//     Ed25519 hashes internally), sent un-prehashed with no hash_algorithm; the
//     raw 64-byte signature is returned (RFC 8037 EdDSA form). Unlike AWS KMS /
//     Azure Key Vault, which have no EdDSA key type, transit supports ed25519
//     end to end.
//
// # Wiring (operator cmd)
//
// ES256 over a transit ecdsa-p256 key, with a renewing token source:
//
//	cfg := vaulttransit.Config{
//	    VaultAddr: "https://vault.internal:8200",
//	    Mount:     "transit",          // or wherever transit is mounted
//	    KeyName:   "sso-signing",
//	    KeyVersion: 3,                  // pin the version (SHOULD) so a
//	                                    // transit rotation doesn't change kid
//	    Namespace: "team-platform",     // Vault Enterprise/HCP (optional)
//	    TokenSource: func(ctx context.Context) (string, error) {
//	        // operator owns token lifecycle: read the agent sink, renew an
//	        // AppRole/k8s-auth token, etc. Called per request.
//	        return myTokenStore.Current(ctx)
//	    },
//	    // HTTPClient: &http.Client{Transport: &http.Transport{
//	    //     TLSClientConfig: &tls.Config{RootCAs: privateCAPool}}},
//	}
//	sgn, err := vaulttransit.NewSigner(cfg)
//	if err != nil { /* ... */ }
//	// Fail loud at startup if the addr/token/key/policy is misconfigured:
//	if _, err := sgn.PublicKey(ctx); err != nil { /* ... */ }
//
//	bridge, pub, err := cryptosigner.ECDSA(sgn) // P-256 / ES256
//	if err != nil { /* ... */ }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, "sso-signing-v3"),
//	)
//
// RS256/PS256 use cryptosigner.RSA(sgn, alg) + WithRSAExternalSigner over a
// transit rsa-* key; EdDSA uses cryptosigner.Ed25519(sgn) +
// WithEd25519ExternalSigner over a transit ed25519 key.
//
// # Operational note
//
// A transit sign is a network round-trip (a few ms on a healthy LAN, more
// across regions), so — as with the cloud-KMS peers — extend the token TTL /
// rely on issuer-side key caching rather than signing on every request's hot
// path, and run a single-issuer cluster on a leader, a shared transit key, or
// the leaderless signing-key aggregation (signingkeys/) so every replica's kid
// is verifiable.
package vaulttransit
