package webauthn

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

// MDSSource selects WHERE the FIDO Metadata Service (MDS) blob is loaded
// from. A configured source turns the attestation policy from an
// honest-client OPERATIONAL control into an ADVERSARY-RESISTANT one: the
// resulting metadata.Provider is set as gw.Config.MDS, so go-webauthn's
// VerifyAttestation validates the attestation certificate CHAIN to the FIDO
// root and matches the AAGUID against the metadata entry's trust anchor. A
// crafted self-signed x5c asserting an allowlisted AAGUID then fails (its
// chain doesn't root in the MDS), closing the residual spoof a bare AAGUID
// allowlist leaves open.
//
// EXACTLY ONE of FilePath / FetchURL supplies the blob bytes. The zero value
// (both empty) means NO MDS — gw.Config.MDS stays nil and the ceremony is
// byte-identical to the operational-control behaviour.
//
// The loaded metadata is a STARTUP SNAPSHOT: the memory provider does not
// refresh. The FIDO MDS rotates roughly monthly (the blob carries a
// nextUpdate date), so operators reload by restarting with a fresh blob, or
// run go-webauthn's providers/cached fetch+refresh provider out-of-band (a
// documented enhancement — see the package docs). A snapshot that has passed
// its nextUpdate still validates; it simply won't know about authenticators
// added since the snapshot.
type MDSSource struct {
	// FilePath is a path to a FIDO MDS blob on disk (the JWS the operator
	// downloads from https://mds3.fido2.org/). Mutually exclusive with
	// FetchURL.
	FilePath string

	// FetchURL is an HTTPS URL the blob is fetched from at boot via net/http
	// (dep-free). Mutually exclusive with FilePath. A non-HTTPS URL is
	// rejected (an MDS blob fetched over plaintext could be substituted in
	// flight; the JWS root check would still catch a tampered blob, but we
	// fail loud rather than rely on it).
	FetchURL string

	// CustomRootPEM, when non-empty, overrides the built-in FIDO production
	// MDS root used to JWS-verify the blob. It is the base64 DER of the root
	// certificate (NOT PEM-armoured — go-webauthn's WithRootCertificate takes
	// the raw base64 body, the same encoding as an x5c entry). This is ONLY
	// for a non-production / test MDS (e.g. the FIDO conformance suite, or an
	// in-house metadata service); production deployments leave it empty so
	// the blob is validated against the real FIDO root baked into
	// go-webauthn. Misusing it to trust an attacker-controlled root would
	// defeat the whole control, so it is deliberately separate from the
	// happy path.
	CustomRootPEM string

	// FetchTimeout bounds the boot-time HTTP fetch (FetchURL only). Zero
	// defaults to 30s. A slow/hung MDS endpoint then fails boot loudly rather
	// than hanging startup forever.
	FetchTimeout time.Duration
}

// Configured reports whether this source actually points at a blob. The zero
// value (no FilePath, no FetchURL) is NOT configured — the caller leaves
// gw.Config.MDS nil and the ceremony is byte-identical to a build that never
// knew about MDS.
func (s MDSSource) Configured() bool {
	return s != MDSSource{} && (strings.TrimSpace(s.FilePath) != "" || strings.TrimSpace(s.FetchURL) != "")
}

// validate checks the source is internally consistent BEFORE any IO, so a
// misconfiguration (both sources set, neither set, plaintext URL) fails loud
// at boot with a precise message rather than a confusing IO error later.
func (s MDSSource) validate() error {
	file, url := strings.TrimSpace(s.FilePath), strings.TrimSpace(s.FetchURL)
	switch {
	case file == "" && url == "":
		return errors.New("webauthn: MDS source has neither file_path nor fetch_url")
	case file != "" && url != "":
		return errors.New("webauthn: MDS source sets BOTH file_path and fetch_url — choose exactly one")
	}
	if url != "" && !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("webauthn: MDS fetch_url must be https, got %q", s.FetchURL)
	}
	return nil
}

// BuildMDSProvider loads + decodes the configured MDS blob and returns a
// metadata.Provider ready to set as gw.Config.MDS. It FAILS LOUD on a
// malformed / tampered / wrong-root blob: the blob is a JWS whose signing
// chain go-webauthn verifies against the FIDO MDS root (or the supplied
// CustomRootPEM), so a substituted or corrupted blob is rejected here at
// boot rather than silently downgrading attestation validation to "no MDS".
//
// The returned provider is the go-webauthn in-memory provider seeded from
// the decoded entries (a startup snapshot — see [MDSSource]). It is NOT used
// by callers that left the source unconfigured; cmd/embedders gate on
// [MDSSource.Configured] and pass nil otherwise (byte-identical default).
func BuildMDSProvider(src MDSSource) (metadata.Provider, error) {
	if err := src.validate(); err != nil {
		return nil, err
	}
	raw, err := loadMDSBlob(src)
	if err != nil {
		return nil, err
	}

	// The decoder JWS-verifies the blob's x5c chain to the root. Default root
	// = go-webauthn's built-in FIDO ProductionMDSRoot; CustomRootPEM swaps it
	// for a test/non-prod root. WithIgnoreEntryParsingErrors lets the decode
	// tolerate individual malformed entries (the production MDS occasionally
	// carries entries this library version can't fully parse) WITHOUT
	// dropping the whole blob — the chain signature is still verified, so the
	// security property (root-validated metadata) holds; a single unparseable
	// authenticator entry just isn't in the lookup set.
	var dopts []metadata.DecoderOption
	dopts = append(dopts, metadata.WithIgnoreEntryParsingErrors())
	if root := strings.TrimSpace(src.CustomRootPEM); root != "" {
		dopts = append(dopts, metadata.WithRootCertificate(root))
	}
	decoder, err := metadata.NewDecoder(dopts...)
	if err != nil {
		return nil, fmt.Errorf("webauthn: build MDS decoder: %w", err)
	}

	// DecodeBytes verifies the JWS signature + chain — a tampered or
	// wrong-root blob errors HERE (fail loud at boot).
	payload, err := decoder.DecodeBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decode MDS blob (chain/signature verification failed): %w", err)
	}
	md, err := decoder.Parse(payload)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse MDS metadata: %w", err)
	}

	// Seed the in-memory provider from the decoded entries. ToMap drops the
	// zero AAGUID, so the provider keys on real authenticator models. The
	// memory provider's defaults (validate-entry / validate-trust-anchor /
	// validate-status all ON, permit-zero-AAGUID OFF) are exactly the
	// adversary-resistant posture we want: an AAGUID with no metadata entry,
	// or one whose attestation chain doesn't verify against the entry's trust
	// anchor, is REJECTED by go-webauthn's ValidateMetadata.
	provider, err := memory.New(memory.WithMetadata(md.ToMap()))
	if err != nil {
		return nil, fmt.Errorf("webauthn: build MDS provider: %w", err)
	}
	return provider, nil
}

// loadMDSBlob returns the raw blob bytes from the configured source (file or
// HTTPS fetch). validate has already guaranteed exactly one is set.
func loadMDSBlob(src MDSSource) ([]byte, error) {
	if file := strings.TrimSpace(src.FilePath); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("webauthn: read MDS blob file %q: %w", file, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("webauthn: MDS blob file %q is empty", file)
		}
		return raw, nil
	}

	url := strings.TrimSpace(src.FetchURL)
	timeout := src.FetchTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url) //nolint:noctx // boot-time one-shot fetch bounded by client.Timeout
	if err != nil {
		return nil, fmt.Errorf("webauthn: fetch MDS blob from %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webauthn: fetch MDS blob from %q: HTTP %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("webauthn: read MDS blob body from %q: %w", url, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("webauthn: MDS blob fetched from %q is empty", url)
	}
	return raw, nil
}
