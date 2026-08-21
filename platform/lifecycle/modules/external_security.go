package modules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExternalProvenance is the signed release statement required by a stock
// server worker admission policy. Signature covers the same fields with the
// signature field removed; the artifact digest is checked against disk.
type ExternalProvenance struct {
	SchemaVersion  uint32 `json:"schema_version"`
	ModuleID       string `json:"module_id"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ReleaseID      string `json:"release_id"`
	BuildProfile   string `json:"build_profile"`
	SourceRevision string `json:"source_revision"`
	Signature      string `json:"signature"`
}

const maxExternalProvenanceBytes = 64 << 10

func verifyExternalExecutable(path, expected, signaturePath string, publicKey []byte, provenancePath string, provenanceKey []byte, moduleID, releaseID, buildProfile string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("external module: open executable: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("external module: hash executable: %w", err)
	}
	digest := hash.Sum(nil)
	if !secureHexEqual(hex.EncodeToString(digest), strings.ToLower(strings.TrimSpace(expected))) {
		return errors.New("external module: executable digest mismatch")
	}
	if signaturePath == "" {
		return verifyExternalProvenance(provenancePath, provenanceKey, moduleID, hex.EncodeToString(digest), releaseID, buildProfile)
	}
	signature, err := readExternalArtifactSignature(signaturePath)
	if err != nil {
		return fmt.Errorf("external module: read artifact signature: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("external module: invalid artifact signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), digest, decoded) {
		return errors.New("external module: artifact signature mismatch")
	}
	return verifyExternalProvenance(provenancePath, provenanceKey, moduleID, hex.EncodeToString(digest), releaseID, buildProfile)
}

func readExternalArtifactSignature(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("external module: read artifact signature: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, fmt.Errorf("external module: read artifact signature: %w", err)
	}
	if len(data) > 4096 {
		return nil, errors.New("external module: artifact signature exceeds size limit")
	}
	return data, nil
}

func validateExternalSignatureSpec(spec ExternalModuleSpec) error {
	if (spec.SignaturePath == "") != (len(spec.SignaturePublicKey) == 0) {
		return errors.New("external module: signature path and public key must be configured together")
	}
	if spec.SignaturePath != "" && !filepath.IsAbs(spec.SignaturePath) {
		return errors.New("external module: signature path must be absolute")
	}
	if len(spec.SignaturePublicKey) != 0 && len(spec.SignaturePublicKey) != ed25519.PublicKeySize {
		return errors.New("external module: Ed25519 public key has invalid size")
	}
	if (spec.ProvenancePath == "") != (len(spec.ProvenancePublicKey) == 0) {
		return errors.New("external module: provenance path and public key must be configured together")
	}
	if spec.ProvenancePath != "" && !filepath.IsAbs(spec.ProvenancePath) {
		return errors.New("external module: provenance path must be absolute")
	}
	if len(spec.ProvenancePublicKey) != 0 && len(spec.ProvenancePublicKey) != ed25519.PublicKeySize {
		return errors.New("external module: provenance Ed25519 public key has invalid size")
	}
	return nil
}

func verifyExternalProvenance(path string, publicKey []byte, moduleID, digest, releaseID, buildProfile string) error {
	if path == "" {
		return nil
	}
	statement, err := readExternalProvenance(path)
	if err != nil {
		return err
	}
	if err := validateExternalProvenanceClaims(statement, moduleID, digest, releaseID, buildProfile); err != nil {
		return err
	}
	return verifyExternalProvenanceSignature(statement, publicKey)
}

func readExternalProvenance(path string) (ExternalProvenance, error) {
	file, err := os.Open(path)
	if err != nil {
		return ExternalProvenance{}, fmt.Errorf("external module: read provenance: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxExternalProvenanceBytes+1))
	if err != nil {
		return ExternalProvenance{}, fmt.Errorf("external module: read provenance: %w", err)
	}
	if len(data) > maxExternalProvenanceBytes {
		return ExternalProvenance{}, errors.New("external module: provenance exceeds size limit")
	}
	var statement ExternalProvenance
	if err := json.Unmarshal(data, &statement); err != nil {
		return ExternalProvenance{}, fmt.Errorf("external module: decode provenance: %w", err)
	}
	return statement, nil
}

func validateExternalProvenanceClaims(statement ExternalProvenance, moduleID, digest, releaseID, buildProfile string) error {
	if statement.SchemaVersion != 1 {
		return errors.New("external module: unsupported provenance schema")
	}
	if statement.ModuleID != moduleID || !strings.EqualFold(statement.ArtifactSHA256, digest) {
		return errors.New("external module: provenance claims do not match artifact")
	}
	for _, claim := range []string{statement.ReleaseID, statement.BuildProfile, statement.SourceRevision} {
		if strings.TrimSpace(claim) == "" {
			return errors.New("external module: provenance claims are incomplete")
		}
	}
	if releaseID != "" && statement.ReleaseID != releaseID {
		return errors.New("external module: provenance release mismatch")
	}
	if buildProfile != "" && statement.BuildProfile != buildProfile {
		return errors.New("external module: provenance build profile mismatch")
	}
	return nil
}

func verifyExternalProvenanceSignature(statement ExternalProvenance, publicKey []byte) error {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(statement.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("external module: invalid provenance signature encoding")
	}
	payload, err := json.Marshal(struct {
		SchemaVersion  uint32 `json:"schema_version"`
		ModuleID       string `json:"module_id"`
		ArtifactSHA256 string `json:"artifact_sha256"`
		ReleaseID      string `json:"release_id"`
		BuildProfile   string `json:"build_profile"`
		SourceRevision string `json:"source_revision"`
	}{statement.SchemaVersion, statement.ModuleID, statement.ArtifactSHA256, statement.ReleaseID, statement.BuildProfile, statement.SourceRevision})
	if err != nil {
		return fmt.Errorf("external module: encode provenance: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return errors.New("external module: provenance signature mismatch")
	}
	return nil
}

func dialExternalAddress(ctx context.Context, network, address string, config *tls.Config, timeout time.Duration) (net.Conn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if config != nil {
		return (&tls.Dialer{Config: config}).DialContext(attemptCtx, network, address)
	}
	return (&net.Dialer{}).DialContext(attemptCtx, network, address)
}

func validateExternalRemoteSpec(spec ExternalModuleSpec) error {
	if externalRemoteHasLocalFields(spec) {
		return errors.New("external module: remote policy cannot include local process fields")
	}
	if err := validateExternalRemoteAddress(spec.RemoteAddress); err != nil {
		return errors.New("external module: remote address must be host:port")
	}
	if err := validateExternalRemoteTLS(spec.TLSConfig); err != nil {
		return err
	}
	return validateSPIFFEID(spec.PeerSPIFFEID)
}

func externalRemoteHasLocalFields(spec ExternalModuleSpec) bool {
	if len(spec.Args) != 0 {
		return true
	}
	for _, field := range []string{spec.Executable, spec.SocketPath, spec.ExpectedSHA256, spec.SignaturePath, spec.ProvenancePath, spec.RequiredReleaseID, spec.RequiredBuildProfile} {
		if field != "" {
			return true
		}
	}
	for _, key := range [][]byte{spec.SignaturePublicKey, spec.ProvenancePublicKey} {
		if len(key) != 0 {
			return true
		}
	}
	return false
}

func validateExternalRemoteAddress(address string) error {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return err
	}
	return nil
}

func validateExternalRemoteTLS(config *tls.Config) error {
	if config == nil || config.InsecureSkipVerify || len(config.Certificates) == 0 {
		return errors.New("external module: remote mTLS configuration is required")
	}
	if config.MinVersion != 0 && config.MinVersion < tls.VersionTLS12 {
		return errors.New("external module: remote TLS requires TLS 1.2 or newer")
	}
	return nil
}

func validateSPIFFEID(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("external module: invalid SPIFFE peer identity")
	}
	return nil
}

func cloneExternalTLSConfig(config *tls.Config, expectedSPIFFEID string) *tls.Config {
	if config == nil {
		return nil
	}
	clone, err := RequireExternalSPIFFEPeer(config, expectedSPIFFEID)
	if err != nil {
		return config.Clone()
	}
	return clone
}

// RequireExternalSPIFFEPeer returns a cloned TLS configuration that requires
// the leaf peer certificate to contain the exact SPIFFE URI. It preserves an
// existing VerifyConnection callback and is suitable for both worker servers
// and remote supervisor clients.
func RequireExternalSPIFFEPeer(config *tls.Config, expectedSPIFFEID string) (*tls.Config, error) {
	if config == nil {
		return nil, errors.New("external module: nil TLS configuration")
	}
	if err := validateSPIFFEID(expectedSPIFFEID); err != nil {
		return nil, err
	}
	clone := config.Clone()
	if expectedSPIFFEID == "" {
		return clone, nil
	}
	original := clone.VerifyConnection
	clone.VerifyConnection = func(state tls.ConnectionState) error {
		if original != nil {
			if err := original(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) > 0 {
			for _, identity := range state.PeerCertificates[0].URIs {
				if identity.String() == expectedSPIFFEID {
					return nil
				}
			}
		}
		return errors.New("external module: remote SPIFFE identity mismatch")
	}
	return clone, nil
}
