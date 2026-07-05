package grpcadmin

import (
	"context"
	"sort"
	"time"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minRuntimeGraceSeconds is the floor for an operator-supplied grace_seconds.
// A rotation whose demoted key is retired before the max access-token TTL would
// strand tokens minted just before it, so we refuse a sub-minute window (ops
// MUST keep it >= the max access-token TTL — see docs/config-reference.md). The
// server DEFAULT (config grace / the 24h const) is trusted and not re-floored.
const minRuntimeGraceSeconds = 60

// Signing-key states surfaced by ListSigningKeys. Only public metadata is ever
// returned — never private key bytes.
const (
	keyStateActive     = "active"
	keyStateVerifyOnly = "verify_only"
)

// KeyAdminService is the admin surface for the server's signing keypair. The
// rotate orchestration is injected from cmd (RevokeAcrossIssuers-style) so the
// admin path produces the SAME side effects as the scheduler path (audit +
// discovery bust + metrics + PublishSigningKeys + coordinated broadcast).
type KeyAdminService struct {
	adminv1.UnimplementedKeyAdminServiceServer
	// rotate performs the primary-issuer rotation + the shared side effects +
	// the grace-delayed local retire. nil when the configured issuer has no
	// runtime-rotation support (custom WithTokenIssuer) → Unimplemented.
	rotate func(ctx context.Context, grace time.Duration) (oldKID, newKID string, err error)
	// externalManaged is true when keys.signing.external != "": an external
	// KMS/HSM owns the key lifecycle, so an in-process rotate would mint a key
	// the backend never sees → FailedPrecondition (checked before rotate).
	externalManaged bool
	// defaultGrace is applied when the request omits grace_seconds (config
	// grace_period when set, else the 24h package default).
	defaultGrace time.Duration
	// issuers backs ListSigningKeys — read-only enumeration of every wired
	// JWKSProvider issuer's public key metadata (available even for external
	// signers, whose keys are still published in JWKS).
	issuers  map[string]sso.TokenIssuer
	recorder *audit.Recorder
}

// KeyAdminConfig bundles the dependencies for NewKeyAdminService. All fields
// optional; a nil Rotate + false ExternalManaged surfaces as Unimplemented.
type KeyAdminConfig struct {
	Rotate          func(ctx context.Context, grace time.Duration) (oldKID, newKID string, err error)
	ExternalManaged bool
	DefaultGrace    time.Duration
	Issuers         map[string]sso.TokenIssuer
	Recorder        *audit.Recorder
}

func NewKeyAdminService(cfg KeyAdminConfig) *KeyAdminService {
	return &KeyAdminService{
		rotate:          cfg.Rotate,
		externalManaged: cfg.ExternalManaged,
		defaultGrace:    cfg.DefaultGrace,
		issuers:         cfg.Issuers,
		recorder:        cfg.Recorder,
	}
}

func (s *KeyAdminService) RotateSigningKey(ctx context.Context, in *adminv1.RotateSigningKeyRequest) (*adminv1.RotateSigningKeyResponse, error) {
	if s.externalManaged {
		return nil, status.Error(codes.FailedPrecondition, "external signer manages its own key lifecycle; rotate it in the KMS/HSM")
	}
	if s.rotate == nil {
		return nil, status.Error(codes.Unimplemented, "the configured signing issuer has no runtime-rotation support")
	}
	grace, err := s.resolveGrace(in)
	if err != nil {
		return nil, err
	}
	oldKID, newKID, err := s.rotate(ctx, grace)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "rotate signing key: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminSigningKeyRotated, "from="+oldKID+" to="+newKID)
	return &adminv1.RotateSigningKeyResponse{
		OldKid:       oldKID,
		NewKid:       newKID,
		GraceSeconds: int64(grace / time.Second),
	}, nil
}

// resolveGrace applies the request's grace_seconds when set (floored at
// minRuntimeGraceSeconds), otherwise the server default.
func (s *KeyAdminService) resolveGrace(in *adminv1.RotateSigningKeyRequest) (time.Duration, error) {
	if in != nil && in.GraceSeconds > 0 {
		if in.GraceSeconds < minRuntimeGraceSeconds {
			return 0, status.Errorf(codes.InvalidArgument, "grace_seconds must be >= %d", minRuntimeGraceSeconds)
		}
		return time.Duration(in.GraceSeconds) * time.Second, nil
	}
	return s.defaultGrace, nil
}

func (s *KeyAdminService) ListSigningKeys(ctx context.Context, _ *adminv1.ListSigningKeysRequest) (*adminv1.ListSigningKeysResponse, error) {
	return &adminv1.ListSigningKeysResponse{Keys: s.collectKeyInfos(ctx)}, nil
}

// collectKeyInfos enumerates public key metadata across every wired JWKSProvider
// issuer, marking the issuer's active signing kid vs demoted/adopted verify-only
// keys. Deduped by kid (a shared kid across issuers appears once) and sorted for
// a stable response. Private key material is never surfaced.
func (s *KeyAdminService) collectKeyInfos(ctx context.Context) []*adminv1.SigningKeyInfo {
	seen := make(map[string]bool)
	out := make([]*adminv1.SigningKeyInfo, 0)
	for _, iss := range s.issuers {
		jp, ok := iss.(core.JWKSProvider)
		if !ok {
			continue
		}
		active := activeKID(iss)
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			continue
		}
		for i := range jwks {
			kid := jwks[i].Kid
			if kid == "" || seen[kid] {
				continue
			}
			seen[kid] = true
			state := keyStateVerifyOnly
			if kid == active {
				state = keyStateActive
			}
			out = append(out, &adminv1.SigningKeyInfo{Kid: kid, Alg: jwks[i].Alg, State: state})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kid < out[j].Kid })
	return out
}

// activeKID returns the issuer's current signing kid, or "" when the issuer does
// not expose one (a symmetric / opaque issuer).
func activeKID(iss sso.TokenIssuer) string {
	if k, ok := iss.(interface{ KeyID() string }); ok {
		return k.KeyID()
	}
	return ""
}
