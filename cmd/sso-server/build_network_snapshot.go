package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/platform/netpolicy"

	netpolicyetcd "github.com/snaplink/sso/platform/netpolicy/etcd"

	"github.com/snaplink/sso/interfaces/snapshot"
)

// buildNetworkStore materializes the netpolicy.Store for cmd.
//
// Memory backend defers to [config.Config.BuildNetworkStore] (which
// applies seeds itself). The etcd backend is constructed here so the
// config package keeps the etcd transitive dep out of its SPI; seeds
// flow through [config.ApplyNetworkPolicySeeds] so both paths share
// identical seed semantics + error wrapping.
//
// Returns (nil, "", nil) when network is disabled. The returned kind
// is "memory" or "etcd"; cmd uses it to decide whether to register a
// /readyz check (memory has no backend health signal to report).
func buildNetworkStore(cfg *config.NetworkConfig, logger spi.Logger) (netpolicy.Store, string, error) {
	if !cfg.Enabled {
		return nil, "", nil
	}
	backend := strings.ToLower(strings.TrimSpace(cfg.Store))
	switch backend {
	case "", "memory":
		store, err := (&config.Config{Network: *cfg}).BuildNetworkStore()
		if err != nil {
			return nil, "", err
		}
		logger.Info("network policy store", "backend", "memory", "seed_policies", len(cfg.Policies))
		return store, "memory", nil
	case "etcd":
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, "", errors.New("network.etcd_endpoints required when network.store=etcd")
		}
		store, err := netpolicyetcd.New(netpolicyetcd.Config{
			Endpoints:   cfg.EtcdEndpoints,
			Prefix:      cfg.EtcdPrefix,
			DialTimeout: cfg.EtcdDialTimeout,
			Username:    cfg.EtcdUsername,
			Password:    cfg.EtcdPassword,
		})
		if err != nil {
			return nil, "", fmt.Errorf("netpolicy/etcd: %w", err)
		}
		if err := config.ApplyNetworkPolicySeeds(context.Background(), store, cfg.Policies); err != nil {
			_ = store.Close()
			return nil, "", err
		}
		logger.Info("network policy store",
			"backend", "etcd",
			"endpoints", cfg.EtcdEndpoints,
			"prefix", cfg.EtcdPrefix,
			"seed_policies", len(cfg.Policies))
		return store, "etcd", nil
	default:
		return nil, "", fmt.Errorf("unknown network.store %q", cfg.Store)
	}
}

// buildSnapshotSubsystem materializes the snapshot Pipeline + Storage from
// SnapshotConfig. Returns (nil, nil, nil) when snapshot.enabled=false. The
// Snapshotter / Restorer that depend on the runtime stores are wired
// separately inside buildApp once those stores exist.
func buildSnapshotSubsystem(cfg *config.Config, logger spi.Logger) (*snapshot.Pipeline, snapshot.Storage, error) {
	if !cfg.Snapshot.Enabled {
		return nil, nil, nil
	}
	store, err := buildSnapshotStorage(cfg.Snapshot.Storage, logger)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := buildSnapshotSealer(cfg.Snapshot.Encryption, logger)
	if err != nil {
		return nil, nil, err
	}
	return &snapshot.Pipeline{Sealer: sealer}, store, nil
}

// loadAESGCMKey resolves the snapshot AES-GCM key from inline YAML
// (cfg.Key — discouraged, secrets in YAML hit git logs) or a file
// (cfg.KeyFile — recommended; KMS-fetched DEKs land there). The
// file or string can be raw 32 bytes, hex-encoded 64 chars, or
// base64-encoded ~44 chars; the helper tries each in turn so
// operators don't have to remember which encoder their KMS emits.
//
// Fails loud when neither source is set OR when no decoding scheme
// produces exactly 32 bytes — silent fallback would surface as
// cryptic AEAD errors at first Seal/Open.
func loadAESGCMKey(cfg config.SnapshotEncryptionConfig) ([]byte, error) {
	raw := []byte(cfg.Key)
	if len(raw) == 0 && cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("snapshot aes-gcm key file: %w", err)
		}
		// A 32-byte file is a raw binary key — use it verbatim. Only trim
		// a trailing newline for longer (text-encoded hex/base64) key
		// files. Trimming first would corrupt a raw key whose final byte
		// is 0x0A/0x0D (~0.78% of random 32-byte keys, e.g. a KMS DEK),
		// truncating it to 31 bytes and failing the load.
		if len(b) == 32 {
			return b, nil
		}
		raw = bytes.TrimRight(b, "\r\n")
	}
	if len(raw) == 0 {
		return nil, errors.New("snapshot.encryption.backend=aes-gcm requires key or key_file")
	}
	// Try raw bytes first (exactly 32).
	if len(raw) == 32 {
		return raw, nil
	}
	// Then hex (64 chars).
	if decoded, err := hex.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	// Then base64 (~44 chars).
	if decoded, err := base64.StdEncoding.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(string(raw)); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, fmt.Errorf("snapshot aes-gcm: key must decode to exactly 32 bytes (raw / hex / base64)")
}

// snapshotRestorerAdapter bridges releases.SnapshotRestorer onto the
// snapshot.Pipeline + snapshot.Storage + snapshot.Restorer trio.
// Lives in the cmd binary so the releases package stays free of any
// snapshot import — keeping the two SDKs independently evolvable.
type snapshotRestorerAdapter struct {
	pipeline *snapshot.Pipeline
	storage  snapshot.Storage
	restorer *snapshot.Restorer
}

func (a *snapshotRestorerAdapter) RestoreByID(ctx context.Context, snapshotID string) error {
	if a.pipeline == nil || a.storage == nil || a.restorer == nil {
		return fmt.Errorf("snapshot subsystem not configured")
	}
	snap, err := a.pipeline.Load(ctx, a.storage, snapshotID)
	if err != nil {
		return fmt.Errorf("load snapshot %q: %w", snapshotID, err)
	}
	// AdvanceBootstrap=false because rollback shouldn't move the
	// bootstrap high-water mark — that's a one-way ratchet for
	// first-boot init, not a release-flip mechanism.
	if _, err := a.restorer.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite}); err != nil {
		return fmt.Errorf("restore snapshot %q: %w", snapshotID, err)
	}
	return nil
}
