package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/yangwb1123/snaplink/platform/audit"
	libauditexport "github.com/yangwb1123/snaplink/platform/audit/auditexport"
)

// latestCheckpointReader is deliberately read-only: export may read an
// attestation but must not gain a write operation.
type latestCheckpointReader interface {
	Latest(context.Context) (*audit.SignedCheckpoint, error)
}

// validateAnchorLatest enforces that the durable checkpoint is selected only
// by an explicit --dsn source and never changes verify or URL semantics.
func validateAnchorLatest(o options) error {
	if !o.anchorLatest {
		return nil
	}
	if o.fromURL != "" || o.verify != "" || o.anchor != "" {
		return usageErrorf("--%s cannot be combined with --%s, --%s, or --%s",
			flagAnchorLatest, flagFromURL, flagVerify, flagAnchor)
	}
	if o.dsn == "" {
		return usageErrorf("--%s requires --%s", flagAnchorLatest, flagDSN)
	}
	return nil
}

// loadLatestCheckpoint reads and verifies the one checkpoint exposed by the
// already-open concrete durable store. It intentionally has no URL fallback.
func loadLatestCheckpoint(ctx context.Context, pager libauditexport.QueryPager) (*audit.SignedCheckpoint, error) {
	reader, ok := pager.(latestCheckpointReader)
	if !ok {
		return nil, errors.New("latest checkpoint is unavailable from this audit store")
	}
	checkpoint, err := reader.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("read latest checkpoint: %w", err)
	}
	if checkpoint == nil {
		return nil, errors.New("no latest audit checkpoint is available")
	}
	if err := audit.VerifyCheckpointSignature(checkpoint); err != nil {
		return nil, fmt.Errorf("latest checkpoint FAILED signature check: %w", err)
	}
	return checkpoint, nil
}

// loadCheckpointFile reads an explicit checkpoint exactly once and verifies
// its signature before the selected event source is opened.
func loadCheckpointFile(path string) (*audit.SignedCheckpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read anchor %s: %w", path, err)
	}
	var checkpoint audit.SignedCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return nil, fmt.Errorf("parse anchor %s: %w", path, err)
	}
	if err := audit.VerifyCheckpointSignature(&checkpoint); err != nil {
		return nil, fmt.Errorf("anchor %s FAILED signature check: %w", path, err)
	}
	return &checkpoint, nil
}

// enforceCheckpointHead is the shared fail-closed relation for file and
// durable anchors: a checkpoint must attest the exact exported head.
func enforceCheckpointHead(head string, checkpoint *audit.SignedCheckpoint) error {
	if head != checkpoint.Checkpoint.HeadHash {
		return fmt.Errorf("anchor head mismatch: bundle head_hash %q, checkpoint attestation %q (checkpoints attest chain heads only)",
			head, checkpoint.Checkpoint.HeadHash)
	}
	return nil
}
