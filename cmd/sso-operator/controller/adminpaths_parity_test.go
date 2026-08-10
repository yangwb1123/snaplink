package controller

// root_consts_parity_test.go is the R1 white-box parity test: it pins the
// controller's unexported admin-path constants to the root module's owned
// constants, so a deploy-tree literal can never silently drift from what
// sso-server actually mounts (shared/core PathAPIPrefix +
// PathAdminConfigRunning / PathAdminConfigClusterDiff). Test-only: the
// root import is exercised solely by this file, so the operator binary
// stays root-free and the out-of-process module posture is preserved.

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestAdminPathConstsMatchRootOwnedConstants(t *testing.T) {
	wantRunning := core.PathAPIPrefix + core.PathAdminConfigRunning
	if runningConfigPath != wantRunning {
		t.Errorf("runningConfigPath = %q, want %q (root-owned consts)", runningConfigPath, wantRunning)
	}
	wantClusterDiff := core.PathAPIPrefix + core.PathAdminConfigClusterDiff
	if clusterDiffPath != wantClusterDiff {
		t.Errorf("clusterDiffPath = %q, want %q (root-owned consts)", clusterDiffPath, wantClusterDiff)
	}
}
