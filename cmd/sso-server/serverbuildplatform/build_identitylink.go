package serverbuildplatform

import (
	"fmt"
	"strings"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/identitylink"
	identitylinkmemory "github.com/snaplink/sso/domains/identitylink/memory"
)

// BuildIdentityLink builds the identitylink.Store (+ optional MergePolicy)
// backing sso.WithIdentityLinkStore / sso.WithIdentityMergePolicy when
// self_service.identity_link.enabled — the self-service GET/DELETE
// /me/identities surface. Only a memory backend exists today
// (domains/identitylink/memory).
//
// The returned MergePolicy is nil for merge_policy "" / "reject" — the
// package's own safe default (identitylink.Resolve already treats a nil
// policy as identitylink.RejectPolicy{}), so the caller should only append
// sso.WithIdentityMergePolicy when it is non-nil, keeping an unset/"reject"
// config byte-identical to never wiring the option at all. "link_only"
// returns identitylink.NewLinkOnlyMergePolicy bound to the SAME store.
//
// Returns (nil, nil, nil) when disabled — byte-identical to a build without
// the feature. An unrecognized merge_policy value fails loud at boot rather
// than silently falling back to the safe default.
func BuildIdentityLink(cfg config.IdentityLinkConfig) (identitylink.Store, identitylink.MergePolicy, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	store := identitylinkmemory.New()
	switch strings.ToLower(strings.TrimSpace(cfg.MergePolicy)) {
	case "", "reject":
		return store, nil, nil
	case "link_only":
		return store, identitylink.NewLinkOnlyMergePolicy(store), nil
	default:
		return nil, nil, fmt.Errorf("self_service.identity_link.merge_policy %q invalid (\"\", \"reject\", or \"link_only\")", cfg.MergePolicy)
	}
}
