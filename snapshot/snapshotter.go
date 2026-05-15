package snapshot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/bootstrap"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
)

// Snapshotter assembles a Snapshot by polling each configured backend's
// List() method. Every dependency is optional — the snapshot only
// includes categories whose backend was wired (and not Excluded). A
// nil Snapshotter field means "skip this category", NOT "fail".
type Snapshotter struct {
	Clients     sso.ClientStore       // optional
	Users       sso.UserProvider      // optional
	Permissions permissions.Provider  // optional; needs MenuLister for menus
	NetPolicy   netpolicy.Store       // optional
	Tracker     bootstrap.Tracker     // optional, for BootstrapState
	Namespace   string                // bootstrap namespace; defaults to "sso-server"
}

// ExportOptions tunes a single Export call.
type ExportOptions struct {
	// SourceNodeID stamps the snapshot with the originating node so
	// restored copies can be traced back. Optional.
	SourceNodeID string

	// Exclude omits the listed categories from the export. Useful when
	// the operator wants to ship clients + users to a peer but not the
	// network policy (which is environment-specific).
	Exclude []ResourceCategory
}

// Export builds the Snapshot. Returns an error if any wired backend
// fails to List; partial snapshots are never returned (it's all or
// nothing — bad data downstream is worse than a bounced export).
func (s *Snapshotter) Export(ctx context.Context, opts ExportOptions) (*Snapshot, error) {
	ns := s.Namespace
	if ns == "" {
		ns = "sso-server"
	}

	id, err := newSnapshotID()
	if err != nil {
		return nil, fmt.Errorf("snapshot: id: %w", err)
	}
	snap := &Snapshot{
		SchemaVersion:   SchemaVersion,
		SnapshotID:      id,
		TakenAtUnix:     timeNow().Unix(),
		SourceNamespace: ns,
		SourceNodeID:    opts.SourceNodeID,
	}

	// Bootstrap state — only meaningful if a Tracker was wired.
	if s.Tracker != nil {
		v, err := s.Tracker.AppliedVersion(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("snapshot: tracker: %w", err)
		}
		snap.BootstrapState = BootstrapState{Namespace: ns, AppliedVersion: v}
	}

	// Clients first — also gives us the clientID list permissions /
	// menus / assignments need to enumerate.
	var clientIDs []string
	if s.Clients != nil && !excluded(CategoryClients, opts.Exclude) {
		cs, err := s.Clients.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: clients.List: %w", err)
		}
		snap.Resources.Clients = cs
		clientIDs = make([]string, 0, len(cs))
		for _, c := range cs {
			clientIDs = append(clientIDs, c.ID)
		}
	} else if s.Permissions != nil || s.NetPolicy != nil {
		// We still need clientIDs for permissions/menus enumeration. If
		// Clients store is nil we can't enumerate; permissions stays
		// empty in that case (operator-acceptable: the destination
		// presumably already has clients seeded).
	}

	if s.Users != nil && !excluded(CategoryUsers, opts.Exclude) {
		us, err := s.Users.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: users.List: %w", err)
		}
		snap.Resources.Users = us
	}

	if s.Permissions != nil && len(clientIDs) > 0 {
		if !excluded(CategoryRoles, opts.Exclude) {
			for _, cid := range clientIDs {
				roles, err := s.Permissions.ListAllRoles(ctx, cid)
				if err != nil {
					return nil, fmt.Errorf("snapshot: roles[%s]: %w", cid, err)
				}
				if len(roles) == 0 {
					continue
				}
				snap.Resources.Roles = append(snap.Resources.Roles, ClientRoles{ClientID: cid, Roles: roles})
			}
		}
		if !excluded(CategoryAssignments, opts.Exclude) {
			for _, cid := range clientIDs {
				as, err := s.Permissions.ListAssignments(ctx, cid)
				if err != nil {
					return nil, fmt.Errorf("snapshot: assignments[%s]: %w", cid, err)
				}
				if len(as) == 0 {
					continue
				}
				snap.Resources.Assignments = append(snap.Resources.Assignments, ClientAssignments{ClientID: cid, Assignments: as})
			}
		}
		if !excluded(CategoryMenus, opts.Exclude) {
			ml, ok := s.Permissions.(permissions.MenuLister)
			if ok {
				for _, cid := range clientIDs {
					menus, err := ml.GetMenus(ctx, cid)
					if err != nil {
						return nil, fmt.Errorf("snapshot: menus[%s]: %w", cid, err)
					}
					if len(menus) == 0 {
						continue
					}
					snap.Resources.Menus = append(snap.Resources.Menus, ClientMenus{ClientID: cid, Menus: menus})
				}
			}
			// If the Provider doesn't implement MenuLister we just skip
			// menus silently — operators can opt-in by upgrading the
			// backend without breaking the export.
		}
	}

	if s.NetPolicy != nil && !excluded(CategoryNetPolicy, opts.Exclude) {
		ps, err := s.NetPolicy.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: netpolicy.List: %w", err)
		}
		snap.Resources.NetPolicy = ps
	}

	return snap, nil
}

// newSnapshotID returns a sortable, time-prefixed ID:
//
//	snap_2026-05-15T08-30-05Z_<6-byte-rand-base64>
//
// The dashes inside the timestamp are intentional — colons are
// problematic in file system paths.
func newSnapshotID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	t := timeNow().Format("2006-01-02T15-04-05Z")
	return "snap_" + t + "_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Validate sanity-checks a Snapshot before persistence. Currently only
// version + non-empty namespace; codec / encryption layers add their
// own checks (checksum, decryption integrity).
func (s *Snapshot) Validate() error {
	if !IsValidSchemaVersion(s.SchemaVersion) {
		return errors.Join(ErrUnknownSchemaVersion, fmt.Errorf("got %q want %q", s.SchemaVersion, SchemaVersion))
	}
	if s.SourceNamespace == "" {
		return errors.New("snapshot: source_namespace required")
	}
	return nil
}
