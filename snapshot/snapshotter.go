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
	Clients     sso.ClientStore      // optional
	Users       sso.UserProvider     // optional
	Permissions permissions.Provider // optional; needs MenuLister for menus
	NetPolicy   netpolicy.Store      // optional
	Tracker     bootstrap.Tracker    // optional, for BootstrapState
	Namespace   string               // bootstrap namespace; defaults to "sso-server"

	// DefaultExportRedactor is applied to every Export that doesn't
	// supply ExportOptions.Redactor. Nil (the default) means NO
	// redaction — the export is byte-identical to the unredacted form,
	// preserving backward compatibility for existing restorable backups.
	// cmd wires SnapshotRedactSecrets() here when snapshot.redact_secrets
	// is set so every export path (gRPC, REST, scheduled) produces a
	// safe-sharing artifact without per-call plumbing. See Redactor for
	// the restore caveat.
	DefaultExportRedactor Redactor
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

	// Redactor, when non-nil, strips secret-bearing fields from the
	// exported snapshot before it is returned (and therefore before it
	// is serialized + sealed). It overrides Snapshotter.DefaultExportRedactor
	// for this one call. Nil falls back to the Snapshotter default.
	//
	// Redaction runs on export-local COPIES of the affected resources,
	// so it NEVER mutates the live store's objects. A redacted snapshot
	// is for inspection / sharing, NOT restore — see Redactor.
	Redactor Redactor
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

	if err := s.exportBootstrapState(ctx, snap, ns); err != nil {
		return nil, err
	}

	// Clients first — also gives us the clientID list permissions /
	// menus / assignments need to enumerate. When the Clients store is nil
	// (or excluded), clientIDs stays empty and permissions/menus
	// enumeration is skipped — operator-acceptable: the destination
	// presumably already has clients seeded.
	clientIDs, err := s.exportClients(ctx, snap, opts)
	if err != nil {
		return nil, err
	}
	if err := s.exportUsers(ctx, snap, opts); err != nil {
		return nil, err
	}
	if err := s.exportPermissions(ctx, snap, opts, clientIDs); err != nil {
		return nil, err
	}
	if err := s.exportNetPolicy(ctx, snap, opts); err != nil {
		return nil, err
	}

	// Redaction is the LAST export step. The effective redactor is the
	// per-call override when set, else the Snapshotter default; nil on
	// both means no redaction and a byte-identical (backward-compatible)
	// export. Some ClientStore backends (the in-memory one) return live
	// pointers from List, so we deep-copy every client into export-local
	// objects BEFORE handing the snapshot to the redactor — that
	// guarantees redaction never zeros a secret on the running server's
	// in-memory client.
	if r := effectiveRedactor(opts.Redactor, s.DefaultExportRedactor); r != nil {
		copyClientsForRedaction(snap)
		r.Redact(snap)
	}

	return snap, nil
}

// exportBootstrapState records the tracker's applied version — only
// meaningful if a Tracker was wired.
func (s *Snapshotter) exportBootstrapState(ctx context.Context, snap *Snapshot, ns string) error {
	if s.Tracker == nil {
		return nil
	}
	v, err := s.Tracker.AppliedVersion(ctx, ns)
	if err != nil {
		return fmt.Errorf("snapshot: tracker: %w", err)
	}
	snap.BootstrapState = BootstrapState{Namespace: ns, AppliedVersion: v}
	return nil
}

// exportClients lists clients into snap and returns the enumerated client
// IDs that downstream permission/menu enumeration depends on.
func (s *Snapshotter) exportClients(ctx context.Context, snap *Snapshot, opts ExportOptions) ([]string, error) {
	if s.Clients == nil || excluded(CategoryClients, opts.Exclude) {
		return nil, nil
	}
	cs, err := s.Clients.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: clients.List: %w", err)
	}
	snap.Resources.Clients = cs
	clientIDs := make([]string, 0, len(cs))
	for _, c := range cs {
		clientIDs = append(clientIDs, c.ID)
	}
	return clientIDs, nil
}

// exportUsers lists users into snap.
func (s *Snapshotter) exportUsers(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	if s.Users == nil || excluded(CategoryUsers, opts.Exclude) {
		return nil
	}
	us, err := s.Users.List(ctx)
	if err != nil {
		return fmt.Errorf("snapshot: users.List: %w", err)
	}
	snap.Resources.Users = us
	return nil
}

// exportPermissions enumerates roles, assignments and menus per client.
func (s *Snapshotter) exportPermissions(ctx context.Context, snap *Snapshot, opts ExportOptions, clientIDs []string) error {
	if s.Permissions == nil || len(clientIDs) == 0 {
		return nil
	}
	if !excluded(CategoryRoles, opts.Exclude) {
		if err := s.exportRoles(ctx, snap, clientIDs); err != nil {
			return err
		}
	}
	if !excluded(CategoryAssignments, opts.Exclude) {
		if err := s.exportAssignments(ctx, snap, clientIDs); err != nil {
			return err
		}
	}
	if !excluded(CategoryMenus, opts.Exclude) {
		if err := s.exportMenus(ctx, snap, clientIDs); err != nil {
			return err
		}
	}
	return nil
}

func (s *Snapshotter) exportRoles(ctx context.Context, snap *Snapshot, clientIDs []string) error {
	for _, cid := range clientIDs {
		roles, err := s.Permissions.ListAllRoles(ctx, cid)
		if err != nil {
			return fmt.Errorf("snapshot: roles[%s]: %w", cid, err)
		}
		if len(roles) == 0 {
			continue
		}
		snap.Resources.Roles = append(snap.Resources.Roles, ClientRoles{ClientID: cid, Roles: roles})
	}
	return nil
}

func (s *Snapshotter) exportAssignments(ctx context.Context, snap *Snapshot, clientIDs []string) error {
	for _, cid := range clientIDs {
		as, err := s.Permissions.ListAssignments(ctx, cid)
		if err != nil {
			return fmt.Errorf("snapshot: assignments[%s]: %w", cid, err)
		}
		if len(as) == 0 {
			continue
		}
		snap.Resources.Assignments = append(snap.Resources.Assignments, ClientAssignments{ClientID: cid, Assignments: as})
	}
	return nil
}

// exportMenus enumerates menus per client. If the Provider doesn't
// implement MenuLister we skip menus silently — operators can opt-in by
// upgrading the backend without breaking the export.
func (s *Snapshotter) exportMenus(ctx context.Context, snap *Snapshot, clientIDs []string) error {
	ml, ok := s.Permissions.(permissions.MenuLister)
	if !ok {
		return nil
	}
	for _, cid := range clientIDs {
		menus, err := ml.GetMenus(ctx, cid)
		if err != nil {
			return fmt.Errorf("snapshot: menus[%s]: %w", cid, err)
		}
		if len(menus) == 0 {
			continue
		}
		snap.Resources.Menus = append(snap.Resources.Menus, ClientMenus{ClientID: cid, Menus: menus})
	}
	return nil
}

// exportNetPolicy lists network policies into snap.
func (s *Snapshotter) exportNetPolicy(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	if s.NetPolicy == nil || excluded(CategoryNetPolicy, opts.Exclude) {
		return nil
	}
	ps, err := s.NetPolicy.List(ctx)
	if err != nil {
		return fmt.Errorf("snapshot: netpolicy.List: %w", err)
	}
	snap.Resources.NetPolicy = ps
	return nil
}

// effectiveRedactor resolves the redactor for one Export: the per-call
// override wins, then the Snapshotter default, else nil (no redaction).
func effectiveRedactor(perCall, def Redactor) Redactor {
	if perCall != nil {
		return perCall
	}
	return def
}

// copyClientsForRedaction replaces snap.Resources.Clients with a slice
// of shallow client copies so a subsequent in-place redaction mutates
// only the export's copies, never the source store's objects. A shallow
// struct copy is sufficient because the redactor only zeros scalar
// string fields (Secret, RegistrationAccessToken); the shared slice
// fields (JWKS, RedirectURIs, ...) are read, never written.
func copyClientsForRedaction(snap *Snapshot) {
	src := snap.Resources.Clients
	if len(src) == 0 {
		return
	}
	out := make([]*sso.Client, len(src))
	for i, c := range src {
		if c == nil {
			continue
		}
		cp := *c
		out[i] = &cp
	}
	snap.Resources.Clients = out
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
