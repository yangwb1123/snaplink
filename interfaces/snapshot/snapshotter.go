package snapshot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// Snapshotter assembles a Snapshot by polling each configured backend's
// List() method. Every dependency is optional — the snapshot only
// includes categories whose backend was wired (and not Excluded). A
// nil Snapshotter field means "skip this category", NOT "fail".
//
// WebAuthn / TOTP / Sealer are the v3 credential-portability seams.
// WebAuthn exports passkeys when the wired store implements
// webauthn.CredentialLister (absent ⇒ category silently omitted, the
// optional-store pattern). TOTP seeds export ONLY when the operator
// explicitly sets ExportOptions.IncludeCredentialSeeds and every gate
// (sealer + PurposeSealer + SeedExporter) is present — a set flag with a
// missing gate is a hard error, never silent absence.
type Snapshotter struct {
	Clients     sso.ClientStore               // optional
	Users       sso.UserProvider              // optional
	Permissions permissions.Provider          // optional; needs MenuLister for menus
	NetPolicy   netpolicy.Store               // optional
	Tenants     tenant.Store                  // optional
	Connections connections.Store             // optional
	Pairwise    security.PairwiseSubjectStore // optional
	Tracker     bootstrap.Tracker             // optional, for BootstrapState
	Namespace   string                        // bootstrap namespace; defaults to "sso-server"

	// WebAuthn is the passkey store the webauthn_credentials category
	// enumerates. Optional: a store that doesn't implement
	// webauthn.CredentialLister (or a nil store) simply omits the
	// category.
	WebAuthn webauthn.UserStore

	// TOTP is the seed store for the opt-in totp_seeds category, and
	// Sealer the master encryption sealer its purpose-separated envelope
	// is derived from. cmd wires the SAME sealer instance the pipeline
	// uses; nil Sealer means no encryption configured, which fails closed
	// (an explicit seed request errors).
	TOTP   authenticators.TOTPStore
	Sealer Sealer

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

	// IncludeCredentialSeeds opts into exporting TOTP seeds inside the
	// purpose-separated sealed envelope (totp_seeds category). Unset (the
	// default) keeps the artifact byte-identical in scope to today. Once
	// set, every missing gate is a HARD error — no encryption sealer, no
	// PurposeSealer derivation, no SeedExporter store — because an
	// operator who explicitly asked must not get silent absence (that is
	// how DR incidents happen).
	IncludeCredentialSeeds bool

	// Redactor, when non-nil, strips secret-bearing fields from the
	// exported snapshot before it is returned (and therefore before it
	// is serialized + sealed). It overrides Snapshotter.DefaultExportRedactor
	// for this one call. Nil falls back to the Snapshotter default.
	//
	// Redaction runs on export-local COPIES of the affected resources,
	// so it NEVER mutates the live store's objects. A redacted snapshot
	// is for inspection / sharing, NOT restore — see Redactor. Redaction
	// and seed export are mutually exclusive: an effective redactor with
	// seeds present fails with ErrSnapshotSeedsWithRedaction (the
	// Redactor interface cannot error and cannot scrub opaque
	// ciphertext, so the pipeline refuses).
	Redactor Redactor
}

// Export builds the Snapshot. Returns an error if any wired backend
// fails to List; partial snapshots are never returned (it's all or
// nothing — bad data downstream is worse than a bounced export).
func (s *Snapshotter) Export(ctx context.Context, opts ExportOptions) (*Snapshot, error) {
	ns := s.namespace()
	snap, err := s.newSnapshot(ns, opts)
	if err != nil {
		return nil, err
	}

	if err := s.exportBootstrapState(ctx, snap, ns); err != nil {
		return nil, err
	}
	if err := s.exportResources(ctx, snap, opts); err != nil {
		return nil, err
	}

	// Redaction XOR seeds: the refusal lives HERE (in Export), not in
	// the Redactor — the interface cannot return errors and cannot scrub
	// opaque ciphertext. An effective redactor with seeds present would
	// either silently drop the category or ship seeds in a redacted
	// artifact; both are unacceptable, so the pipeline refuses. All
	// in-repo export paths go through Export; anything calling Redact
	// directly bypasses this check by construction.
	if snap.Resources.SeedEnvelope != nil && effectiveRedactor(opts.Redactor, s.DefaultExportRedactor) != nil {
		return nil, ErrSnapshotSeedsWithRedaction
	}

	s.applyRedaction(snap, opts)
	return snap, nil
}

// namespace resolves the configured bootstrap namespace, defaulting to
// "sso-server" when unset.
func (s *Snapshotter) namespace() string {
	if s.Namespace == "" {
		return "sso-server"
	}
	return s.Namespace
}

// newSnapshot allocates a fresh Snapshot envelope with a generated ID and
// the current timestamp.
func (s *Snapshotter) newSnapshot(ns string, opts ExportOptions) (*Snapshot, error) {
	id, err := newSnapshotID()
	if err != nil {
		return nil, fmt.Errorf("snapshot: id: %w", err)
	}
	return &Snapshot{
		SchemaVersion:   SchemaVersion,
		SnapshotID:      id,
		TakenAtUnix:     timeNow().Unix(),
		SourceNamespace: ns,
		SourceNodeID:    opts.SourceNodeID,
		Categories:      make([]ResourceCategory, 0),
	}, nil
}

// exportResources polls each wired backend in the order downstream
// enumeration depends on. The v3 credential categories enumerate after
// users: webauthn credentials and TOTP seeds both key on restored
// identities.
func (s *Snapshotter) exportResources(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	tenantIDs, err := s.exportTenants(ctx, snap, opts)
	if err != nil {
		return err
	}
	if err := s.exportConnections(ctx, snap, opts, tenantIDs); err != nil {
		return err
	}
	// Clients first — also gives us the clientID list permissions /
	// menus / assignments need to enumerate. When the Clients store is nil
	// (or excluded), clientIDs stays empty and permissions/menus
	// enumeration is skipped — operator-acceptable: the destination
	// presumably already has clients seeded.
	clientIDs, err := s.exportClients(ctx, snap, opts)
	if err != nil {
		return err
	}
	if err := s.exportUsers(ctx, snap, opts); err != nil {
		return err
	}
	if err := s.exportWebAuthn(ctx, snap, opts); err != nil {
		return err
	}
	if err := s.exportTotpSeeds(ctx, snap, opts); err != nil {
		return err
	}
	if err := s.exportPairwise(ctx, snap, opts); err != nil {
		return err
	}
	if err := s.exportPermissions(ctx, snap, opts, clientIDs); err != nil {
		return err
	}
	return s.exportNetPolicy(ctx, snap, opts)
}

func (s *Snapshotter) exportPairwise(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	if s.Pairwise == nil || excluded(CategoryPairwise, opts.Exclude) {
		return nil
	}
	lister, ok := s.Pairwise.(security.PairwiseSubjectLister)
	if !ok {
		return errors.Join(ErrUnsupportedRestore, errors.New("pairwise backend cannot list all records"))
	}
	items, err := lister.ListPairwiseSubjects(ctx)
	if err != nil {
		return fmt.Errorf("snapshot: pairwise.ListPairwiseSubjects: %w", err)
	}
	snap.Resources.Pairwise = items
	snap.markCategory(CategoryPairwise)
	return nil
}

func (s *Snapshotter) exportTenants(ctx context.Context, snap *Snapshot, opts ExportOptions) ([]string, error) {
	if s.Tenants == nil {
		return nil, nil
	}
	tenants, err := s.Tenants.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: tenants.ListTenants: %w", err)
	}
	ids := make([]string, 0, len(tenants))
	for _, item := range tenants {
		ids = append(ids, item.ID)
	}
	if !excluded(CategoryTenants, opts.Exclude) {
		snap.Resources.Tenants = tenants
		snap.markCategory(CategoryTenants)
	}
	if excluded(CategoryTenantDomains, opts.Exclude) {
		return ids, nil
	}
	domains, err := s.Tenants.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: tenants.ListDomains: %w", err)
	}
	snap.Resources.TenantDomains = domains
	snap.markCategory(CategoryTenantDomains)
	return ids, nil
}

func (s *Snapshotter) exportConnections(ctx context.Context, snap *Snapshot, opts ExportOptions, tenantIDs []string) error {
	if s.Connections == nil || excluded(CategoryConnections, opts.Exclude) {
		return nil
	}
	if lister, ok := s.Connections.(connections.Lister); ok {
		items, err := lister.List(ctx)
		if err != nil {
			return fmt.Errorf("snapshot: connections.List: %w", err)
		}
		snap.Resources.Connections = items
		snap.markCategory(CategoryConnections)
		return nil
	}
	for _, tenantID := range tenantIDs {
		items, err := s.Connections.ByTenant(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("snapshot: connections.ByTenant[%s]: %w", tenantID, err)
		}
		snap.Resources.Connections = append(snap.Resources.Connections, items...)
	}
	snap.markCategory(CategoryConnections)
	return nil
}

// applyRedaction runs the LAST export step. The effective redactor is the
// per-call override when set, else the Snapshotter default; nil on both
// means no redaction and a byte-identical (backward-compatible) export.
// Some ClientStore backends (the in-memory one) return live pointers from
// List, so we deep-copy every client into export-local objects BEFORE
// handing the snapshot to the redactor — that guarantees redaction never
// zeros a secret on the running server's in-memory client.
func (s *Snapshotter) applyRedaction(snap *Snapshot, opts ExportOptions) {
	if r := effectiveRedactor(opts.Redactor, s.DefaultExportRedactor); r != nil {
		copyClientsForRedaction(snap)
		copyUsersForRedaction(snap)
		copyConnectionsForRedaction(snap)
		r.Redact(snap)
	}
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
	snap.markCategory(CategoryClients)
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
	snap.markCategory(CategoryUsers)
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
		snap.markCategory(CategoryRoles)
	}
	if !excluded(CategoryAssignments, opts.Exclude) {
		if err := s.exportAssignments(ctx, snap, clientIDs); err != nil {
			return err
		}
		snap.markCategory(CategoryAssignments)
	}
	if !excluded(CategoryMenus, opts.Exclude) {
		if err := s.exportMenus(ctx, snap, clientIDs); err != nil {
			return err
		}
		snap.markCategory(CategoryMenus)
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
	snap.markCategory(CategoryNetPolicy)
	return nil
}

func (s *Snapshot) markCategory(category ResourceCategory) {
	if !excluded(category, s.Categories) {
		s.Categories = append(s.Categories, category)
	}
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
