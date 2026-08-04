package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/yangwb1123/snaplink/platform/configaudit"
)

// DiffStatus classifies one entry against the other side.
type DiffStatus string

const (
	// DiffInserted means the entry exists only on the "after" side (it
	// will be created by a restore).
	DiffInserted DiffStatus = "inserted"
	// DiffUpdated means the entry exists on both sides but its content
	// differs.
	DiffUpdated DiffStatus = "updated"
	// DiffDeleted means the entry exists only on the "before" side (a
	// replace restore will wipe it).
	DiffDeleted DiffStatus = "deleted"
)

// DiffOptions tunes one Diff call.
type DiffOptions struct {
	// Exclude omits the listed categories from the diff output.
	Exclude []ResourceCategory
}

// DiffEntry is one changed item. Changes carries the RFC 6902 patch for
// "updated" entries (from platform/configaudit.Diff) with paths like
// "/clients/{id}/redirect_uris". Inserted and deleted entries never carry
// changes.
type DiffEntry struct {
	ID      string           `json:"id"`
	Status  DiffStatus       `json:"status"`
	Changes []configaudit.Op `json:"changes,omitempty"`
}

// CategoryDiff is one category's outcome: counts plus the changed entries.
// Unchanged entries are never listed — they exist only as counts, so two
// identical snapshots produce a CategoryDiff with zero entries.
type CategoryDiff struct {
	Category  ResourceCategory `json:"category"`
	Inserted  int              `json:"inserted"`
	Updated   int              `json:"updated"`
	Deleted   int              `json:"deleted"`
	Unchanged int              `json:"unchanged"`
	Entries   []DiffEntry      `json:"entries,omitempty"`
}

// DiffResult is the full entry-level diff of one snapshot pair. Categories
// are emitted in AllCategories() order; entries within a category are sorted
// by identity key; change ops are sorted by path. The same pair of inputs
// therefore always yields byte-identical JSON — the determinism property the
// restore preview digest and the Compare RPC's replayability depend on.
type DiffResult struct {
	Categories []CategoryDiff `json:"categories,omitempty"`
}

// Diff computes the entry-level difference between two snapshots without
// touching any backend. before is the baseline (e.g. the snapshot a restore
// would apply), after is the comparison state (e.g. the current live
// state): an entry only in after is "inserted", only in before is "deleted",
// present on both with different content is "updated".
//
// Identity keys match the restorer's per-category alignment exactly:
// tenants→Tenant.ID, tenant_domains→Domain.Hostname, connections→
// Connection.ID, clients→Client.ID, users→User.ID, pairwise→PairwiseSub,
// roles→(ClientID, Role.Code), assignments→(ClientID, UserID),
// menus→ClientID, netpolicy→Policy.Name. A category is diffed iff BOTH
// sides include it and it is not excluded; a nil/empty side means "nothing
// of this kind".
//
// The inputs are never mutated: every client/user/connection entry is
// deep-copied and the copies are passed through SnapshotRedactSecrets, so
// credential-bearing values (client secrets, user password attributes,
// connection secret config keys) never reach the output — a diff is an
// inspection surface, never a credential channel. Redaction also makes the
// classification match restore reality for clients, whose secrets are
// json:"-" and backfilled by the restorer anyway.
func Diff(before, after *Snapshot, opts DiffOptions) (*DiffResult, error) {
	if before == nil || after == nil {
		return nil, errors.New("snapshot: diff requires two snapshots")
	}
	b, err := cloneForDiff(before)
	if err != nil {
		return nil, err
	}
	a, err := cloneForDiff(after)
	if err != nil {
		return nil, err
	}
	SnapshotRedactSecrets().Redact(b)
	SnapshotRedactSecrets().Redact(a)

	out := &DiffResult{Categories: make([]CategoryDiff, 0, len(AllCategories()))}
	for _, cat := range AllCategories() {
		if excluded(cat, opts.Exclude) || !before.IncludesCategory(cat) || !after.IncludesCategory(cat) {
			continue
		}
		bi, err := indexCategory(cat, b)
		if err != nil {
			return nil, fmt.Errorf("snapshot diff: %s before: %w", cat, err)
		}
		ai, err := indexCategory(cat, a)
		if err != nil {
			return nil, fmt.Errorf("snapshot diff: %s after: %w", cat, err)
		}
		out.Categories = append(out.Categories, classifyCategory(cat, bi, ai))
	}
	return out, nil
}

// SnapshotDigest returns a stable sha256 hex digest of the snapshot's
// REDACTED resources in canonical form. The digest covers every included
// category's entries sorted by identity key (List order is unspecified per
// the store interfaces), with clients/users/connections redacted — and
// excludes all envelope metadata (SnapshotID, TakenAtUnix, SourceNodeID,
// SourceNamespace, Kind, BootstrapState, Categories), so two nodes holding
// identical redacted state with identical category coverage produce equal
// digests regardless of when or where the snapshots were taken. The digest
// is the cheap cross-node drift signal for automation: unequal digests mean
// the states differ (or their category coverage differs — an operator-
// visible distinction, never a false alarm).
func SnapshotDigest(s *Snapshot) (string, error) {
	if s == nil {
		return "", errors.New("snapshot: nil snapshot")
	}
	out, err := cloneForDiff(s)
	if err != nil {
		return "", err
	}
	SnapshotRedactSecrets().Redact(out)
	canonical, err := canonicalResources(out)
	if err != nil {
		return "", err
	}
	return configaudit.Digest(canonical)
}

// canonicalResources maps each included category to its identity-sorted,
// JSON-normalized entry list. Marshaling a map[string]any sorts keys, so
// the Digest is byte-stable across runs and nodes. An included-but-empty
// category appears as an empty list, keeping "covered with zero entries"
// distinguishable from "category not covered" — a coverage difference is a
// true positive of the drift signal.
func canonicalResources(s *Snapshot) (map[string]any, error) {
	res := make(map[string]any, len(AllCategories()))
	for _, cat := range AllCategories() {
		if !s.IncludesCategory(cat) {
			continue
		}
		idx, err := indexCategory(cat, s)
		if err != nil {
			return nil, fmt.Errorf("snapshot digest: %s: %w", cat, err)
		}
		list := make([]any, 0, len(idx))
		for _, k := range sortedKeys(idx) {
			list = append(list, idx[k])
		}
		res[string(cat)] = list
	}
	return res, nil
}

// cloneForDiff shallow-copies the envelope and deep-copies every entry the
// redactor mutates (clients, users, connections) so Diff and SnapshotDigest
// never touch the caller's objects. The remaining categories are read-only
// in both paths.
func cloneForDiff(s *Snapshot) (*Snapshot, error) {
	if s == nil {
		return nil, errors.New("snapshot: nil snapshot")
	}
	out := *s
	out.Resources = s.Resources
	copyClientsForRedaction(&out)
	copyUsersForRedaction(&out)
	copyConnectionsForRedaction(&out)
	return &out, nil
}

// indexCategory flattens one category into identity-keyed, JSON-normalized
// entries (map[string]any). Identity keys are the restorer's alignment keys,
// so the diff and the restore always agree on which entry is which.
func indexCategory(cat ResourceCategory, s *Snapshot) (map[string]map[string]any, error) {
	switch cat {
	case CategoryTenants:
		return indexTenants(s)
	case CategoryTenantDomains:
		return indexTenantDomains(s)
	case CategoryConnections:
		return indexConnections(s)
	case CategoryClients:
		return indexClients(s)
	case CategoryUsers:
		return indexUsers(s)
	case CategoryPairwise:
		return indexPairwise(s)
	case CategoryRoles:
		return indexRoles(s)
	case CategoryAssignments:
		return indexAssignments(s)
	case CategoryMenus:
		return indexMenus(s)
	case CategoryNetPolicy:
		return indexNetPolicy(s)
	}
	return map[string]map[string]any{}, nil
}

func addIndexedEntry(idx map[string]map[string]any, id string, entry any) error {
	normalized, err := marshalEntry(entry)
	if err == nil {
		idx[id] = normalized
	}
	return err
}

func indexTenants(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.Tenants {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.ID, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexTenantDomains(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.TenantDomains {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.Hostname, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexConnections(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.Connections {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.ID, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexClients(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.Clients {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.ID, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexUsers(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.Users {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.ID, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexPairwise(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.Pairwise {
		if err := addIndexedEntry(idx, entry.PairwiseSub, entry); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func indexRoles(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, clientRoles := range s.Resources.Roles {
		for _, role := range clientRoles.Roles {
			if err := addIndexedEntry(idx, roleKeyID(clientRoles.ClientID, role.Code), role); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexAssignments(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, clientAssignments := range s.Resources.Assignments {
		for _, assignment := range clientAssignments.Assignments {
			id := assignmentKeyID(clientAssignments.ClientID, assignment.UserID)
			if err := addIndexedEntry(idx, id, assignment); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

func indexMenus(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, clientMenus := range s.Resources.Menus {
		if len(clientMenus.Menus) == 0 {
			continue
		}
		if err := addIndexedEntry(idx, clientMenus.ClientID, clientMenus); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func indexNetPolicy(s *Snapshot) (map[string]map[string]any, error) {
	idx := make(map[string]map[string]any)
	for _, entry := range s.Resources.NetPolicy {
		if entry != nil {
			if err := addIndexedEntry(idx, entry.Name, entry); err != nil {
				return nil, err
			}
		}
	}
	return idx, nil
}

// classifyCategory compares two identity-keyed indexes and emits the
// category's counts + changed entries in deterministic (sorted-key) order.
func classifyCategory(cat ResourceCategory, bi, ai map[string]map[string]any) CategoryDiff {
	cd := CategoryDiff{Category: cat}
	keys := unionKeys(bi, ai)
	sort.Strings(keys)
	for _, k := range keys {
		bv, bok := bi[k]
		av, aok := ai[k]
		switch {
		case !bok && aok:
			cd.Inserted++
			cd.Entries = append(cd.Entries, DiffEntry{ID: k, Status: DiffInserted})
		case bok && !aok:
			cd.Deleted++
			cd.Entries = append(cd.Entries, DiffEntry{ID: k, Status: DiffDeleted})
		default:
			if ops := configaudit.Diff(bv, av); len(ops) == 0 {
				cd.Unchanged++
			} else {
				cd.Updated++
				cd.Entries = append(cd.Entries, DiffEntry{ID: k, Status: DiffUpdated, Changes: ops})
			}
		}
	}
	return cd
}

// unionKeys returns the identity keys present on either side.
func unionKeys(bi, ai map[string]map[string]any) []string {
	seen := make(map[string]bool, len(bi)+len(ai))
	for k := range bi {
		seen[k] = true
	}
	for k := range ai {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// marshalEntry normalizes one typed entry into the map[string]any shape
// configaudit.Diff expects. encoding/json sorts map keys, so the same entry
// always marshals identically — the stable baseline the classification and
// the digest share.
func marshalEntry(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// roleKeyID is the display identity for one (clientID, role code) pair.
// Slash separates the halves; role codes are admin-configured strings and
// client IDs are opaque, so collisions are not a concern for display.
func roleKeyID(clientID, code string) string { return clientID + "/" + code }

// assignmentKeyID is the display identity for one (clientID, userID) pair.
func assignmentKeyID(clientID, userID string) string { return clientID + "/" + userID }
