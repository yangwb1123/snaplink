// Package builtin holds the bootstrap.Step implementations the sso-server
// registers automatically. Each is gated behind a Runner so they only fire
// on first boot (or after a new step is added). The admin user's password
// is generated with crypto/rand and emitted to stdout exactly once — the
// operator MUST capture it from the boot log on first run.
package builtin

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
	"github.com/snaplink/sso/snapshot"
	"github.com/snaplink/sso/snapshot/loader"
)

// AdminSeed bundles the dependencies that need to be reachable when the
// built-in steps run.
type AdminSeed struct {
	Permissions permissions.Provider // required
	Users       sso.UserProvider     // required
	Clients     sso.ClientStore      // required for Step 4 (admin client)
	Netpolicy   netpolicy.Store      // optional; Step 3 skips when nil

	// Tunables.
	AdminUserID    string // default "admin"
	AdminClientID  string // empty string by default — matches empty-aud admin tokens
	AdminRoleCode  string // default "sso-admin"
	AdminClientApp string // default "Snaplink Admin"

	// Where to print the generated admin password. nil → fmt.Printf to stdout.
	PasswordPrinter func(password string)
}

// RestorePlan describes a first-boot snapshot import. Pass it to
// ApplyRestore before runner.Run() — the Restorer's AdvanceBootstrap
// support means the Runner naturally skips seed steps already covered
// by the snapshot (the Tracker high-water mark jumps to whatever the
// snapshot recorded).
//
// We don't model this as a bootstrap.Step because the Runner skips any
// step whose Version is <= the tracker's current applied_version, and a
// fresh tracker starts at 0 — there's no Version that runs strictly
// before the existing seeds (1..N) without renumbering them, which
// would force seed_admin_user to re-run on existing deployments and
// overwrite the captured admin password.
type RestorePlan struct {
	URI      string               // file://... | inline:... ; empty = no-op
	Pipeline *snapshot.Pipeline   // codec + sealer
	Restorer *snapshot.Restorer   // applies snap onto destination stores
	Mode     snapshot.RestoreMode // defaults to ModeOverwrite
}

// ApplyRestore loads the snapshot at plan.URI through plan.Pipeline,
// applies it via plan.Restorer (with AdvanceBootstrap=true so the
// Tracker bumps to the snapshot's recorded version), and returns the
// Report. Returns (nil, nil) when plan is nil or URI is empty —
// callers can pass an unconditional plan and let this be a no-op.
//
// plan.Restorer.Tracker MUST already be wired so the bootstrap
// high-water mark advances; otherwise the Runner will re-run seed
// steps the snapshot already covered.
func ApplyRestore(ctx context.Context, plan *RestorePlan) (*snapshot.Report, error) {
	if plan == nil || plan.URI == "" {
		return nil, nil
	}
	if plan.Pipeline == nil || plan.Restorer == nil {
		return nil, errors.New("builtin.ApplyRestore: Pipeline and Restorer required")
	}
	st, name, err := loader.FromURI(plan.URI)
	if err != nil {
		return nil, fmt.Errorf("builtin.ApplyRestore: load uri: %w", err)
	}
	snap, err := plan.Pipeline.Load(ctx, st, name)
	if err != nil {
		return nil, fmt.Errorf("builtin.ApplyRestore: pipeline load: %w", err)
	}
	mode := plan.Mode
	if mode == "" {
		mode = snapshot.ModeOverwrite
	}
	rep, err := plan.Restorer.Restore(ctx, snap, snapshot.RestoreOptions{
		Mode:             mode,
		AdvanceBootstrap: true,
	})
	if err != nil {
		return rep, fmt.Errorf("builtin.ApplyRestore: restore: %w", err)
	}
	return rep, nil
}

// Steps returns the canonical list of built-in steps the sso-server should
// register at boot. They live under namespace "sso-server"; consumer apps
// pick their own namespace and their own Steps.
//
// Versioning convention: 1, 2, 3, ... ordered by dependency. Adding a new
// step in the future appends a new version; existing deployments only run
// the new one.
func Steps(seed *AdminSeed) []bootstrap.Step {
	if seed == nil {
		return nil
	}
	if seed.AdminUserID == "" {
		seed.AdminUserID = "admin"
	}
	if seed.AdminRoleCode == "" {
		seed.AdminRoleCode = "sso-admin"
	}
	if seed.AdminClientApp == "" {
		seed.AdminClientApp = "Snaplink Admin"
	}
	if seed.PasswordPrinter == nil {
		seed.PasswordPrinter = func(p string) {
			fmt.Printf("\n=========================================================\n")
			fmt.Printf(" SSO admin user seeded — capture this password NOW. It is\n")
			fmt.Printf(" printed once and never again.\n")
			fmt.Printf("   user_id: %s\n   password: %s\n", seed.AdminUserID, p)
			fmt.Printf("=========================================================\n\n")
		}
	}

	steps := []bootstrap.Step{
		bootstrap.StepFunc("seed_admin_role", 1, func(ctx context.Context) error {
			if seed.Permissions == nil {
				return fmt.Errorf("seed_admin_role: permissions provider required")
			}
			err := seed.Permissions.AddRole(ctx, seed.AdminClientID, permissions.Role{
				Code:        seed.AdminRoleCode,
				Name:        "SSO Administrator",
				Description: "Full admin:* scope across the control plane.",
				Permissions: []string{sso.AdminScope},
			})
			// AddRole returns ErrRoleExists if a previous boot already created
			// it — treat as success so we still mark applied. (The Runner only
			// calls Run once per version, but defensive).
			if errors.Is(err, permissions.ErrRoleExists) {
				return nil
			}
			return err
		}),

		bootstrap.StepFunc("seed_admin_user", 2, func(ctx context.Context) error {
			if seed.Users == nil {
				return fmt.Errorf("seed_admin_user: user provider required")
			}
			password, err := generatePassword(24)
			if err != nil {
				return fmt.Errorf("seed_admin_user: rand: %w", err)
			}
			user := &sso.User{
				ID:         seed.AdminUserID,
				ExternalID: seed.AdminUserID,
				Provider:   "password",
				Attributes: map[string]string{
					"seeded_password": password,
				},
			}
			if err := seed.Users.CreateOrUpdate(ctx, user); err != nil {
				return err
			}
			if seed.Permissions != nil {
				if err := seed.Permissions.AssignRoles(ctx, user.ID, seed.AdminClientID, []string{seed.AdminRoleCode}); err != nil {
					return fmt.Errorf("seed_admin_user: assign role: %w", err)
				}
			}
			seed.PasswordPrinter(password)
			return nil
		}),

		bootstrap.StepFunc("seed_default_netpolicy", 3, func(ctx context.Context) error {
			if seed.Netpolicy == nil {
				return nil // optional dependency; nothing to do
			}
			// Only seed when there are no policies yet — operators may have
			// already populated via YAML or the API.
			existing, err := seed.Netpolicy.List(ctx)
			if err != nil {
				return fmt.Errorf("seed_default_netpolicy: list: %w", err)
			}
			if len(existing) > 0 {
				return nil
			}
			_, err = seed.Netpolicy.Apply(ctx, &netpolicy.Policy{
				Name:     "intranet",
				CIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				Priority: 100,
				Metadata: map[string]string{"seeded_by": "bootstrap"},
			})
			return err
		}),

		bootstrap.StepFunc("seed_admin_client", 4, func(ctx context.Context) error {
			if seed.Clients == nil {
				return nil
			}
			// Skip if the operator already declared a client with this ID
			// in YAML (typical when migrating an existing deployment).
			if _, err := seed.Clients.Get(ctx, "sso-admin"); err == nil {
				return nil
			}
			secret, err := generatePassword(32)
			if err != nil {
				return fmt.Errorf("seed_admin_client: rand: %w", err)
			}
			err = seed.Clients.Add(ctx, &sso.Client{
				ID:                    "sso-admin",
				Secret:                secret,
				Name:                  seed.AdminClientApp,
				AllowedAuthenticators: []string{"password"},
				TokenStrategy:         sso.TokenStrategyJWT,
				AllowedScopes:         []string{sso.AdminScope, sso.AdminScopeRead, sso.AdminScopeWrite},
				Active:                true,
			})
			if errors.Is(err, sso.ErrClientExists) {
				return nil
			}
			return err
		}),
	}
	return steps
}

// generatePassword returns a base64url-encoded random string of n bytes.
// 24 bytes ≈ 192 bits — well above what NIST recommends for password-style
// secrets, so users can paste it once and rotate later.
func generatePassword(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
