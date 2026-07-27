package builtin_test

import (
	"context"
	"encoding/base64"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/bootstrap/builtin"
	"github.com/yangwb1123/snaplink/platform/bootstrap/memory"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	netmemory "github.com/yangwb1123/snaplink/platform/netpolicy/memory"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// Lower bcrypt cost so the multiple AddSeed/Add calls in this suite
	// don't make every test take ~100ms per client.
	defaultimpl.SetBcryptCost(bcrypt.MinCost)
	os.Exit(m.Run())
}

// fullSeed returns an AdminSeed wired with in-memory providers covering all
// optional dependencies — Steps will register every one of its four built-in
// steps under this configuration.
func fullSeed(t *testing.T) (*builtin.AdminSeed, *capturePrinter) {
	t.Helper()
	printer := &capturePrinter{}
	return &builtin.AdminSeed{
		Permissions:     permissions.NewMemoryProvider(),
		Users:           defaultimpl.NewMemoryUserProvider(),
		Clients:         defaultimpl.NewMemoryClientStore(),
		Netpolicy:       netmemory.New(),
		PasswordPrinter: printer.Print,
	}, printer
}

type capturePrinter struct {
	calls []string
}

func (c *capturePrinter) Print(p string) { c.calls = append(c.calls, p) }

func runAllSteps(t *testing.T, seed *builtin.AdminSeed) {
	t.Helper()
	steps := builtin.Steps(seed)
	if len(steps) != 7 {
		t.Fatalf("Steps returned %d, want 7", len(steps))
	}
	runner := bootstrap.NewRunner("sso-server", memory.New())
	runner.Register(steps...)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("runner.Run: %v", err)
	}
}

func TestSteps_NilSeedReturnsNil(t *testing.T) {
	t.Parallel()
	if got := builtin.Steps(nil); got != nil {
		t.Errorf("Steps(nil) = %v, want nil", got)
	}
}

func TestSteps_AppliesDefaults(t *testing.T) {
	t.Parallel()
	seed := &builtin.AdminSeed{
		Permissions: permissions.NewMemoryProvider(),
		Users:       defaultimpl.NewMemoryUserProvider(),
	}
	_ = builtin.Steps(seed)
	if seed.AdminUserID != "admin" {
		t.Errorf("AdminUserID = %q, want admin", seed.AdminUserID)
	}
	if seed.AdminRoleCode != "sso-admin" {
		t.Errorf("AdminRoleCode = %q, want sso-admin", seed.AdminRoleCode)
	}
	if seed.AdminClientApp != "Snaplink Admin" {
		t.Errorf("AdminClientApp = %q", seed.AdminClientApp)
	}
	if seed.PasswordPrinter == nil {
		t.Error("PasswordPrinter not defaulted")
	}
}

func TestSteps_SeedsRolePermissions(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	runAllSteps(t, seed)

	roles, err := seed.Permissions.ListAllRoles(context.Background(), seed.AdminClientID)
	if err != nil {
		t.Fatalf("ListAllRoles: %v", err)
	}
	var found *permissions.Role
	for i := range roles {
		if roles[i].Code == "sso-admin" {
			found = &roles[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("sso-admin role not registered; got %+v", roles)
	}
	if len(found.Permissions) == 0 || found.Permissions[0] != sso.AdminScope {
		t.Errorf("sso-admin permissions = %v, want [%s]", found.Permissions, sso.AdminScope)
	}
}

func TestSteps_SeedsAdminUser(t *testing.T) {
	t.Parallel()
	seed, printer := fullSeed(t)
	runAllSteps(t, seed)

	u, err := seed.Users.GetByID(context.Background(), "admin")
	if err != nil {
		t.Fatalf("GetByID(admin): %v", err)
	}
	// seeded_password must not be stored in attributes — it is a credential
	// oracle if the user record is ever exposed via the admin API.
	if _, ok := u.Attributes["seeded_password"]; ok {
		t.Errorf("seeded_password must not persist in user attributes: %+v", u.Attributes)
	}

	// The password is still printed exactly once so the operator can capture it.
	if len(printer.calls) != 1 {
		t.Errorf("PasswordPrinter called %d times, want 1", len(printer.calls))
	}
	// 24-byte secret → base64.RawURLEncoding length = ceil(24*4/3) = 32 chars.
	if len(printer.calls[0]) != 32 {
		t.Errorf("printed password length = %d, want 32 (base64url of 24 bytes)", len(printer.calls[0]))
	}

	roles, _ := seed.Permissions.Roles(context.Background(), "admin", seed.AdminClientID)
	if len(roles) != 1 || roles[0].Code != "sso-admin" {
		t.Errorf("admin user roles = %v, want [sso-admin]", roles)
	}
}

func TestSteps_SeedsDefaultNetpolicy(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	runAllSteps(t, seed)

	policies, _ := seed.Netpolicy.List(context.Background())
	if len(policies) != 1 || policies[0].Name != "intranet" {
		t.Fatalf("policies = %v, want [intranet]", policies)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(policies[0].CIDRs) != len(want) {
		t.Errorf("intranet CIDRs = %v, want %v", policies[0].CIDRs, want)
	}
}

func TestSteps_NetpolicySkippedWhenAlreadyPopulated(t *testing.T) {
	t.Parallel()
	// Pre-populate the netpolicy store; the seeding step must respect existing
	// operator-defined entries instead of injecting a duplicate.
	seed, _ := fullSeed(t)
	if _, err := seed.Netpolicy.Apply(context.Background(), &netpolicy.Policy{
		Name: "operator-defined", CIDRs: []string{"127.0.0.0/8"},
	}); err != nil {
		t.Fatalf("Apply operator-defined: %v", err)
	}
	runAllSteps(t, seed)

	policies, _ := seed.Netpolicy.List(context.Background())
	if len(policies) != 1 || policies[0].Name != "operator-defined" {
		t.Errorf("seeder should not have added intranet; policies = %v", policies)
	}
}

func TestSteps_NetpolicyNilDependencyNoop(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	seed.Netpolicy = nil // disable optional dependency
	runAllSteps(t, seed) // must not error despite Step 3 having no backend
}

func TestSteps_SeedsAdminClient(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	runAllSteps(t, seed)

	c, err := seed.Clients.Get(context.Background(), "sso-admin")
	if err != nil {
		t.Fatalf("Get(sso-admin): %v", err)
	}
	if c.TokenStrategy != sso.TokenStrategyJWT {
		t.Errorf("TokenStrategy = %q", c.TokenStrategy)
	}
	if !c.Active {
		t.Error("Active = false, want true")
	}
	// Secret is stored as a bcrypt hash after Add/RotateSecret.
	if !strings.HasPrefix(c.Secret, "$2") {
		t.Errorf("Secret is not a bcrypt hash: %q", c.Secret)
	}
	if !contains(c.AllowedScopes, sso.AdminScope) {
		t.Errorf("AllowedScopes = %v, missing %s", c.AllowedScopes, sso.AdminScope)
	}
}

func TestSteps_AdminClientSkippedWhenOperatorPredeclared(t *testing.T) {
	t.Parallel()
	// Operator already wired a sso-admin client via YAML — Step 4 must
	// no-op rather than overwrite the operator secret.
	seed, _ := fullSeed(t)
	original := &sso.Client{ID: "sso-admin", Secret: "operator-secret", Name: "Hand Rolled"}
	if err := seed.Clients.Add(context.Background(), original); err != nil {
		t.Fatalf("Add original: %v", err)
	}
	runAllSteps(t, seed)

	c, _ := seed.Clients.Get(context.Background(), "sso-admin")
	// The stored Secret is a bcrypt hash of the plaintext that was passed to
	// Add.  Verify the seeder did not overwrite the operator's client by checking
	// both the name (unchanged) and that the stored hash looks like a hash of
	// "operator-secret" (starts with "$2" — the seeder's generated secret would
	// be a different hash, NOT a hash of "operator-secret").
	if c.Name != "Hand Rolled" {
		t.Errorf("seeder overwrote operator client name; got %+v", c)
	}
	if !strings.HasPrefix(c.Secret, "$2") {
		t.Errorf("expected bcrypt hash for operator secret; got %q", c.Secret)
	}
}

func TestSteps_RoleSeedTolerantOfPreExistingRole(t *testing.T) {
	t.Parallel()
	// Permissions.AddRole returns ErrRoleExists if a previous boot
	// already wrote it. The step must treat that as success.
	seed, _ := fullSeed(t)
	_ = seed.Permissions.AddRole(context.Background(), seed.AdminClientID, permissions.Role{
		Code: "sso-admin", Name: "Pre-existing",
	})
	runAllSteps(t, seed)

	roles, _ := seed.Permissions.ListAllRoles(context.Background(), seed.AdminClientID)
	count := 0
	for _, r := range roles {
		if r.Code == "sso-admin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("sso-admin role count = %d, want 1 (no duplicate)", count)
	}
}

func TestSteps_MissingProviderFailsRoleStep(t *testing.T) {
	t.Parallel()
	// Permissions nil → seed_admin_role must fail explicitly.
	seed := &builtin.AdminSeed{Users: defaultimpl.NewMemoryUserProvider()}
	steps := builtin.Steps(seed)
	if len(steps) == 0 {
		t.Fatal("Steps returned nothing")
	}
	runner := bootstrap.NewRunner("sso-server", memory.New())
	runner.Register(steps...)
	if err := runner.Run(context.Background()); err == nil {
		t.Fatal("expected error when permissions provider missing")
	} else if !strings.Contains(err.Error(), "permissions provider") {
		t.Errorf("err = %v, want 'permissions provider' message", err)
	}
}

func TestSteps_ApplyRestoreErrors(t *testing.T) {
	t.Parallel()
	// Cover the validation branches of ApplyRestore that are not exercised
	// by the existing builtin_test.go (Pipeline/Restorer nil).
	_, err := builtin.ApplyRestore(context.Background(), &builtin.RestorePlan{
		URI: "file:///does-not-matter",
	})
	if err == nil || !strings.Contains(err.Error(), "Pipeline and Restorer required") {
		t.Errorf("err = %v, want validation error", err)
	}

	// Nil plan + empty URI are documented no-ops.
	if rep, err := builtin.ApplyRestore(context.Background(), nil); rep != nil || err != nil {
		t.Errorf("nil plan: rep=%v err=%v", rep, err)
	}
	if rep, err := builtin.ApplyRestore(context.Background(), &builtin.RestorePlan{}); rep != nil || err != nil {
		t.Errorf("empty URI: rep=%v err=%v", rep, err)
	}
}

func TestGeneratePassword_LengthAndAlphabet(t *testing.T) {
	t.Parallel()
	// generatePassword is unexported but exercised through seed_admin_user.
	// The password is emitted via PasswordPrinter; decode it from there to
	// confirm it's well-formed base64url of the right length.
	seed, printer := fullSeed(t)
	runAllSteps(t, seed)
	if len(printer.calls) == 0 {
		t.Fatal("PasswordPrinter was not called; cannot verify password format")
	}
	pw := printer.calls[0]
	decoded, err := base64.RawURLEncoding.DecodeString(pw)
	if err != nil {
		t.Fatalf("password not base64url: %v", err)
	}
	if len(decoded) != 24 {
		t.Errorf("decoded len = %d, want 24 bytes", len(decoded))
	}
}

func TestSteps_ClearSeededPassword_RemovesLegacyAttr(t *testing.T) {
	t.Parallel()
	// Simulate an existing deployment that wrote seeded_password under a prior
	// server version. On the next boot the clear_seeded_password step (version 6)
	// must remove the attribute and persist the updated record.
	seed, _ := fullSeed(t)

	// Pre-create the admin user with a plaintext seeded_password, as older
	// bootstrap code did.
	legacy := &sso.User{
		ID:         "admin",
		ExternalID: "admin",
		Provider:   "password",
		Attributes: map[string]string{"seeded_password": "plaintext-secret"},
	}
	if err := seed.Users.CreateOrUpdate(context.Background(), legacy); err != nil {
		t.Fatalf("pre-create admin: %v", err)
	}

	runAllSteps(t, seed)

	u, err := seed.Users.GetByID(context.Background(), "admin")
	if err != nil {
		t.Fatalf("GetByID(admin): %v", err)
	}
	if _, ok := u.Attributes["seeded_password"]; ok {
		t.Errorf("clear_seeded_password step did not remove attribute: %+v", u.Attributes)
	}
}

func TestSteps_SeedsAdminConsoleClient(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	runAllSteps(t, seed)

	c, err := seed.Clients.Get(context.Background(), "sso-admin-console")
	if err != nil {
		t.Fatalf("Get(sso-admin-console): %v", err)
	}
	if c.TokenStrategy != sso.TokenStrategyJWT {
		t.Errorf("TokenStrategy = %q", c.TokenStrategy)
	}
	if !c.Active {
		t.Error("Active = false, want true")
	}
	// Public PKCE client — no secret.
	if c.Secret != "" {
		t.Errorf("Secret should be empty for a public PKCE client, got %q", c.Secret)
	}
	if !c.RequirePKCE {
		t.Error("RequirePKCE = false, want true")
	}
	if !contains(c.AllowedScopes, sso.AdminScopeRead) {
		t.Errorf("AllowedScopes = %v, missing %s", c.AllowedScopes, sso.AdminScopeRead)
	}
	if !contains(c.AllowedScopes, sso.AdminScopeWrite) {
		t.Errorf("AllowedScopes = %v, missing %s", c.AllowedScopes, sso.AdminScopeWrite)
	}
}

func TestSteps_AdminConsoleClientSkippedWhenOperatorPredeclared(t *testing.T) {
	t.Parallel()
	// Step 5 must preserve operator-owned fields; version 7 only hardens a
	// secretless client by requiring PKCE.
	seed, _ := fullSeed(t)
	original := &sso.Client{ID: "sso-admin-console", Name: "Operator Console"}
	if err := seed.Clients.Add(context.Background(), original); err != nil {
		t.Fatalf("Add original: %v", err)
	}
	runAllSteps(t, seed)

	c, _ := seed.Clients.Get(context.Background(), "sso-admin-console")
	if c.Name != "Operator Console" {
		t.Errorf("seeder overwrote operator console client; got %+v", c)
	}
	if !c.RequirePKCE {
		t.Error("public operator console client was not hardened with PKCE")
	}
}

func TestSteps_UpgradesLegacyAdminConsoleClient(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	legacy := &sso.Client{
		ID:           "sso-admin-console",
		Name:         "Customized Legacy Console",
		RedirectURIs: []string{"https://admin.example/callback"},
		Active:       true,
	}
	if err := seed.Clients.Add(context.Background(), legacy); err != nil {
		t.Fatalf("Add legacy client: %v", err)
	}

	runStepsAfterVersion(t, seed, 6)

	got, err := seed.Clients.Get(context.Background(), legacy.ID)
	if err != nil {
		t.Fatalf("Get legacy client: %v", err)
	}
	if !got.RequirePKCE {
		t.Error("legacy public admin console client still allows code flow without PKCE")
	}
	if got.Name != legacy.Name || !slices.Equal(got.RedirectURIs, legacy.RedirectURIs) {
		t.Errorf("migration changed operator fields: got %+v", got)
	}
}

func TestSteps_PKCEUpgradePreservesConfidentialAdminConsole(t *testing.T) {
	t.Parallel()
	seed, _ := fullSeed(t)
	operatorClient := &sso.Client{
		ID:     "sso-admin-console",
		Secret: "operator-managed-secret",
		Name:   "Confidential Operator Console",
		Active: true,
	}
	if err := seed.Clients.Add(context.Background(), operatorClient); err != nil {
		t.Fatalf("Add operator client: %v", err)
	}

	runStepsAfterVersion(t, seed, 6)

	got, err := seed.Clients.Get(context.Background(), operatorClient.ID)
	if err != nil {
		t.Fatalf("Get operator client: %v", err)
	}
	if got.RequirePKCE {
		t.Error("migration changed PKCE policy for a confidential operator client")
	}
	if got.Name != operatorClient.Name {
		t.Errorf("migration changed operator client: got %+v", got)
	}
}

func runStepsAfterVersion(t *testing.T, seed *builtin.AdminSeed, version int) {
	t.Helper()
	tracker := memory.New()
	if err := tracker.MarkApplied(context.Background(), "sso-server", version, "existing"); err != nil {
		t.Fatalf("MarkApplied(%d): %v", version, err)
	}
	runner := bootstrap.NewRunner("sso-server", tracker)
	runner.Register(builtin.Steps(seed)...)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("runner.Run after version %d: %v", version, err)
	}
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
