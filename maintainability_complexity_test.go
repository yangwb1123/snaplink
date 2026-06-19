package sso

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Harness gate (Harness Engineering): per-FUNCTION maintainability budgets —
// cyclomatic complexity and function length — enforced as committed tests so
// they run inside `go test` / `make ci` WITHOUT the generative `make harness`
// (checks/complexity.py) stack, which rewrites tracked files and depends on
// gocyclo/gocognit binaries being installed. This mirrors the ratchet +
// frozen-backlog design of TestMaintainability_FileSizeBudget, with two
// improvements over the Python gate it replaces:
//
//   - Whole-module scope. The Python gate's IGNORE_PATTERN excluded ~40
//     directories (federation/ scim/ admin/ config/ cluster/ …), so most of the
//     tree was never measured; and its exemptions matched by SUBSTRING (every
//     *Validate / *Match / *Score was exempt everywhere). This test measures
//     every parent-module function and keys exemptions precisely by file:func.
//   - Frozen ceiling. Each exemption stores the value measured when it was
//     introduced. An exempt function may not regress PAST that ceiling, and must
//     be removed from the list once it drops back under budget. The backlog only
//     ever shrinks.
//
// Scope: parent-module, non-generated, non-test .go files (same skipDirs set as
// the file-size gate). Nested modules (kms/ saml/ redis/ ldap/ …) own their
// go.mod and are out of scope here. Complexity counts the full function body
// INCLUDING nested function literals, so a closure-heavy function is not split
// into artificially small pieces (this can read higher than a per-closure tool
// like gocyclo; the backlog is seeded from THIS counter, so it is internally
// consistent).
const (
	maxFuncComplexity = 15
	maxFuncLines      = 50
)

// funcMetric is one measured top-level function.
type funcMetric struct {
	key   string // "relpath:funcname", e.g. "oauth/refresh_token.go:(*Server).rotate"
	cyclo int
	lines int
}

// cycloExemptions / funcLenExemptions are the frozen backlogs of functions that
// exceeded the budget when this gate was introduced. Each value is the measure
// at introduction (the ceiling). SHRINK THESE LISTS; never grow them, and never
// raise a ceiling. Regenerate after a refactor with:
//
//	SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .
var cycloExemptions = map[string]int{
	"authenticators/keypair.go:(*KeyPairAuthenticator).Authenticate":     17,
	"caep/receiver_construct.go:NewReceiver":                             19,
	"caep/receiver_receive.go:(*Receiver).Receive":                       36,
	"cmd/sso-server/build_stores.go:buildApp":                            23,
	"defaultimpl/ecdsa_validate.go:(*ECDSAJWTIssuer).Validate":           23,
	"defaultimpl/ed25519_validate.go:(*Ed25519JWTIssuer).Validate":       23,
	"defaultimpl/rsa_validate.go:(*RSAJWTIssuer).Validate":               23,
	"mesh_authz.go:(*Server).MeshAuthorize":                              19,
	"oauth/bind.go:formIntoStruct":                                       20,
	"oauth/claims_param.go:parseClaimsSection":                           17,
	"oauth/dcr_validate.go:ValidateDCRMetadata":                          16,
	"oauth/handle_ciba.go:HandleBackchannelAuth":                         27,
	"oauth/handle_introspect.go:HandleIntrospect":                        19,
	"oauth/handle_par.go:HandlePAR":                                      23,
	"oauth/handle_register.go:HandleRegister":                            16,
	"oidc/handle_end_session.go:HandleEndSession":                        28,
	"oidc/handle_silent_renewal.go:HandleSilentRenewal":                  30,
	"oidc/userinfo_signing.go:MaybeSignUserInfo":                         19,
	"security/jwks_verify.go:VerifyCompactJWS":                           19,
	"server_backchannel_logout.go:(*Server).fanOutBackchannelLogout":     18,
	"server_ciba_token.go:(*Server).handleCIBATokenGrant":                21,
	"server_device.go:(*Server).handleDeviceCode":                        19,
	"server_device.go:(*Server).handleDeviceTokenGrant":                  19,
	"server_discovery_cache.go:(*Server).computeDiscoverySnapshot":       17,
	"server_discovery_config.go:(*Server).buildOIDCConfiguration":        30,
	"server_dpop.go:verifyDPoPProof":                                     24,
	"server_finish_login.go:(*Server).finishLogin":                       57,
	"server_jar.go:verifyJAR":                                            28,
	"server_login.go:(*Server).handleLogin":                              66,
	"server_logout.go:(*Server).handleLogout":                            19,
	"server_mfa.go:(*Server).handleMFAComplete":                          24,
	"server_native_sso.go:(*Server).handleDeviceSecretExchange":          24,
	"server_pairwise.go:verifyJWTClientAssertion":                        29,
	"server_refresh_grant.go:(*Server).handleRefreshTokenGrant":          25,
	"server_resolve_login.go:(*Server).resolveLoginRequest":              26,
	"server_routes.go:(*Server).Mount":                                   52,
	"server_tenant_residency.go:(*Server).checkTenantNotSuspended":       16,
	"server_tenant_residency.go:(*Server).checkTenantResidency":          19,
	"server_token.go:(*Server).handleToken":                              41,
	"server_token_authcode.go:(*Server).handleAuthCodeTokenGrant":        27,
	"server_token_exchange.go:(*Server).handleTokenExchangeGrant":        60,
	"server_userinfo.go:(*Server).handleUserInfo":                        17,
	"server_userinfo.go:projectUserInfoForOIDC":                          26,
	"signingkeys/etcd/etcd_keepalive.go:(*Registry).supervisedKeepAlive": 16,
}

var funcLenExemptions = map[string]int{
	"accessors_handlers.go:(*Server).BuildHandlerDeps":                   78,
	"authenticators/keypair.go:(*KeyPairAuthenticator).Authenticate":     67,
	"authenticators/webauthn/mds.go:BuildMDSProvider":                    51,
	"authenticators/webauthn/webauthn.go:NewHelper":                      71,
	"caep/event_mapper.go:mapAuditEvent":                                 55,
	"caep/receiver_construct.go:NewReceiver":                             81,
	"caep/receiver_receive.go:(*Receiver).Receive":                       198,
	"caep/revoker.go:(*userProviderResolver).ResolveLocalSubject":        51,
	"cmd/sso-server/build_stores.go:buildApp":                            77,
	"cmd/sso-server/main.go:main":                                        84,
	"defaultimpl/ecdsa_issue.go:(*ECDSAJWTIssuer).Issue":                 82,
	"defaultimpl/ecdsa_validate.go:(*ECDSAJWTIssuer).Validate":           101,
	"defaultimpl/ed25519_issue.go:(*Ed25519JWTIssuer).Issue":             88,
	"defaultimpl/ed25519_jwks.go:(*Ed25519JWTIssuer).JWKS":               65,
	"defaultimpl/ed25519_validate.go:(*Ed25519JWTIssuer).Validate":       110,
	"defaultimpl/rsa_issue.go:(*RSAJWTIssuer).Issue":                     74,
	"defaultimpl/rsa_validate.go:(*RSAJWTIssuer).Validate":               102,
	"defaultimpl/vaulttransit/signer_request.go:(*Signer).doRequest":     57,
	"defaultimpl/vaulttransit/signer_sign.go:(*Signer).Sign":             52,
	"defaultimpl/vaulttransit/signer_sign.go:buildSignRequest":           57,
	"federation/registration_metadata.go:MetadataToClient":               53,
	"handlers.go:(*Server).handleAuthzPolicyBundle":                      58,
	"mesh_authz.go:(*Server).MeshAuthorize":                              154,
	"metrics/metrics_ctor.go:NewWithRegistry":                            293,
	"middleware/trusted_proxy.go:(*TrustedProxies).resolve":              52,
	"oauth/bind.go:formIntoStruct":                                       51,
	"oauth/dcr_validate.go:ValidateDCRMetadata":                          52,
	"oauth/handle_ciba.go:HandleBackchannelAuth":                         166,
	"oauth/handle_introspect.go:HandleIntrospect":                        93,
	"oauth/handle_introspect.go:introspectAccess":                        58,
	"oauth/handle_par.go:HandlePAR":                                      149,
	"oauth/handle_register.go:HandleRegister":                            146,
	"oauth/handle_register.go:HandleRegistrationPut":                     79,
	"oauth/handle_revoke.go:HandleRevoke":                                70,
	"oauth/handle_revoke.go:HandleRevokeAll":                             59,
	"oidc/handle_end_session.go:HandleEndSession":                        138,
	"oidc/handle_silent_renewal.go:HandleSilentRenewal":                  175,
	"oidc/handlers.go:HandleJWKS":                                        63,
	"oidc/userinfo_signing.go:MaybeSignUserInfo":                         94,
	"security/jwks_verify.go:VerifyCompactJWS":                           72,
	"security/jwks_verify.go:verifyJWSWithJWK":                           70,
	"security/spiffe_svid.go:ParseSPIFFEURI":                             52,
	"server_backchannel_logout.go:(*Server).fanOutBackchannelLogout":     86,
	"server_ciba_token.go:(*Server).handleCIBATokenGrant":                111,
	"server_device.go:(*Server).handleDeviceCode":                        125,
	"server_device.go:(*Server).handleDeviceTokenGrant":                  110,
	"server_device.go:(*Server).handleDeviceVerify":                      66,
	"server_discovery_cache.go:(*Server).computeDiscoverySnapshot":       60,
	"server_discovery_config.go:(*Server).buildOIDCConfiguration":        264,
	"server_dpop.go:verifyDPoPProof":                                     121,
	"server_finish_login.go:(*Server).finishLogin":                       355,
	"server_jar.go:verifyJAR":                                            104,
	"server_key_rotation.go:(*Server).scheduleCoordinatedRetire":         66,
	"server_login.go:(*Server).handleLogin":                              403,
	"server_logout.go:(*Server).handleConsentGate":                       90,
	"server_logout.go:(*Server).handleLogout":                            69,
	"server_mfa.go:(*Server).handleMFAComplete":                          151,
	"server_mfa.go:(*Server).issueMFAChallenge":                          93,
	"server_native_sso.go:(*Server).handleDeviceSecretExchange":          135,
	"server_oauth.go:(*Server).handleCallback":                           62,
	"server_pairwise.go:verifyJWTClientAssertion":                        113,
	"server_refresh_grant.go:(*Server).handleRefreshTokenGrant":          177,
	"server_resolve_login.go:(*Server).resolveLoginRequest":              86,
	"server_routes.go:(*Server).Handler":                                 69,
	"server_routes.go:(*Server).Mount":                                   277,
	"server_token.go:(*Server).handleToken":                              294,
	"server_token_authcode.go:(*Server).handleAuthCodeTokenGrant":        146,
	"server_token_exchange.go:(*Server).handleTokenExchangeGrant":        398,
	"server_userinfo.go:(*Server).handleUserInfo":                        146,
	"server_userinfo.go:projectUserInfoForOIDC":                          68,
	"signing_key_aggregation_loop.go:(*Server).tryAdoptIntoIssuer":       51,
	"signingkeys/etcd/etcd_keepalive.go:(*Registry).Publish":             57,
	"signingkeys/etcd/etcd_keepalive.go:(*Registry).supervisedKeepAlive": 107,
	"snapshot/snapshotter.go:(*Snapshotter).Export":                      56,
	"sso_newserver.go:NewServer":                                         94,
	"testkit/testkit.go:NewServer":                                       68,
}

func TestMaintainability_CyclomaticComplexity(t *testing.T) {
	checkFuncBudget(t, "cyclo", maxFuncComplexity,
		func(m funcMetric) int { return m.cyclo }, cycloExemptions)
}

func TestMaintainability_FunctionLength(t *testing.T) {
	checkFuncBudget(t, "lines", maxFuncLines,
		func(m funcMetric) int { return m.lines }, funcLenExemptions)
}

// checkFuncBudget enforces one per-function budget with frozen-ceiling ratchet
// semantics: new violations fail, exempt functions that regress past their
// frozen ceiling fail, and exemptions that are no longer needed (now under
// budget, or whose function vanished) fail as stale so the list only shrinks.
func checkFuncBudget(t *testing.T, kind string, threshold int, value func(funcMetric) int, exempt map[string]int) {
	metrics := collectFuncMetrics(t)
	seen := make(map[string]bool, len(exempt))
	var violations, regressions, stale []string

	for _, m := range metrics {
		v := value(m)
		frozen, isExempt := exempt[m.key]
		if isExempt {
			seen[m.key] = true
			if v <= threshold {
				stale = append(stale, fmt.Sprintf("%s (%s now %d <= %d)", m.key, kind, v, threshold))
			} else if v > frozen {
				regressions = append(regressions, fmt.Sprintf("%s (%s %d > frozen ceiling %d)", m.key, kind, v, frozen))
			}
			continue
		}
		if v > threshold {
			violations = append(violations, fmt.Sprintf("%s (%s %d > %d)", m.key, kind, v, threshold))
		}
	}
	for key := range exempt {
		if !seen[key] {
			stale = append(stale, fmt.Sprintf("%s (exemption for missing function — remove it)", key))
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d function(s) exceed the %s budget of %d — extract sub-functions "+
			"(see skills/refactor-high-complexity.md) instead of growing the function:\n  %s",
			len(violations), kind, threshold, strings.Join(violations, "\n  "))
	}
	if len(regressions) > 0 {
		sort.Strings(regressions)
		t.Errorf("%d exempt function(s) regressed past their frozen %s ceiling — exempt "+
			"functions may not get worse:\n  %s", len(regressions), kind, strings.Join(regressions, "\n  "))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%d %s exemption(s) no longer needed — remove them (the backlog must only "+
			"shrink):\n  %s", len(stale), kind, strings.Join(stale, "\n  "))
	}
}

// collectFuncMetrics parses every in-scope parent-module .go file once and
// returns the cyclomatic complexity and line span of each top-level function.
func collectFuncMetrics(t *testing.T) []funcMetric {
	var out []funcMetric
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel := filepath.ToSlash(path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			out = append(out, funcMetric{
				key:   rel + ":" + funcName(fn),
				cyclo: funcComplexity(fn),
				lines: funcLineSpan(fset, fn),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// funcComplexity is the standard cyclomatic count (gocyclo algorithm): 1 plus
// one per branching node, walking nested function literals as part of the body.
func funcComplexity(fn *ast.FuncDecl) int {
	c := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			c++
		case *ast.BinaryExpr:
			if s.Op == token.LAND || s.Op == token.LOR {
				c++
			}
		}
		return true
	})
	return c
}

// funcLineSpan is the function's total footprint, from the `func` keyword to the
// closing brace of its body, inclusive.
func funcLineSpan(fset *token.FileSet, fn *ast.FuncDecl) int {
	return fset.Position(fn.End()).Line - fset.Position(fn.Pos()).Line + 1
}

// funcName renders a stable name including the receiver type, e.g.
// "(*Server).handleLogin" or "buildApp".
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return "(" + recvTypeName(fn.Recv.List[0].Type) + ")." + fn.Name.Name
	}
	return fn.Name.Name
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + recvTypeName(t.X)
	case *ast.IndexExpr: // generic receiver: T[P]
		return recvTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver: T[P, Q]
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// seedMaintainabilityExemptions is a one-shot helper: run with
// SEED_MAINTAINABILITY=1 to print Go map literals for the current backlog. Not a
// gate — it asserts nothing.
func TestSeedMaintainabilityExemptions(t *testing.T) {
	if os.Getenv("SEED_MAINTAINABILITY") != "1" {
		t.Skip("set SEED_MAINTAINABILITY=1 to regenerate exemption backlogs")
	}
	metrics := collectFuncMetrics(t)
	emitSeed("cycloExemptions", metrics, maxFuncComplexity, func(m funcMetric) int { return m.cyclo })
	emitSeed("funcLenExemptions", metrics, maxFuncLines, func(m funcMetric) int { return m.lines })
}

func emitSeed(name string, metrics []funcMetric, threshold int, value func(funcMetric) int) {
	var lines []string
	for _, m := range metrics {
		if v := value(m); v > threshold {
			lines = append(lines, fmt.Sprintf("\t%q: %d,", m.key, v))
		}
	}
	sort.Strings(lines)
	// Markers let an external splice script extract the literal cleanly from
	// stdout without the t.Log file:line prefix.
	fmt.Printf("//SEED-BEGIN %s\n%s\n//SEED-END %s\n", name, strings.Join(lines, "\n"), name)
}
