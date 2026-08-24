// Package serveraccount mounts the internal account-summary endpoint: a
// machine-readable snapshot of a subject's identity, tenants, permissions,
// and security posture, consumed by the account source (aero-id) rather than
// by browsers. This is an API-only internal boundary, intentionally absent
// from docs/openapi.yaml and never a frontend route. The canonical subject
// header is accepted only from a peer trusted by the shared proxy-boundary
// middleware when that middleware is configured. Split out of the command
// root so the frozen cmd/sso-server go-file ceiling and the 500-line file
// budget both hold; mirrors the serverwebauthn mount pattern (deps struct +
// Mount on the SSO router).
package serveraccount

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const (
	accountSummaryPath               = "/internal/account-summary"
	accountSummaryCanonicalUIDHeader = "X-Aero-Canonical-UID"
	accountSummaryScope              = "account:summary:read"
	accountSummaryAudience           = "snaplink-account-source"
	accountSummaryErrMissingToken    = "missing_token"
	accountSummaryErrInvalidToken    = "invalid_token"
	accountSummaryErrInsufficient    = "insufficient_scope"
	accountSummaryErrInvalidRequest  = "invalid_request"
	accountSummaryErrUnavailable     = "source_unavailable"
	accountSummaryErrUseDPoPNonce    = "use_dpop_nonce"
	maxAccountSummaryQuery           = 8 << 10
	maxAccountSummaryToken           = 16 << 10
	maxAccountSummarySubject         = 512
	maxAccountSummaryAccountID       = 128
)

var snaplinkAccountDatasets = map[string]struct{}{
	"snaplink.identity":    {},
	"snaplink.tenants":     {},
	"snaplink.permissions": {},
	"snaplink.security":    {},
}

type snaplinkAccountSummary struct {
	SourceRegion string                    `json:"source_region"`
	Version      int64                     `json:"version"`
	GeneratedAt  time.Time                 `json:"generated_at"`
	Complete     bool                      `json:"complete"`
	Datasets     map[string]map[string]any `json:"datasets"`
	Sources      []map[string]any          `json:"sources"`
	Memberships  []map[string]any          `json:"memberships"`
}

// accountSummaryDeps are the command-root dependencies the endpoint needs,
// passed in explicitly so this package stays below the sso root god-package.
type accountSummaryDeps struct {
	server   *sso.Server
	users    sso.UserProvider
	recorder *audit.Recorder
}

// Mount registers GET /internal/account-summary on the SSO router so the
// endpoint shares the same middleware stack (tracing, metrics, rate-limit,
// CORS) as the built-in endpoints. Mounted AFTER a.server.Handler() so the
// router has been initialized — Handle errors otherwise.
func Mount(server *sso.Server, users sso.UserProvider, recorder *audit.Recorder, logger spi.Logger) error {
	if server == nil || users == nil {
		return errors.New("account summary requires a server and user provider")
	}
	deps := &accountSummaryDeps{server: server, users: users, recorder: recorder}
	if err := server.Handle(http.MethodGet, accountSummaryPath, deps.handle); err != nil {
		return err
	}
	if logger != nil {
		logger.Info("aero-id account summary route mounted", "path", accountSummaryPath)
	}
	return nil
}

func (d *accountSummaryDeps) handle(w http.ResponseWriter, r *http.Request) {
	ctx := core.NewContext(w, r)
	d.server.TokenNoStoreHeaders(ctx)
	claims, status, code := d.authenticate(ctx)
	if status != 0 {
		d.writeError(ctx, status, code)
		return
	}
	accountID, canonicalUID, datasets, ok := parseAccountSummaryRequest(r)
	if !ok {
		d.writeError(ctx, http.StatusBadRequest, accountSummaryErrInvalidRequest)
		return
	}
	user, err := d.users.GetByID(r.Context(), canonicalUID)
	if err != nil && !errors.Is(err, core.ErrNoSuchUser) {
		d.writeError(ctx, http.StatusServiceUnavailable, accountSummaryErrUnavailable)
		return
	}
	response := compileAccountSummary(user, accountID, datasets, time.Now().UTC())
	ctx.ResponseWriter().Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(ctx.ResponseWriter()).Encode(response); err != nil {
		return
	}
	accountSummaryReadAudit(d.recorder, r, claims, canonicalUID, datasets)
}

// compileAccountSummary builds the account-source payload from the user row;
// a nil user (unknown subject) yields a per-dataset not_found so callers can
// never distinguish a missing subject from a missing dataset.
func compileAccountSummary(user *core.User, accountID string, datasets []string, now time.Time) snaplinkAccountSummary {
	response := snaplinkAccountSummary{
		SourceRegion: accountSourceRegion(), Version: now.UnixMilli(), GeneratedAt: now, Complete: true,
		Datasets: map[string]map[string]any{}, Sources: []map[string]any{}, Memberships: []map[string]any{},
	}
	if user == nil {
		for _, dataset := range datasets {
			response.Datasets[dataset] = map[string]any{"status": "not_found"}
		}
		return response
	}
	updated := user.UpdatedAt
	if updated.IsZero() {
		updated = user.CreatedAt
	}
	if !updated.IsZero() {
		response.Version = updated.UTC().UnixMilli()
	}
	for _, dataset := range datasets {
		switch dataset {
		case "snaplink.identity":
			response.Datasets[dataset] = map[string]any{
				"email": user.Email, "username": user.Username, "name": user.Name,
				"display_name": user.DisplayName, "status": accountUserStatus(user),
			}
		case "snaplink.tenants":
			response.Datasets[dataset] = map[string]any{"items": []any{}}
		case "snaplink.permissions":
			response.Datasets[dataset] = map[string]any{"roles": []any{}, "permissions": []any{}}
		case "snaplink.security":
			response.Datasets[dataset] = map[string]any{"status": accountUserStatus(user)}
		}
	}
	response.Sources = append(response.Sources, map[string]any{
		"source_account_id": user.ID, "scope_type": "account", "scope_id": accountID,
		"status": accountUserStatus(user), "data": map[string]any{},
	})
	return response
}

func (d *accountSummaryDeps) writeError(ctx core.HandlerContext, status int, code string) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		challengeCode := code
		if code == accountSummaryErrMissingToken {
			challengeCode = ""
		}
		d.server.SetResourceBearerChallenge(ctx, accountSummaryAudience, challengeCode, "")
	}
	writeAccountSummaryError(ctx.ResponseWriter(), status, code)
}

func (d *accountSummaryDeps) authenticate(ctx core.HandlerContext) (*core.TokenClaims, int, string) {
	token := oauth.ResourceToken(ctx.Request())
	if token == "" {
		return nil, http.StatusUnauthorized, accountSummaryErrMissingToken
	}
	if len(token) > maxAccountSummaryToken {
		return nil, http.StatusUnauthorized, accountSummaryErrInvalidToken
	}
	claims, err := d.server.ValidateToken(ctx.Request().Context(), token)
	if err != nil || !core.IsAccessTokenClaims(claims) {
		return nil, http.StatusUnauthorized, accountSummaryErrInvalidToken
	}
	if err := d.server.VerifyDPoPBearer(ctx, claims); err != nil {
		if d.server.IsDPoPNonceRequired(err) {
			d.server.StampDPoPNonce(ctx)
			return nil, http.StatusUnauthorized, accountSummaryErrUseDPoPNonce
		}
		return nil, http.StatusUnauthorized, accountSummaryErrInvalidToken
	}
	if err := d.server.VerifyMTLSBearer(ctx, claims); err != nil {
		return nil, http.StatusUnauthorized, accountSummaryErrInvalidToken
	}
	if !accountSummaryServiceClaims(claims) {
		return nil, http.StatusForbidden, accountSummaryErrInsufficient
	}
	return claims, 0, ""
}

func accountSummaryReadAudit(recorder *audit.Recorder, r *http.Request, claims *core.TokenClaims, canonicalUID string, datasets []string) {
	event := &audit.Event{
		Type: audit.EventAccountSummaryRead, Outcome: audit.OutcomeSuccess,
		ActorID: claims.Subject, ClientID: claims.ClientID,
	}
	audit.SetMeta(event, "target_user_id", canonicalUID)
	audit.SetMeta(event, "datasets", strings.Join(datasets, ","))
	recorder.Record(r.Context(), event)
}

func accountSummaryServiceClaims(claims *core.TokenClaims) bool {
	return claims != nil && claims.Issuer != "" && claims.ClientID != "" &&
		claims.Subject == claims.ClientID && claims.JTI != "" &&
		claims.AuthTime.IsZero() && len(claims.AMR) == 0 && claims.ACR == "" &&
		claims.SID == "" && claims.Actor == nil && claims.MayAct == nil &&
		len(claims.Audience) == 1 && claims.Audience[0] == accountSummaryAudience &&
		containsAccountClaim(claims.Scopes, accountSummaryScope)
}

func accountSummaryQueryKeysAllowed(query url.Values) bool {
	for key := range query {
		if key != "account_id" && key != "dataset" {
			return false
		}
	}
	return true
}

func singleAccountSummaryQueryValue(query url.Values, key string) (string, bool) {
	values, ok := query[key]
	if !ok || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func accountSummaryCanonicalSubject(r *http.Request) (string, bool) {
	values := r.Header.Values(accountSummaryCanonicalUIDHeader)
	if len(values) != 1 || !validAccountSummaryIdentifier(values[0], maxAccountSummarySubject) {
		return "", false
	}
	return values[0], true
}

func validAccountSummaryIdentifier(value string, limit int) bool {
	return value != "" && len(value) <= limit && value == strings.TrimSpace(value) &&
		!strings.ContainsAny(value, ",;") &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}

func parseAccountSummaryRequest(r *http.Request) (string, string, []string, bool) {
	if r == nil || r.URL == nil || len(r.URL.RawQuery) > maxAccountSummaryQuery {
		return "", "", nil, false
	}
	if info, present := peertrust.RequestInfoFrom(r); present && !info.ForwardedHeadersTrusted {
		return "", "", nil, false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !accountSummaryQueryKeysAllowed(query) {
		return "", "", nil, false
	}
	accountID, ok := singleAccountSummaryQueryValue(query, "account_id")
	if !ok || !validAccountSummaryIdentifier(accountID, maxAccountSummaryAccountID) {
		return "", "", nil, false
	}
	canonicalUID, ok := accountSummaryCanonicalSubject(r)
	if !ok {
		return "", "", nil, false
	}
	datasets, ok := requestedSnaplinkDatasets(query)
	return accountID, canonicalUID, datasets, ok
}

func requestedSnaplinkDatasets(query url.Values) ([]string, bool) {
	requested := query["dataset"]
	if len(requested) == 0 {
		requested = make([]string, 0, len(snaplinkAccountDatasets))
		for dataset := range snaplinkAccountDatasets {
			requested = append(requested, dataset)
		}
	}
	seen := make(map[string]struct{}, len(requested))
	result := make([]string, 0, len(requested))
	for _, dataset := range requested {
		if _, allowed := snaplinkAccountDatasets[dataset]; !allowed {
			return nil, false
		}
		if _, duplicate := seen[dataset]; !duplicate {
			seen[dataset] = struct{}{}
			result = append(result, dataset)
		}
	}
	sort.Strings(result)
	return result, true
}

func accountSourceRegion() string {
	if value := strings.TrimSpace(os.Getenv("SNAPLINK_ACCOUNT_SOURCE_REGION")); value != "" {
		return value
	}
	return "local"
}

func accountUserStatus(user *core.User) string {
	if user != nil && user.IsActive() {
		return "active"
	}
	return "inactive"
}

func containsAccountClaim(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func writeAccountSummaryError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
