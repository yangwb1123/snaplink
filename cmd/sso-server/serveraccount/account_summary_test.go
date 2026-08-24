package serveraccount

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

type accountSummaryTokenIssuer struct {
	claims *core.TokenClaims
	err    error
}

func (i accountSummaryTokenIssuer) Issue(context.Context, *core.Subject, []string) (*core.Token, error) {
	return nil, errors.New("account summary test issuer does not issue")
}

func (i accountSummaryTokenIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return i.claims, i.err
}

func (i accountSummaryTokenIssuer) Revoke(context.Context, string) error { return nil }

type failingAccountSummarySink struct{}

func (failingAccountSummarySink) Record(context.Context, *audit.Event) error {
	return errors.New("audit sink unavailable")
}

func (failingAccountSummarySink) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, errors.New("audit sink unavailable")
}

func (failingAccountSummarySink) Get(context.Context, string) (*audit.Event, error) {
	return nil, errors.New("audit sink unavailable")
}

func accountSummaryTestClaims() *core.TokenClaims {
	return &core.TokenClaims{
		TokenUse: core.TokenUseAccessToken, Subject: "account-source", Issuer: "https://sso.example",
		Audience: []string{accountSummaryAudience}, Scopes: []string{accountSummaryScope},
		ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(), JTI: "jti-1", ClientID: "account-source",
	}
}

func accountSummaryTestDeps(claims *core.TokenClaims) (*accountSummaryDeps, *defaultimpl.MemoryUserProvider) {
	server := sso.NewServer(sso.WithTokenIssuer("test", accountSummaryTokenIssuer{claims: claims}))
	users := defaultimpl.NewMemoryUserProvider()
	return &accountSummaryDeps{
		server: server, users: users, recorder: audit.New(failingAccountSummarySink{}),
	}, users
}

func accountSummaryRequest(token, rawQuery, subject string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, accountSummaryPath+"?"+rawQuery, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if subject != "" {
		r.Header.Set(accountSummaryCanonicalUIDHeader, subject)
	}
	return r
}

func TestRequestedSnaplinkDatasetsAreAllowListedAndStable(t *testing.T) {
	request := httptest.NewRequest("GET", "/internal/account-summary?dataset=snaplink.security&dataset=snaplink.identity&dataset=snaplink.security", nil)
	got, ok := requestedSnaplinkDatasets(request.URL.Query())
	if !ok || len(got) != 2 || got[0] != "snaplink.identity" || got[1] != "snaplink.security" {
		t.Fatalf("datasets = %#v/%v", got, ok)
	}
	request = httptest.NewRequest("GET", "/internal/account-summary?dataset=snaplink.password", nil)
	if _, ok := requestedSnaplinkDatasets(request.URL.Query()); ok {
		t.Fatal("sensitive/unknown dataset accepted")
	}
}

func TestParseAccountSummaryRequestRequiresOpaqueAccountAndCanonicalSubject(t *testing.T) {
	request := httptest.NewRequest("GET", "/internal/account-summary?account_id=account-1", nil)
	request.Header.Set(accountSummaryCanonicalUIDHeader, "user-1")
	accountID, canonicalUID, datasets, ok := parseAccountSummaryRequest(request)
	if !ok || accountID != "account-1" || canonicalUID != "user-1" || len(datasets) != 4 {
		t.Fatalf("parsed = %q/%q/%#v/%v", accountID, canonicalUID, datasets, ok)
	}
	request.Header.Del(accountSummaryCanonicalUIDHeader)
	if _, _, _, ok := parseAccountSummaryRequest(request); ok {
		t.Fatal("missing canonical subject accepted")
	}
}

func TestParseAccountSummaryRequestRejectsForgedAndOversizedInput(t *testing.T) {
	claims := accountSummaryTestClaims()
	deps, _ := accountSummaryTestDeps(claims)
	valid := func(rawQuery string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		deps.handle(rr, accountSummaryRequest("opaque", rawQuery, "user-1"))
		return rr
	}
	for _, test := range []struct {
		name   string
		query  string
		header string
		multi  bool
	}{
		{name: "unknown dataset", query: "account_id=account-1&dataset=snaplink.password"},
		{name: "unknown query", query: "account_id=account-1&extra=value"},
		{name: "duplicate account", query: "account_id=account-1&account_id=account-2"},
		{name: "malformed query", query: "account_id=%ZZ"},
		{name: "whitespace subject", query: "account_id=account-1", header: " user-1"},
		{name: "header list injection", query: "account_id=account-1", header: "user-1,user-2"},
		{name: "duplicate subject headers", query: "account_id=account-1", header: "user-1", multi: true},
		{name: "oversized account", query: "account_id=" + strings.Repeat("x", maxAccountSummaryAccountID+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			subject := test.header
			if subject == "" {
				subject = "user-1"
			}
			r := accountSummaryRequest("opaque", test.query, subject)
			if test.multi {
				r.Header.Add(accountSummaryCanonicalUIDHeader, "user-2")
			}
			rr := httptest.NewRecorder()
			deps.handle(rr, r)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			assertAccountSummaryNoStore(t, rr)
		})
	}
	if got := valid("account_id=" + strings.Repeat("x", maxAccountSummaryQuery)); got.Code != http.StatusBadRequest {
		t.Fatalf("oversized query status = %d, want 400", got.Code)
	}
	oversizedToken := httptest.NewRecorder()
	deps.handle(oversizedToken, accountSummaryRequest(strings.Repeat("x", maxAccountSummaryToken+1), "account_id=account-1", "user-1"))
	if oversizedToken.Code != http.StatusUnauthorized {
		t.Fatalf("oversized token status = %d, want 401", oversizedToken.Code)
	}
	assertAccountSummaryNoStore(t, oversizedToken)

	r := accountSummaryRequest("opaque", "account_id=account-1", "user-1")
	r = r.WithContext(peertrust.WithRequestInfo(r.Context(), peertrust.RequestInfo{ForwardedHeadersTrusted: false}))
	rr := httptest.NewRecorder()
	deps.handle(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("untrusted canonical header status = %d, want 400", rr.Code)
	}
}

func TestAccountSummaryBearerChallenges(t *testing.T) {
	claims := accountSummaryTestClaims()
	deps, _ := accountSummaryTestDeps(claims)
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, accountSummaryPath+"?account_id=account-1", nil)
	deps.handle(rr, r)
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") != `Bearer realm="snaplink-account-source"` {
		t.Fatalf("missing-token response = %d, challenge=%q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
	assertAccountSummaryNoStore(t, rr)

	claims.TokenUse = core.TokenUseIDToken
	rr = httptest.NewRecorder()
	deps.handle(rr, accountSummaryRequest("opaque", "account_id=account-1", "user-1"))
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("invalid-token response = %d, challenge=%q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
}

func TestAccountSummaryAcceptsOnlyServiceTokenShape(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*core.TokenClaims)
		wantStatus int
	}{
		{name: "user subject", mutate: func(c *core.TokenClaims) { c.Subject = "user-1" }, wantStatus: http.StatusForbidden},
		{name: "auth time", mutate: func(c *core.TokenClaims) { c.AuthTime = time.Now() }, wantStatus: http.StatusForbidden},
		{name: "amr", mutate: func(c *core.TokenClaims) { c.AMR = []string{"password"} }, wantStatus: http.StatusForbidden},
		{name: "wrong audience", mutate: func(c *core.TokenClaims) { c.Audience = []string{"other-service"} }, wantStatus: http.StatusForbidden},
		{name: "additional audience", mutate: func(c *core.TokenClaims) { c.Audience = []string{accountSummaryAudience, "other-service"} }, wantStatus: http.StatusForbidden},
		{name: "missing scope", mutate: func(c *core.TokenClaims) { c.Scopes = nil }, wantStatus: http.StatusForbidden},
		{name: "subject client mismatch", mutate: func(c *core.TokenClaims) { c.ClientID = "other-client" }, wantStatus: http.StatusForbidden},
		{name: "id token", mutate: func(c *core.TokenClaims) { c.TokenUse = core.TokenUseIDToken }, wantStatus: http.StatusUnauthorized},
		{name: "untyped token", mutate: func(c *core.TokenClaims) { c.TokenUse = "" }, wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := accountSummaryTestClaims()
			test.mutate(claims)
			deps, _ := accountSummaryTestDeps(claims)
			rr := httptest.NewRecorder()
			deps.handle(rr, accountSummaryRequest("opaque", "account_id=account-1", "user-1"))
			if rr.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, test.wantStatus, rr.Body.String())
			}
			assertAccountSummaryNoStore(t, rr)
		})
	}
}

func TestAccountSummaryUnknownUserAndDatasetUseSameFailure(t *testing.T) {
	claims := accountSummaryTestClaims()
	deps, users := accountSummaryTestDeps(claims)
	if err := users.CreateOrUpdate(context.Background(), &core.User{ID: "user-1", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}

	known := httptest.NewRecorder()
	deps.handle(known, accountSummaryRequest("opaque", "account_id=account-1", "user-1"))
	if known.Code != http.StatusOK || !strings.Contains(known.Body.String(), "user@example.com") {
		t.Fatalf("known user response = %d %s", known.Code, known.Body.String())
	}
	assertAccountSummaryNoStore(t, known)

	unknown := httptest.NewRecorder()
	deps.handle(unknown, accountSummaryRequest("opaque", "account_id=account-1", "missing-user"))
	assertAccountSummaryNoStore(t, unknown)

	badDataset := httptest.NewRecorder()
	deps.handle(badDataset, accountSummaryRequest("opaque", "account_id=account-1&dataset=unknown", "user-1"))
	if badDataset.Code != http.StatusBadRequest || !strings.Contains(badDataset.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("unknown dataset response = %d %s", badDataset.Code, badDataset.Body.String())
	}
	assertAccountSummaryNoStore(t, badDataset)
	if unknown.Code != badDataset.Code || unknown.Body.String() != badDataset.Body.String() {
		t.Fatalf("unknown user/dataset responses differ: user=%d %q dataset=%d %q", unknown.Code, unknown.Body.String(), badDataset.Code, badDataset.Body.String())
	}
}

func TestMountAccountSummaryAfterServerHandler(t *testing.T) {
	claims := accountSummaryTestClaims()
	deps, users := accountSummaryTestDeps(claims)
	if err := users.CreateOrUpdate(context.Background(), &core.User{ID: "user-1"}); err != nil {
		t.Fatal(err)
	}
	h := deps.server.Handler()
	if err := Mount(deps.server, users, deps.recorder, nil); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, accountSummaryRequest("opaque", "account_id=account-1", "user-1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("mounted route status = %d, body=%s", rr.Code, rr.Body.String())
	}
	assertAccountSummaryNoStore(t, rr)
}

func assertAccountSummaryNoStore(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %q/%q, want no-store/no-cache", rr.Header().Get("Cache-Control"), rr.Header().Get("Pragma"))
	}
}
