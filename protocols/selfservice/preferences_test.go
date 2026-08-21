package selfservice

import (
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func seedUser(t *testing.T, d *testDeps, id string, attrs map[string]string) {
	t.Helper()
	u := &core.User{ID: id}
	u.Attributes = attrs
	if err := d.users.CreateOrUpdate(t.Context(), u); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

func TestHandleMyPreferencesGet_AllowlistOnly(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedUser(t, d, "alice", map[string]string{
		"locale":             "zh-CN",
		"sverp:theme_mode":   "dark",
		"password_hash":      "SECRET", // must never leak
		"sv_sso:legacy_id":   "123",
	})

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyPreferencesGet(d, ctx, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["locale"] != "zh-CN" {
		t.Errorf("locale = %v, want zh-CN", body["locale"])
	}
	if body["sverp:theme_mode"] != "dark" {
		t.Errorf("theme_mode = %v, want dark", body["sverp:theme_mode"])
	}
	if _, leaked := body["password_hash"]; leaked {
		t.Errorf("credential attribute leaked: %v", body["password_hash"])
	}
	if _, leaked := body["sv_sso:legacy_id"]; leaked {
		t.Errorf("non-allowlisted attribute leaked")
	}
}

func TestHandleMyPreferencesGet_MissingUserIs500(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyPreferencesGet(d, ctx, "unknown-user")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestHandleMyPreferencesPut_MergesAndPersists(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedUser(t, d, "alice", map[string]string{"locale": "en-US"})

	ctx, rec := newCtx(http.MethodPut, core.ContentTypeJSON,
		`{"locale":"zh-CN","sverp:theme_mode":"dark","zoneinfo":"Asia/Shanghai"}`)
	HandleMyPreferencesPut(d, ctx, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	got, err := d.users.GetByID(t.Context(), "alice")
	if err != nil {
		t.Fatalf("reload alice: %v", err)
	}
	if got.Attributes["locale"] != "zh-CN" {
		t.Errorf("locale = %q, want zh-CN", got.Attributes["locale"])
	}
	if got.Attributes["sverp:theme_mode"] != "dark" {
		t.Errorf("theme_mode = %q, want dark", got.Attributes["sverp:theme_mode"])
	}
	if got.Attributes["zoneinfo"] != "Asia/Shanghai" {
		t.Errorf("zoneinfo = %q, want Asia/Shanghai", got.Attributes["zoneinfo"])
	}
}

func TestHandleMyPreferencesPut_RejectsUnknownOrInvalid(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"password_hash":"x"}`,           // unknown key — fail closed
		`{"locale":"not a locale!!"}`,     // invalid BCP47
		`{"sverp:theme_mode":"neon"}`,     // invalid theme
		`{"zoneinfo":"bad\u0000zone"}`,    // control char
	}
	for _, body := range cases {
		d := newTestDeps()
		seedUser(t, d, "alice", nil)
		ctx, rec := newCtx(http.MethodPut, core.ContentTypeJSON, body)
		HandleMyPreferencesPut(d, ctx, "alice")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestHandleMyPreferencesPut_EmptyRemovesKey(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	seedUser(t, d, "alice", map[string]string{"locale": "zh-CN"})

	ctx, rec := newCtx(http.MethodPut, core.ContentTypeJSON, `{"locale":""}`)
	HandleMyPreferencesPut(d, ctx, "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	got, err := d.users.GetByID(t.Context(), "alice")
	if err != nil {
		t.Fatalf("reload alice: %v", err)
	}
	if _, ok := got.Attributes["locale"]; ok {
		t.Errorf("locale not removed: %v", got.Attributes)
	}
	if got.Attributes["password_hash"] != "" {
		t.Errorf("unexpected attribute after merge")
	}
}