package echoadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func do(t *testing.T, r *EchoRouter, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	if rdr != nil {
		req = httptest.NewRequest(method, path, rdr)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestEchoRouter_GET(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/hello", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{"msg": "hi"})
	})
	rec := do(t, r, http.MethodGet, "/hello", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var got map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["msg"] != "hi" {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestEchoRouter_POSTAndBind(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	type in struct {
		Name string `json:"name"`
	}
	r.POST("/echo", func(c sso.HandlerContext) {
		var v in
		if err := c.Bind(&v); err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, map[string]string{"name": v.Name})
	})
	rec := do(t, r, http.MethodPost, "/echo", `{"name":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"alice"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestEchoRouter_DELETE(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.DELETE("/things/:id", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{"deleted": c.Param("id")})
	})
	rec := do(t, r, http.MethodDelete, "/things/abc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"deleted":"abc"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestEchoRouter_PATCH(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.PATCH("/things/:id", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{"patched": c.Param("id")})
	})
	rec := do(t, r, http.MethodPatch, "/things/abc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"patched":"abc"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestEchoRouter_Query(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/search", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{"q": c.Query("q")})
	})
	rec := do(t, r, http.MethodGet, "/search?q=foo", "")
	if !strings.Contains(rec.Body.String(), `"q":"foo"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestEchoRouter_Redirect(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/r", func(c sso.HandlerContext) {
		c.Redirect(http.StatusFound, "/elsewhere")
	})
	rec := do(t, r, http.MethodGet, "/r", "")
	if rec.Code != http.StatusFound {
		t.Errorf("code = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/elsewhere" {
		t.Errorf("Location = %q", loc)
	}
}

func TestEchoRouter_SetGet(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.Use(func(c sso.HandlerContext) {
		c.Set("user_id", "u-alice")
	})
	r.GET("/me", func(c sso.HandlerContext) {
		v, _ := c.Get("user_id").(string)
		c.JSON(http.StatusOK, map[string]string{"u": v})
	})
	rec := do(t, r, http.MethodGet, "/me", "")
	if !strings.Contains(rec.Body.String(), `"u":"u-alice"`) {
		t.Errorf("body = %s — middleware Set didn't reach handler", rec.Body.String())
	}
}

func TestEchoRouter_MiddlewareInvocationCount(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	var calls atomic.Int32
	r.Use(func(c sso.HandlerContext) { calls.Add(1) })
	r.GET("/x", func(c sso.HandlerContext) { c.JSON(200, "ok") })

	_ = do(t, r, http.MethodGet, "/x", "")
	_ = do(t, r, http.MethodGet, "/x", "")
	if got := calls.Load(); got != 2 {
		t.Errorf("middleware calls = %d, want 2", got)
	}
}

func TestEchoRouter_Group(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.Use(func(c sso.HandlerContext) { c.Set("base", "yes") })

	api := r.Group("/api", func(c sso.HandlerContext) { c.Set("api", "yes") })
	api.GET("/ping", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{
			"base": c.Get("base").(string),
			"api":  c.Get("api").(string),
		})
	})

	rec := do(t, r, http.MethodGet, "/api/ping", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"base":"yes"`) || !strings.Contains(body, `"api":"yes"`) {
		t.Errorf("group did not inherit + extend middlewares: %s", body)
	}
}

func TestEchoRouter_RequestAndResponseWriter(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/peek", func(c sso.HandlerContext) {
		if c.Request() == nil {
			t.Error("Request() returned nil")
		}
		if c.ResponseWriter() == nil {
			t.Error("ResponseWriter() returned nil")
		}
		c.JSON(http.StatusOK, "ok")
	})
	_ = do(t, r, http.MethodGet, "/peek", "")
}

func TestEchoRouter_AcceptsExistingEngine(t *testing.T) {
	t.Parallel()
	e := echo.New()
	r := NewEchoRouter(e)
	if r.engine != e {
		t.Error("constructor did not accept the supplied engine")
	}
	r.GET("/x", func(c sso.HandlerContext) { c.JSON(200, "ok") })
	rec := do(t, r, http.MethodGet, "/x", "")
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d", rec.Code)
	}
}

// TestEchoRouter_UnmatchedByteIdenticalToHTTPNotFound pins the constructor's
// unmatched-response normalization (Decision 2): unknown path, wrong
// method, HEAD/OPTIONS on a GET-only route, and the trailing-slash variant
// all answer http.NotFound's exact bytes — never echo's native JSON
// {"message":"Not Found"} / 405+Allow. Deleting the RouteNotFound
// installation in the constructor makes this test (and the shared
// conformance suite) fail immediately.
func TestEchoRouter_UnmatchedByteIdenticalToHTTPNotFound(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/known", func(c sso.HandlerContext) { c.JSON(http.StatusOK, "ok") })

	ref := httptest.NewRecorder()
	http.NotFound(ref, httptest.NewRequest(http.MethodGet, "/known", nil))

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"unknown path", http.MethodGet, "/never-registered"},
		{"method mismatch", http.MethodPost, "/known"},
		{"HEAD on GET route", http.MethodHead, "/known"},
		{"OPTIONS on known path", http.MethodOptions, "/known"},
		{"trailing slash", http.MethodGet, "/known/"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, r, tc.method, tc.path, "")
			if rec.Code != ref.Code || rec.Body.String() != ref.Body.String() || !headersEqualEcho(rec.Header(), ref.Header()) {
				t.Errorf("%s %s: got (%d, %q, %v), want (%d, %q, %v)",
					tc.method, tc.path, rec.Code, rec.Body.String(), rec.Header(),
					ref.Code, ref.Body.String(), ref.Header())
			}
		})
	}
}

func headersEqualEcho(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

// TestEchoRouter_GateOffSentinel_WithCustomErrorHandler pins the delegating
// HTTPErrorHandler wrapper (Decision 3b): when the embedder installs an
// error handler that does NOT early-return on committed responses (echo's
// Response.Write has no committed guard, so a second write would corrupt
// the 404 bytes), the gate sentinel must still be swallowed and the
// gated-off response must stay byte-identical to http.NotFound.
func TestEchoRouter_GateOffSentinel_WithCustomErrorHandler(t *testing.T) {
	t.Parallel()
	e := echo.New()
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		_ = c.String(http.StatusInternalServerError, "custom-error")
	}
	r := NewEchoRouter(e)

	live := false
	core.NewGatedRouter(r, func() bool { return live }).GET("/secret", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, "ok")
	})

	ref := httptest.NewRecorder()
	http.NotFound(ref, httptest.NewRequest(http.MethodGet, "/secret", nil))
	rec := do(t, r, http.MethodGet, "/secret", "")
	if rec.Code != ref.Code || rec.Body.String() != ref.Body.String() {
		t.Errorf("gated-off response = (%d, %q), want (%d, %q) — the sentinel reached the custom error handler and double-wrote",
			rec.Code, rec.Body.String(), ref.Code, ref.Body.String())
	}
}

// TestEchoRouter_UseAfterRegisterDoesNotAffectRegisteredRoutes pins the
// registration-time snapshot contract (Decision 3c, StdRouter semantics): a
// route registered before Use() must not see the new middleware; a route
// registered after must. The pre-fix adapter read e.middlewares at request
// time and retroactively mutated registered routes — this test was red
// then.
func TestEchoRouter_UseAfterRegisterDoesNotAffectRegisteredRoutes(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	read := func(c sso.HandlerContext) {
		late, _ := c.Get("late").(string)
		c.JSON(http.StatusOK, map[string]string{"late": late})
	}
	r.GET("/a", read)
	r.Use(func(c sso.HandlerContext) { c.Set("late", "yes") })
	r.GET("/b", read)

	if got := do(t, r, http.MethodGet, "/a", "").Body.String(); !strings.Contains(got, `"late":""`) {
		t.Errorf("/a = %s — Use after registration must not affect already-registered routes", got)
	}
	if got := do(t, r, http.MethodGet, "/b", "").Body.String(); !strings.Contains(got, `"late":"yes"`) {
		t.Errorf("/b = %s — Use before registration must affect the route", got)
	}
}

// TestEchoRouter_ConcurrentUseAndServeHTTP is the -race tripwire for the
// snapshot design: the request path never reads e.middlewares (each route
// closes over a registration-time copy), so concurrent Use()+ServeHTTP is
// race-free by construction. The race detector fails loudly if someone
// reverts wrapHandler to a request-time slice read.
func TestEchoRouter_ConcurrentUseAndServeHTTP(t *testing.T) {
	t.Parallel()
	r := NewEchoRouter()
	r.GET("/x", func(c sso.HandlerContext) { c.JSON(http.StatusOK, "ok") })

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.Use(func(c sso.HandlerContext) { c.Set("noise", "yes") })
		}()
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		}()
	}
	wg.Wait()
}
