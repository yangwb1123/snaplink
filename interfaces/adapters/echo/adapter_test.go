package echoadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/snaplink/sso/interfaces/sso"
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
