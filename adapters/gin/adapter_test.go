package ginadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/snaplink/sso"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode) // suppress the framework's noisy startup banner
	m.Run()
}

func do(t *testing.T, r *GinRouter, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestGinRouter_GET(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_POSTAndBind(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_DELETE(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_Query(t *testing.T) {
	r := NewGinRouter()
	r.GET("/search", func(c sso.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{"q": c.Query("q")})
	})
	rec := do(t, r, http.MethodGet, "/search?q=foo", "")
	if !strings.Contains(rec.Body.String(), `"q":"foo"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestGinRouter_Redirect(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_SetGet(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_MiddlewareInvocationCount(t *testing.T) {
	r := NewGinRouter()
	var calls atomic.Int32
	r.Use(func(c sso.HandlerContext) { calls.Add(1) })
	r.GET("/x", func(c sso.HandlerContext) { c.JSON(200, "ok") })

	_ = do(t, r, http.MethodGet, "/x", "")
	_ = do(t, r, http.MethodGet, "/x", "")
	if got := calls.Load(); got != 2 {
		t.Errorf("middleware calls = %d, want 2", got)
	}
}

func TestGinRouter_Group(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_RequestAndResponseWriter(t *testing.T) {
	r := NewGinRouter()
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

func TestGinRouter_AcceptsExistingEngine(t *testing.T) {
	e := gin.New()
	r := NewGinRouter(e)
	if r.engine != e {
		t.Error("constructor did not accept the supplied engine")
	}
	r.GET("/x", func(c sso.HandlerContext) { c.JSON(200, "ok") })
	rec := do(t, r, http.MethodGet, "/x", "")
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d", rec.Code)
	}
}
