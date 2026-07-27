package oauth

// Hot-path benchmark for oauth.BindParams — every OAuth/OIDC endpoint
// (/token, /par, /introspect, /revoke, …) binds its request body through
// this one function on every request, over BOTH form-urlencoded
// (RFC-mandatory) and JSON bodies. The form path runs reflection over the
// destination struct's json tags, so it is the allocation-sensitive one.
//
// New file, dep-free (std testing only). b.ReportAllocs() + a
// package-level sink that consumes the bound result.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// benchTokenForm is a representative authorization_code token-exchange
// request struct: the exact shape a /token handler binds. It exercises
// every branch of formIntoStruct — string, bool, and the []string
// (multi-value + space-separated) paths.
type benchTokenForm struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code"`
	RedirectURI  string   `json:"redirect_uri"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	CodeVerifier string   `json:"code_verifier"`
	Scope        []string `json:"scope"`    // space-separated single value
	Resource     []string `json:"resource"` // RFC 8707 multi-value
	OpenIDOnly   bool     `json:"openid"`
}

// Package-level sinks so the compiler cannot elide the bind work.
var (
	benchBindSink benchTokenForm
	benchBindErr  error
)

const benchFormBody = "grant_type=authorization_code&" +
	"code=SplxlOBeZQQYbYS6WxSbIA&" +
	"redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&" +
	"client_id=web-app&" +
	"client_secret=s3cr3t-value-1234567890&" +
	"code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&" +
	"scope=openid%20profile%20email%20offline_access&" +
	"resource=https%3A%2F%2Fapi.example.com&" +
	"resource=https%3A%2F%2Fother.example.com&" +
	"openid=true"

const benchJSONBody = `{` +
	`"grant_type":"authorization_code",` +
	`"code":"SplxlOBeZQQYbYS6WxSbIA",` +
	`"redirect_uri":"https://client.example.com/cb",` +
	`"client_id":"web-app",` +
	`"client_secret":"s3cr3t-value-1234567890",` +
	`"code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",` +
	`"scope":["openid","profile","email","offline_access"],` +
	`"resource":["https://api.example.com","https://other.example.com"],` +
	`"openid":true}`

// newBenchCtx builds a real core.Context over an httptest request with
// the given body + content type — the same HandlerContext the live
// handlers pass to BindParams.
func newBenchCtx(body, contentType string) core.HandlerContext {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set(core.HeaderContentType, contentType)
	return core.NewContext(httptest.NewRecorder(), r)
}

func BenchmarkBindParamsForm(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// A fresh request per iteration: BindParams calls ParseForm,
		// which consumes the body, so a shared request would only bind
		// once. The request build is part of the realistic per-request
		// cost.
		ctx := newBenchCtx(benchFormBody, "application/x-www-form-urlencoded")
		var req benchTokenForm
		benchBindErr = BindParams(ctx, &req)
		benchBindSink = req
	}
}

func BenchmarkBindParamsJSON(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := newBenchCtx(benchJSONBody, core.ContentTypeJSON)
		var req benchTokenForm
		benchBindErr = BindParams(ctx, &req)
		benchBindSink = req
	}
}
