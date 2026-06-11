package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/core"
)

// fuzzBindTarget exercises every branch of formIntoStruct (string, bool,
// []string) plus the json.RawMessage path the real OAuth request structs use,
// so the fuzzer drives the full decode surface rather than a single field.
type fuzzBindTarget struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret,omitempty"`
	ResponseType string          `json:"response_type"`
	AllowRefresh bool            `json:"allow_refresh"`
	Scope        []string        `json:"scope"`
	Resource     []string        `json:"resource"`
	Claims       json.RawMessage `json:"claims"`
	Ignored      string          `json:"-"`
	Untagged     string
}

// FuzzBindParams throws arbitrary Content-Type + body bytes at the real
// oauth.BindParams (and thus formIntoStruct / json decode) and asserts it
// NEVER panics. BindParams sits on /token, /par, /introspect, /revoke, /ciba —
// every credential endpoint — parsing fully attacker-controlled bodies, so a
// panic on a malformed body is a remote DoS. A decode error is an expected,
// acceptable outcome; only a panic (or a wedged reflect Set) is a finding.
func FuzzBindParams(f *testing.F) {
	// ctSelector picks the Content-Type deterministically from the fuzzed
	// byte so the fuzzer explores BOTH the form and JSON paths.
	f.Add(uint8(0), []byte(`client_id=abc&scope=openid%20profile&allow_refresh=true&resource=a&resource=b`))
	f.Add(uint8(0), []byte(`scope=a,b,c`))
	f.Add(uint8(0), []byte(`client_id=%ZZ`)) // bad percent-encoding → ParseForm error
	f.Add(uint8(0), []byte(``))
	f.Add(uint8(0), []byte(`=&=&&;;`))
	f.Add(uint8(1), []byte(`{"client_id":"abc","scope":["openid"],"allow_refresh":true,"claims":{"x":1}}`))
	f.Add(uint8(1), []byte(`{"scope":"not-an-array"}`)) // type mismatch → decode error
	f.Add(uint8(1), []byte(`{`))                        // truncated JSON
	f.Add(uint8(1), []byte(`null`))
	f.Add(uint8(2), []byte(`anything at all`)) // unknown CT → JSON default path
	f.Add(uint8(2), []byte("\x00\x01\xff"))

	f.Fuzz(func(t *testing.T, ctSelector uint8, body []byte) {
		var ct string
		switch ctSelector % 4 {
		case 0:
			ct = "application/x-www-form-urlencoded"
		case 1:
			ct = "application/json; charset=utf-8"
		case 2:
			ct = "text/plain" // unexpected CT → JSON default branch
		default:
			ct = "" // missing CT → JSON default branch
		}

		req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(body))
		if ct != "" {
			req.Header.Set(core.HeaderContentType, ct)
		} else {
			req.Header.Del(core.HeaderContentType)
		}
		ctx := core.NewContext(httptest.NewRecorder(), req)

		var v fuzzBindTarget
		// The contract under test: this MUST NOT panic for any input. An
		// error return is fine and expected for malformed bodies.
		_ = BindParams(ctx, &v)
	})
}
