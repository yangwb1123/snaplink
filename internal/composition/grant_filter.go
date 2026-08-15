package composition

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	HeaderCacheControl = "Cache-Control"
	HeaderPragma       = "Pragma"
	ValueNoStore       = "no-store"
	ValueNoCache       = "no-cache"
	invalidGrantChoice = "invalid"
)

// authorizationCodeOnly is the small editions' grant filter: the token
// endpoint accepts only the authorization_code grant, and rejects every
// other grant type with an indistinguishable no-store 400 invalid_grant.
func authorizationCodeOnly(w http.ResponseWriter, r *http.Request) bool {
	grantType, ok := readGrantType(r)
	if !ok || grantType == "" || grantType == "authorization_code" {
		return true
	}
	w.Header().Set(HeaderCacheControl, ValueNoStore)
	w.Header().Set(HeaderPragma, ValueNoCache)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		sso.KeyError: sso.ErrUnsupportedGrantType,
	})
	return false
}

func readGrantType(r *http.Request) (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) > MaxBodyBytes {
		return "", false
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			GrantType string `json:"grant_type"`
		}
		if json.Unmarshal(raw, &body) != nil {
			return "", false
		}
		return body.GrantType, true
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return "", false
	}
	grantTypes := values["grant_type"]
	if len(grantTypes) != 1 {
		return invalidGrantChoice, true
	}
	return grantTypes[0], true
}
