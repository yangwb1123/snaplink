package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/snaplink/sso/interfaces/sso"
)

const (
	headerCacheControl = "Cache-Control"
	headerPragma       = "Pragma"
	valueNoStore       = "no-store"
	valueNoCache       = "no-cache"
	invalidGrantChoice = "invalid"
)

func authorizationCodeOnly(w http.ResponseWriter, r *http.Request) bool {
	grantType, ok := readGrantType(r)
	if !ok || grantType == "" || grantType == "authorization_code" {
		return true
	}
	w.Header().Set(headerCacheControl, valueNoStore)
	w.Header().Set(headerPragma, valueNoCache)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		sso.KeyError: sso.ErrUnsupportedGrantType,
	})
	return false
}

func readGrantType(r *http.Request) (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) > maxBodyBytes {
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
