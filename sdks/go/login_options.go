package snaplink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

func normalizeOptions(options LoginOptions) (loginConfig, error) {
	base, err := normalizeHTTP(options.BaseURL, "base_url", options.AllowInsecureHTTPForDevelopment, false)
	if err != nil {
		return loginConfig{}, err
	}
	if strings.TrimSpace(options.ClientID) == "" {
		return loginConfig{}, &Error{Status: 0, Code: "invalid_request", Description: "client_id is required"}
	}
	redirect, err := normalizeHTTP(options.RedirectURI, "redirect_uri", options.AllowInsecureHTTPForDevelopment, true)
	if err != nil {
		return loginConfig{}, err
	}
	returnTo := options.ReturnTo
	if returnTo == "" {
		returnTo = redirect
	}
	returnURL, err := normalizeHTTP(returnTo, "return_to", options.AllowInsecureHTTPForDevelopment, true)
	if err != nil {
		return loginConfig{}, err
	}
	if !sameOrigin(returnURL, redirect) {
		return loginConfig{}, &Error{Status: 0, Code: "invalid_request", Description: "return_to must use the redirect URI origin"}
	}
	loginPage := options.LoginPageURL
	if loginPage == "" {
		loginPage = strings.TrimRight(base, "/") + "/login/"
	}
	if _, err := normalizeHTTP(loginPage, "login_page_url", options.AllowInsecureHTTPForDevelopment, true); err != nil {
		return loginConfig{}, err
	}
	ttl := options.TransactionTTL
	if ttl <= 0 {
		ttl = defaultTransactionTTL
	}
	scope := options.Scope
	if len(scope) == 0 {
		scope = []string{"openid", "profile", "email"}
	}
	if err := validateValues(scope, "scope"); err != nil {
		return loginConfig{}, err
	}
	return loginConfig{baseURL: base, clientID: options.ClientID, loginPage: loginPage,
		redirectURI: redirect, returnTo: returnURL, scope: scope, resource: options.Resource,
		options: options, ttl: ttl}, nil
}

func buildLoginURL(config loginConfig, state, challenge string) (string, error) {
	u, err := url.Parse(config.loginPage)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "code_challenge", "code_challenge_method", "resource", "prompt", "max_age", "login_hint", "acr_values", "ui_locales"} {
		query.Del(key)
	}
	query.Set("client_id", config.clientID)
	query.Set("redirect_uri", config.redirectURI)
	query.Set("response_type", "code")
	query.Set("response_mode", "query")
	query.Set("scope", strings.Join(config.scope, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	for _, resource := range config.resource {
		if resource == "" {
			return "", &Error{Status: 0, Code: "invalid_request", Description: "resource values must be non-empty"}
		}
		query.Add("resource", resource)
	}
	setOptional(query, "prompt", config.options.Prompt)
	setOptional(query, "login_hint", config.options.LoginHint)
	setOptional(query, "acr_values", config.options.AcrValues)
	setOptional(query, "ui_locales", config.options.UILocales)
	if config.options.MaxAge != nil {
		if *config.options.MaxAge < 0 {
			return "", &Error{Status: 0, Code: "invalid_request", Description: "max_age must be non-negative"}
		}
		query.Set("max_age", fmt.Sprint(*config.options.MaxAge))
	}
	u.RawQuery, u.Fragment = query.Encode(), ""
	return u.String(), nil
}

func setOptional(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

func callbackValues(raw, redirectURI string, allowInsecure bool) (callback, bool, error) {
	if raw == "" {
		return callback{}, false, nil
	}
	normalized, err := normalizeHTTP(raw, "callback_url", allowInsecure, true)
	if err != nil {
		return callback{}, false, err
	}
	if canonicalURL(normalized) != canonicalURL(redirectURI) {
		return callback{}, false, &Error{Status: 0, Code: "invalid_request", Description: "callback_url does not match redirect_uri"}
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return callback{}, false, err
	}
	values := u.Query()
	return callback{code: values.Get("code"), state: values.Get("state"), issuer: values.Get("iss"),
		err: values.Get("error"), errorDescription: values.Get("error_description")}, true, nil
}

func normalizeHTTP(raw, name string, allowInsecure, allowQuery bool) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " is required"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " must be an absolute HTTP(S) URL"}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (allowInsecure || loopback(u.Hostname()))) {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " must use HTTPS or loopback HTTP"}
	}
	if (!allowQuery && u.RawQuery != "") || u.Fragment != "" {
		return "", &Error{Status: 0, Code: "invalid_request", Description: name + " contains a forbidden query or fragment"}
	}
	return u.String(), nil
}

func sameOrigin(a, b string) bool {
	left, _ := url.Parse(a)
	right, _ := url.Parse(b)
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

func validateValues(values []string, name string) error {
	for _, value := range values {
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }) >= 0 {
			return &Error{Status: 0, Code: "invalid_request", Description: name + " values must be non-empty and whitespace-free"}
		}
	}
	return nil
}

func pkce() (string, string, error) {
	verifier, err := randomURL(64)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func randomURL(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func storeKey(clientID string) string { return "snaplink.login.v1:" + url.QueryEscape(clientID) }

func loopback(host string) bool {
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
