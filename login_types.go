package sso

import (
	"encoding/json"

)

// loginRequest is the parsed /auth/login request body.
type loginRequest struct {
	Provider             string            `json:"provider"`
	Credential           map[string]string `json:"credential"`
	ClientID             string            `json:"client_id"`
	Scope                []string          `json:"scope"`
	State                string            `json:"state"`
	ResponseType         string            `json:"response_type"`
	RedirectURI          string            `json:"redirect_uri"`
	Nonce                string            `json:"nonce"`
	CodeChallenge        string            `json:"code_challenge"`
	CodeChallengeMethod  string            `json:"code_challenge_method"`
	Resource             []string          `json:"resource"`
	RequestURI           string            `json:"request_uri"`
	AuthorizationDetails json.RawMessage   `json:"authorization_details"`
	Request              string            `json:"request"`
	Prompt               string            `json:"prompt"`
	IDTokenHint          string            `json:"id_token_hint"`
	MaxAge               *int64            `json:"max_age"`
	LoginHint            string            `json:"login_hint"`
	ResponseMode         string            `json:"response_mode"`
	ACRValues            string            `json:"acr_values"`
	UILocales            string            `json:"ui_locales"`
	Claims               json.RawMessage   `json:"claims"`
	ConsentChallengeID   string            `json:"consent_challenge_id"`
}
