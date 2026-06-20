package oauth

// TokenRequest is the bound /token endpoint request — every parameter across
// every grant type (authorization_code, refresh_token, device_code, CIBA,
// token-exchange, client_credentials) plus the RFC 7521/7523 client-assertion
// fields. It was promoted from an anonymous struct inside the root dispatcher to
// a named oauth type so the per-grant handlers can be extracted with a stable,
// shared signature. Bound via BindParams (form-urlencoded + JSON).
type TokenRequest struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RefreshToken string   `json:"refresh_token"`
	Scope        string   `json:"scope"`
	RedirectURI  string   `json:"redirect_uri"`
	CodeVerifier string   `json:"code_verifier"` // PKCE RFC 7636 §4.5
	DeviceCode   string   `json:"device_code"`   // RFC 8628 §3.4 device grant
	AuthReqID    string   `json:"auth_req_id"`   // OIDC CIBA Core §10.1 grant
	Resource     []string `json:"resource"`      // RFC 8707 resource indicators

	// RFC 8693 token-exchange parameters.
	SubjectToken       string   `json:"subject_token"`
	SubjectTokenType   string   `json:"subject_token_type"`
	ActorToken         string   `json:"actor_token"`
	ActorTokenType     string   `json:"actor_token_type"`
	Audience           []string `json:"audience"`
	RequestedTokenType string   `json:"requested_token_type"`
	// RFC 9470 step-up: caller may demand the exchanged token carries an ACR at
	// least as strong as one in this list.
	ACRValues string `json:"acr_values"`

	// RFC 7521 + 7523 JWT bearer client authentication.
	ClientAssertion     string `json:"client_assertion"`
	ClientAssertionType string `json:"client_assertion_type"`
}
