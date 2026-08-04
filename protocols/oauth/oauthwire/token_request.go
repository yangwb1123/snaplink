package oauthwire

import "encoding/json"

// TokenRequest is the bound /token endpoint request — every parameter across
// every grant type (authorization_code, refresh_token, device_code, CIBA,
// token-exchange, client_credentials) plus the RFC 7521/7523 client-assertion
// fields. It was promoted from an anonymous struct inside the root dispatcher to
// a named oauth type so the per-grant handlers can be extracted with a stable,
// shared signature. Bound via BindParams (form-urlencoded + JSON).
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// ClientSecretPresent distinguishes omission from an explicitly empty
	// secret without retaining any additional credential material.
	ClientSecretPresent bool     `json:"-"`
	RefreshToken        string   `json:"refresh_token"`
	Scope               string   `json:"scope"`
	RedirectURI         string   `json:"redirect_uri"`
	CodeVerifier        string   `json:"code_verifier"` // PKCE RFC 7636 §4.5
	DeviceCode          string   `json:"device_code"`   // RFC 8628 §3.4 device grant
	AuthReqID           string   `json:"auth_req_id"`   // OIDC CIBA Core §10.1 grant
	Resource            []string `json:"resource"`      // RFC 8707 resource indicators

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

	// RFC 9321 Transaction Token Request parameters. Reached only when
	// requested_token_type names the Txn-Token URN (txntoken.TokenType);
	// every other requested_token_type ignores these two fields exactly
	// as it does today.
	Purp           string `json:"purp"`
	RequestContext string `json:"request_context"`

	// RFC 7521 + 7523 JWT bearer client authentication.
	ClientAssertion            string `json:"client_assertion"`
	ClientAssertionType        string `json:"client_assertion_type"`
	ClientAssertionPresent     bool   `json:"-"`
	ClientAssertionTypePresent bool   `json:"-"`

	// Assertion is the bearer JWT for the JWT Bearer Token Grant (RFC 7523 §2.1).
	// The client presents a signed JWT as the authorization grant, rather than
	// an authorization code, refresh token, or other credential.
	Assertion string `json:"assertion"`

	// AgentSessionID is for the delegation_token grant
	// (core.GrantTypeAgentDelegation, domains/tokenexchange/agentidentity):
	// the previously-created AgentSession id a human's authorization of an
	// AI agent produced. Ignored by every other grant type.
	AgentSessionID string `json:"agent_session_id"`
}

// UnmarshalJSON retains parameter presence without retaining raw request data.
func (r *TokenRequest) UnmarshalJSON(data []byte) error {
	type plain TokenRequest
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = TokenRequest(decoded)
	_, r.ClientSecretPresent = fields["client_secret"]
	_, r.ClientAssertionPresent = fields["client_assertion"]
	_, r.ClientAssertionTypePresent = fields["client_assertion_type"]
	return nil
}
