package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// clientColumns is the canonical ordered column list shared by the SELECT,
// INSERT, upsert, and scan paths so they cannot drift. The order matches
// clientWriteArgs exactly; id is first so the UPDATE can drop it (it moves to
// the trailing WHERE).
var clientColumns = []string{
	"id", "secret", "name", "redirect_uris", "allowed_scopes",
	"allowed_authenticators", "token_strategy", "active", "tenant_id", "require_pkce",
	"jwks", "allowed_resources", "allowed_request_uris", "registration_access_token",
	"post_logout_redirect_uris", "allowed_authorization_details",
	"refresh_token_ttl", "access_token_ttl", "allowed_pkce_methods",
	"require_signed_request_object", "require_par",
	"device_code_ttl", "device_code_poll_interval",
	"userinfo_signed_response_alg",
	"idtoken_encrypted_response_alg", "idtoken_encrypted_response_enc",
	"userinfo_encrypted_response_alg", "userinfo_encrypted_response_enc",
	"backchannel_logout_uri", "subject_type", "sector_identifier_uri",
	"frontchannel_logout_uri", "federation", "attributes",
	"secret_rotated_at", "client_trust_score", "client_trust_set_at",
}

// clientWriteArgs is the ordered argument bundle shared by INSERT, upsert, and
// UPDATE — identical projection to clientColumns. Booleans are encoded as 0/1
// INTEGERs and durations as int64 nanoseconds (BIGINT), matching the schema.
func clientWriteArgs(c *sso.Client, secret, rat string) []any {
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	reqURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	authzDetails, _ := json.Marshal(c.AllowedAuthorizationDetailsTypes)
	pkceM, _ := json.Marshal(c.AllowedPKCEMethods)
	attrs, _ := json.Marshal(c.Attributes)

	return []any{
		c.ID, secret, c.Name,
		string(redirects), string(scopes), string(auths),
		c.TokenStrategy, boolToInt(c.Active), c.TenantID, boolToInt(c.RequirePKCE),
		string(jwks), string(resources), string(reqURIs), rat,
		string(postLogout), string(authzDetails),
		int64(c.RefreshTokenTTL), int64(c.AccessTokenTTL), string(pkceM),
		boolToInt(c.RequireSignedRequestObject), boolToInt(c.RequirePAR),
		int64(c.DeviceCodeTTL), int64(c.DeviceCodePollInterval),
		c.UserinfoSignedResponseAlg,
		c.IDTokenEncryptedResponseAlg, c.IDTokenEncryptedResponseEnc,
		c.UserinfoEncryptedResponseAlg, c.UserinfoEncryptedResponseEnc,
		c.BackchannelLogoutURI, c.SubjectType, c.SectorIdentifierURI,
		c.FrontchannelLogoutURI, boolToInt(c.Federation), string(attrs),
		unixNanoOrZero(c.SecretRotatedAt),
		c.ClientTrustScore, unixNanoOrZero(c.ClientTrustSetAt),
	}
}

// unixNanoOrZero renders a timestamp for storage: a zero time maps to the
// sentinel 0 (never tracked/scored), never a huge negative UnixNano, so
// scanClient can round-trip the "unset" sentinel faithfully — see
// core.Client.SecretRotatedAt / ClientTrustSetAt.
func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// clientWritePrep hashes the secret + registration access token and builds the
// shared write-argument bundle. Add / Put / Update funnel through here.
func clientWritePrep(c *sso.Client) ([]any, error) {
	secret, err := hashClientSecretField(c.Secret, "secret")
	if err != nil {
		return nil, err
	}
	rat, err := hashClientSecretField(c.RegistrationAccessToken, "rat")
	if err != nil {
		return nil, err
	}
	return clientWriteArgs(c, secret, rat), nil
}

// clientScanRow holds the raw column values scanned from a client row before
// they are normalized onto an sso.Client. Booleans arrive as INTEGER (int64),
// durations as BIGINT (int64).
type clientScanRow struct {
	c                                                      sso.Client
	redirects, scopes, auths                               string
	jwksBlob, resources, reqURIs, postLogout, authzDetails string
	pkceM, attrsBlob                                       string
	activeInt, requirePKCEInt                              int64
	requireSROInt, requirePARInt, federationInt            int64
	secret, name, tokenStrategy, tenantID                  string
	rat                                                    string
	refreshTTL, accessTTL, dcTTL, dcPoll                   int64
	userinfoSigAlg                                         string
	idtEncAlg, idtEncEnc, uiEncAlg, uiEncEnc               string
	bclURI, subjectType, sectorURI, fclURI                 string
	secretRotatedAtUnixNs                                  int64
	clientTrustSetAtUnixNs                                 int64
}

// scanInto reads every column of clientColumns into the raw row holder in
// exact order.
func (r *clientScanRow) scanInto(s scanner) error {
	return s.Scan(
		&r.c.ID, &r.secret, &r.name,
		&r.redirects, &r.scopes, &r.auths,
		&r.tokenStrategy, &r.activeInt, &r.tenantID, &r.requirePKCEInt,
		&r.jwksBlob, &r.resources, &r.reqURIs, &r.rat,
		&r.postLogout, &r.authzDetails,
		&r.refreshTTL, &r.accessTTL, &r.pkceM,
		&r.requireSROInt, &r.requirePARInt,
		&r.dcTTL, &r.dcPoll,
		&r.userinfoSigAlg,
		&r.idtEncAlg, &r.idtEncEnc, &r.uiEncAlg, &r.uiEncEnc,
		&r.bclURI, &r.subjectType, &r.sectorURI, &r.fclURI,
		&r.federationInt, &r.attrsBlob, &r.secretRotatedAtUnixNs,
		&r.c.ClientTrustScore, &r.clientTrustSetAtUnixNs,
	)
}

// scalars copies the non-JSON columns onto the embedded sso.Client, converting
// the integer-encoded booleans and nanosecond durations.
func (r *clientScanRow) scalars() {
	c := &r.c
	c.Secret = r.secret
	c.RegistrationAccessToken = r.rat
	c.Name = r.name
	c.TokenStrategy = r.tokenStrategy
	c.TenantID = r.tenantID
	c.Active = r.activeInt != 0
	c.RequirePKCE = r.requirePKCEInt != 0
	c.RequireSignedRequestObject = r.requireSROInt != 0
	c.RequirePAR = r.requirePARInt != 0
	c.Federation = r.federationInt != 0
	c.RefreshTokenTTL = time.Duration(r.refreshTTL)
	c.AccessTokenTTL = time.Duration(r.accessTTL)
	c.DeviceCodeTTL = time.Duration(r.dcTTL)
	c.DeviceCodePollInterval = time.Duration(r.dcPoll)
	c.UserinfoSignedResponseAlg = r.userinfoSigAlg
	c.IDTokenEncryptedResponseAlg = r.idtEncAlg
	c.IDTokenEncryptedResponseEnc = r.idtEncEnc
	c.UserinfoEncryptedResponseAlg = r.uiEncAlg
	c.UserinfoEncryptedResponseEnc = r.uiEncEnc
	c.BackchannelLogoutURI = r.bclURI
	c.SubjectType = r.subjectType
	c.SectorIdentifierURI = r.sectorURI
	c.FrontchannelLogoutURI = r.fclURI
	// 0 stays the zero time.Time (never tracked) — see
	// core.Client.SecretRotatedAt; time.Unix(0, 0) would otherwise decode to
	// the 1970 epoch, which is NOT the same "unknown" sentinel.
	if r.secretRotatedAtUnixNs != 0 {
		c.SecretRotatedAt = time.Unix(0, r.secretRotatedAtUnixNs).UTC()
	}
	// 0 stays the zero time.Time ("never scored") — see
	// core.Client.ClientTrustSetAt; time.Unix(0, 0) would otherwise decode
	// to the 1970 epoch, which is NOT the same "unscored" sentinel.
	if r.clientTrustSetAtUnixNs != 0 {
		c.ClientTrustSetAt = time.Unix(0, r.clientTrustSetAtUnixNs).UTC()
	}
}

// unmarshalClientJSON treats empty / "[]" / "{}" / "null" blobs as the zero
// value (so a round-tripped empty slice stays nil) and otherwise decodes.
func unmarshalClientJSON(blob string, dst any, field string) error {
	if blob == "" || blob == "[]" || blob == "{}" || blob == "null" {
		return nil
	}
	if err := json.Unmarshal([]byte(blob), dst); err != nil {
		return fmt.Errorf("postgres: unmarshal %s: %w", field, err)
	}
	return nil
}

// jsonFields hydrates the JSON-encoded slice / map columns onto the client.
func (r *clientScanRow) jsonFields() error {
	c := &r.c
	for _, f := range []struct {
		blob  string
		dst   any
		field string
	}{
		{r.redirects, &c.RedirectURIs, "redirect_uris"},
		{r.scopes, &c.AllowedScopes, "allowed_scopes"},
		{r.auths, &c.AllowedAuthenticators, "allowed_authenticators"},
		{r.jwksBlob, &c.JWKS, "jwks"},
		{r.resources, &c.AllowedResources, "allowed_resources"},
		{r.reqURIs, &c.AllowedRequestURIs, "allowed_request_uris"},
		{r.postLogout, &c.PostLogoutRedirectURIs, "post_logout_redirect_uris"},
		{r.authzDetails, &c.AllowedAuthorizationDetailsTypes, "allowed_authorization_details"},
		{r.pkceM, &c.AllowedPKCEMethods, "allowed_pkce_methods"},
		{r.attrsBlob, &c.Attributes, "attributes"},
	} {
		if err := unmarshalClientJSON(f.blob, f.dst, f.field); err != nil {
			return err
		}
	}
	return nil
}

func scanClient(s scanner) (*sso.Client, error) {
	var r clientScanRow
	if err := r.scanInto(s); err != nil {
		return nil, err
	}
	r.scalars()
	if err := r.jsonFields(); err != nil {
		return nil, err
	}
	return &r.c, nil
}
