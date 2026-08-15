package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// hashClientSecretField re-hashes value only when it is a non-empty
// plaintext (a value already shaped like a bcrypt hash is preserved
// verbatim, keeping the secret-preservation semantics that Add / Put /
// Update share). label scopes the wrapped error for diagnosis.
func hashClientSecretField(value, label string) (string, error) {
	if isBcryptHash(value) || value == "" {
		return value, nil
	}
	h, err := hashClientSecret(value)
	if err != nil {
		return "", fmt.Errorf("sqlite: hash %s: %w", label, err)
	}
	return h, nil
}

// clientWriteArgs is the ordered argument bundle shared by the INSERT,
// INSERT OR REPLACE, and UPDATE statements. Keeping the projection in
// one place stops the three write paths from drifting against the
// column list in clientSelectAll.
//
// secret_rotated_at is taken VERBATIM from c.SecretRotatedAt (never
// stamped here): Add is the only write path that baselines it to "now"
// (before calling clientWritePrep), matching the existing round-trip
// discipline every Update caller already needs for c.Secret itself — an
// Update that doesn't want to disturb the rotation clock must read the
// current record first, exactly as it must to avoid clobbering Secret.
func clientWriteArgs(c *sso.Client, secret, rat string) ([]any, error) {
	redirects, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	auths, _ := json.Marshal(c.AllowedAuthenticators)
	jwks, _ := json.Marshal(c.JWKS)
	resources, _ := json.Marshal(c.AllowedResources)
	reqURIs, _ := json.Marshal(c.AllowedRequestURIs)
	postLogout, _ := json.Marshal(c.PostLogoutRedirectURIs)
	authzDetails, _ := json.Marshal(c.AllowedAuthorizationDetailsTypes)
	pkceM, _ := json.Marshal(c.AllowedPKCEMethods)
	attrs, _ := json.Marshal(clientAttributesForStorage(c))

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
		c.PreviousSecret, unixNanoOrZero(c.SecretOverlapUntil),
		unixNanoOrZero(c.SecretExpiresAt),
	}, nil
}

func clientAttributesForStorage(c *sso.Client) map[string]string {
	out := make(map[string]string, len(c.Attributes)+8)
	for key, value := range c.Attributes {
		out[key] = value
	}
	data, _ := json.Marshal(c.GrantTypes)
	out["_snaplink_client_grant_types"] = string(data)
	out["_snaplink_client_token_auth_method"] = c.TokenEndpointAuthMethod
	out["_snaplink_client_tls_subject_dn"] = c.TLSClientAuthSubjectDN
	out["_snaplink_client_tls_san_dns"] = c.TLSClientAuthSANDNS
	out["_snaplink_client_tls_san_email"] = c.TLSClientAuthSANEmail
	out["_snaplink_client_tls_san_uri"] = c.TLSClientAuthSANURI
	out["_snaplink_client_previous_rat"] = c.PreviousRegistrationAccessToken
	out["_snaplink_client_rat_overlap_until"] = c.RegistrationAccessTokenOverlapUntil.UTC().Format(time.RFC3339Nano)
	out["_snaplink_client_login_page_uri"] = c.LoginPageURI
	return out
}

func hydrateClientAttributes(c *sso.Client) {
	if c.Attributes == nil {
		return
	}
	_ = json.Unmarshal([]byte(c.Attributes["_snaplink_client_grant_types"]), &c.GrantTypes)
	c.TokenEndpointAuthMethod = c.Attributes["_snaplink_client_token_auth_method"]
	c.TLSClientAuthSubjectDN = c.Attributes["_snaplink_client_tls_subject_dn"]
	c.TLSClientAuthSANDNS = c.Attributes["_snaplink_client_tls_san_dns"]
	c.TLSClientAuthSANEmail = c.Attributes["_snaplink_client_tls_san_email"]
	c.TLSClientAuthSANURI = c.Attributes["_snaplink_client_tls_san_uri"]
	c.PreviousRegistrationAccessToken = c.Attributes["_snaplink_client_previous_rat"]
	c.LoginPageURI = c.Attributes["_snaplink_client_login_page_uri"]
	c.RegistrationAccessTokenOverlapUntil, _ = time.Parse(
		time.RFC3339Nano, c.Attributes["_snaplink_client_rat_overlap_until"],
	)
	for _, key := range []string{
		"_snaplink_client_grant_types", "_snaplink_client_token_auth_method",
		"_snaplink_client_tls_subject_dn", "_snaplink_client_tls_san_dns",
		"_snaplink_client_tls_san_email", "_snaplink_client_tls_san_uri",
		"_snaplink_client_previous_rat", "_snaplink_client_rat_overlap_until",
		"_snaplink_client_login_page_uri",
	} {
		delete(c.Attributes, key)
	}
}

// clientWritePrep hashes the secret + registration access token and
// builds the shared write-argument bundle. Add / Put / Update only
// differ in their SQL verb, so they all funnel through here.
func clientWritePrep(c *sso.Client) ([]any, error) {
	secret, err := hashClientSecretField(c.Secret, "secret")
	if err != nil {
		return nil, err
	}
	rat, err := hashClientSecretField(c.RegistrationAccessToken, "rat")
	if err != nil {
		return nil, err
	}
	previousRAT, err := hashClientSecretField(c.PreviousRegistrationAccessToken, "previous rat")
	if err != nil {
		return nil, err
	}
	prepared := *c
	prepared.PreviousRegistrationAccessToken = previousRAT
	return clientWriteArgs(&prepared, secret, rat)
}

// clientScanRow holds the raw column values scanned from a client row
// before they are normalized onto an sso.Client. Grouping them keeps
// scanClient's Scan call and the assignment step under budget.
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
	previousSecret                                         string
	secretOverlapUntilUnixNs                               int64
	secretExpiresAtUnixNs                                  int64
}

// scanInto reads every column of the SELECT projection into the raw
// row holder in the exact order of clientSelectAll.
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
		&r.previousSecret, &r.secretOverlapUntilUnixNs,
		&r.secretExpiresAtUnixNs,
	)
}

// scalars copies the non-JSON columns onto the embedded sso.Client,
// converting the integer-encoded booleans and nanosecond durations.
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
	c.PreviousSecret = r.previousSecret
	if r.secretOverlapUntilUnixNs != 0 {
		c.SecretOverlapUntil = time.Unix(0, r.secretOverlapUntilUnixNs).UTC()
	}
	if r.secretExpiresAtUnixNs != 0 {
		c.SecretExpiresAt = time.Unix(0, r.secretExpiresAtUnixNs).UTC()
	}
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, 0, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithOverlap(ctx context.Context, clientID string, overlap time.Duration) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, overlap, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithLifecycle(ctx context.Context, clientID string, overlap, lifetime time.Duration) (string, error) {
	plain, err := generateClientSecret()
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plain)
	if err != nil {
		return "", fmt.Errorf("sqlite: hash rotated secret: %w", err)
	}
	now := time.Now()
	until := time.Time{}
	if overlap > 0 {
		until = now.Add(overlap)
	}
	res, err := s.db.Load().ExecContext(ctx, `UPDATE clients SET
		previous_secret = CASE WHEN ? > 0 THEN secret ELSE '' END,
		secret_overlap_until = ?, secret = ?, secret_rotated_at = ?, secret_expires_at = ? WHERE id = ?`,
		int64(overlap), unixNanoOrZero(until), hashed, unixNanoOrZero(now),
		unixNanoOrZero(clientrotation.ExpiresAt(now, lifetime)), clientID)
	if err != nil {
		return "", fmt.Errorf("sqlite: rotate secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sso.ErrNoSuchClient
	}
	return plain, nil
}

// unmarshalClientJSON treats empty / "[]" / "{}" / "null" blobs as the
// zero value (so a round-tripped empty slice stays nil) and otherwise
// decodes into dst.
func unmarshalClientJSON(blob string, dst any, field string) error {
	if blob == "" || blob == "[]" || blob == "{}" || blob == "null" {
		return nil
	}
	if err := json.Unmarshal([]byte(blob), dst); err != nil {
		return fmt.Errorf("sqlite: unmarshal %s: %w", field, err)
	}
	return nil
}

// jsonFields hydrates the JSON-encoded slice / map columns onto the
// embedded sso.Client.
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
	hydrateClientAttributes(c)
	return nil
}
