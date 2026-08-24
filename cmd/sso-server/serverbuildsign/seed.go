package serverbuildsign

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/caep"
)

// SeedClients loads the configured clients into the freshly-built store,
// validating each CAEP receiver endpoint at boot. Lives here beside the
// identity-store schema boot gates (this package owns identity-store
// construction-time checks) so the command root stays under its frozen
// go-file ceiling.
func SeedClients(cfg *config.Config, clientStore sso.ClientStore) error {
	for _, c := range cfg.Clients {
		seeded := newSeededClient(&c)
		if err := validateSeededCaepReceiver(&c); err != nil {
			return err
		}
		if err := clientStore.Add(context.Background(), seeded); err != nil {
			if !errors.Is(err, sso.ErrClientExists) {
				return fmt.Errorf("seed client %q: %w", c.ID, err)
			}
			if err := ReconcileLegacySeededPublicClient(context.Background(), clientStore, seeded); err != nil {
				return fmt.Errorf("reconcile public client %q: %w", c.ID, err)
			}
		}
	}
	return nil
}

// newSeededClient maps one YAML client block onto the sso.Client value the
// store persists. Pure field mapping — the only transformation is the JWKS
// shape conversion.
func newSeededClient(c *config.ClientConfig) *sso.Client {
	return &sso.Client{
		ID:                               c.ID,
		Secret:                           c.Secret,
		Name:                             c.Name,
		RedirectURIs:                     c.RedirectURIs,
		RedirectURIPatterns:              c.RedirectURIPatterns,
		AllowedScopes:                    c.AllowedScopes,
		AllowedAuthenticators:            c.AllowedAuthenticators,
		LoginPageURI:                     c.LoginPageURI,
		TokenStrategy:                    c.TokenStrategy,
		Active:                           c.Active,
		TenantID:                         c.TenantID,
		RequirePKCE:                      c.RequirePKCE,
		TokenEndpointAuthMethod:          c.TokenEndpointAuthMethod,
		AllowedResources:                 c.AllowedResources,
		PostLogoutRedirectURIs:           c.PostLogoutRedirectURIs,
		AllowedAuthorizationDetailsTypes: c.AllowedAuthorizationDetailsTypes,
		RefreshTokenTTL:                  c.RefreshTokenTTL,
		AccessTokenTTL:                   c.AccessTokenTTL,
		AllowedPKCEMethods:               c.AllowedPKCEMethods,
		RequireSignedRequestObject:       c.RequireSignedRequestObject,
		RequirePAR:                       c.RequirePAR,
		AllowPasswordlessOnly:            c.AllowPasswordlessOnly,
		AllowedRequestURIs:               c.AllowedRequestURIs,
		DeviceCodeTTL:                    c.DeviceCodeTTL,
		DeviceCodePollInterval:           c.DeviceCodePollInterval,
		UserinfoSignedResponseAlg:        c.UserinfoSignedResponseAlg,
		IDTokenSignedResponseAlg:         c.IDTokenSignedResponseAlg,
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		SubjectType:                      c.SubjectType,
		SectorIdentifierURI:              c.SectorIdentifierURI,
		FrontchannelLogoutURI:            c.FrontchannelLogoutURI,
		JWKS:                             serverbuildstore.ConvertClientJWKs(c.JWKS),
		Attributes:                       c.Attributes,
		SkipConsent:                      c.SkipConsent,
		ConsentRefreshInterval:           c.ConsentRefreshInterval,
	}
}

// ReconcileLegacySeededPublicClient upgrades an operator-provisioned SPA
// that predates YAML support for token_endpoint_auth_method. It deliberately
// only changes the empty legacy default to "none" and enables PKCE: an
// explicit stored method or a secret-bearing client is never silently converted
// to a public client. An existing PKCE-method policy also wins over YAML.
// Exported so the command-root regression suite can exercise it directly.
func ReconcileLegacySeededPublicClient(ctx context.Context, store sso.ClientStore, seeded *sso.Client) error {
	if seeded.TokenEndpointAuthMethod != "none" {
		return nil
	}
	existing, err := store.Get(ctx, seeded.ID)
	if err != nil {
		return err
	}
	if existing.TokenEndpointAuthMethod != "" {
		return nil
	}
	if existing.Secret != "" {
		return errors.New("refusing to convert a secret-bearing client to public authentication")
	}
	existing.TokenEndpointAuthMethod = "none"
	existing.RequirePKCE = true
	if len(existing.AllowedPKCEMethods) == 0 && len(seeded.AllowedPKCEMethods) > 0 {
		existing.AllowedPKCEMethods = append([]string(nil), seeded.AllowedPKCEMethods...)
	}
	return store.Update(ctx, existing)
}

// validateSeededCaepReceiver rejects a client whose caep_receiver_endpoint
// is not https at boot; plaintext would exfiltrate revocation SETs (same
// anti-exfil rule as the admin gRPC path).
func validateSeededCaepReceiver(c *config.ClientConfig) error {
	if ep := c.Attributes[caep.AttrReceiverEndpoint]; ep != "" {
		if err := caep.ValidateReceiverEndpoint(ep); err != nil {
			return fmt.Errorf("client %q caep_receiver_endpoint: %w", c.ID, err)
		}
	}
	return nil
}
