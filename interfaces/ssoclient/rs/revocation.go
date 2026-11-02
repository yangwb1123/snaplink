package rs

import "context"

// checkRevocation runs only after the mode's existing validation gates. The
// backend's verdict and failures deliberately share the inactive-token class;
// neither backend details nor cancellation may become a validation oracle.
func checkRevocation(ctx context.Context, claims *Claims, cfg Config) error {
	if cfg.RevocationCheck == nil {
		return nil
	}
	if claims.JTI == "" || ctx.Err() != nil {
		return ErrTokenInactive
	}
	revoked, err := cfg.RevocationCheck(ctx, RevocationToken{
		Issuer:   cfg.Issuer,
		TenantID: claims.TenantID,
		ClientID: claims.ClientID,
		JTI:      claims.JTI,
	})
	// A backend that ignores cancellation cannot admit a canceled request.
	if revoked || err != nil || ctx.Err() != nil {
		return ErrTokenInactive
	}
	return nil
}
