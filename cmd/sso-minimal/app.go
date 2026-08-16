package main

import (
	"net/http"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
)

// buildHandler assembles the minimal composition root: the shared
// composition with the minimal edition's surface hooks and the OIDC/tracing
// option hook.
func buildHandler(cfg composition.RuntimeConfig) (http.Handler, error) {
	return composition.BuildHandler(cfg, composition.BuildOptions{
		ExtraClients: []composition.ClientSeed{cfg.Second},
		SessionGate:  composition.NewOPSessionGate(),
		ExtraOptions: minimalExtraOptions,
		Surface: composition.SurfaceHooks{
			IsMetadata: minimalMetadataPath,
			Allowed:    minimalRouteAllowed,
			Narrow:     minimalNarrowMetadata,
		},
	})
}

// minimalExtraOptions wires the minimal-only surfaces: the ID-token issuer
// (OIDC) and the single correlation/tracing switch (Decision 7: WithTracing
// installs middleware.Correlation — the OTel span + X-Request-Id wrapper).
func minimalExtraOptions(issuer *defaultimpl.Ed25519JWTIssuer) []sso.Option {
	return []sso.Option{
		sso.WithIDTokenIssuer(issuer),
		sso.WithTracing("sso-minimal"),
	}
}
