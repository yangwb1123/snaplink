package main

import (
	"net/http"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
)

// buildHandler assembles the prototype composition root: the shared
// composition with the prototype edition's surface hooks and no extra
// OIDC/tracing options.
func buildHandler(cfg composition.RuntimeConfig) (http.Handler, error) {
	return composition.BuildHandler(cfg, composition.BuildOptions{
		ExtraClients: []composition.ClientSeed{cfg.Second},
		SessionGate:  composition.NewOPSessionGate(),
		ExtraOptions: prototypeExtraOptions,
		Surface: composition.SurfaceHooks{
			IsMetadata: prototypeMetadataPath,
			Allowed:    prototypeRouteAllowed,
			Narrow:     prototypeNarrowMetadata,
		},
	})
}

// prototypeExtraOptions wires nothing extra: the prototype edition serves no
// OIDC surface (no ID-token issuer) and no request tracing.
func prototypeExtraOptions(*defaultimpl.Ed25519JWTIssuer) []sso.Option {
	return nil
}
