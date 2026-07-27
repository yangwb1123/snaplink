package main

import "github.com/snaplink/sso/platform/buildinfo"

type runtimeEdition string

const (
	editionPrototype runtimeEdition = "prototype"
	editionMinimal   runtimeEdition = "minimal"

	defaultTenantID = "default"
)

func configuredRuntimeEdition() runtimeEdition {
	return editionForProfile(buildinfo.BuildProfile)
}

func editionForProfile(profile string) runtimeEdition {
	if profile == string(editionPrototype) {
		return editionPrototype
	}
	return editionMinimal
}

func (e runtimeEdition) oidcEnabled() bool {
	return e == editionMinimal
}

func (e runtimeEdition) tracingEnabled() bool {
	return e == editionMinimal
}

func defaultScopesForEdition(edition runtimeEdition) string {
	if edition == editionPrototype {
		return "profile,email"
	}
	return "openid,profile,email"
}
