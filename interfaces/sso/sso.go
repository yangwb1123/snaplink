package sso

// Server is the core SSO orchestrator. Its ~60 fields are grouped into
// anonymously-embedded sub-structs (sso_wiring.go, sso_federation_mesh.go,
// sso_cluster.go, sso_protocol.go, sso_cache.go, sso_selfservice.go) by concern,
// so no single file holds the whole god-struct. Embedding is anonymous, so every
// s.<field> access and every With* option keeps working unchanged via Go field
// promotion — the struct's public shape and behavior are identical.
type Server struct {
	wiringState
	federationMeshState
	clusterState
	protocolState
	cacheState
	selfServiceState
}
