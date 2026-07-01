package config

// The pluggable config Source backends (env, file, flag) live in the config/sources
// leaf package so this directory stays within the per-directory file-count budget —
// mirroring the existing config/etcd backend. These aliases preserve the historical
// config.{EnvSource,FileSource,FlagSource} / config.New*Source import surface for the
// server wiring (cmd/sso-server) and the internal Load() path; each backend satisfies
// the Source interface structurally, so no interface guard or import-back is needed.

import "github.com/snaplink/sso/config/sources"

type (
	EnvSource  = sources.EnvSource
	FileSource = sources.FileSource
	FlagSource = sources.FlagSource
)

const (
	DefaultEnvPrefix    = sources.DefaultEnvPrefix
	DefaultEnvSeparator = sources.DefaultEnvSeparator
)

var (
	NewEnvSource  = sources.NewEnvSource
	NewFileSource = sources.NewFileSource
	NewFlagSource = sources.NewFlagSource
)

// SecretResolver aliases are intentionally NOT re-exported here: the
// config.SecretResolver interface lives in package config (secrets.go),
// and the implementations (StaticSecretResolver, ExecSecretResolver) live
// in config/sources. Downstream code (cmd/sso-server) imports them directly
// from config/sources and registers them via Loader.WithSecretResolvers.
//
// Example wiring:
//
//	import (
//	    "github.com/snaplink/sso/config"
//	    "github.com/snaplink/sso/config/sources"
//	)
//
//	resolver := sources.NewExecSecretResolver("aws", myResolveFunc)
//	cfg, err := config.NewLoader(sources...).
//	    WithSecretResolvers(resolver).
//	    Load(ctx)
