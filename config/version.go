package config

import (
	"fmt"
	"log/slog"
)

// CurrentSchemaVersion is the expected version value for the current
// Config structure. Increment when making a backward-incompatible
// change to the YAML schema (renaming, removing, or changing the
// semantics of a field). Backward-compatible additions (new optional
// fields) do NOT require a version bump.
const CurrentSchemaVersion = 1

// ValidateVersion checks that cfg.Version matches CurrentSchemaVersion.
// When cfg.Version is 0 (unset) it prints a warning suggesting the user
// set it explicitly. Returns an error only when the version is set but
// does not match (mismatch → the config may be for a different server
// version).
func ValidateVersion(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	switch {
	case cfg.Version == 0:
		slog.Warn("config: version field is unset; add 'version: 1' to your config.yaml " +
			"to opt into schema validation and suppress this warning")
	case cfg.Version != CurrentSchemaVersion:
		return fmt.Errorf("config: schema version %d does not match expected version %d; "+
			"your config.yaml may be for a different server release", cfg.Version, CurrentSchemaVersion)
	}
	return nil
}
