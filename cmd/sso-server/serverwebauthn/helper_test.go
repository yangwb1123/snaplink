package serverwebauthn

import "github.com/yangwb1123/snaplink/shared/spi"

// quietLogger is a no-op logger for tests that exercise wiring without
// asserting on log output.
func quietLogger() spi.Logger { return spi.NopLogger{} }
