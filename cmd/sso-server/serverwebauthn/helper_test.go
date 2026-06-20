package serverwebauthn

import "github.com/snaplink/sso/shared/spi"

// quietLogger is a no-op logger for tests that exercise wiring without
// asserting on log output.
func quietLogger() spi.Logger { return spi.NopLogger{} }
