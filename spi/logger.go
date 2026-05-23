package spi

// Logger is the interface for SDK logging.
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Info(msg string, keysAndValues ...any)  {}
func (NopLogger) Error(msg string, keysAndValues ...any) {}
func (NopLogger) Debug(msg string, keysAndValues ...any) {}
