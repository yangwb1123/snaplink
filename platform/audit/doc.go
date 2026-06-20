// Package audit records security-relevant events from the SSO server (logins,
// logouts, token issuance, code sends, etc.) into a pluggable Sink and
// supports filtered querying.
//
// The package has zero dependency on the sso package — the sso package
// imports audit and creates Events from its internal state. Callers who want
// to write events from other layers (a custom Authenticator, a downstream
// gateway) can use the same Recorder/Sink without going through sso.
package audit
