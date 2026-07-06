// Package wasmauth implements a [core.Authenticator] hosted on wazero, a
// pure-Go (no cgo, no external process) WebAssembly runtime — the
// authentication-verification counterpart to
// platform/lifecycle/wasmauthz's authorization-DECISION engine. The two
// are deliberately SEPARATE, independent packages (see
// docs/wasmauthz.md's "What this is NOT" section, which named this exact
// package as the missing half): authorizing an already-authenticated
// request and verifying a credential in the first place are different
// concerns with different ABIs, and wasmauthz's own package doc is
// explicit that its Request/Decision shape is authorization-specific.
//
// An operator supplies the bytes of a COMPILED .wasm module implementing
// a small, fixed ABI (mirroring wasmauthz's own alloc/call/dealloc
// interop pattern almost exactly — see New's doc for the exact exports
// required); the resulting Authenticator calls into it once per
// Authenticate call, verifying a custom credential shape a built-in
// authenticator doesn't support (e.g. a proprietary hardware-token
// protocol, a bespoke passwordless scheme, a legacy on-prem auth system
// being bridged in) without this SDK needing to ship code for every
// possible scheme.
//
// # Wire format
//
//	Request:  {"credential": {"...": "..."}}   // req.Credential, verbatim
//	Result:   {"authenticated": bool, "subject_id": string,
//	           "claims": {"...": "..."}, "reason": string}
//
// subject_id becomes AuthResult.UserID/ExternalID; claims becomes
// AuthResult.Attributes; reason is for audit/debugging only, mirroring
// wasmauthz's Decision.Reason — never parsed or acted on.
//
// # Fail-closed (the same doctrine as wasmauthz, applied to authentication)
//
// Any error from Authenticate — a guest trap, a malformed response, an
// out-of-bounds pointer, the per-call timeout firing, or a Result with
// authenticated=true but an empty subject_id — is a REJECTED login,
// never a successful one. A WASM policy module is untrusted,
// operator-supplied code; an authenticator that failed OPEN on a broken
// or malicious module would turn every ABI bug into an authentication
// bypass — the single worst failure mode this SDK's oracle-leak/
// anti-enumeration posture (AGENTS.md §3) exists to prevent. Every
// rejection collapses to the SAME generic error, exactly like this
// codebase's other authenticators (e.g. domains/authenticators's
// cost-matched dummy bcrypt hash for an unknown user) — the guest module
// itself decides subject existence, wrong-credential, and malformed-
// request all look identical from the outside.
//
// # What this does NOT attempt
//
// Unlike this SDK's own password-based authenticators, this package
// CANNOT guarantee constant-time evaluation inside the guest — the guest
// is arbitrary operator-supplied code, so any timing side-channel
// between "unknown subject" and "wrong credential" is the POLICY
// AUTHOR's responsibility to close (e.g. by always doing equivalent work
// on both paths), not something the host runtime can enforce or paper
// over from the outside.
package wasmauth
