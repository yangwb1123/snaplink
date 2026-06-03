package idp

import "errors"

// errInflateTooLarge is returned when a DEFLATEd SAMLRequest inflates past the
// bomb cap. Surfaced to the handler as the oracle-safe saml_request_invalid.
var errInflateTooLarge = errors.New("saml/idp: inflated request exceeds size limit")

// errRequestInvalid is the internal sentinel the SSO handler collapses every
// AuthnRequest decode/shape/allowlist failure onto. Its Error() string IS the
// wire code (sso.ErrSAMLRequestInvalid) so a stray surfacing still emits the
// stable code, but the handler maps to the wire code explicitly — the per-cause
// detail is DISCARDED (never surfaced) so a probe can't distinguish a bad ACS
// URL from a malformed request from an unknown SP (oracle-safety, AGENTS.md §2).
var errRequestInvalid = errors.New("saml_request_invalid")

// errNoSPMatch is returned by the SP-resolution scan when no registered client
// carries the AuthnRequest's Issuer as its saml_sp_entity_id. Collapsed to
// saml_request_invalid by the caller (no SP-enumeration oracle).
var errNoSPMatch = errors.New("saml/idp: no registered SP matches the AuthnRequest issuer")
