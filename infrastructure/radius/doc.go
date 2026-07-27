// Package radiusauth provides a RADIUS authenticator for snaplink/sso, letting
// operators authenticate users against an external RADIUS server — the SSO
// acting as a RADIUS CLIENT. It is the integration for enterprises whose
// identity lives behind RADIUS / Microsoft NPS (Network Policy Server), a
// FreeRADIUS deployment, or any RFC 2865 server.
//
// This file is the package overview + the operator-fork wiring guide. The
// implementation, security rationale, and per-field documentation live in
// authenticator.go, exchange.go, and config.go.
//
// # Why a separate Go module
//
// The RADIUS dependency (layeh.com/radius, the standard pure-Go RADIUS library)
// lives ONLY in this module's go.mod (github.com/yangwb1123/snaplink/radius). The core
// sso module's go.mod stays byte-free of it — the firm zero-external-SDK-in-core
// invariant that also isolates kms/awskms (aws-sdk-go-v2), redis (go-redis),
// saml (crewjam/saml), ldap (go-ldap/ldap/v3), and kerberos (gokrb5). Operators
// who need RADIUS auth opt in by importing this submodule from their own forked
// cmd binary; nothing in the core module imports it.
//
// # How it reaches the server (no package-main import)
//
// A separate module's package CANNOT import cmd's package main, so this module
// references no cmd type. It exposes its OWN importable constructor, New, which
// returns an *Authenticator implementing the ROOT sso.Authenticator interface.
// The operator's fork registers it through the SAME seam the built-in
// authenticators use — either sso.WithAuthenticator at server construction, or
// srv.RegisterAuthenticator afterward — and whitelists its Name under each
// client's allowed_authenticators so clients may select it via provider=<name>
// at /auth/login.
//
// # Operator-fork wiring (copy-pasteable)
//
//	package main
//
//	import (
//		"log"
//		"os"
//
//		"github.com/yangwb1123/snaplink/interfaces/sso"
//		radiusauth "github.com/yangwb1123/snaplink/radius"
//		"layeh.com/radius"
//		"layeh.com/radius/rfc2865"
//	)
//
//	func main() {
//		// 1. Build the authenticator from operator config. Construction validates
//		//    the server list, the (REQUIRED) shared secret, and the RadSec posture;
//		//    an invalid config fails boot CLOSED. It performs no network I/O, so a
//		//    down RADIUS server does not block startup.
//		radAuth, err := radiusauth.New(radiusauth.Config{
//			Name:    "corp-nps",                                    // provider=corp-nps
//			Servers: []string{"nps1.corp.example.com:1812",         // failover order
//				"nps2.corp.example.com:1812"},
//			SharedSecret:  os.Getenv("RADIUS_SHARED_SECRET"),       // REQUIRED; never hardcode
//			NASIdentifier: "sso.corp.example.com",                  // identifies this SSO to NPS
//			ReplyAttributeMapping: map[radius.Type]string{          // map ONLY what you want on the token
//				rfc2865.FilterID_Type: "filter_id",
//				rfc2865.Class_Type:    "radius_class",
//			},
//			// RECOMMENDED for any untrusted segment: RadSec (RADIUS-over-TLS).
//			//   UseRadSec:       true,                  // dial TLS (port ~2083)
//			//   RadSecCACertPEM: caBundle,              // verify the server cert
//			//   RadSecServerName: "nps1.corp.example.com",
//		})
//		if err != nil {
//			log.Fatalf("radius authenticator: %v", err)
//		}
//
//		// 2. Register it on the server (either form works):
//		srv := sso.NewServer(
//			// ... other options ...
//			sso.WithAuthenticator(radAuth),
//		)
//		// or, after construction:
//		//   srv.RegisterAuthenticator(radAuth)
//
//		// 3. Whitelist "corp-nps" under each client's allowed_authenticators
//		//    (config.yaml clients[].allowed_authenticators) so clients may pick it.
//		//    Then a client logs in with provider=corp-nps and a username/password
//		//    credential, which Authenticate verifies against the RADIUS server.
//		_ = srv
//	}
//
// Note on ReplyAttributeMapping: its key type is map[radius.Type]string where
// radius.Type comes from layeh.com/radius — a well-known attribute Type
// (rfc2865.FilterID_Type, rfc2865.Class_Type) or a numeric vendor-specific
// Type. Only the listed attributes are read and projected onto the token; a
// server cannot smuggle an unmapped attribute. An operator may wire SEVERAL
// Authenticators (one Config each) for multiple RADIUS realms, distinguished by
// Name.
//
// # Security summary (details in authenticator.go + config.go)
//
//   - User enumeration: a RADIUS server returns Access-Reject for an unknown
//     user AND for a wrong password — never distinguishing them. The
//     authenticator preserves that: every Access-Reject collapses to the single
//     generic ErrAuthFailed, and a transport/server failure returns the distinct
//     ErrServerUnavailable (independent of whether the user exists). Neither
//     leaks an enumeration signal. An empty password is rejected before any
//     exchange (no anonymous bypass).
//   - Shared secret (the trust anchor): REQUIRED and non-empty. layeh encrypts
//     the PAP User-Password with it (RFC 2865 §5.2) AND validates the server's
//     Response Authenticator with it on every reply, so a forged Access-Accept
//     produced without the secret is rejected (surfaced as ErrServerUnavailable,
//     never a false-positive login). The secret is never logged and never placed
//     on the AuthResult.
//   - Transport security: plain RADIUS/UDP PAP is only as secure as the shared
//     secret and the network path — its confidentiality rests entirely on those.
//     RadSec (RADIUS-over-TLS, RFC 6614; UseRadSec) wraps the whole exchange in
//     TLS (mutual-auth capable via RadSecClientCertPEM/KeyPEM) and is STRONGLY
//     RECOMMENDED for any traffic crossing an untrusted segment; IPsec is an
//     alternative. The shared-secret Response-Authenticator validation still
//     applies on top of TLS (defense in depth).
//   - Bounded: a per-request Timeout + bounded Retries cap a slow/dead server so
//     it cannot hang a login.
//
// layeh.com/radius stays in this module's go.mod; the core sso module never
// imports it.
package radiusauth
