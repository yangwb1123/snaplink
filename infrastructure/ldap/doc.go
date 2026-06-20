// Package ldapauth provides an LDAP / Active Directory authenticator for
// snaplink/sso, letting operators authenticate users DIRECTLY against an
// enterprise LDAP/AD directory over TLS via the secure search-then-bind flow.
//
// This file is the package overview + the operator-fork wiring guide. The
// implementation, security rationale, and per-field documentation live in
// authenticator.go and config.go.
//
// # Why a separate Go module
//
// The LDAP dependency (github.com/go-ldap/ldap/v3 and its asn1-ber transitive
// dep) lives ONLY in this module's go.mod (github.com/snaplink/sso/ldap). The
// core sso module's go.mod stays byte-free of it — the firm
// zero-external-SDK-in-core invariant that also isolates kms/awskms
// (aws-sdk-go-v2), redis (go-redis), and saml (crewjam/saml). Operators who
// need directory auth opt in by importing this submodule from their own forked
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
// client's allowed_authenticators so clients may select it via
// provider=<name> at /auth/login.
//
// # Operator-fork wiring (copy-pasteable)
//
//	package main
//
//	import (
//		"log"
//
//		"github.com/snaplink/sso/interfaces/sso"
//		ldapauth "github.com/snaplink/sso/ldap"
//	)
//
//	func main() {
//		// 1. Build the authenticator from operator config. Construction
//		//    validates the TLS posture + filter; an invalid config fails boot
//		//    CLOSED (it performs no network I/O, so a down directory does not
//		//    block startup).
//		ldapAuth, err := ldapauth.New(ldapauth.Config{
//			Name:    "corp-ad",                                  // provider=corp-ad
//			URLs:    []string{"ldaps://dc1.corp.example.com:636", // failover order
//				"ldaps://dc2.corp.example.com:636"},
//			BindDN:       "cn=svc-sso,ou=svc,dc=corp,dc=example,dc=com", // read-only service acct
//			BindPassword: os.Getenv("LDAP_BIND_PASSWORD"),              // never hardcode
//			BaseDN:       "ou=people,dc=corp,dc=example,dc=com",
//			UserFilter:   "(&(objectClass=user)(sAMAccountName=%s))",   // AD; %s = escaped username
//			IDAttribute:  "sAMAccountName",
//			AttributeMapping: map[string]string{
//				"mail":        "email",
//				"displayName": "name",
//			},
//			GroupAttribute: "memberOf", // read group DNs straight off the user entry
//			// TLS is on via the ldaps:// URLs; for ldap:// set StartTLS: true.
//			// CACertPEM / ServerName / TLSConfig customize verification.
//		})
//		if err != nil {
//			log.Fatalf("ldap authenticator: %v", err)
//		}
//
//		// 2. Register it on the server (either form works):
//		srv := sso.NewServer(
//			// ... other options ...
//			sso.WithAuthenticator(ldapAuth),
//		)
//		// or, after construction:
//		//   srv.RegisterAuthenticator(ldapAuth)
//
//		// 3. Whitelist "corp-ad" under each client's allowed_authenticators
//		//    (config.yaml clients[].allowed_authenticators) so clients may pick
//		//    it. Then a client logs in with provider=corp-ad and a
//		//    username/password credential, which Authenticate verifies against
//		//    the directory.
//		_ = srv
//	}
//
// An operator may wire SEVERAL Authenticators (one Config each) for multiple
// directories, distinguished by Name.
//
// # Security summary (details in authenticator.go)
//
//   - LDAP injection: every user-supplied value in a search filter (username;
//     and the user DN/username in the optional group filter) is escaped with
//     ldap.EscapeFilter. The raw value is NEVER formatted into a filter.
//   - User enumeration: an unknown user (search miss) is indistinguishable from
//     a wrong password — both return the single generic ErrAuthFailed, and both
//     pay a comparable timing cost (a search miss still triggers a dummy bind),
//     mirroring the password authenticator's cost-matched dummy bcrypt hash.
//   - TLS by default: credentials travel only over ldaps:// or StartTLS;
//     plaintext / InsecureSkipVerify needs an explicit AllowInsecure dev
//     opt-out. Bind credentials and the user password are never logged and
//     never placed on the AuthResult.
//   - Bounded: DialTimeout + RequestTimeout cap a slow/dead directory so it
//     cannot hang a login.
package ldapauth
