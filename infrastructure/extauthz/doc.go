// Package extauthz implements the Envoy gRPC external authorization service
// (envoy.service.auth.v3.Authorization) for the snaplink/sso server. It is
// the gRPC-mode companion to the HTTP-mode mesh ext_authz endpoint that
// ships in the core module (handleMeshExtAuthz, mounted via
// sso.WithMeshExtAuthz): a service mesh whose ext_authz filter is
// configured in gRPC mode points its filter at this service instead of the
// HTTP path, and gets the SAME per-request token validation + upstream
// identity injection.
//
// # Why a separate nested module
//
// The Envoy API (github.com/envoyproxy/go-control-plane) is a large
// external dependency that MUST NOT enter the core sso module's go.mod (the
// firm zero-external-SDK invariant — see AGENTS.md §2/§4 and the
// kms/awskms + redis precedents). This module carries go-control-plane and
// google.golang.org/grpc in its OWN go.mod and resolves the core module via
// a local replace, so the root module graph stays SDK-free. There is
// deliberately no go.work (a workspace would merge the build lists and
// surface go-control-plane in the root `go list -m all`).
//
// # How it reuses the core decision (no duplicated auth logic)
//
// All authorization logic lives in the core, dep-free MeshAuthorize seam
// (mesh_authz.go, Phase A): bearer extraction + validation EXACTLY like
// /userinfo, the DPoP/mTLS sender-constraint, the read-side data-residency
// gate, and the X-Auth-* identity derivation. *sso.Server satisfies the
// MeshAuthorizer interface in this package. Check does ONLY wire<->seam
// mapping:
//
//   - CheckRequest.Attributes.Request.Http -> sso.MeshAuthorizeRequest
//     (Method; the URL rebuilt from Scheme+Host+Path[+Query] for the DPoP
//     htu binding; the lower-cased Headers map -> a canonical http.Header
//     carrying the bearer, the DPoP proof, and the X-Forwarded-* chain).
//   - CheckRequest.Attributes.Source.Certificate (Envoy's URL-encoded PEM
//     peer cert) -> the *x509.Certificate for the mTLS sender-constraint.
//   - On ALLOW: a CheckResponse with grpc-status OK and an OkHttpResponse
//     whose Headers carry the DERIVED X-Auth-{Subject,Client-Id,Scopes,
//     Expires,Roles} for Envoy to inject upstream, and whose
//     HeadersToRemove strip any client-supplied X-Auth-* inbound.
//   - On DENY: a CheckResponse with grpc-status PERMISSION_DENIED and a
//     DeniedHttpResponse of 401 + a WWW-Authenticate Bearer challenge and
//     NO body (oracle-safe — no per-cause detail). The sole exception is the
//     RFC 9449 §8/§9 DPoP nonce handshake: when the seam reports a fresh
//     nonce is required (a DPoP-bound token whose proof lacked a valid
//     nonce), the DENY additionally carries a DPoP-Nonce header + the
//     use_dpop_nonce challenge so a mesh-only DPoP client can reissue —
//     matching HTTP mode, and protocol-required rather than an oracle leak.
//
// Because the seam is the single source of truth, a stolen DPoP- or
// mTLS-bound token presented as a plain bearer is DENIED over gRPC just as
// it is over HTTP, and a residency-denied request is DENIED with no
// identity leak.
//
// # Trust model (edge-strip — AGENTS.md §2)
//
// Every injected X-Auth-* header is DERIVED from the validated token; an
// inbound X-Auth-* is NEVER trusted. The upstream trusts the injected
// headers ONLY because the sidecar ran this check, so this service:
//
//   - sets each X-Auth-* with OVERWRITE_IF_EXISTS_OR_ADD, and
//   - lists every X-Auth-* in OkHttpResponse.HeadersToRemove,
//
// so a client-smuggled X-Auth-* cannot survive to the upstream. This
// service is MESH-INTERNAL: only the trusted sidecar should reach it, and
// the mesh MUST strip client-supplied X-Auth-* at ingress (the same
// edge-strip model as X-Forwarded-* / mtls.backend: header).
//
// # Operator wiring (the fork constructs + registers it)
//
// A nested module cannot import the cmd `package main`, so the operator's
// own binary owns construction and registration. With a built *sso.Server:
//
//	import (
//		"net"
//
//		"github.com/yangwb1123/snaplink/interfaces/sso"
//		"github.com/yangwb1123/snaplink/extauthz"
//		authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
//		"google.golang.org/grpc"
//	)
//
//	func serveExtAuthz(srv *sso.Server, addr string) error {
//		// srv satisfies extauthz.MeshAuthorizer via its MeshAuthorize method.
//		authzServer := extauthz.NewAuthorizationServer(srv)
//
//		grpcServer := grpc.NewServer( /* mesh-internal mTLS creds, etc. */ )
//		authv3.RegisterAuthorizationServer(grpcServer, authzServer)
//
//		lis, err := net.Listen("tcp", addr)
//		if err != nil {
//			return err
//		}
//		return grpcServer.Serve(lis)
//	}
//
// Then configure Envoy/Istio's ext_authz HTTP filter in gRPC mode with a
// cluster pointing at addr (grpc_service.envoy_grpc.cluster_name), so each
// upstream request is authorized by this service before it is proxied.
//
// # Panic containment
//
// Check recovers a panic from the injected MeshAuthorizer itself and
// collapses it to the same oracle-safe invalid_token DENY as any other
// validation failure (fail-CLOSED, never ALLOW) — see safeMeshAuthorize.
// Pass extauthz.WithLogger(l) to NewAuthorizationServer to make a recovered
// panic observable; it is otherwise silent (a plain DENY on the wire, same
// as a bad token). This is defense in depth ONLY for the MeshAuthorize call
// itself: grpc-go's default Handler dispatch, unlike net/http's ServeMux,
// installs no panic recovery of its own, so operators should ALSO register a
// grpc.UnaryInterceptor with panic recovery (e.g.
// github.com/grpc-ecosystem/go-grpc-middleware/v2's recovery interceptor) on
// grpcServer above — that layer is what protects everything this package
// doesn't own (request/response marshaling, other services on the same
// grpc.Server).
package extauthz
