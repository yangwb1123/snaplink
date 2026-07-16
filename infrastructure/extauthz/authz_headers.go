package extauthz

import (
	"net/http"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// headersToHTTP converts Envoy's lower-cased header map into a canonical
// http.Header via Set, so the stdlib-based readers in the seam find their
// values. Envoy guarantees the inbound keys are lower-cased (HTTP header
// keys are case-insensitive), and http.Header.Set canonicalizes each key
// through textproto.CanonicalMIMEHeaderKey, so "authorization" lands under
// "Authorization" where bearerToken reads it, and the X-Forwarded-* chain
// lands under its canonical keys.
//
// DPoP is correct WITHOUT special-casing: the canonical proof header is
// "DPoP", and CanonicalMIMEHeaderKey maps both "dpop" (on Set here) and
// "DPoP" (on the seam's Get) to the SAME interned key "Dpop", so the proof
// stored here is exactly what the seam's Get("DPoP") retrieves.
func headersToHTTP(in map[string]string) http.Header {
	out := make(http.Header, len(in))
	for k, v := range in {
		out.Set(k, v)
	}
	return out
}

// requestHeaders picks the header representation Envoy actually populated.
// By default Envoy fills httpAttrs.Headers (the map[string]string
// headersToHTTP reads); when the ext_authz filter is configured with
// encode_raw_headers: true, Envoy's own proto docs say Headers "will not be
// set" and HeaderMap is populated instead. Falling through to
// headersToHTTP(nil) in that mode would silently produce an EMPTY
// http.Header — no Authorization, no DPoP, no X-Forwarded-* — which denies
// every single request with the bare missing-credentials challenge: a
// total, silent outage (a clean 401, not a crash or an error log) for any
// operator who enables that documented, supported option. Prefer Headers
// when Envoy populated it; fall back to HeaderMap only when Headers is
// empty.
func requestHeaders(h *authv3.AttributeContext_HttpRequest) http.Header {
	if headers := h.GetHeaders(); len(headers) > 0 {
		return headersToHTTP(headers)
	}
	return headersFromHeaderMap(h.GetHeaderMap())
}

// headersFromHeaderMap converts Envoy's raw-header representation
// (HeaderMap, populated only under encode_raw_headers: true) into a
// canonical http.Header. The proto docs for HeaderMap explicitly warn that,
// unlike the default Headers map, "headers with the same key are not
// combined into a single comma separated header" here — so we comma-join
// same-key entries ourselves (Envoy's own merge convention for the default
// path, RFC 7230 §3.2.2), keeping this fallback's shape identical to the
// normal case rather than silently changing multi-value semantics (e.g.
// Header.Get on a multi-hop X-Forwarded-For) based on an unrelated Envoy
// config flag. Only Key + RawValue are populated in this mode (the proto
// docs say Value is not); Value is read as a defensive fallback.
func headersFromHeaderMap(hm *corev3.HeaderMap) http.Header {
	entries := hm.GetHeaders()
	grouped := make(map[string][]string, len(entries))
	order := make([]string, 0, len(entries))
	for _, hv := range entries {
		v := hv.GetValue()
		if v == "" {
			v = string(hv.GetRawValue())
		}
		key := hv.GetKey()
		if _, seen := grouped[key]; !seen {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], v)
	}
	out := make(http.Header, len(order))
	for _, key := range order {
		out.Set(key, strings.Join(grouped[key], ","))
	}
	return out
}
