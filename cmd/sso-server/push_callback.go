package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/spi"
)

// pushCallbackDeps bundles the dependencies the push approval
// callback handler needs to mark approvals APPROVED / DENIED.
// Constructed from the cmd MFA wiring when
// mfa.provider.push.callback.enabled is true.
//
// User-device callbacks are deployment-specific in real
// production setups (mobile app proxies through the operator's
// gateway, transport-specific signing, etc) — this handler is the
// reference impl. Operators wanting custom auth / payload shapes
// fork it; the SDK's PushApprovalStore.SetStatus is the stable
// seam.
type pushCallbackDeps struct {
	Store        defaultimpl.PushApprovalStore
	BearerToken  string       // empty disables bearer-token check
	AllowedCIDRs []*net.IPNet // empty disables IP gate
	Logger       spi.Logger
	// Notify wakes a Verify blocked on the just-resolved approval id
	// (the channel-notify fast path). nil when the provider didn't opt
	// into WithPushChannelNotify — the handler then relies on Verify's
	// poll fallback. Always safe to call: the SDK's Notify is itself a
	// no-op when channel-notify is off.
	Notify func(approvalID string)
}

// buildPushCallbackDeps assembles pushCallbackDeps from the YAML
// config — parses the CIDR strings into *net.IPNet (failing loud
// on bad input rather than silently dropping the entry). notify is
// the optional channel-notify wakeup (nil when the provider didn't
// opt in).
func buildPushCallbackDeps(cfg config.MFAPushCallbackConfig, store defaultimpl.PushApprovalStore, notify func(string), logger spi.Logger) (*pushCallbackDeps, error) {
	allowed := make([]*net.IPNet, 0, len(cfg.AllowedCIDRs))
	for _, c := range cfg.AllowedCIDRs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("mfa.provider.push.callback.allowed_cidrs[%q]: %w", c, err)
		}
		allowed = append(allowed, ipnet)
	}
	return &pushCallbackDeps{
		Store:        store,
		BearerToken:  cfg.BearerToken,
		AllowedCIDRs: allowed,
		Logger:       logger,
		Notify:       notify,
	}, nil
}

// mountPushCallbackRoute registers POST /push/approval/{id}/{decision}
// on the SSO router. decision MUST be approve | deny. The handler:
//
//  1. Validates the configured bearer token (when set) — constant-
//     time compare.
//  2. Validates the configured IP allowlist (when set) — parses
//     RemoteAddr OR the first X-Forwarded-For hop. Trust the XFF
//     hop only if the deploy has a trusted reverse proxy stripping
//     untrusted client-supplied headers; same threat model as the
//     rest of the cmd's XFF surfaces.
//  3. Calls Store.SetStatus(id, status).
//  4. Returns 204 on success, 400/401/403/404/409 for the
//     enumerated failure modes.
//
// Returns nil when deps is nil (operator disabled the callback).
func mountPushCallbackRoute(srv *sso.Server, deps *pushCallbackDeps) error {
	if deps == nil || deps.Store == nil {
		return nil
	}
	const route = "/push/approval/:id/:decision"
	return srv.Handle(http.MethodPost, route, pushCallbackHandler(deps))
}

func pushCallbackHandler(deps *pushCallbackDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Bearer + IP gates first — short-circuit before doing any work.
		if !checkPushCallbackBearer(w, r, deps) {
			return
		}
		if !checkPushCallbackIP(w, r, deps) {
			return
		}

		// Decision routing — path params via the SDK router's
		// :param syntax. Use path.Base on the URL.Path as a
		// fallback for routers that don't expose params via
		// context (current SDK does, but be defensive).
		id, decision := parsePushCallbackPath(r.URL.Path)
		if id == "" || decision == "" {
			writePushCallbackError(w, http.StatusBadRequest, "invalid_path", "expected /push/approval/{id}/{decision}")
			return
		}
		status, ok := pushDecisionStatus(decision)
		if !ok {
			writePushCallbackError(w, http.StatusBadRequest, "invalid_decision", "decision must be approve|deny")
			return
		}
		writePushCallbackResult(w, deps, r, id, decision, status)
	}
}

// checkPushCallbackBearer enforces the configured bearer token (constant-time
// compare). Returns false after writing the error when the check fails; true
// (pass) when no token is configured or it matches.
func checkPushCallbackBearer(w http.ResponseWriter, r *http.Request, deps *pushCallbackDeps) bool {
	if deps.BearerToken == "" {
		return true
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		writePushCallbackError(w, http.StatusUnauthorized, "missing_bearer", "Authorization: Bearer required")
		return false
	}
	if !constantTimeEq(strings.TrimPrefix(hdr, "Bearer "), deps.BearerToken) {
		writePushCallbackError(w, http.StatusUnauthorized, "invalid_bearer", "bearer token mismatch")
		return false
	}
	return true
}

// checkPushCallbackIP enforces the configured CIDR allowlist. Returns false
// after writing the error when the source IP is unparsable or not allowed; true
// (pass) when no allowlist is configured or the IP matches.
func checkPushCallbackIP(w http.ResponseWriter, r *http.Request, deps *pushCallbackDeps) bool {
	if len(deps.AllowedCIDRs) == 0 {
		return true
	}
	ip := callbackClientIP(r)
	if ip == nil {
		writePushCallbackError(w, http.StatusForbidden, "ip_not_allowed", "could not parse client IP")
		return false
	}
	for _, cidr := range deps.AllowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	writePushCallbackError(w, http.StatusForbidden, "ip_not_allowed", "source IP not in allowlist")
	return false
}

// pushDecisionStatus maps the path decision segment to a store status. ok=false
// for anything other than approve|deny.
func pushDecisionStatus(decision string) (defaultimpl.PushApprovalStatus, bool) {
	switch decision {
	case "approve":
		return defaultimpl.PushApprovalApproved, true
	case "deny":
		return defaultimpl.PushApprovalDenied, true
	default:
		return "", false
	}
}

// writePushCallbackResult performs Store.SetStatus and maps its outcome to the
// enumerated HTTP responses (204 / 404 / 409 / 500). On success it wakes any
// blocked Verify AFTER the store write so the woken Verify observes the resolved
// status (the ordering the lost-wakeup contract relies on).
func writePushCallbackResult(w http.ResponseWriter, deps *pushCallbackDeps, r *http.Request, id, decision string, status defaultimpl.PushApprovalStatus) {
	err := deps.Store.SetStatus(r.Context(), id, status)
	switch {
	case err == nil:
		if deps.Notify != nil {
			deps.Notify(id)
		}
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, defaultimpl.ErrPushApprovalNotFound):
		writePushCallbackError(w, http.StatusNotFound, "not_found", "approval id unknown or expired")
	case errors.Is(err, defaultimpl.ErrPushApprovalResolved):
		writePushCallbackError(w, http.StatusConflict, "already_resolved", "approval already approved/denied")
	default:
		if deps.Logger != nil {
			deps.Logger.Error("push callback SetStatus", "error", err, "approval_id", id, "decision", decision)
		}
		writePushCallbackError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

// parsePushCallbackPath extracts (id, decision) from
// /push/approval/{id}/{decision}. Returns ("", "") when the path
// shape doesn't match.
func parsePushCallbackPath(urlPath string) (string, string) {
	// Strip a trailing slash + the /push/approval prefix.
	urlPath = strings.TrimSuffix(urlPath, "/")
	const prefix = "/push/approval/"
	if !strings.HasPrefix(urlPath, prefix) {
		return "", ""
	}
	rest := urlPath[len(prefix):]
	if rest == "" {
		return "", ""
	}
	// Take the LAST path component as decision; everything before
	// it (after the prefix) is the id. Use path.Split.
	dir, file := path.Split(rest)
	if file == "" || dir == "" {
		return "", ""
	}
	return strings.TrimSuffix(dir, "/"), file
}

// callbackClientIP returns the request's client IP — XFF-aware,
// falls back to RemoteAddr. Same threat model as the rest of the
// cmd's XFF surfaces (trust the first hop iff the operator has a
// trusted reverse proxy stripping untrusted headers).
func callbackClientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx > 0 {
			xff = xff[:idx]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return normalizeIP(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return normalizeIP(ip)
	}
	return nil
}

// normalizeIP collapses an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
// to its 4-byte IPv4 form so it matches IPv4 CIDR allowlists: net's
// IPNet.Contains is address-family-sensitive, so a v4-mapped v6 from an
// ingress would otherwise fail to match a plain IPv4 CIDR. Genuine IPv6
// and plain IPv4 are returned unchanged.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// writePushCallbackError emits a small JSON envelope matching the
// rest of cmd's webauthn/MFA error shape so SPAs that already
// handle those don't need a special case for push.
func writePushCallbackError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{
		"error":             code,
		"error_description": desc,
	})
	_, _ = fmt.Fprintln(w, string(body))
}

// constantTimeEq compares two strings in constant time WRT their
// length (length mismatch is observable, but the per-byte compare
// is not). Used for bearer-token check to keep timing attacks off
// the table.
func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
