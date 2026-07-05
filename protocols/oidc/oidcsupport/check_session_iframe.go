package oidcsupport

import (
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// CheckSessionCookieName is the (deliberately narrow-scoped, non-HttpOnly)
// cookie the SDK stamps at /auth/login and clears at /end_session, carrying
// the SAME browser_state value BuildSessionState hashed into the login
// response's session_state. The checkSessionIframeHTML page below reads it
// via document.cookie to recompute its own view of the current session
// state entirely client-side — no network round trip, no server-side
// lookup, matching OpenID Connect Session Management 1.0 §2's design.
const CheckSessionCookieName = "op_browser_state"

// checkSessionIframeHTML is the OpenID Connect Session Management 1.0 §2
// check_session_iframe: a static page an RP embeds in a hidden iframe. Per
// the spec, it:
//
//  1. Listens for a postMessage from the RP's own page of the form
//     "client_id session_state".
//  2. Extracts the salt (the suffix after the LAST "." — session_state
//     itself is base64url, which never contains "."), and recomputes
//     Base64url(SHA-256(client_id + " " + e.origin + " " + browser_state + " " + salt))
//     using its OWN browser_state (read from CheckSessionCookieName) and
//     e.origin — the RP page's origin as stamped by the browser itself on
//     the MessageEvent, which a malicious postMessage payload cannot spoof.
//  3. postMessage()s "unchanged" / "changed" / "error" back to e.source at
//     e.origin ONLY — never broadcast, so no third party observes the
//     result.
//
// Byte-identical content on every request (no per-request templating,
// deliberately) — this is the whole point of a static, cacheable OP iframe
// RPs load once and query repeatedly rather than re-fetching.
const checkSessionIframeHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>OP Session Check</title></head>
<body><script>
(function(){
"use strict";
var COOKIE_NAME = "` + CheckSessionCookieName + `";

function readCookie(name){
var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
return m ? decodeURIComponent(m[1]) : "";
}

// Base64url per RFC 4648 §5, matching the server's base64.RawURLEncoding —
// built straight off the raw digest bytes (not a hex round trip).
function toBase64url(buf){
var b = new Uint8Array(buf), bin = "";
for(var i = 0; i < b.length; i++){ bin += String.fromCharCode(b[i]); }
return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function respond(source, origin, status){
if(source) source.postMessage(status, origin);
}

window.addEventListener("message", function(e){
var data = String(e.data || "");
var sp = data.indexOf(" ");
if(sp < 0){ respond(e.source, e.origin, "error"); return; }
var clientID = data.slice(0, sp);
var sessionState = data.slice(sp + 1);
var dot = sessionState.lastIndexOf(".");
if(dot < 0){ respond(e.source, e.origin, "error"); return; }
var salt = sessionState.slice(dot + 1);
if(!window.crypto || !window.crypto.subtle){ respond(e.source, e.origin, "error"); return; }
var browserState = readCookie(COOKIE_NAME);
var msg = clientID + " " + e.origin + " " + browserState + " " + salt;
window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg)).then(function(digest){
var computed = toBase64url(digest) + "." + salt;
respond(e.source, e.origin, computed === sessionState ? "unchanged" : "changed");
}).catch(function(){ respond(e.source, e.origin, "error"); });
}, false);
})();
</script></body></html>
`

// RenderCheckSessionIframe writes the check_session_iframe HTML page.
// Deliberately NOT sent with X-Frame-Options: DENY (unlike every other
// server-rendered page in this SDK) — the entire point of this endpoint is
// to BE embedded, by any RP, in a hidden iframe. The page carries no secret
// and performs no server-observable action on its own; the postMessage
// protocol it implements is OpenID Connect Session Management 1.0 §2's
// design for letting an RP detect OP login-state changes without a
// same-origin cookie of its own.
func RenderCheckSessionIframe(ctx core.HandlerContext) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// Static, deployment-constant content (no per-request or per-user data)
	// — safe, and expected, to cache: RPs load this iframe once and poll it
	// in-process via postMessage rather than re-fetching.
	h.Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(checkSessionIframeHTML))
}
