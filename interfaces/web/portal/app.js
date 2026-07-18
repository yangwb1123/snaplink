"use strict";
var $ = function (id) { return document.getElementById(id); };
var token = "";
// mySub holds the authenticated subject from /me. The account-deletion card
// requires the user to echo it back as a confirmation guard.
var mySub = "";

// API paths are parent-relative: the SPA is served at /portal/, endpoints at the root.
function api(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ "Authorization": "Bearer " + token }, opts.headers || {});
  return fetch(".." + path, opts);
}
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
  return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
}); }

function showMsg(el, text, ok) { el.textContent = text; el.className = "msg " + (ok ? "ok" : "err"); }

// deviceHint reduces a raw User-Agent to a friendly "Browser on OS" label for
// the session list; falls back to a truncated UA when it can't classify.
function deviceHint(ua) {
  ua = String(ua || "");
  var browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome"
    : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "";
  var os = /Windows/.test(ua) ? "Windows" : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Android/.test(ua) ? "Android" : /iPhone|iPad|iOS/.test(ua) ? "iOS"
    : /Linux/.test(ua) ? "Linux" : "";
  if (browser && os) return browser + " on " + os;
  return browser || os || (ua.length > 40 ? ua.slice(0, 40) + "…" : ua);
}

// --- Auth ---
$("login-btn").onclick = function () {
  var t = $("token-input").value.trim();
  if (!t) { showMsg($("login-msg"), "Enter a token.", false); return; }
  token = t;
  // Probe /me to validate the token before showing the app.
  api("/me").then(function (r) {
    if (!r.ok) throw new Error("invalid token");
    return r.json();
  }).then(function (me) {
    sessionStorage.setItem("sso_portal_token", token);
    $("login-screen").style.display = "none";
    $("app").style.display = "block";
    render(me);
    loadAll();
  }).catch(function () { showMsg($("login-msg"), "That token was not accepted.", false); });
};
$("signout-btn").onclick = function () {
  sessionStorage.removeItem("sso_portal_token");
  token = "";
  $("app").style.display = "none";
  $("login-screen").style.display = "flex";
  $("token-input").value = "";
};

// --- Render overview ---
function render(me) {
  mySub = me.sub || "";
  $("whoami").textContent = me.sub || "";
  $("erase-confirm").placeholder = mySub;
  var u = me.user || {};
  var rows = [
    ["Subject", me.sub],
    ["Name", u.name],
    ["Email", u.email],
    ["Active sessions", me.active_sessions],
    ["Connected apps", me.granted_apps],
  ];
  $("profile").innerHTML = rows.filter(function (r) { return r[1] != null && r[1] !== ""; })
    .map(function (r) { return '<div class="kv"><span class="k">' + esc(r[0]) + '</span><span>' + esc(r[1]) + "</span></div>"; })
    .join("") || '<div class="empty">No profile data.</div>';
  $("name-input").value = u.name || "";
  renderAttrs(u.attributes);
}

// renderAttrs builds editable key/value rows for the custom attributes map.
// The server enforces an allowlist, so a save may silently drop or reject some
// keys; the section only appears when the user has at least one attribute.
function renderAttrs(attrs) {
  var section = $("attrs-section");
  var keys = attrs ? Object.keys(attrs) : [];
  if (!keys.length) { section.style.display = "none"; $("attrs").innerHTML = ""; return; }
  $("attrs").innerHTML = keys.map(function (k) {
    return '<div class="field"><label>' + esc(k) + '</label>' +
      '<input type="text" data-attr="' + esc(k) + '" value="' + esc(attrs[k]) + '" autocomplete="off"></div>';
  }).join("");
  section.style.display = "block";
}

// Self-service display-name edit (PATCH /me). An empty input leaves the name
// unchanged server-side, so this never clears a name by accident.
(function () {
  var btn = $("save-name-btn");
  if (!btn) return;
  btn.onclick = function () {
    api("/me", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("name-input").value }),
    }).then(function () { loadAll(); });
  };
})();

// Save custom attributes (PATCH /me {attributes}). The server applies only the
// keys on its self-editable allowlist and may reject others, so we never assume
// success: a non-200 surfaces as an error rather than a silent "saved".
(function () {
  var btn = $("save-attrs-btn");
  if (!btn) return;
  btn.onclick = function () {
    var attrs = {};
    Array.prototype.forEach.call($("attrs").querySelectorAll("input[data-attr]"), function (inp) {
      attrs[inp.getAttribute("data-attr")] = inp.value;
    });
    api("/me", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attributes: attrs }),
    }).then(function (r) {
      if (r.status === 404) { showMsg($("attrs-msg"), "Profile editing is not available.", false); return; }
      if (!r.ok) { showMsg($("attrs-msg"), "Some attributes could not be saved.", false); return; }
      showMsg($("attrs-msg"), "Attributes saved.", true);
      reloadProfile();
    }).catch(function () { showMsg($("attrs-msg"), "Request failed.", false); });
  };
})();

// reloadProfile re-fetches /me so the profile + attributes reflect the latest
// server state (e.g. after the allowlist dropped a rejected key).
function reloadProfile() {
  api("/me").then(function (r) { return r.ok ? r.json() : null; }).then(function (me) {
    if (me) render(me);
  });
}

function loadAll() { loadSessions(); loadDevices(); loadConsents(); loadMFA(); loadAuthz(); loadOrganizations(); }

// --- B2B org membership (list + leave + accept invite). The card hides itself
// when /me/organizations is not mounted (TenantUserStore not wired). ---
function loadOrganizations() {
  api("/me/organizations").then(function (r) {
    if (r.status !== 200) { $("orgs-card").style.display = "none"; return null; }
    return r.json();
  }).then(function (d) {
    if (d == null) return;
    $("orgs-card").style.display = "block";
    var list = (d && d.organizations) || [];
    if (!list.length) {
      $("orgs").innerHTML = '<div class="empty">You are not a member of any organization.</div>';
      return;
    }
    $("orgs").innerHTML = list.map(function (o) {
      return '<div class="row"><div><div class="name">' + esc(o.tenant_id) + '</div>' +
        '<div class="meta">' + esc(o.role || "member") + "</div></div>" +
        '<button class="btn btn-danger btn-sm" data-org="' + esc(o.tenant_id) + '">Leave</button></div>';
    }).join("");
    Array.prototype.forEach.call($("orgs").querySelectorAll("button[data-org]"), function (b) {
      b.onclick = function () {
        api("/me/organizations/" + encodeURIComponent(b.getAttribute("data-org")), { method: "DELETE" })
          .then(function () { loadOrganizations(); });
      };
    });
  }).catch(function () { $("orgs-card").style.display = "none"; });
}

$("invite-accept-btn").onclick = function () {
  var tok = $("invite-token").value.trim();
  if (!tok) { showMsg($("orgs-msg"), "Paste an invitation token.", false); return; }
  api("/me/invitations/accept", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: tok }),
  }).then(function (r) {
    if (r.status === 404) { showMsg($("orgs-msg"), "Invitations are not enabled.", false); return; }
    if (r.status !== 200) { showMsg($("orgs-msg"), "That invitation was not accepted.", false); return; }
    $("invite-token").value = "";
    showMsg($("orgs-msg"), "You have joined the organization.", true);
    loadOrganizations();
  }).catch(function () { showMsg($("orgs-msg"), "Request failed.", false); });
};

// --- Sessions ---
function loadSessions() {
  api("/sessions/me").then(function (r) { return r.json(); }).then(function (d) {
    var list = (d && d.sessions) || [];
    if (!list.length) { $("sessions").innerHTML = '<div class="empty">No active sessions.</div>'; return; }
    $("sessions").innerHTML = list.map(function (s) {
      var meta = s.created_at ? ("since " + esc(String(s.created_at).slice(0, 10))) : "";
      if (s.expires_at) meta += (meta ? " · " : "") + "expires " + esc(String(s.expires_at).slice(0, 10));
      // Device/location context (best-effort; present only when the server
      // captured it). Helps the user recognize an unfamiliar session.
      var dev = [];
      if (s.ip) dev.push(esc(s.ip));
      if (s.user_agent) dev.push(esc(deviceHint(s.user_agent)));
      var devLine = dev.length ? '<div class="meta">' + dev.join(" · ") + "</div>" : "";
      return '<div class="row"><div><div class="name">' + esc(s.id) + '</div>' +
        '<div class="meta">' + meta + "</div>" + devLine + "</div>" +
        '<button class="btn btn-danger btn-sm" data-sid="' + esc(s.id) + '">Revoke</button></div>';
    }).join("");
    Array.prototype.forEach.call($("sessions").querySelectorAll("button[data-sid]"), function (b) {
      b.onclick = function () {
        api("/sessions/me/" + encodeURIComponent(b.getAttribute("data-sid")), { method: "DELETE" })
          .then(function () { loadSessions(); });
      };
    });
  });
}

// "Sign out everywhere": revoke every other session (the API preserves the
// current one by default), then refresh the list.
(function () {
  var btn = $("signout-others-btn");
  if (!btn) return;
  btn.onclick = function () {
    api("/sessions/me", { method: "DELETE" }).then(function () { loadSessions(); });
  };
})();

// --- Trusted devices ---
function loadDevices() {
  api("/me/devices").then(function (r) {
    if (r.status !== 200) { $("devices-card").style.display = "none"; return null; }
    return r.json();
  }).then(function (d) {
    if (d == null) return;
    $("devices-card").style.display = "block";
    var list = (d && d.devices) || [];
    if (!list.length) { $("devices").innerHTML = '<div class="empty">No trusted devices.</div>'; return; }
    $("devices").innerHTML = list.map(function (dev) {
      var meta = dev.created_at ? "trusted since " + esc(String(dev.created_at).slice(0, 10)) : "";
      if (dev.expires_at) meta += (meta ? " \u00b7 " : "") + "expires " + esc(String(dev.expires_at).slice(0, 10));
      var devName = dev.name || deviceHint(dev.user_agent || "");
      var devLine = dev.ip ? '<div class="meta">' + esc(dev.ip) + "</div>" : "";
      return '<div class="row"><div><div class="name">' + esc(devName) + '</div>' +
        '<div class="meta">' + meta + "</div>" + devLine + "</div>" +
        '<button class="btn btn-danger btn-sm" data-did="' + esc(dev.id) + '">Revoke</button></div>';
    }).join("");
    Array.prototype.forEach.call($("devices").querySelectorAll("button[data-did]"), function (b) {
      b.onclick = function () {
        api("/me/devices/" + encodeURIComponent(b.getAttribute("data-did")), { method: "DELETE" })
          .then(function () { loadDevices(); });
      };
    });
  }).catch(function () { $("devices-card").style.display = "none"; });
}

// --- Consents ---
function loadConsents() {
  api("/consents/me").then(function (r) { return r.json(); }).then(function (d) {
    var list = (d && d.consents) || [];
    if (!list.length) { $("consents").innerHTML = '<div class="empty">No connected applications.</div>'; return; }
    $("consents").innerHTML = list.map(function (c) {
      return '<div class="row"><div><div class="name">' + esc(c.client_id) + '</div>' +
        '<div class="meta">' + esc((c.scopes || []).join(" ")) + "</div></div>" +
        '<button class="btn btn-danger btn-sm" data-cid="' + esc(c.client_id) + '">Revoke</button></div>';
    }).join("");
    Array.prototype.forEach.call($("consents").querySelectorAll("button[data-cid]"), function (b) {
      b.onclick = function () {
        api("/consents/me/" + encodeURIComponent(b.getAttribute("data-cid")), { method: "DELETE" })
          .then(function () { loadConsents(); });
      };
    });
  });
}

// --- MFA factors ---
function loadMFA() {
  api("/me/mfa").then(function (r) {
    if (r.status === 404) { $("mfa").innerHTML = '<div class="empty">Factor management is not enabled.</div>'; return null; }
    return r.json();
  }).then(function (d) {
    if (!d) return;
    var list = (d && d.factors) || [];
    if (!list.length) { $("mfa").innerHTML = '<div class="empty">No second factors registered.</div>'; return; }
    $("mfa").innerHTML = list.map(function (f) {
      var meta = esc(f.method);
      if (f.added_at) meta += " · added " + esc(String(f.added_at).slice(0, 10));
      return '<div class="row"><div><div class="name">' + esc(f.label || f.method) + '</div>' +
        '<div class="meta">' + meta + "</div></div>" +
        '<button class="btn btn-danger btn-sm" data-fid="' + esc(f.id) + '">Remove</button></div>';
    }).join("");
    Array.prototype.forEach.call($("mfa").querySelectorAll("button[data-fid]"), function (b) {
      b.onclick = function () {
        api("/me/mfa/" + encodeURIComponent(b.getAttribute("data-fid")), { method: "DELETE" })
          .then(function () { loadMFA(); });
      };
    });
  });
}

// --- TOTP enrollment (begin -> confirm). Stateless: the secret from begin is
// held client-side and posted back to confirm with a code proving possession.
(function () {
  var addBtn = $("totp-add-btn"), panel = $("totp-enroll");
  if (!addBtn || !panel) return;
  var pendingSecret = "";
  addBtn.onclick = function () {
    api("/me/mfa/totp/begin", { method: "POST" }).then(function (r) {
      if (r.status !== 200) {
        showMsg($("totp-msg"), "TOTP enrollment is not enabled.", false);
        panel.style.display = "block";
        return null;
      }
      return r.json();
    }).then(function (d) {
      if (!d) return;
      pendingSecret = d.secret || "";
      $("totp-secret").textContent = pendingSecret;
      $("totp-uri").href = d.otpauth_uri || "#";
      $("totp-msg").textContent = "";
      panel.style.display = "block";
    });
  };
  $("totp-confirm-btn").onclick = function () {
    var code = $("totp-code").value;
    if (!pendingSecret || !code) { showMsg($("totp-msg"), "Enter the 6-digit code.", false); return; }
    api("/me/mfa/totp/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: pendingSecret, code: code, label: $("totp-label").value }),
    }).then(function (r) {
      if (r.status === 201) {
        panel.style.display = "none";
        pendingSecret = "";
        $("totp-code").value = ""; $("totp-label").value = "";
        loadMFA();
        return;
      }
      showMsg($("totp-msg"), "That code was not accepted. Check your device clock and try again.", false);
    });
  };
})();

// --- Passkey (WebAuthn) registration. Standard create() ceremony: begin
// returns CredentialCreation options (base64url challenge/user.id), the
// browser mints a credential, finish commits it. Bearer-bound server-side, so
// it only ever adds a passkey to the signed-in account.
function b64urlToBuf(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  var pad = s.length % 4; if (pad) s += "====".slice(pad);
  var bin = atob(s), buf = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  var bytes = new Uint8Array(buf), str = "";
  for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
(function () {
  var btn = $("passkey-add-btn");
  if (!btn) return;
  btn.onclick = function () {
    if (!window.PublicKeyCredential) { showMsg($("passkey-msg"), "This browser does not support passkeys.", false); return; }
    api("/me/mfa/webauthn/begin", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })
      .then(function (r) {
        if (r.status !== 200) { showMsg($("passkey-msg"), "Passkey registration is not available.", false); return null; }
        return r.json();
      })
      .then(function (d) {
        if (!d) return null;
        var sid = d.session_id, pk = (d.options && d.options.publicKey) || {};
        pk.challenge = b64urlToBuf(pk.challenge);
        pk.user.id = b64urlToBuf(pk.user.id);
        (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
        return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
          var payload = {
            id: cred.id,
            rawId: bufToB64url(cred.rawId),
            type: cred.type,
            response: {
              attestationObject: bufToB64url(cred.response.attestationObject),
              clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            },
            clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
          };
          return api("/me/mfa/webauthn/finish?session_id=" + encodeURIComponent(sid), {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
          });
        });
      })
      .then(function (r) {
        if (!r) return;
        if (r.status === 201) { showMsg($("passkey-msg"), "Passkey added.", true); loadMFA(); return; }
        showMsg($("passkey-msg"), "Passkey registration was not completed.", false);
      })
      .catch(function () { showMsg($("passkey-msg"), "Passkey registration was cancelled or failed.", false); });
  };
})();

// --- Password change ---
$("pw-btn").onclick = function () {
  var cur = $("cur-pw").value, next = $("new-pw").value;
  if (!cur || !next) { showMsg($("pw-msg"), "Fill in both fields.", false); return; }
  api("/me/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: cur, new_password: next }),
  }).then(function (r) {
    if (r.status === 204) {
      showMsg($("pw-msg"), "Password updated.", true);
      $("cur-pw").value = ""; $("new-pw").value = "";
    } else if (r.status === 404) {
      showMsg($("pw-msg"), "Password change is not enabled.", false);
    } else {
      showMsg($("pw-msg"), "Current password was not accepted.", false);
    }
  }).catch(function () { showMsg($("pw-msg"), "Request failed.", false); });
};

// --- Authorization disclosure (read-only). roles/permissions/menus are always
// mounted but return 501 when no permission provider is wired; on 501 (or any
// non-200) the section stays empty so the card only shows real data. The card
// is hidden entirely when nothing resolved. ---
function loadAuthz() {
  var card = $("authz-card");
  var pending = 3, any = false;
  function done() {
    pending--;
    if (pending === 0) { card.style.display = any ? "block" : "none"; }
  }
  function fetchSection(path, build, target) {
    api(path).then(function (r) {
      if (r.status !== 200) return null;
      return r.json();
    }).then(function (d) {
      var html = d ? build(d) : "";
      if (html) { any = true; $(target).innerHTML = html; }
      else { $(target).innerHTML = ""; }
      done();
    }).catch(function () { $(target).innerHTML = ""; done(); });
  }
  fetchSection("/roles/me", function (d) {
    var list = (d && d.roles) || [];
    if (!list.length) return "";
    return "<h2>Roles</h2>" + list.map(function (role) {
      return '<div class="row"><div><div class="name">' + esc(role.name || role.code) + '</div>' +
        '<div class="meta">' + esc(role.code) + "</div></div></div>";
    }).join("");
  }, "authz-roles");
  fetchSection("/permissions/me", function (d) {
    var list = (d && d.permissions) || [];
    if (!list.length) return "";
    return "<h2>Permissions</h2>" + list.map(function (p) {
      var meta = p.resource ? esc(p.resource) : "";
      return '<div class="row"><div><div class="name">' + esc(p.code) + '</div>' +
        '<div class="meta">' + meta + "</div></div></div>";
    }).join("");
  }, "authz-perms");
  fetchSection("/menus/me", function (d) {
    var list = (d && d.menus) || [];
    if (!list.length) return "";
    return "<h2>Menu access</h2>" + list.map(function (m) {
      var meta = m.path ? esc(m.path) : "";
      return '<div class="row"><div><div class="name">' + esc(m.name || m.id) + '</div>' +
        '<div class="meta">' + meta + "</div></div></div>";
    }).join("");
  }, "authz-menus");
}

// --- Email change (begin -> verify). Mirrors the TOTP two-leg pattern: leg 1
// posts the new address and, on success, reveals leg 2 for the code delivered
// to it. A 404 from either leg means the feature is not wired (POST is
// side-effecting, so we cannot probe it on load — detect it on submit). ---
$("email-change-btn").onclick = function () {
  var newEmail = $("new-email").value.trim();
  if (!newEmail) { showMsg($("email-msg"), "Enter a new email address.", false); return; }
  api("/me/email/change", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ new_email: newEmail }),
  }).then(function (r) {
    if (r.status === 404) { showMsg($("email-msg"), "Email change is not enabled.", false); return; }
    if (r.status === 200) {
      showMsg($("email-msg"), "We sent a verification code to " + newEmail + ".", true);
      $("email-verify").style.display = "block";
      return;
    }
    showMsg($("email-msg"), "That email could not be used.", false);
  }).catch(function () { showMsg($("email-msg"), "Request failed.", false); });
};
$("email-verify-btn").onclick = function () {
  var t = $("email-token").value.trim();
  if (!t) { showMsg($("email-msg"), "Enter the verification code.", false); return; }
  api("/me/email/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: t }),
  }).then(function (r) {
    if (r.status === 404) { showMsg($("email-msg"), "Email change is not enabled.", false); return; }
    if (r.status === 200) {
      showMsg($("email-msg"), "Your email has been updated.", true);
      $("email-verify").style.display = "none";
      $("new-email").value = ""; $("email-token").value = "";
      loadAll();
      reloadProfile();
      return;
    }
    showMsg($("email-msg"), "That code was not accepted.", false);
  }).catch(function () { showMsg($("email-msg"), "Request failed.", false); });
};

// --- GDPR data export. GET /me/data-export returns the bundle as JSON; on 200
// we turn it into a browser download. 404 means the feature is not wired. ---
$("export-btn").onclick = function () {
  showMsg($("export-msg"), "Preparing your export...", true);
  api("/me/data-export").then(function (r) {
    if (r.status === 404) { showMsg($("export-msg"), "Data export is not enabled.", false); return null; }
    if (r.status !== 200) { showMsg($("export-msg"), "Export failed.", false); return null; }
    return r.text();
  }).then(function (body) {
    if (body == null) return;
    var blob = new Blob([body], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "my-data.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showMsg($("export-msg"), "Your data has been downloaded.", true);
  }).catch(function () { showMsg($("export-msg"), "Request failed.", false); });
};

// --- Account deletion (GDPR Art. 17). A dry-run preview shows what would be
// removed; the real delete requires the user to echo their own subject in
// `confirm` (CSRF / accidental-deletion guard). 404 means the feature is not
// wired (POST is side-effecting, so this is detected on submit). ---
function eraseSummary(d) {
  var parts = [];
  parts.push("Refresh tokens: " + (d.refresh_tokens_deleted || 0));
  parts.push("Sessions: " + (d.sessions_destroyed || 0));
  parts.push("User record: " + (d.user_deleted ? "yes" : "no"));
  if (d.skipped && d.skipped.length) parts.push("Skipped: " + d.skipped.join(", "));
  return parts.join(" · ");
}
$("erase-preview-btn").onclick = function () {
  api("/me/account/erase", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dry_run: true }),
  }).then(function (r) {
    if (r.status === 404) { showMsg($("erase-msg"), "Account deletion is not enabled.", false); return null; }
    if (r.status !== 200) { showMsg($("erase-msg"), "Could not preview deletion.", false); return null; }
    return r.json();
  }).then(function (d) {
    if (!d) return;
    $("erase-preview").innerHTML = '<div class="meta" style="padding:10px 0">Would remove — ' + esc(eraseSummary(d)) + "</div>";
    $("erase-msg").className = "msg";
    $("erase-msg").textContent = "";
  }).catch(function () { showMsg($("erase-msg"), "Request failed.", false); });
};
$("erase-btn").onclick = function () {
  var confirm = $("erase-confirm").value.trim();
  if (confirm !== mySub) { showMsg($("erase-msg"), "Type your subject exactly to confirm.", false); return; }
  api("/me/account/erase", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: confirm, confirm: confirm, dry_run: false }),
  }).then(function (r) {
    if (r.status === 404) { showMsg($("erase-msg"), "Account deletion is not enabled.", false); return null; }
    if (r.status !== 200) { showMsg($("erase-msg"), "Deletion was not confirmed.", false); return null; }
    return r.json();
  }).then(function (d) {
    if (!d) return;
    // Account is gone — drop the token and return to the login screen.
    sessionStorage.removeItem("sso_portal_token");
    token = ""; mySub = "";
    $("app").style.display = "none";
    $("login-screen").style.display = "flex";
    $("token-input").value = "";
    showMsg($("login-msg"), "Your account has been deleted.", true);
  }).catch(function () { showMsg($("erase-msg"), "Request failed.", false); });
};

// --- Resume a stored session ---
(function () {
  var saved = sessionStorage.getItem("sso_portal_token");
  if (!saved) return;
  token = saved;
  api("/me").then(function (r) {
    if (!r.ok) throw new Error("expired");
    return r.json();
  }).then(function (me) {
    $("login-screen").style.display = "none";
    $("app").style.display = "block";
    render(me);
    loadAll();
  }).catch(function () { sessionStorage.removeItem("sso_portal_token"); token = ""; });
})();
