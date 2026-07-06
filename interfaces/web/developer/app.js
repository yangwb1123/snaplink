// ---- State ----
// lastRegistered holds the just-returned DCRResponse from POST /register so
// "Manage This App" can pivot straight to the Manage tab without making the
// developer re-type what was just issued.
var lastRegistered = null;
// currentApp holds the full DCRResponse behind the loaded Manage-tab app —
// PUT must round-trip every field this form does NOT expose (grant_types,
// response_types, allowed_authenticators, allowed_resources,
// post_logout_redirect_uris, ...) UNCHANGED, since the server takes those
// verbatim from the request with no stored-value fallback (unlike
// token_strategy/token_endpoint_auth_method, which the server itself
// preserves when omitted). Dropping them here would silently wipe real
// client capabilities on every save.
var currentApp = null;

// ---- Helpers ----
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function splitLines(s) { return s.split('\n').map(function(x) { return x.trim(); }).filter(Boolean); }

function kvTable(rows) {
  return rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
}

// parseErrorBody reads this SDK's standard OAuth-style error shape
// ({"error":"...", "error_description":"..."}) — the same shape /register
// and /register/:client_id return on every failure.
function parseErrorBody(r) {
  return r.json().then(function(d) {
    throw new Error(d.error_description || d.error || ('HTTP ' + r.status));
  }).catch(function(e) {
    throw new Error(e.message || ('HTTP ' + r.status));
  });
}

// ---- Tabs ----
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(function(b) {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.tab').forEach(function(t) {
    t.classList.toggle('active', t.id === 'tab-' + name);
  });
}

// ---- Register ----
function showRegisterError(msg) {
  var el = document.getElementById('register-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideRegisterError() {
  document.getElementById('register-error').style.display = 'none';
}

function submitRegistration() {
  hideRegisterError();
  var body = {
    client_name: document.getElementById('reg-name').value.trim(),
    redirect_uris: splitLines(document.getElementById('reg-redirect-uris').value),
    scope: document.getElementById('reg-scope').value.trim(),
    token_endpoint_auth_method: document.getElementById('reg-auth-method').value,
    token_strategy: document.getElementById('reg-token-strategy').value
  };
  var headers = { 'Content-Type': 'application/json' };
  var iat = document.getElementById('reg-initial-access-token').value.trim();
  if (iat) headers['Authorization'] = 'Bearer ' + iat;

  fetch('/register', { method: 'POST', headers: headers, body: JSON.stringify(body) })
    .then(function(r) {
      if (!r.ok) return parseErrorBody(r);
      return r.json();
    }).then(function(d) {
      showRegisterResult(d);
    }).catch(function(e) {
      showRegisterError(e.message);
    });
}

// showRegisterResult displays the ONE-TIME-ONLY credentials (client_secret,
// registration_access_token) — the server never re-issues them on a
// subsequent GET/PUT, so this is the only chance the developer has to
// capture them.
function showRegisterResult(d) {
  lastRegistered = d;
  var rows = [['Client ID', '<code>' + esc(d.client_id) + '</code>']];
  if (d.client_secret) {
    rows.push(['Client Secret', '<code>' + esc(d.client_secret) + '</code>']);
  }
  if (d.registration_access_token) {
    rows.push(['Registration Access Token', '<code>' + esc(d.registration_access_token) + '</code>']);
  }
  if (d.registration_client_uri) {
    rows.push(['Registration Client URI', '<code>' + esc(d.registration_client_uri) + '</code>']);
  }
  document.getElementById('register-result-table').innerHTML = kvTable(rows);
  document.getElementById('register-result').style.display = 'block';
}

// ---- Manage ----
function showManageLoadError(msg) {
  var el = document.getElementById('manage-load-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideManageLoadError() {
  document.getElementById('manage-load-error').style.display = 'none';
}

function showManageFormError(msg) {
  var el = document.getElementById('manage-form-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideManageFormError() {
  document.getElementById('manage-form-error').style.display = 'none';
}

function populateManageForm(d) {
  document.getElementById('mf-name').value = d.client_name || '';
  document.getElementById('mf-redirect-uris').value = (d.redirect_uris || []).join('\n');
  document.getElementById('mf-scope').value = d.scope || '';
  document.getElementById('mf-token-strategy').value = d.token_strategy || 'jwt';
}

// loadApp fetches the app's current registration via RFC 7592 GET,
// authenticated by the registration_access_token alone (no admin bearer,
// no login) — this is the credential the developer received at /register.
function loadApp() {
  hideManageLoadError();
  var clientID = document.getElementById('mg-client-id').value.trim();
  var token = document.getElementById('mg-token').value.trim();
  if (!clientID || !token) {
    showManageLoadError('Client ID and registration access token are both required.');
    return;
  }
  fetch('/register/' + encodeURIComponent(clientID), {
    headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' }
  }).then(function(r) {
    // The server collapses every failure (wrong token, unknown client_id)
    // to the SAME 401 shape by design (anti-enumeration) — never try to
    // distinguish them here.
    if (!r.ok) return parseErrorBody(r);
    return r.json();
  }).then(function(d) {
    currentApp = d;
    populateManageForm(d);
    document.getElementById('manage-form-card').style.display = 'block';
  }).catch(function() {
    document.getElementById('manage-form-card').style.display = 'none';
    currentApp = null;
    showManageLoadError('Invalid client ID or registration access token.');
  });
}

// saveApp sends a full RFC 7592 PUT: it starts from the last GET's full
// response (preserving every field this form doesn't expose) and only
// overlays the four fields the form actually edits.
function saveApp() {
  hideManageFormError();
  if (!currentApp) return;
  var clientID = document.getElementById('mg-client-id').value.trim();
  var token = document.getElementById('mg-token').value.trim();

  var body = Object.assign({}, currentApp);
  delete body.client_id;
  delete body.client_secret;
  delete body.client_id_issued_at;
  delete body.client_secret_expires_at;
  delete body.registration_access_token;
  delete body.registration_client_uri;
  body.client_name = document.getElementById('mf-name').value.trim();
  body.redirect_uris = splitLines(document.getElementById('mf-redirect-uris').value);
  body.scope = document.getElementById('mf-scope').value.trim();
  body.token_strategy = document.getElementById('mf-token-strategy').value;

  fetch('/register/' + encodeURIComponent(clientID), {
    method: 'PUT',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) return parseErrorBody(r);
    return r.json();
  }).then(function(d) {
    currentApp = d;
    // A rotated registration_access_token (only when the operator enabled
    // rotate_access_token) invalidates the one just used to authenticate
    // THIS save — swap it in so the next save/delete still works.
    if (d.registration_access_token) {
      document.getElementById('mg-token').value = d.registration_access_token;
    }
    populateManageForm(d);
    alert('Saved.');
  }).catch(function(e) {
    showManageFormError(e.message);
  });
}

function deleteApp() {
  if (!currentApp) return;
  if (!confirm('Delete this app (' + currentApp.client_id + ')? This cannot be undone.')) return;
  var clientID = document.getElementById('mg-client-id').value.trim();
  var token = document.getElementById('mg-token').value.trim();
  fetch('/register/' + encodeURIComponent(clientID), {
    method: 'DELETE',
    headers: { 'Authorization': 'Bearer ' + token }
  }).then(function(r) {
    if (!r.ok && r.status !== 204) return parseErrorBody(r);
    document.getElementById('manage-form-card').style.display = 'none';
    document.getElementById('mg-client-id').value = '';
    document.getElementById('mg-token').value = '';
    currentApp = null;
    alert('App deleted.');
  }).catch(function(e) {
    showManageFormError(e.message);
  });
}

// ---- Event wiring ----
// addEventListener throughout (never inline onclick=""), same CSP
// script-src rationale as the admin console and other embedded SPAs: a
// security-headers deployment with no 'unsafe-inline' silently drops
// inline handler attributes.
document.getElementById('tab-register-btn').addEventListener('click', function() { switchTab('register'); });
document.getElementById('tab-manage-btn').addEventListener('click', function() { switchTab('manage'); });
document.getElementById('register-submit-btn').addEventListener('click', submitRegistration);
document.getElementById('register-manage-btn').addEventListener('click', function() {
  if (!lastRegistered) return;
  document.getElementById('mg-client-id').value = lastRegistered.client_id;
  document.getElementById('mg-token').value = lastRegistered.registration_access_token || '';
  switchTab('manage');
  loadApp();
});
document.getElementById('manage-load-btn').addEventListener('click', loadApp);
document.getElementById('manage-save-btn').addEventListener('click', saveApp);
document.getElementById('manage-delete-btn').addEventListener('click', deleteApp);
