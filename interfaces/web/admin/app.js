// ---- State ----
var token = '';
var currentPage = 'dashboard';
var auditCurrentPage = 1;
var auditHasMore = false;
var auditDebounceTimer = null;
var auditPageSize = 50;
// clientsCache / usersCache hold the last-fetched list keyed by id, so the
// delegated "View" click handlers below can look up the full record without
// re-fetching it or round-tripping it through an inline onclick="" attribute
// (a CSP script-src with no 'unsafe-inline' — the SDK's conservative
// security-headers default — blocks inline event-handler attributes; only
// listeners attached via addEventListener run).
var clientsCache = {};
var usersCache = {};
// currentClientDetail holds the full record behind the open client-detail
// panel, so the Edit/Delete/Approve/Reject/Rotate-secret actions (which
// only have the panel's DOM, not a fresh fetch) know which client they
// apply to.
var currentClientDetail = null;
// clientFormMode / clientFormOriginalId track whether the client form panel
// is creating a new client or editing an existing one (whose id the PUT
// URL needs — the id INPUT is disabled but still present during edit, so
// this is belt-and-suspenders against a stale/empty value).
var clientFormMode = 'create';
var clientFormOriginalId = '';
// Same shape as the client-form state above, for the Users and Tenants
// create/edit forms.
var currentUserDetail = null;
var userFormMode = 'create';
var userFormOriginalId = '';
var currentTenantDetail = null;
var tenantFormMode = 'create';
var tenantFormOriginalId = '';
var tenantsCache = {};
var currentDomainDetail = null;
var domainFormMode = 'create';
var domainFormOriginalHostname = '';
var domainsCache = {};

// SSO_ADMIN_CLIENT_ID is the public, PKCE-required OAuth client this
// console dogfoods against its own server as — seeded server-side by
// platform/bootstrap/builtin's stepSeedAdminConsoleClient (id, scopes,
// and RequirePKCE=true fixed there; RedirectURIs left for the operator to
// set to wherever this page is actually served from).
var SSO_ADMIN_CLIENT_ID = 'sso-admin-console';
var SSO_ADMIN_SCOPE = 'openid profile admin:read admin:write';

// ---- Auth ----
function doLogin() {
  var t = document.getElementById('token-input').value.trim();
  if (!t) {
    showLoginError('Token is required.');
    return;
  }
  // Store token in sessionStorage — scoped to the browser tab and cleared when the tab closes.
  sessionStorage.setItem('sso_admin_token', t);
  token = t;
  hideLoginError();
  showApp();
}

function doLogout() {
  sessionStorage.removeItem('sso_admin_token');
  token = '';
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('token-input').value = '';
}

// ---- Auth: dogfood OAuth 2.0 Authorization Code + PKCE ----
// base64url encodes an ArrayBuffer/Uint8Array without padding — the form
// RFC 7636 requires for code_verifier/code_challenge.
function base64url(buf) {
  var bytes = new Uint8Array(buf);
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// generateCodeVerifier mints a 64-byte random verifier (86 base64url
// chars) — comfortably inside the server's accepted [43,128] window
// (shared/core/consts_oauth.go PKCEVerifierMinLen/MaxLen) with margin,
// unlike a minimal 32-byte verifier which lands exactly at the 43-char
// floor.
function generateCodeVerifier() {
  var arr = new Uint8Array(64);
  crypto.getRandomValues(arr);
  return base64url(arr);
}

function generateState() {
  var arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return base64url(arr);
}

// sha256CodeChallenge computes RFC 7636 S256: BASE64URL(SHA256(verifier)).
// The seeded sso-admin-console client sets RequirePKCE=true but never sets
// AllowedPKCEMethods, so the server would also accept "plain"
// (oauthwire.IsPKCEMethodAllowedForClient treats an empty allowlist as
// "any method") — S256 is used unconditionally anyway because it's the
// only PKCE method that doesn't expose the verifier if the challenge
// itself is ever observed (RFC 7636 §4.2, mandatory under OAuth 2.1).
function sha256CodeChallenge(verifier) {
  var bytes = new TextEncoder().encode(verifier);
  return crypto.subtle.digest('SHA-256', bytes).then(base64url);
}

function ssoLoginRedirectURI() {
  return window.location.origin + window.location.pathname;
}

// startSSOLogin redirects the browser to the hosted login page
// (/login/, mounted only when the operator wires WithHostedLoginFS) with
// a standard RFC 6749 §4.1 + RFC 7636 authorization request. The
// code_verifier/state are stashed in sessionStorage — they must survive
// the full-page navigation away and back.
function startSSOLogin() {
  var verifier = generateCodeVerifier();
  var state = generateState();
  var redirectURI = ssoLoginRedirectURI();
  sha256CodeChallenge(verifier).then(function(challenge) {
    sessionStorage.setItem('sso_admin_oauth_verifier', verifier);
    sessionStorage.setItem('sso_admin_oauth_state', state);
    sessionStorage.setItem('sso_admin_oauth_redirect_uri', redirectURI);
    var params = new URLSearchParams();
    params.set('response_type', 'code');
    params.set('client_id', SSO_ADMIN_CLIENT_ID);
    params.set('redirect_uri', redirectURI);
    params.set('scope', SSO_ADMIN_SCOPE);
    params.set('code_challenge', challenge);
    params.set('code_challenge_method', 'S256');
    params.set('state', state);
    window.location.href = '/login/?' + params.toString();
  }).catch(function(e) {
    showLoginError('Could not start SSO login: ' + e.message);
  });
}

// handleOAuthCallback checks for a ?code=&state= (or ?error=) query string
// left by the hosted login page's redirect back to this same URL. Returns
// true when this load IS such a callback (whether it succeeds or fails) —
// the boot sequence must not also fall through to the plain
// "resume a saved token" path in that case. Always strips the query
// string via replaceState so a page refresh never replays the exchange.
function handleOAuthCallback() {
  var params = new URLSearchParams(window.location.search);
  var code = params.get('code');
  var oauthError = params.get('error');
  if (!code && !oauthError) return false;

  var savedState = sessionStorage.getItem('sso_admin_oauth_state');
  var verifier = sessionStorage.getItem('sso_admin_oauth_verifier');
  var redirectURI = sessionStorage.getItem('sso_admin_oauth_redirect_uri');
  sessionStorage.removeItem('sso_admin_oauth_state');
  sessionStorage.removeItem('sso_admin_oauth_verifier');
  sessionStorage.removeItem('sso_admin_oauth_redirect_uri');
  window.history.replaceState({}, '', window.location.pathname);

  if (oauthError) {
    showLoginError('SSO login failed: ' + (params.get('error_description') || oauthError));
    return true;
  }
  var state = params.get('state');
  if (!state || state !== savedState || !verifier) {
    showLoginError('SSO login failed: invalid or expired login attempt — please try again.');
    return true;
  }
  exchangeCodeForToken(code, verifier, redirectURI);
  return true;
}

// exchangeCodeForToken performs the RFC 6749 §4.1.3 + RFC 7636 §4.5
// token exchange. A public (secret-less) client authenticates with
// PKCE's code_verifier alone — no client_secret is sent or needed.
function exchangeCodeForToken(code, verifier, redirectURI) {
  var body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', redirectURI);
  body.set('client_id', SSO_ADMIN_CLIENT_ID);
  body.set('code_verifier', verifier);

  fetch('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  }).then(function(r) {
    return r.json().then(function(d) { return { ok: r.ok, body: d }; });
  }).then(function(res) {
    if (!res.ok || !res.body.access_token) {
      throw new Error(res.body.error_description || res.body.error || 'token exchange failed');
    }
    sessionStorage.setItem('sso_admin_token', res.body.access_token);
    token = res.body.access_token;
    hideLoginError();
    showApp();
  }).catch(function(e) {
    showLoginError('SSO login failed: ' + e.message);
  });
}

function showLoginError(msg) {
  var el = document.getElementById('login-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideLoginError() {
  document.getElementById('login-error').style.display = 'none';
}

function showApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  navigate('dashboard');
}

// ---- Navigation ----
function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.classList.toggle('active', el.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(function(el) {
    el.classList.toggle('active', el.id === 'page-' + page);
  });
  currentPage = page;

  if (page === 'dashboard') loadDashboard();
  else if (page === 'clients') loadClients();
  else if (page === 'users') loadUsers();
  else if (page === 'tenants') loadTenants();
  else if (page === 'domains') loadDomains();
  else if (page === 'sessions') loadSessions();
  else if (page === 'audit') loadAudit(1);
}

// ---- API helpers ----
function apiFetch(path, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  opts.headers['Authorization'] = 'Bearer ' + token;
  opts.headers['Accept'] = 'application/json';
  return fetch(path, opts).then(function(resp) {
    if (resp.status === 401 || resp.status === 403) {
      doLogout();
      throw new Error('Unauthorized — token may be expired or lack admin scope.');
    }
    return resp;
  });
}

function setContent(id, html) {
  document.getElementById(id).innerHTML = html;
}

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtTime(unix) {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleString();
}

function badge(val, trueLabel, trueClass, falseLabel, falseClass) {
  if (val) return '<span class="badge ' + trueClass + '">' + esc(trueLabel) + '</span>';
  return '<span class="badge ' + falseClass + '">' + esc(falseLabel) + '</span>';
}

// splitLines / splitSpace tokenize a textarea/input's raw value for the
// repeated-string proto fields (redirect_uris, allowed_regions, ...).
function splitLines(s) { return s.split('\n').map(function(x) { return x.trim(); }).filter(Boolean); }
function splitSpace(s) { return s.trim().split(/\s+/).filter(Boolean); }

// parseKeyValueLines turns a "key=value" per-line textarea into a plain
// object — used for the User/Tenant map<string,string> fields
// (attributes/settings). A line with no "=" is skipped rather than
// guessed at.
function parseKeyValueLines(s) {
  var out = {};
  splitLines(s).forEach(function(line) {
    var i = line.indexOf('=');
    if (i <= 0) return;
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return out;
}

// formatKeyValueLines is parseKeyValueLines' inverse, for pre-filling an
// edit form from an already-fetched record's map field.
function formatKeyValueLines(obj) {
  if (!obj || typeof obj !== 'object') return '';
  return Object.keys(obj).map(function(k) { return k + '=' + obj[k]; }).join('\n');
}

// ---- Dashboard ----
function loadDashboard() {
  // Liveness
  fetch('/livez').then(function(r) {
    document.getElementById('stat-live').textContent = r.ok ? 'Alive' : 'Down';
    document.getElementById('stat-live').style.color = r.ok ? '#68d391' : '#fc8181';
  }).catch(function() {
    document.getElementById('stat-live').textContent = 'Error';
    document.getElementById('stat-live').style.color = '#fc8181';
  });

  // Readiness
  fetch('/readyz').then(function(r) {
    document.getElementById('stat-ready').textContent = r.ok ? 'Ready' : 'Not Ready';
    document.getElementById('stat-ready').style.color = r.ok ? '#68d391' : '#fc8181';
    if (!r.ok) {
      return r.json().then(function(data) {
        renderReadyzDetail(data);
      }).catch(function() {});
    }
  }).catch(function() {
    document.getElementById('stat-ready').textContent = 'Error';
    document.getElementById('stat-ready').style.color = '#fc8181';
  });

  // OIDC discovery
  fetch('/.well-known/openid-configuration').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    renderOIDCInfo(d);
  }).catch(function(e) {
    setContent('oidc-info', '<div class="error-msg">' + esc(e.message) + '</div>');
    setContent('oidc-features', '');
  });
}

function renderReadyzDetail(data) {
  // data is {check_name: "ok" | error_string}
  var html = '';
  if (data && typeof data === 'object') {
    for (var k in data) {
      var ok = data[k] === 'ok';
      html += '<div class="health-row"><div class="health-dot ' + (ok ? 'ok' : 'fail') + '"></div>';
      html += '<span style="color:' + (ok ? '#68d391' : '#fc8181') + '">' + esc(k) + ': ' + esc(data[k]) + '</span></div>';
    }
  }
  if (html) {
    var card = document.createElement('div');
    card.className = 'card';
    card.style.marginBottom = '20px';
    card.innerHTML = '<div class="card-title">Readiness Checks</div>' + html;
    document.getElementById('page-dashboard').insertBefore(card,
      document.getElementById('page-dashboard').querySelector('.card'));
  }
}

function renderOIDCInfo(d) {
  document.getElementById('stat-issuer').textContent = d.issuer || '—';

  var infoFields = [
    ['Issuer', d.issuer],
    ['Authorization Endpoint', d.authorization_endpoint],
    ['Token Endpoint', d.token_endpoint],
    ['UserInfo Endpoint', d.userinfo_endpoint],
    ['JWKS URI', d.jwks_uri],
    ['Registration Endpoint', d.registration_endpoint || '—'],
    ['Pushed Auth Req Endpoint', d.pushed_authorization_request_endpoint || '—'],
  ];

  var html = '<div class="info-grid">';
  infoFields.forEach(function(row) {
    html += '<div class="info-item"><div class="info-key">' + esc(row[0]) + '</div>';
    html += '<div class="info-val">' + esc(row[1] || '—') + '</div></div>';
  });
  html += '</div>';
  setContent('oidc-info', html);

  // Features
  var features = [
    ['PKCE (S256)', d.code_challenge_methods_supported && d.code_challenge_methods_supported.indexOf('S256') !== -1],
    ['Pushed Auth Requests', !!d.pushed_authorization_request_endpoint],
    ['Dynamic Client Reg', !!d.registration_endpoint],
    ['Device Authorization', !!d.device_authorization_endpoint],
    ['Backchannel Logout', d.backchannel_logout_supported],
    ['Frontchannel Logout', d.frontchannel_logout_supported],
    ['JARM', d.authorization_signing_alg_values_supported && d.authorization_signing_alg_values_supported.length > 0],
    ['JAR', d.request_object_signing_alg_values_supported && d.request_object_signing_alg_values_supported.length > 0],
    ['mTLS Token Binding', d.tls_client_certificate_bound_access_tokens],
    ['DPoP', d.dpop_signing_alg_values_supported && d.dpop_signing_alg_values_supported.length > 0],
  ];

  var fhtml = '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  features.forEach(function(f) {
    fhtml += '<span class="badge ' + (f[1] ? 'badge-green' : 'badge-gray') + '">' + esc(f[0]) + '</span>';
  });
  fhtml += '</div>';

  var algs = (d.id_token_signing_alg_values_supported || []).join(', ');
  if (algs) {
    fhtml += '<div style="margin-top:12px;font-size:12px;color:#8892b0;">Signing algs: ' + esc(algs) + '</div>';
  }
  setContent('oidc-features', fhtml);
}

// ---- Clients ----
// Field names below (tokenStrategy, allowedScopes, redirectUris,
// allowedAuthenticators) are lowerCamelCase because these responses come
// from the grpc-gateway JSON marshaler (protojson), which emits the
// camelCase JSON name for each proto field by default — NOT the
// snake_case proto field name itself. Unlike the audit-log and session
// endpoints (hand-rolled JSON with explicit snake_case struct tags), the
// Clients/Users pages are the only ones backed by the proto-based admin
// gRPC-gateway, so they're the only ones that need this casing.
function loadClients() {
  closeDetail('client');
  setContent('clients-content', '<div class="loading">Loading...</div>');
  apiFetch('/api/v1/admin/clients').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var clients = d.clients || [];
    clientsCache = {};
    if (!clients.length) {
      setContent('clients-content', '<div class="empty">No clients found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>ID</th><th>Name</th><th>Status</th><th>Strategy</th><th>Scopes</th><th></th>';
    html += '</tr></thead><tbody>';
    clients.forEach(function(c) {
      clientsCache[c.id] = c;
      html += '<tr>';
      html += '<td><code>' + esc(c.id) + '</code></td>';
      html += '<td>' + esc(c.name) + '</td>';
      html += '<td>' + badge(c.active, 'Active', 'badge-green', 'Pending / Inactive', 'badge-red') + '</td>';
      html += '<td><span class="badge badge-blue">' + esc(c.tokenStrategy || 'jwt') + '</span></td>';
      html += '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc((c.allowedScopes || []).join(' ')) + '</td>';
      html += '<td><button class="btn btn-sm" data-action="view-client" data-id="' + esc(c.id) + '">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('clients-content', html);
  }).catch(function(e) {
    setContent('clients-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showClientDetail(c) {
  if (!c) return;
  currentClientDetail = c;
  document.getElementById('clients-list').style.display = 'none';
  document.getElementById('client-form-panel').classList.remove('open');
  document.getElementById('client-detail').classList.add('open');

  var rows = [
    ['ID', '<code>' + esc(c.id) + '</code>'],
    ['Name', esc(c.name)],
    ['Active', badge(c.active, 'Active', 'badge-green', 'Pending / Inactive', 'badge-red')],
    ['Token Strategy', '<span class="badge badge-blue">' + esc(c.tokenStrategy || 'jwt') + '</span>'],
    ['Allowed Scopes', esc((c.allowedScopes || []).join(', ') || '—')],
    ['Redirect URIs', esc((c.redirectUris || []).join('\n') || '—')],
    ['Allowed Authenticators', esc((c.allowedAuthenticators || []).join(', ') || '—')],
  ];
  var html = rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
  document.getElementById('client-detail-table').innerHTML = html;
  renderClientDetailActions(c);
}

// renderClientDetailActions builds the action button row for the open
// client-detail panel. Approve/Reject only appear for a pending
// (active=false) client — an already-active client has nothing to
// approve, and the plain Edit form already covers "reactivate a
// deliberately deactivated client" without the destructive Reject-deletes
// semantics.
function renderClientDetailActions(c) {
  var html = '<button class="btn btn-sm" data-action="edit-client">Edit</button>';
  html += '<button class="btn btn-sm" data-action="rotate-secret">Rotate Secret</button>';
  if (!c.active) {
    html += '<button class="btn btn-success" data-action="approve-client">Approve</button>';
    html += '<button class="btn btn-danger" data-action="reject-client">Reject &amp; Delete</button>';
  }
  html += '<button class="btn btn-danger" data-action="delete-client">Delete</button>';
  document.getElementById('client-detail-actions').innerHTML = html;
}

// ---- Clients: create / edit form ----
function showClientForm(mode, c) {
  clientFormMode = mode;
  clientFormOriginalId = c ? c.id : '';
  document.getElementById('clients-list').style.display = 'none';
  document.getElementById('client-detail').classList.remove('open');
  document.getElementById('client-form-panel').classList.add('open');
  hideClientFormError();
  document.getElementById('client-form-title').textContent = mode === 'edit' ? 'Edit Client' : 'New Client';
  document.getElementById('cf-id').disabled = mode === 'edit';
  document.getElementById('cf-id').value = c ? (c.id || '') : '';
  document.getElementById('cf-name').value = c ? (c.name || '') : '';
  document.getElementById('cf-redirect-uris').value = c ? (c.redirectUris || []).join('\n') : '';
  document.getElementById('cf-scopes').value = c ? (c.allowedScopes || []).join(' ') : '';
  document.getElementById('cf-authenticators').value = c ? (c.allowedAuthenticators || []).join(' ') : '';
  document.getElementById('cf-strategy').value = c ? (c.tokenStrategy || 'jwt') : 'jwt';
  document.getElementById('cf-active').checked = c ? !!c.active : true;
}

function hideClientForm() {
  document.getElementById('client-form-panel').classList.remove('open');
  document.getElementById('clients-list').style.display = '';
}

function showClientFormError(msg) {
  var el = document.getElementById('client-form-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideClientFormError() {
  document.getElementById('client-form-error').style.display = 'none';
}

// readClientForm reads the form into a Client-shaped object using the
// SAME camelCase field names the gateway expects on the wire (see the
// casing note above loadClients) — Create/Update's JSON body maps
// directly onto the proto Client message (google.api.http body:"client"),
// not a {"client":{...}} wrapper.
function readClientForm() {
  return {
    id: document.getElementById('cf-id').value.trim(),
    name: document.getElementById('cf-name').value.trim(),
    redirectUris: splitLines(document.getElementById('cf-redirect-uris').value),
    allowedScopes: splitSpace(document.getElementById('cf-scopes').value),
    allowedAuthenticators: splitSpace(document.getElementById('cf-authenticators').value),
    tokenStrategy: document.getElementById('cf-strategy').value,
    active: document.getElementById('cf-active').checked
  };
}

// gatewayErrorMessage extracts the message from a grpc-gateway error body
// ({"code":<int>,"message":"...","details":[...]}) — a different shape
// from this SDK's own OAuth-style {"error":...} bodies, since the admin
// REST surface is auto-generated by protoc-gen-grpc-gateway rather than
// hand-rolled.
function gatewayErrorMessage(r) {
  return r.json().then(function(d) {
    throw new Error(d.message || ('HTTP ' + r.status));
  }).catch(function(e) {
    throw new Error(e.message || ('HTTP ' + r.status));
  });
}

function submitClientForm() {
  var body = readClientForm();
  if (!body.id) {
    showClientFormError('Client ID is required.');
    return;
  }
  var isEdit = clientFormMode === 'edit';
  var url = '/api/v1/admin/clients' + (isEdit ? '/' + encodeURIComponent(clientFormOriginalId) : '');
  apiFetch(url, {
    method: isEdit ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    hideClientForm();
    loadClients();
  }).catch(function(e) {
    showClientFormError(e.message);
  });
}

// ---- Clients: detail-panel actions ----
function editCurrentClient() {
  if (!currentClientDetail) return;
  showClientForm('edit', currentClientDetail);
}

function deleteCurrentClient() {
  if (!currentClientDetail) return;
  if (!confirm('Delete client "' + currentClientDetail.name + '" (' + currentClientDetail.id + ')? This cannot be undone.')) return;
  apiFetch('/api/v1/admin/clients/' + encodeURIComponent(currentClientDetail.id), { method: 'DELETE' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      closeDetail('client');
      loadClients();
    }).catch(function(e) { alert('Delete failed: ' + e.message); });
}

function approveCurrentClient() {
  if (!currentClientDetail) return;
  apiFetch('/api/v1/admin/clients/' + encodeURIComponent(currentClientDetail.id) + '/approve', { method: 'POST' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      return r.json();
    }).then(function(d) {
      showClientDetail(d.client);
      loadClients();
    }).catch(function(e) { alert('Approve failed: ' + e.message); });
}

function rejectCurrentClient() {
  if (!currentClientDetail) return;
  var reason = prompt('Reason for rejecting "' + currentClientDetail.name + '" (optional):', '');
  if (reason === null) return; // cancelled
  if (!confirm('Reject and DELETE client "' + currentClientDetail.name + '"? This cannot be undone.')) return;
  apiFetch('/api/v1/admin/clients/' + encodeURIComponent(currentClientDetail.id) + '/reject', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: reason })
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    closeDetail('client');
    loadClients();
  }).catch(function(e) { alert('Reject failed: ' + e.message); });
}

function rotateCurrentClientSecret() {
  if (!currentClientDetail) return;
  if (!confirm('Rotate the client_secret for "' + currentClientDetail.name + '"? The old secret stops working immediately.')) return;
  apiFetch('/api/v1/admin/clients/' + encodeURIComponent(currentClientDetail.id) + '/rotate-secret', { method: 'POST' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      return r.json();
    }).then(function(d) {
      alert('New client_secret (displayed once — copy it now):\n\n' + d.secret);
    }).catch(function(e) { alert('Rotate failed: ' + e.message); });
}

function closeDetail(type) {
  if (type === 'client') {
    document.getElementById('clients-list').style.display = '';
    document.getElementById('client-detail').classList.remove('open');
    document.getElementById('client-form-panel').classList.remove('open');
    currentClientDetail = null;
  } else if (type === 'user') {
    document.getElementById('users-list').style.display = '';
    document.getElementById('user-detail').classList.remove('open');
    document.getElementById('user-form-panel').classList.remove('open');
    currentUserDetail = null;
  } else if (type === 'tenant') {
    document.getElementById('tenants-list').style.display = '';
    document.getElementById('tenant-detail').classList.remove('open');
    document.getElementById('tenant-form-panel').classList.remove('open');
    currentTenantDetail = null;
  } else if (type === 'domain') {
    document.getElementById('domains-list').style.display = '';
    document.getElementById('domain-detail').classList.remove('open');
    document.getElementById('domain-form-panel').classList.remove('open');
    currentDomainDetail = null;
  }
}

// ---- Users ----
// Same camelCase-from-protojson note as the Clients section above applies
// here (externalId, not external_id).
function loadUsers() {
  closeDetail('user');
  setContent('users-content', '<div class="loading">Loading...</div>');
  apiFetch('/api/v1/admin/users').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var users = d.users || [];
    usersCache = {};
    if (!users.length) {
      setContent('users-content', '<div class="empty">No users found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>ID</th><th>External ID</th><th>Provider</th><th></th>';
    html += '</tr></thead><tbody>';
    users.forEach(function(u) {
      usersCache[u.id] = u;
      html += '<tr>';
      html += '<td><code>' + esc(u.id) + '</code></td>';
      html += '<td>' + esc(u.externalId || '—') + '</td>';
      html += '<td><span class="badge badge-blue">' + esc(u.provider || '—') + '</span></td>';
      html += '<td><button class="btn btn-sm" data-action="view-user" data-id="' + esc(u.id) + '">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('users-content', html);
  }).catch(function(e) {
    setContent('users-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showUserDetail(u) {
  if (!u) return;
  currentUserDetail = u;
  document.getElementById('users-list').style.display = 'none';
  document.getElementById('user-form-panel').classList.remove('open');
  document.getElementById('user-detail').classList.add('open');

  var rows = [
    ['ID', '<code>' + esc(u.id) + '</code>'],
    ['External ID', esc(u.externalId || '—')],
    ['Provider', '<span class="badge badge-blue">' + esc(u.provider || '—') + '</span>'],
  ];

  // Attributes
  if (u.attributes && typeof u.attributes === 'object') {
    for (var k in u.attributes) {
      // Never render credential values — the seeded_password attribute
      // in particular should not be displayed.
      if (k === 'seeded_password') {
        rows.push([esc(k), '<span style="color:#4a5568">[redacted]</span>']);
      } else {
        rows.push([esc(k), esc(u.attributes[k])]);
      }
    }
  }

  var html = rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
  document.getElementById('user-detail-table').innerHTML = html;
  document.getElementById('user-detail-actions').innerHTML =
    '<button class="btn btn-sm" data-action="edit-user">Edit</button>' +
    '<button class="btn btn-danger" data-action="delete-user">Delete</button>';
}

// ---- Users: create / edit form ----
function showUserForm(mode, u) {
  userFormMode = mode;
  userFormOriginalId = u ? u.id : '';
  document.getElementById('users-list').style.display = 'none';
  document.getElementById('user-detail').classList.remove('open');
  document.getElementById('user-form-panel').classList.add('open');
  hideUserFormError();
  document.getElementById('user-form-title').textContent = mode === 'edit' ? 'Edit User' : 'New User';
  document.getElementById('uf-id').disabled = mode === 'edit';
  document.getElementById('uf-id').value = u ? (u.id || '') : '';
  document.getElementById('uf-external-id').value = u ? (u.externalId || '') : '';
  document.getElementById('uf-provider').value = u ? (u.provider || '') : '';
  document.getElementById('uf-attributes').value = u ? formatKeyValueLines(u.attributes) : '';
}

function hideUserForm() {
  document.getElementById('user-form-panel').classList.remove('open');
  document.getElementById('users-list').style.display = '';
}

function showUserFormError(msg) {
  var el = document.getElementById('user-form-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideUserFormError() {
  document.getElementById('user-form-error').style.display = 'none';
}

function readUserForm() {
  return {
    id: document.getElementById('uf-id').value.trim(),
    externalId: document.getElementById('uf-external-id').value.trim(),
    provider: document.getElementById('uf-provider').value.trim(),
    attributes: parseKeyValueLines(document.getElementById('uf-attributes').value)
  };
}

function submitUserForm() {
  var body = readUserForm();
  if (!body.id) {
    showUserFormError('User ID is required.');
    return;
  }
  var isEdit = userFormMode === 'edit';
  var url = '/api/v1/admin/users' + (isEdit ? '/' + encodeURIComponent(userFormOriginalId) : '');
  apiFetch(url, {
    method: isEdit ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    hideUserForm();
    loadUsers();
  }).catch(function(e) {
    showUserFormError(e.message);
  });
}

function editCurrentUser() {
  if (!currentUserDetail) return;
  showUserForm('edit', currentUserDetail);
}

function deleteCurrentUser() {
  if (!currentUserDetail) return;
  if (!confirm('Delete user "' + currentUserDetail.id + '"? This cannot be undone.')) return;
  apiFetch('/api/v1/admin/users/' + encodeURIComponent(currentUserDetail.id), { method: 'DELETE' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      closeDetail('user');
      loadUsers();
    }).catch(function(e) { alert('Delete failed: ' + e.message); });
}

// ---- Tenants ----
function loadTenants() {
  closeDetail('tenant');
  setContent('tenants-content', '<div class="loading">Loading...</div>');
  apiFetch('/api/v1/admin/tenants').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var tenants = d.tenants || [];
    tenantsCache = {};
    if (!tenants.length) {
      setContent('tenants-content', '<div class="empty">No tenants found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>ID</th><th>Name</th><th>Slug</th><th>Status</th><th></th>';
    html += '</tr></thead><tbody>';
    tenants.forEach(function(t) {
      tenantsCache[t.id] = t;
      html += '<tr>';
      html += '<td><code>' + esc(t.id) + '</code></td>';
      html += '<td>' + esc(t.name) + '</td>';
      html += '<td>' + esc(t.slug || '—') + '</td>';
      html += '<td>' + badge(t.status === 'active', 'Active', 'badge-green', esc(t.status || 'suspended'), 'badge-red') + '</td>';
      html += '<td><button class="btn btn-sm" data-action="view-tenant" data-id="' + esc(t.id) + '">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('tenants-content', html);
  }).catch(function(e) {
    setContent('tenants-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showTenantDetail(t) {
  if (!t) return;
  currentTenantDetail = t;
  document.getElementById('tenants-list').style.display = 'none';
  document.getElementById('tenant-form-panel').classList.remove('open');
  document.getElementById('tenant-detail').classList.add('open');

  var rows = [
    ['ID', '<code>' + esc(t.id) + '</code>'],
    ['Name', esc(t.name)],
    ['Slug', esc(t.slug || '—')],
    ['Status', badge(t.status === 'active', 'Active', 'badge-green', esc(t.status || 'suspended'), 'badge-red')],
    ['Home Region', esc(t.homeRegion || '—')],
    ['Allowed Regions', esc((t.allowedRegions || []).join(', ') || '—')],
    ['Enforce Writes', badge(t.enforceWrites, 'Yes', 'badge-green', 'No', 'badge-gray')],
  ];
  if (t.settings && typeof t.settings === 'object') {
    for (var k in t.settings) {
      rows.push(['Setting: ' + esc(k), esc(t.settings[k])]);
    }
  }
  var html = rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
  document.getElementById('tenant-detail-table').innerHTML = html;
  renderTenantDetailActions(t);
}

// renderTenantDetailActions: Suspend/Activate uses the dedicated
// SetTenantStatus RPC (surgical status-only flip on the server, avoiding
// a read-modify-write race with the settings/regions the plain Edit form
// covers) rather than routing status through Update.
function renderTenantDetailActions(t) {
  var html = '<button class="btn btn-sm" data-action="edit-tenant">Edit</button>';
  if (t.status === 'active') {
    html += '<button class="btn btn-danger" data-action="suspend-tenant">Suspend</button>';
  } else {
    html += '<button class="btn btn-success" data-action="activate-tenant">Activate</button>';
  }
  html += '<button class="btn btn-danger" data-action="delete-tenant">Delete</button>';
  document.getElementById('tenant-detail-actions').innerHTML = html;
}

// ---- Tenants: create / edit form ----
function showTenantForm(mode, t) {
  tenantFormMode = mode;
  tenantFormOriginalId = t ? t.id : '';
  document.getElementById('tenants-list').style.display = 'none';
  document.getElementById('tenant-detail').classList.remove('open');
  document.getElementById('tenant-form-panel').classList.add('open');
  hideTenantFormError();
  document.getElementById('tenant-form-title').textContent = mode === 'edit' ? 'Edit Tenant' : 'New Tenant';
  document.getElementById('tf-id').disabled = mode === 'edit';
  document.getElementById('tf-id').value = t ? (t.id || '') : '';
  document.getElementById('tf-slug').value = t ? (t.slug || '') : '';
  document.getElementById('tf-name').value = t ? (t.name || '') : '';
  document.getElementById('tf-home-region').value = t ? (t.homeRegion || '') : '';
  document.getElementById('tf-allowed-regions').value = t ? (t.allowedRegions || []).join(' ') : '';
  document.getElementById('tf-settings').value = t ? formatKeyValueLines(t.settings) : '';
  document.getElementById('tf-enforce-writes').checked = t ? !!t.enforceWrites : false;
}

function hideTenantForm() {
  document.getElementById('tenant-form-panel').classList.remove('open');
  document.getElementById('tenants-list').style.display = '';
}

function showTenantFormError(msg) {
  var el = document.getElementById('tenant-form-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideTenantFormError() {
  document.getElementById('tenant-form-error').style.display = 'none';
}

// readTenantForm deliberately omits `status` — a NEW tenant's status
// defaults to the server's own CreateTenant default, and an EXISTING
// tenant's status is only ever changed via the dedicated Suspend/Activate
// actions (SetTenantStatus), never through this form/Update.
function readTenantForm() {
  return {
    id: document.getElementById('tf-id').value.trim(),
    slug: document.getElementById('tf-slug').value.trim(),
    name: document.getElementById('tf-name').value.trim(),
    homeRegion: document.getElementById('tf-home-region').value.trim(),
    allowedRegions: splitSpace(document.getElementById('tf-allowed-regions').value),
    settings: parseKeyValueLines(document.getElementById('tf-settings').value),
    enforceWrites: document.getElementById('tf-enforce-writes').checked
  };
}

function submitTenantForm() {
  var body = readTenantForm();
  if (!body.id) {
    showTenantFormError('Tenant ID is required.');
    return;
  }
  var isEdit = tenantFormMode === 'edit';
  var url = '/api/v1/admin/tenants' + (isEdit ? '/' + encodeURIComponent(tenantFormOriginalId) : '');
  apiFetch(url, {
    method: isEdit ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    hideTenantForm();
    loadTenants();
  }).catch(function(e) {
    showTenantFormError(e.message);
  });
}

function editCurrentTenant() {
  if (!currentTenantDetail) return;
  showTenantForm('edit', currentTenantDetail);
}

function deleteCurrentTenant() {
  if (!currentTenantDetail) return;
  if (!confirm('Delete tenant "' + currentTenantDetail.name + '" (' + currentTenantDetail.id + ')? This cannot be undone.')) return;
  apiFetch('/api/v1/admin/tenants/' + encodeURIComponent(currentTenantDetail.id), { method: 'DELETE' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      closeDetail('tenant');
      loadTenants();
    }).catch(function(e) { alert('Delete failed: ' + e.message); });
}

function setCurrentTenantStatus(status) {
  if (!currentTenantDetail) return;
  apiFetch('/api/v1/admin/tenants/' + encodeURIComponent(currentTenantDetail.id) + ':set-status', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: status })
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    return r.json();
  }).then(function(d) {
    showTenantDetail(d.tenant);
    loadTenants();
  }).catch(function(e) { alert('Status change failed: ' + e.message); });
}

// ---- Domains ----
// Same TenantAdminService gRPC-gateway (same camelCase-from-protojson
// note as Clients/Users/Tenants above) — Domain{hostname, tenantId,
// defaultClientId, isApex, branding}. hostname is the primary key (no
// separate id field), so it's what the edit/delete/URL paths key off.
function loadDomains() {
  closeDetail('domain');
  setContent('domains-content', '<div class="loading">Loading...</div>');
  apiFetch('/api/v1/admin/domains').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var domains = d.domains || [];
    domainsCache = {};
    if (!domains.length) {
      setContent('domains-content', '<div class="empty">No domains found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>Hostname</th><th>Tenant ID</th><th>Default Client</th><th>Apex</th><th></th>';
    html += '</tr></thead><tbody>';
    domains.forEach(function(d) {
      domainsCache[d.hostname] = d;
      html += '<tr>';
      html += '<td><code>' + esc(d.hostname) + '</code></td>';
      html += '<td>' + esc(d.tenantId || '—') + '</td>';
      html += '<td>' + esc(d.defaultClientId || '—') + '</td>';
      html += '<td>' + badge(d.isApex, 'Yes', 'badge-blue', 'No', 'badge-gray') + '</td>';
      html += '<td><button class="btn btn-sm" data-action="view-domain" data-id="' + esc(d.hostname) + '">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('domains-content', html);
  }).catch(function(e) {
    setContent('domains-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showDomainDetail(d) {
  if (!d) return;
  currentDomainDetail = d;
  document.getElementById('domains-list').style.display = 'none';
  document.getElementById('domain-form-panel').classList.remove('open');
  document.getElementById('domain-detail').classList.add('open');

  var rows = [
    ['Hostname', '<code>' + esc(d.hostname) + '</code>'],
    ['Tenant ID', esc(d.tenantId || '—')],
    ['Default Client ID', esc(d.defaultClientId || '—')],
    ['Apex Domain', badge(d.isApex, 'Yes', 'badge-blue', 'No', 'badge-gray')],
  ];
  if (d.branding && typeof d.branding === 'object') {
    for (var k in d.branding) {
      rows.push(['Branding: ' + esc(k), esc(d.branding[k])]);
    }
  }
  var html = rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
  document.getElementById('domain-detail-table').innerHTML = html;
  document.getElementById('domain-detail-actions').innerHTML =
    '<button class="btn btn-sm" data-action="edit-domain">Edit</button>' +
    '<button class="btn btn-danger" data-action="delete-domain">Delete</button>';
}

// ---- Domains: create / edit form ----
function showDomainForm(mode, d) {
  domainFormMode = mode;
  domainFormOriginalHostname = d ? d.hostname : '';
  document.getElementById('domains-list').style.display = 'none';
  document.getElementById('domain-detail').classList.remove('open');
  document.getElementById('domain-form-panel').classList.add('open');
  hideDomainFormError();
  document.getElementById('domain-form-title').textContent = mode === 'edit' ? 'Edit Domain' : 'New Domain';
  document.getElementById('df-hostname').disabled = mode === 'edit';
  document.getElementById('df-hostname').value = d ? (d.hostname || '') : '';
  document.getElementById('df-tenant-id').value = d ? (d.tenantId || '') : '';
  document.getElementById('df-default-client-id').value = d ? (d.defaultClientId || '') : '';
  document.getElementById('df-is-apex').checked = d ? !!d.isApex : false;
  document.getElementById('df-branding').value = d ? formatKeyValueLines(d.branding) : '';
}

function hideDomainForm() {
  document.getElementById('domain-form-panel').classList.remove('open');
  document.getElementById('domains-list').style.display = '';
}

function showDomainFormError(msg) {
  var el = document.getElementById('domain-form-error');
  el.textContent = msg;
  el.style.display = 'block';
}

function hideDomainFormError() {
  document.getElementById('domain-form-error').style.display = 'none';
}

function readDomainForm() {
  return {
    hostname: document.getElementById('df-hostname').value.trim(),
    tenantId: document.getElementById('df-tenant-id').value.trim(),
    defaultClientId: document.getElementById('df-default-client-id').value.trim(),
    isApex: document.getElementById('df-is-apex').checked,
    branding: parseKeyValueLines(document.getElementById('df-branding').value)
  };
}

function submitDomainForm() {
  var body = readDomainForm();
  if (!body.hostname) {
    showDomainFormError('Hostname is required.');
    return;
  }
  var isEdit = domainFormMode === 'edit';
  var url = '/api/v1/admin/domains' + (isEdit ? '/' + encodeURIComponent(domainFormOriginalHostname) : '');
  apiFetch(url, {
    method: isEdit ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) return gatewayErrorMessage(r);
    hideDomainForm();
    loadDomains();
  }).catch(function(e) {
    showDomainFormError(e.message);
  });
}

function editCurrentDomain() {
  if (!currentDomainDetail) return;
  showDomainForm('edit', currentDomainDetail);
}

function deleteCurrentDomain() {
  if (!currentDomainDetail) return;
  if (!confirm('Delete domain "' + currentDomainDetail.hostname + '"? This cannot be undone.')) return;
  apiFetch('/api/v1/admin/domains/' + encodeURIComponent(currentDomainDetail.hostname), { method: 'DELETE' })
    .then(function(r) {
      if (!r.ok) return gatewayErrorMessage(r);
      closeDetail('domain');
      loadDomains();
    }).catch(function(e) { alert('Delete failed: ' + e.message); });
}

// ---- Sessions ----
function loadSessions() {
  setContent('sessions-content', '<div class="loading">Loading...</div>');
  document.getElementById('sessions-count').textContent = '';
  apiFetch('/api/v1/admin/sessions').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var sessions = d.sessions || [];
    document.getElementById('sessions-count').textContent = sessions.length + ' session(s)';
    if (!sessions.length) {
      setContent('sessions-content', '<div class="empty">No active sessions.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>Session ID</th><th>User ID</th><th>Created</th><th>Expires</th><th></th>';
    html += '</tr></thead><tbody>';
    sessions.forEach(function(s) {
      html += '<tr>';
      html += '<td><code>' + esc(s.id) + '</code></td>';
      html += '<td>' + esc(s.user_id) + '</td>';
      html += '<td>' + esc(fmtTime(s.created_at_unix)) + '</td>';
      html += '<td>' + esc(fmtTime(s.expires_at_unix)) + '</td>';
      html += '<td><button class="btn btn-danger" data-action="revoke-session" data-id="' + esc(s.id) + '">Revoke</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('sessions-content', html);
  }).catch(function(e) {
    setContent('sessions-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function revokeSession(sessionId) {
  if (!confirm('Revoke session ' + sessionId + '?')) return;
  // The admin token revoke endpoint accepts session_id in the body.
  apiFetch('/api/v1/admin/tokens/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId })
  }).then(function(r) {
    if (!r.ok) {
      return r.json().then(function(d) {
        throw new Error(d.message || 'HTTP ' + r.status);
      }).catch(function() { throw new Error('HTTP ' + r.status); });
    }
    loadSessions();
  }).catch(function(e) {
    alert('Revoke failed: ' + e.message);
  });
}

// ---- Audit Log ----
function debouncedAuditLoad() {
  clearTimeout(auditDebounceTimer);
  auditDebounceTimer = setTimeout(function() { loadAudit(1); }, 350);
}

function loadAudit(page) {
  auditCurrentPage = page || 1;
  setContent('audit-content', '<div class="loading">Loading...</div>');

  var params = new URLSearchParams();
  params.set('limit', String(auditPageSize));
  params.set('offset', String((auditCurrentPage - 1) * auditPageSize));

  var search = document.getElementById('audit-search').value.trim();
  var outcome = document.getElementById('audit-outcome').value;
  if (search) params.set('q', search);
  if (outcome) params.set('outcome', outcome);

  apiFetch('/api/v1/audit/events?' + params.toString()).then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var events = d.events || [];
    auditHasMore = events.length === auditPageSize;

    document.getElementById('audit-prev').disabled = auditCurrentPage <= 1;
    document.getElementById('audit-next').disabled = !auditHasMore;
    document.getElementById('audit-page-info').textContent = 'Page ' + auditCurrentPage;

    if (!events.length) {
      setContent('audit-content', '<div class="empty">No events found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>Time</th><th>Type</th><th>Outcome</th><th>Subject</th><th>Client</th><th>Provider</th>';
    html += '</tr></thead><tbody>';
    events.forEach(function(e) {
      var outcomeClass = e.outcome === 'success' ? 'badge-green' : (e.outcome === 'failure' ? 'badge-red' : 'badge-gray');
      html += '<tr>';
      html += '<td style="white-space:nowrap">' + esc(e.timestamp ? new Date(e.timestamp).toLocaleString() : fmtTime(e.timestamp_unix)) + '</td>';
      html += '<td><code>' + esc(e.type || e.event_type) + '</code></td>';
      html += '<td><span class="badge ' + outcomeClass + '">' + esc(e.outcome) + '</span></td>';
      html += '<td>' + esc(e.subject_id || '—') + '</td>';
      html += '<td>' + esc(e.client_id || '—') + '</td>';
      html += '<td>' + esc(e.provider || '—') + '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('audit-content', html);
  }).catch(function(e) {
    setContent('audit-content', '<div class="error-msg">' + esc(e.message) + '</div>');
    document.getElementById('audit-prev').disabled = true;
    document.getElementById('audit-next').disabled = true;
  });
}

function auditPage(dir) {
  var next = auditCurrentPage + dir;
  if (next < 1) return;
  if (dir > 0 && !auditHasMore) return;
  loadAudit(next);
}

// ---- Keyboard shortcut ----
document.getElementById('token-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') doLogin();
});

// ---- Event wiring ----
// Every control below used to be an inline onclick/oninput/onchange
// attribute. Those are inline scripts under CSP (script-src), so with the
// SDK's security-headers default enabled (no 'unsafe-inline') the browser
// would silently refuse to run them. addEventListener always runs regardless
// of CSP script-src, so wiring is centralized here instead.
function wireStaticEventHandlers() {
  document.getElementById('login-btn').addEventListener('click', doLogin);
  document.getElementById('logout-btn').addEventListener('click', doLogout);
  var ssoBtn = document.getElementById('sso-login-btn');
  if (window.crypto && window.crypto.subtle) {
    ssoBtn.addEventListener('click', startSSOLogin);
  } else {
    // crypto.subtle needs a secure context (HTTPS, or localhost) — hide
    // the button rather than offer a control that will always fail with
    // a confusing error on a plain-HTTP deployment.
    ssoBtn.style.display = 'none';
    document.querySelector('.sso-login-hint').style.display = 'none';
    document.querySelector('.login-divider').style.display = 'none';
  }
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.addEventListener('click', function() { navigate(el.dataset.page); });
  });
  document.getElementById('client-detail-back').addEventListener('click', function() {
    closeDetail('client');
  });
  document.getElementById('user-detail-back').addEventListener('click', function() {
    closeDetail('user');
  });
  document.getElementById('tenant-detail-back').addEventListener('click', function() {
    closeDetail('tenant');
  });
  document.getElementById('domain-detail-back').addEventListener('click', function() {
    closeDetail('domain');
  });
  document.getElementById('client-new-btn').addEventListener('click', function() {
    showClientForm('create', null);
  });
  document.getElementById('client-form-back').addEventListener('click', hideClientForm);
  document.getElementById('client-form-save').addEventListener('click', submitClientForm);
  document.getElementById('client-detail-actions').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var actions = {
      'edit-client': editCurrentClient,
      'delete-client': deleteCurrentClient,
      'approve-client': approveCurrentClient,
      'reject-client': rejectCurrentClient,
      'rotate-secret': rotateCurrentClientSecret
    };
    var fn = actions[btn.dataset.action];
    if (fn) fn();
  });
  document.getElementById('user-new-btn').addEventListener('click', function() {
    showUserForm('create', null);
  });
  document.getElementById('user-form-back').addEventListener('click', hideUserForm);
  document.getElementById('user-form-save').addEventListener('click', submitUserForm);
  document.getElementById('user-detail-actions').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var actions = { 'edit-user': editCurrentUser, 'delete-user': deleteCurrentUser };
    var fn = actions[btn.dataset.action];
    if (fn) fn();
  });
  document.getElementById('tenant-new-btn').addEventListener('click', function() {
    showTenantForm('create', null);
  });
  document.getElementById('tenant-form-back').addEventListener('click', hideTenantForm);
  document.getElementById('tenant-form-save').addEventListener('click', submitTenantForm);
  document.getElementById('tenant-detail-actions').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var actions = {
      'edit-tenant': editCurrentTenant,
      'delete-tenant': deleteCurrentTenant,
      'suspend-tenant': function() { setCurrentTenantStatus('suspended'); },
      'activate-tenant': function() { setCurrentTenantStatus('active'); }
    };
    var fn = actions[btn.dataset.action];
    if (fn) fn();
  });
  document.getElementById('domain-new-btn').addEventListener('click', function() {
    showDomainForm('create', null);
  });
  document.getElementById('domain-form-back').addEventListener('click', hideDomainForm);
  document.getElementById('domain-form-save').addEventListener('click', submitDomainForm);
  document.getElementById('domain-detail-actions').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var actions = { 'edit-domain': editCurrentDomain, 'delete-domain': deleteCurrentDomain };
    var fn = actions[btn.dataset.action];
    if (fn) fn();
  });
  document.getElementById('audit-search').addEventListener('input', debouncedAuditLoad);
  document.getElementById('audit-outcome').addEventListener('change', function() { loadAudit(1); });
  document.getElementById('audit-prev').addEventListener('click', function() { auditPage(-1); });
  document.getElementById('audit-next').addEventListener('click', function() { auditPage(1); });

  // Delegated listeners for rows rendered after the initial page load
  // (client/user "View", session "Revoke") — the parent container node is
  // stable across setContent() re-renders, so one listener attached here
  // covers every future render.
  document.getElementById('clients-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="view-client"]');
    if (btn) showClientDetail(clientsCache[btn.dataset.id]);
  });
  document.getElementById('users-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="view-user"]');
    if (btn) showUserDetail(usersCache[btn.dataset.id]);
  });
  document.getElementById('tenants-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="view-tenant"]');
    if (btn) showTenantDetail(tenantsCache[btn.dataset.id]);
  });
  document.getElementById('domains-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="view-domain"]');
    if (btn) showDomainDetail(domainsCache[btn.dataset.id]);
  });
  document.getElementById('sessions-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="revoke-session"]');
    if (btn) revokeSession(btn.dataset.id);
  });
}
wireStaticEventHandlers();

// ---- Boot ----
(function() {
  // A returning OAuth redirect (?code=&state= or ?error=) takes priority
  // over resuming a saved token — it's this tab's current, in-progress
  // login attempt.
  if (handleOAuthCallback()) return;
  var saved = sessionStorage.getItem('sso_admin_token');
  if (saved) {
    token = saved;
    showApp();
  }
})();
