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
  var splitLines = function(s) { return s.split('\n').map(function(x) { return x.trim(); }).filter(Boolean); };
  var splitSpace = function(s) { return s.trim().split(/\s+/).filter(Boolean); };
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
  }
}

// ---- Users ----
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
  document.getElementById('users-list').style.display = 'none';
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
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.addEventListener('click', function() { navigate(el.dataset.page); });
  });
  document.getElementById('client-detail-back').addEventListener('click', function() {
    closeDetail('client');
  });
  document.getElementById('user-detail-back').addEventListener('click', function() {
    closeDetail('user');
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
  document.getElementById('sessions-content').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action="revoke-session"]');
    if (btn) revokeSession(btn.dataset.id);
  });
}
wireStaticEventHandlers();

// ---- Boot ----
(function() {
  var saved = sessionStorage.getItem('sso_admin_token');
  if (saved) {
    token = saved;
    showApp();
  }
})();
