// ---- State ----
var token = '';
var currentPage = 'dashboard';
var auditCurrentPage = 1;
var auditHasMore = false;
var auditDebounceTimer = null;
var auditPageSize = 50;

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
function loadClients() {
  closeDetail('client');
  setContent('clients-content', '<div class="loading">Loading...</div>');
  apiFetch('/api/v1/admin/clients').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).then(function(d) {
    var clients = d.clients || [];
    if (!clients.length) {
      setContent('clients-content', '<div class="empty">No clients found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>ID</th><th>Name</th><th>Status</th><th>Strategy</th><th>Scopes</th><th></th>';
    html += '</tr></thead><tbody>';
    clients.forEach(function(c) {
      html += '<tr>';
      html += '<td><code>' + esc(c.id) + '</code></td>';
      html += '<td>' + esc(c.name) + '</td>';
      html += '<td>' + badge(c.active, 'Active', 'badge-green', 'Inactive', 'badge-red') + '</td>';
      html += '<td><span class="badge badge-blue">' + esc(c.token_strategy || 'jwt') + '</span></td>';
      html += '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc((c.allowed_scopes || []).join(' ')) + '</td>';
      html += '<td><button class="btn btn-sm" onclick="showClientDetail(' + JSON.stringify(JSON.stringify(c)) + ')">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('clients-content', html);
  }).catch(function(e) {
    setContent('clients-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showClientDetail(jsonStr) {
  var c = JSON.parse(jsonStr);
  document.getElementById('clients-list').style.display = 'none';
  document.getElementById('client-detail').classList.add('open');

  var rows = [
    ['ID', '<code>' + esc(c.id) + '</code>'],
    ['Name', esc(c.name)],
    ['Active', badge(c.active, 'Active', 'badge-green', 'Inactive', 'badge-red')],
    ['Token Strategy', '<span class="badge badge-blue">' + esc(c.token_strategy || 'jwt') + '</span>'],
    ['Allowed Scopes', esc((c.allowed_scopes || []).join(', '))],
    ['Redirect URIs', esc((c.redirect_uris || []).join('\n') || '—')],
    ['Allowed Authenticators', esc((c.allowed_authenticators || []).join(', ') || '—')],
    ['Require PKCE', badge(c.require_pkce, 'Yes', 'badge-green', 'No', 'badge-gray')],
  ];
  var html = rows.map(function(r) {
    return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
  }).join('');
  document.getElementById('client-detail-table').innerHTML = html;
}

function closeDetail(type) {
  if (type === 'client') {
    document.getElementById('clients-list').style.display = '';
    document.getElementById('client-detail').classList.remove('open');
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
    if (!users.length) {
      setContent('users-content', '<div class="empty">No users found.</div>');
      return;
    }
    var html = '<table><thead><tr>';
    html += '<th>ID</th><th>External ID</th><th>Provider</th><th></th>';
    html += '</tr></thead><tbody>';
    users.forEach(function(u) {
      html += '<tr>';
      html += '<td><code>' + esc(u.id) + '</code></td>';
      html += '<td>' + esc(u.external_id || '—') + '</td>';
      html += '<td><span class="badge badge-blue">' + esc(u.provider || '—') + '</span></td>';
      html += '<td><button class="btn btn-sm" onclick="showUserDetail(' + JSON.stringify(JSON.stringify(u)) + ')">View</button></td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    setContent('users-content', html);
  }).catch(function(e) {
    setContent('users-content', '<div class="error-msg">' + esc(e.message) + '</div>');
  });
}

function showUserDetail(jsonStr) {
  var u = JSON.parse(jsonStr);
  document.getElementById('users-list').style.display = 'none';
  document.getElementById('user-detail').classList.add('open');

  var rows = [
    ['ID', '<code>' + esc(u.id) + '</code>'],
    ['External ID', esc(u.external_id || '—')],
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
      html += '<td><button class="btn btn-danger" onclick="revokeSession(' + JSON.stringify(s.id) + ')">Revoke</button></td>';
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

// ---- Boot ----
(function() {
  var saved = sessionStorage.getItem('sso_admin_token');
  if (saved) {
    token = saved;
    showApp();
  }
})();
