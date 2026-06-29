package oidc

import (
	"html/template"
	"net/http"
)

// DeviceVerifyData carries values rendered into the device verification HTML page.
type DeviceVerifyData struct {
	UserCode string // pre-filled user_code from query param
}

var deviceVerifyTemplate = template.Must(template.New("deviceVerify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device Verification</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:#f5f5f7;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#1d1d1f;line-height:1.5}
.container{background:#fff;border-radius:16px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:40px 32px;max-width:400px;width:90%;text-align:center}
h1{font-size:24px;font-weight:600;margin-bottom:8px}
p{font-size:15px;color:#6e6e73;margin-bottom:24px}
input{width:100%;padding:14px 16px;font-size:18px;letter-spacing:2px;text-align:center;border:2px solid #d2d2d7;border-radius:12px;outline:none;transition:border-color .2s;font-family:monospace}
input:focus{border-color:#0071e3}
button{width:100%;padding:14px;font-size:17px;font-weight:500;color:#fff;background:#0071e3;border:none;border-radius:12px;cursor:pointer;transition:background .2s;margin-top:16px}
button:hover{background:#0077ed}
button:disabled{opacity:.5;cursor:not-allowed}
.spinner{display:inline-block;width:36px;height:36px;border:3px solid #e8e8ed;border-top-color:#0071e3;border-radius:50%;animation:spin .8s linear infinite;margin:16px 0}
@keyframes spin{to{transform:rotate(360deg)}}
.status-text{font-size:15px;color:#6e6e73;margin-top:8px}
.success-icon{font-size:48px;color:#30d158;margin-bottom:8px}
.error-icon{font-size:48px;color:#ff453a;margin-bottom:8px}
.redirect-note{font-size:13px;color:#8e8e93;margin-top:16px}
.invalid-code{color:#ff453a;font-size:14px;margin-top:8px;display:none}
</style>
</head>
<body>
<div class="container">
  <div id="form-section">
    <h1>Device Verification</h1>
    <p>Enter the code displayed on your device.</p>
    <form id="code-form" onsubmit="return submitCode()">
      <input type="text" id="code-input" name="user_code"
             placeholder="e.g. ABCD-1234" autocomplete="off"
             autofocus required>
      <div class="invalid-code" id="invalid-code">Please enter a valid code.</div>
      <button type="submit" id="submit-btn">Verify</button>
    </form>
    <p class="redirect-note">Having trouble? Make sure you entered the code exactly as shown.</p>
  </div>

  <div id="polling-section" style="display:none">
    <h1>Authorization Requested</h1>
    <p>Now check your device and approve the request.</p>
    <div class="spinner"></div>
    <p class="status-text" id="status-message">Waiting for approval…</p>
  </div>

  <div id="success-section" style="display:none">
    <div class="success-icon">✓</div>
    <h1>Device Authorized</h1>
    <p>You have successfully authorized this device. You may close this page.</p>
    <p class="redirect-note" id="redirect-message"></p>
  <div id="redirect-uri" data-uri="" style="display:none"></div>
  </div>

  <div id="denied-section" style="display:none">
    <div class="error-icon">✗</div>
    <h1>Access Denied</h1>
    <p>The authorization request was denied.</p>
  </div>

  <div id="expired-section" style="display:none">
    <div class="error-icon">✗</div>
    <h1>Code Expired</h1>
    <p>This verification code has expired. Please request a new code on your device.</p>
  </div>

  <div id="error-section" style="display:none">
    <div class="error-icon">✗</div>
    <h1>Something Went Wrong</h1>
    <p class="status-text" id="error-message">An unexpected error occurred.</p>
  </div>
</div>

<script>
(function(){
  var codeInput = document.getElementById('code-input');
  var userCode = "{{.UserCode}}";
  if (typeof userCode === 'string' && userCode.length > 0) {
    codeInput.value = userCode;
  }

  var ru = new URLSearchParams(window.location.search).get('redirect_uri');
  if (ru) {
    try {
      var p = new URL(ru);
      if (p.protocol === 'https:' || p.protocol === 'http:') {
        document.getElementById('redirect-uri').setAttribute('data-uri', p.href);
      }
    } catch(e) {}
  }
})();

function submitCode() {
  var input = document.getElementById('code-input');
  var code = input.value.trim();
  if (!code) {
    document.getElementById('invalid-code').style.display = 'block';
    return false;
  }
  document.getElementById('invalid-code').style.display = 'none';
  document.getElementById('form-section').style.display = 'none';
  document.getElementById('polling-section').style.display = 'block';
  pollStatus(code);
  return false;
}

function pollStatus(code) {
  (function poll() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/device/verify?check=' + encodeURIComponent(code), true);
    xhr.onload = function() {
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          switch (data.status) {
            case 'approved':
              showSuccess();
              return;
            case 'denied':
              showDenied();
              return;
            case 'expired':
              showExpired();
              return;
            case 'not_found':
            case 'invalid':
              showError('Invalid code. Please try again with the correct code from your device.');
              return;
            case 'pending':
              document.getElementById('status-message').textContent = 'Waiting for approval\u2026';
              setTimeout(poll, 3000);
              return;
            default:
              setTimeout(poll, 3000);
              return;
          }
        } catch(e) {
          setTimeout(poll, 3000);
        }
      } else {
        setTimeout(poll, 3000);
      }
    };
    xhr.onerror = function() {
      setTimeout(poll, 3000);
    };
    xhr.send();
  })();
}

function showSuccess() {
  document.getElementById('polling-section').style.display = 'none';
  document.getElementById('success-section').style.display = 'block';
  var ru = document.getElementById('redirect-uri').getAttribute('data-uri');
  if (ru) {
    try {
      var parsed = new URL(ru);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') { return; }
    } catch(e) { return; }
    var msg = document.getElementById('redirect-message');
    var a = document.createElement('a');
    a.href = parsed.href;
    a.textContent = parsed.href;
    msg.textContent = 'Redirecting to ';
    msg.appendChild(a);
    msg.appendChild(document.createTextNode('\u2026'));
    setTimeout(function(){ window.location.href = parsed.href; }, 2000);
  }
}

function showDenied() {
  document.getElementById('polling-section').style.display = 'none';
  document.getElementById('denied-section').style.display = 'block';
}

function showExpired() {
  document.getElementById('polling-section').style.display = 'none';
  document.getElementById('expired-section').style.display = 'block';
}

function showError(msg) {
  document.getElementById('polling-section').style.display = 'none';
  document.getElementById('error-section').style.display = 'block';
  document.getElementById('error-message').textContent = msg || 'An unexpected error occurred.';
}
<\/script>
</body>
</html>
`))

// RenderDeviceVerifyPage writes the RFC 8628 device verification HTML page. The
// page shows a simple form for entering a user_code, then polls for approval
// status. No authentication is required to view this page.
func RenderDeviceVerifyPage(w http.ResponseWriter, userCode string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = deviceVerifyTemplate.Execute(w, DeviceVerifyData{
		UserCode: userCode,
	})
}
