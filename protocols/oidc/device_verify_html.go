package oidc

import (
	"html/template"
	"net/http"
)

// DeviceVerifyData carries values rendered into the device verification HTML page.
type DeviceVerifyData struct {
	UserCode   string   // pre-filled user_code from query param
	ClientID   string   // client_id when info is available
	ClientName string   // display name of the requesting application
	Scopes     []string // requested scopes
}

var deviceVerifyTemplate = template.Must(template.New("deviceVerify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device Verification</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--brand-primary:#6366f1;--brand-primary-hover:#4f46e5}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f3f4f6;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#111827;line-height:1.5}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 4px 16px rgba(0,0,0,.06);max-width:420px;width:90%;padding:36px 32px}
h1{font-size:1.2rem;font-weight:600;text-align:center;margin-bottom:4px}
.subtitle{font-size:.875rem;color:#6b7280;text-align:center;margin-bottom:20px}
.view{display:none}.view.active{display:block}
label{display:block;font-size:.875rem;font-weight:500;margin-bottom:4px;color:#374151}
input[type="text"],input[type="password"]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:.9375rem;color:#111827;background:#fff;transition:border-color .15s;outline:none}
input:focus{border-color:var(--brand-primary);box-shadow:0 0 0 3px rgba(99,102,241,.15)}
.field{margin-bottom:16px}
.btn{width:100%;padding:11px;border:none;border-radius:8px;font-size:.9375rem;font-weight:600;cursor:pointer;transition:background .15s,transform .1s;display:inline-flex;align-items:center;justify-content:center;gap:8px}
.btn:active{transform:scale(.98)}
.btn-primary{background:var(--brand-primary);color:#fff}
.btn-primary:hover{background:var(--brand-primary-hover)}
.btn-secondary{background:transparent;color:var(--brand-primary);border:1px solid #d1d5db;margin-top:8px}
.btn-secondary:hover{background:#f9fafb}
.btn-row{margin-top:20px}
.error-box{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;color:#991b1b;font-size:.875rem;padding:10px 12px;margin-bottom:16px;display:none}
.error-box.visible{display:block}
.success-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;color:#166534;font-size:.875rem;padding:10px 12px;margin-bottom:16px;text-align:center;display:none}
.success-box.visible{display:block}
.device-info{border:1px solid #e5e7eb;border-radius:8px;padding:14px;margin-bottom:20px;background:#f9fafb}
.device-info .app-name{font-weight:600;font-size:.95rem;color:#111827;margin-bottom:4px}
.device-info .code-display{font-size:1.1rem;letter-spacing:2px;font-family:monospace;color:var(--brand-primary);font-weight:600;margin-bottom:8px}
.scope-list{list-style:none;margin-top:8px}
.scope-list li{padding:4px 0;font-size:.85rem;color:#6b7280;display:flex;align-items:center;gap:6px}
.scope-list li::before{content:"";display:inline-block;width:6px;height:6px;background:var(--brand-primary);border-radius:50%;flex-shrink:0}
.spinner{display:none;width:18px;height:18px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite}
.loading .spinner{display:inline-block}
.loading .btn-label{display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.big-spinner{display:inline-block;width:36px;height:36px;border:3px solid #e8e8ed;border-top-color:var(--brand-primary);border-radius:50%;animation:spin .8s linear infinite;margin:16px 0}
.status-text{font-size:.875rem;color:#6b7280;margin-top:8px;text-align:center}
.success-icon{font-size:48px;color:#22c55e;margin-bottom:8px;text-align:center}
.error-icon{font-size:48px;color:#ef4444;margin-bottom:8px;text-align:center}
.redirect-note{font-size:.8rem;color:#9ca3af;margin-top:16px;text-align:center}
.back-link{display:block;text-align:center;margin-top:16px;font-size:.875rem;color:#6b7280;cursor:pointer;text-decoration:underline}
.back-link:hover{color:var(--brand-primary)}
.logo{text-align:center;margin-bottom:20px}
.logo svg{width:40px;height:40px;display:inline-block}
</style>
</head>
<body>
<div class="card">
<div class="logo">
<svg viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><rect width="44" height="44" rx="10" fill="var(--brand-primary)"/><path d="M22 10C15.373 10 10 15.373 10 22s5.373 12 12 12 12-5.373 12-12S28.627 10 22 10zm0 5a4 4 0 110 8 4 4 0 010-8zm0 17c-3.315 0-6.26-1.517-8.2-3.9a9.96 9.96 0 0116.4 0C28.26 30.483 25.315 32 22 32z" fill="#fff"/></svg>
</div>

<!-- Form section: enter user_code -->
<div id="view-form" class="view active">
<h1>Device Verification</h1>
<p class="subtitle">Enter the code shown on your device.</p>
<form id="code-form" onsubmit="return submitCode()">
<div class="field">
<label for="code-input">Verification code</label>
<input type="text" id="code-input" name="user_code"
placeholder="e.g. ABCD-1234" autocomplete="off"
autofocus required style="letter-spacing:2px;text-align:center;font-family:monospace;font-size:1.1rem">
</div>
<div class="error-box" id="code-error">Please enter a valid code.</div>
<button type="submit" class="btn btn-primary" id="submit-btn"><span class="btn-label">Verify</span><span class="spinner"></span></button>
</form>
<p class="redirect-note">Having trouble? Make sure you entered the code exactly as shown on your device.</p>
</div>

<!-- Sign-in section: login form + device info -->
<div id="view-signin" class="view">
<h1>Authorize this device</h1>
<p class="subtitle">Sign in to approve the authorization request.</p>
<div class="device-info" id="device-info">
<div class="app-name" id="info-client-name">Application</div>
<div class="code-display" id="info-user-code">ABCD-1234</div>
<div style="font-size:.8rem;color:#9ca3af">Requesting access to:</div>
<ul class="scope-list" id="info-scopes"></ul>
</div>
<div class="error-box" id="signin-error"></div>
<form id="signin-form" onsubmit="return submitSignin()">
<div class="field">
<label for="username">Username</label>
<input type="text" id="username" name="username" autocomplete="username" required placeholder="you@example.com">
</div>
<div class="field">
<label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required>
</div>
<div class="btn-row">
<button type="submit" class="btn btn-primary" id="signin-btn"><span class="btn-label">Sign in &amp; Approve</span><span class="spinner"></span></button>
</div>
</form>
<a class="back-link" id="back-to-form">Use a different code</a>
</div>

<!-- Polling section: waiting for approval (POST-approval polling) -->
<div id="view-polling" class="view">
<h1>Authorization Requested</h1>
<p class="subtitle">Now check your device and approve the request.</p>
<div style="text-align:center"><div class="big-spinner"></div></div>
<p class="status-text" id="poll-status">Waiting for approval...</p>
</div>

<!-- Success section -->
<div id="view-success" class="view">
<div class="success-icon">&#10003;</div>
<h1>Device Authorized</h1>
<p style="text-align:center;font-size:.9rem;color:#6b7280">You have successfully authorized this device. You may close this page.</p>
<div id="redirect-uri" data-uri="" style="display:none"></div>
</div>

<!-- Denied section -->
<div id="view-denied" class="view">
<div class="error-icon">&#10007;</div>
<h1>Access Denied</h1>
<p style="text-align:center;font-size:.9rem;color:#6b7280">The authorization request was denied.</p>
</div>

<!-- Expired section -->
<div id="view-expired" class="view">
<div class="error-icon">&#10007;</div>
<h1>Code Expired</h1>
<p style="text-align:center;font-size:.9rem;color:#6b7280">This verification code has expired. Please request a new code on your device.</p>
</div>

<!-- Error section -->
<div id="view-error" class="view">
<div class="error-icon">&#10007;</div>
<h1>Something Went Wrong</h1>
<p class="status-text" id="error-message">An unexpected error occurred.</p>
<a class="back-link" id="error-back">Try again</a>
</div>
</div>

<script>
(function(){
"use strict";

// ---- State ----
var currentUserCode = "";
var currentBearerToken = "";
var pollingTimer = null;

// ---- DOM shortcuts ----
function $(id){return document.getElementById(id)}

function showView(name){
["view-form","view-signin","view-polling","view-success","view-denied","view-expired","view-error"].forEach(function(v){
var el = $(v);
if(el) el.classList.toggle("active", v === "view-" + name);
});
}

function setError(boxId, msg){
var box = $(boxId);
if(!box) return;
if(msg){
box.textContent = msg;
box.classList.add("visible");
} else {
box.textContent = "";
box.classList.remove("visible");
}
}

function setLoading(btn, loading){
btn.disabled = loading;
btn.classList.toggle("loading", loading);
}

// ---- Pre-fill user_code from query param ----
var initialCode = "{{.UserCode}}";
if(typeof initialCode === "string" && initialCode.length > 0){
$("code-input").value = initialCode;
}

// ---- Back button ----
$("back-to-form").addEventListener("click", function(){
showView("form");
setError("signin-error", "");
currentUserCode = "";
currentBearerToken = "";
});

$("error-back").addEventListener("click", function(){
showView("form");
setError("code-error", "");
});

// ---- Step 1: Submit code ----
function submitCode(){
var input = $("code-input");
var code = input.value.trim();
if(!code){
setError("code-error", "Please enter a valid code.");
return false;
}
setError("code-error", "");
setLoading($("submit-btn"), true);

var xhr = new XMLHttpRequest();
xhr.open("GET", "/device/verify?info=" + encodeURIComponent(code), true);
xhr.onload = function(){
setLoading($("submit-btn"), false);
if(xhr.status === 200){
try{
var data = JSON.parse(xhr.responseText);
if(data.status === "ok"){
showSignin(code, data);
return;
}
}catch(e){}
}
// If info endpoint returns error or unknown code, show the polling flow as fallback
// (the device might already be approved by another channel)
currentUserCode = code;
showView("polling");
$("poll-status").textContent = "Checking status...";
pollStatus(code);
};
xhr.onerror = function(){
setLoading($("submit-btn"), false);
// Fallback: start polling
currentUserCode = code;
showView("polling");
$("poll-status").textContent = "Waiting for approval...";
pollStatus(code);
};
xhr.send();
return false;
}

// ---- Step 2: Show sign-in form with device info ----
function showSignin(code, info){
currentUserCode = code;
$("info-client-name").textContent = info.client_name || "Application";
$("info-client-name").setAttribute("data-client-id", info.client_id || "");
$("info-user-code").textContent = code;
var list = $("info-scopes");
list.innerHTML = "";
var scopes = info.scopes || [];
if(scopes.length === 0){
var li = document.createElement("li");
li.textContent = "Basic access";
list.appendChild(li);
} else {
scopes.forEach(function(s){
var li = document.createElement("li");
li.textContent = s;
list.appendChild(li);
});
}
showView("signin");
setError("signin-error", "");
}

// ---- Step 3: Submit login credentials ----
function submitSignin(){
var username = $("username").value.trim();
var password = $("password").value;
if(!username || !password){
setError("signin-error", "Please enter your username and password.");
return false;
}
setError("signin-error", "");
setLoading($("signin-btn"), true);

var clientId = $("info-client-name").getAttribute("data-client-id") || "";

// POST to /auth/login
var body = JSON.stringify({
provider: "password",
client_id: clientId,
credential: {username: username, password: password}
});

var xhr = new XMLHttpRequest();
xhr.open("POST", "/auth/login", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.onload = function(){
setLoading($("signin-btn"), false);
if(xhr.status === 200){
try{
var data = JSON.parse(xhr.responseText);
if(data.access_token){
currentBearerToken = data.access_token;
approveDevice();
return;
}
}catch(e){}
}
// Login failed
try{
var err = JSON.parse(xhr.responseText);
setError("signin-error", err.error_description || err.error || "Authentication failed. Please try again.");
}catch(e){
setError("signin-error", "Authentication failed. Please try again.");
}
};
xhr.onerror = function(){
setLoading($("signin-btn"), false);
setError("signin-error", "Network error. Please try again.");
};
xhr.send(body);
return false;
}

// ---- Step 4: Approve device with bearer token ----
function approveDevice(){
var body = JSON.stringify({user_code: currentUserCode, approve: true});
var xhr = new XMLHttpRequest();
xhr.open("POST", "/device/verify", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.setRequestHeader("Authorization", "Bearer " + currentBearerToken);
xhr.onload = function(){
if(xhr.status === 200){
// Approved -- show polling to wait for token issuance
showView("polling");
$("poll-status").textContent = "Approved... waiting for token";
pollStatus(currentUserCode);
} else if(xhr.status === 400){
// Already approved or other state -- start polling
showView("polling");
$("poll-status").textContent = "Waiting for token...";
pollStatus(currentUserCode);
} else {
showView("error");
$("error-message").textContent = "Failed to authorize device. Please try again.";
}
};
xhr.onerror = function(){
showView("error");
$("error-message").textContent = "Network error. Please try again.";
};
xhr.send(body);
}

// ---- Step 5: Poll device status ----
function pollStatus(code){
if(pollingTimer) clearTimeout(pollingTimer);
(function poll(){
var xhr = new XMLHttpRequest();
xhr.open("GET", "/device/verify?check=" + encodeURIComponent(code), true);
xhr.onload = function(){
if(xhr.status === 200){
try{
var data = JSON.parse(xhr.responseText);
switch(data.status){
case "approved":
showView("success");
showRedirect();
return;
case "denied":
showView("denied");
return;
case "expired":
showView("expired");
return;
case "not_found":
case "invalid":
showView("error");
$("error-message").textContent = "Invalid code. Please try again with the correct code from your device.";
return;
case "pending":
$("poll-status").textContent = "Waiting for approval...";
pollingTimer = setTimeout(poll, 3000);
return;
default:
pollingTimer = setTimeout(poll, 3000);
return;
}
}catch(e){
pollingTimer = setTimeout(poll, 3000);
}
} else {
pollingTimer = setTimeout(poll, 3000);
}
};
xhr.onerror = function(){
pollingTimer = setTimeout(poll, 3000);
};
xhr.send();
})();
}

// ---- Redirect handling ----
function showRedirect(){
var ru = $("redirect-uri").getAttribute("data-uri");
if(ru){
try{
var parsed = new URL(ru);
if(parsed.protocol !== "https:" && parsed.protocol !== "http:") return;
}catch(e){ return; }
var msg = document.createElement("p");
msg.style.cssText = "text-align:center;font-size:.8rem;color:#9ca3af;margin-top:12px";
msg.textContent = "Redirecting to " + ru + "...";
$("view-success").appendChild(msg);
setTimeout(function(){ window.location.href = ru; }, 2000);
}
}

// ---- Parse redirect_uri from query ----
var ru = new URLSearchParams(window.location.search).get("redirect_uri");
if(ru){
try{
var p = new URL(ru);
if(p.protocol === "https:" || p.protocol === "http:"){
$("redirect-uri").setAttribute("data-uri", p.href);
}
}catch(e){}
}

// ---- Expose submitCode globally for form onsubmit ----
window.submitCode = submitCode;
window.submitSignin = submitSignin;

})();
</script>
</body>
</html>
`))

// RenderDeviceVerifyPage writes the RFC 8628 device verification HTML page. The
// page shows a form for entering a user_code, an inline sign-in form for
// authentication, and polls for approval status. No authentication is
// required to view this page.
//
// When data.ClientID is non-empty the page can inline the client name; the
// scopes and client_name are rendered as device info on the sign-in view.
func RenderDeviceVerifyPage(w http.ResponseWriter, data DeviceVerifyData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = deviceVerifyTemplate.Execute(w, data)
}
