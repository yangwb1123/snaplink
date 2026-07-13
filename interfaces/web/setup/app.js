(function () {
  "use strict";

  // The SPA is served at /setup/, so server APIs are one level up.
  var statusURL = "../api/v1/setup/status";
  var setupURL = "../api/v1/setup";
  var brandingURL = "../branding";

  // Collected across steps; POSTed once at the end.
  var admin = null;

  function $(id) { return document.getElementById(id); }

  function showView(name) {
    ["loading", "already", "admin", "app", "done"].forEach(function (v) {
      $("view-" + v).classList.toggle("active", v === name);
    });
    // Step dots: 1 on the admin step, 1+2 on the app step.
    var steps = $("steps");
    if (name === "admin" || name === "app") {
      steps.style.display = "flex";
      $("dot-1").classList.toggle("on", name === "admin" || name === "app");
      $("dot-2").classList.toggle("on", name === "app");
    } else {
      steps.style.display = "none";
    }
  }

  function setError(boxId, msg) {
    var box = $(boxId);
    if (msg) { box.textContent = msg; box.classList.add("visible"); }
    else { box.textContent = ""; box.classList.remove("visible"); }
  }

  function setLoading(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("loading", on);
  }

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  // Best-effort white-label theming, identical contract to the login SPA.
  (function loadBranding() {
    fetch(brandingURL, { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var b = data && data.branding;
        if (!b) { return; }
        if (b.primary_color) {
          document.documentElement.style.setProperty("--brand-primary", b.primary_color);
          document.documentElement.style.setProperty("--brand-primary-hover", b.primary_color);
        }
        if (b.logo_url) {
          var img = $("brand-logo"), mark = $("brand-mark");
          img.src = b.logo_url; img.style.display = "inline-block";
          if (mark) { mark.style.display = "none"; }
        }
        if (b.brand_name) { document.title = "Setup - " + b.brand_name; }
      })
      .catch(function () {});
  })();

  // Decide the entry view: already-initialized deployments show the bounce.
  (function init() {
    fetch(statusURL, { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : { setup_required: true }; })
      .then(function (d) { showView(d && d.setup_required ? "admin" : "already"); })
      .catch(function () { showView("admin"); });
  })();

  // Step 1: capture the first admin, advance to the optional app step.
  $("admin-form").addEventListener("submit", function (e) {
    e.preventDefault();
    setError("admin-error", "");
    var u = $("username").value.trim();
    var p = $("password").value;
    var p2 = $("password2").value;
    if (!u) { setError("admin-error", "Please enter a username."); return; }
    if (p.length < 8) { setError("admin-error", "Password must be at least 8 characters."); return; }
    if (p !== p2) { setError("admin-error", "Passwords do not match."); return; }
    admin = { username: u, password: p };
    showView("app");
  });

  // Step 2 submit: register the first application, then finish.
  $("app-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var name = $("app-name").value.trim();
    var redirect = $("app-redirect").value.trim();
    if (!name) { setError("app-error", "Enter an application name, or use Skip and finish."); return; }
    var app = { name: name };
    if (redirect) { app.redirect_uris = [redirect]; }
    finish($("app-btn"), app);
  });

  // Skip: finish with the admin only.
  $("skip-btn").addEventListener("click", function () {
    finish($("skip-btn"), null);
  });

  // POST the collected setup and render the result.
  function finish(btn, app) {
    setError("app-error", "");
    setLoading(btn, true);
    var payload = { admin: admin };
    if (app) { payload.application = app; }
    fetch(setupURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function (r) { return r.json().then(function (d) { return { status: r.status, data: d }; }); })
      .then(function (res) {
        setLoading(btn, false);
        if (res.status === 200 && res.data.ok) { renderDone(res.data.created || {}); return; }
        if (res.status === 409) { showView("already"); return; }
        setError("app-error", (res.data && res.data.error) ? ("Setup failed: " + res.data.error) : "Setup failed.");
      })
      .catch(function () { setLoading(btn, false); setError("app-error", "Network error. Please try again."); });
  }

  function renderDone(created) {
    var html = "<div class=\"cred\">Admin username: <b>" + esc(created.admin) + "</b></div>";
    if (created.application) {
      html += "<div class=\"cred\">Application <b>client_id</b>: " + esc(created.application.client_id) +
        "<br>Application <b>client_secret</b>: " + esc(created.application.client_secret) +
        "<span class=\"warn\">Copy the client secret now - it is not shown again.</span></div>";
    }
    $("done-detail").innerHTML = html;
    showView("done");
  }
})();
