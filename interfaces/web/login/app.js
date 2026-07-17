(function () {
  "use strict";

  // --- Parse OAuth params from the query string ---
  var q = new URLSearchParams(location.search);
  var oauthParams = {
    client_id:             q.get("client_id")             || "",
    scope:                 (q.get("scope") || "openid").split(" ").filter(Boolean),
    state:                 q.get("state")                 || "",
    response_type:         q.get("response_type")         || "",
    redirect_uri:          q.get("redirect_uri")          || "",
    nonce:                 q.get("nonce")                  || "",
    code_challenge:        q.get("code_challenge")         || "",
    code_challenge_method: q.get("code_challenge_method")  || "",
    resource:              q.getAll("resource"),
    provider:              q.get("provider")               || "password",
  };

  // --- DOM helpers ---
  function $(id) { return document.getElementById(id); }

  // --- i18n bootstrap ---
  // Kicks off the locale bundle fetch immediately, in parallel with the
  // branding/provider probes below; applyDOM re-paints every data-i18n-
  // tagged element once the bundle lands. A slow/failed fetch just leaves
  // the English fallback markup already baked into index.html on screen —
  // never a blank page (see i18n.js's fetchBundle/t doc comments).
  i18n.init({
    basePath: "locales/",
    supported: ["en", "es"],
    defaultLocale: "en"
  }).then(function () {
    i18n.applyDOM(document);
    document.documentElement.lang = i18n.locale;
  });

  function showView(name) {
    ["login","mfa","consent","success"].forEach(function(v) {
      var el = $("view-" + v);
      el.classList.toggle("active", v === name);
    });
  }

  function setError(boxId, msg) {
    var box = $(boxId);
    if (msg) {
      box.textContent = msg;
      box.classList.add("visible");
    } else {
      box.textContent = "";
      box.classList.remove("visible");
    }
  }

  function setLoading(btn, loading) {
    btn.disabled = loading;
    btn.classList.toggle("loading", loading);
  }

  // --- Build relative /auth/login URL ---
  // The SPA is at /login/ and the endpoint is at /auth/login.
  // From the browser's perspective the relative URL "../auth/login" works
  // regardless of any reverse-proxy prefix because both paths are served
  // by the same origin.
  var loginURL    = "../auth/login";
  var mfaURL      = "../auth/mfa";
  var brandingURL = "../branding";
  var forgotURL   = "../auth/forgot-password";
  var registerURL = "../auth/register";

  // WebAuthn conditional-mediation (passkey autofill) endpoints.
  // Relative from /login/ — the server mounts them at /webauthn/login/conditional/*.
  var conditionalBeginURL  = "../webauthn/login/conditional/begin";
  var conditionalFinishURL = "../webauthn/login/conditional/finish";

  // --- State ---
  var currentMFAChallengeID = "";
  var currentMFAMethods     = [];
  var selectedMFAMethod     = "";
  var savedLoginPayload     = null; // for consent re-submit
  var savedConsentChallengeID = ""; // server-issued challenge from consent_required response
  var consentClientName     = ""; // server-provided app display name (consent_required)
  var consentScopeDescriptions = {}; // server-provided scope -> description (consent_required)

  // --- Magic-link auto-submit ---
  // A clicked magic-link email lands here with ?token=<opaque>#email=<addr>
  // (see domains/authenticators/email.go's MagicLinkAuthenticator.SendCode
  // doc comment for why the email rides in the URL FRAGMENT rather than a
  // second "&"-joined query param: it keeps the emailed link free of any
  // character the SMTP sender's html/template-based renderer would mangle).
  // Reuses the SAME /auth/login POST every other provider uses — no new
  // endpoint, no new request shape — with credential.email/code exactly like
  // the email-OTP provider expects.
  //
  // Caveat: because the link may be opened in a different browser/device
  // than the one that started the OAuth flow (or no flow at all — the user
  // may have arrived here directly from their inbox), this page has no way
  // to recover the original client_id/redirect_uri/state/nonce — SendCode
  // only ever receives an email address (shared CodeSender contract with
  // every other code-based authenticator), so it cannot embed them in the
  // link either. A deployment that needs the click to resume a SPECIFIC
  // client's authorization request must pin magiclink to one default client
  // or extend the /auth/send-code caller to persist that context
  // out-of-band; that is not solved here.
  (function magicLinkAutoSubmit() {
    var token = q.get("token");
    if (!token) return;
    var hashParams = new URLSearchParams(location.hash.replace(/^#/, ""));
    var email = hashParams.get("email");
    if (!email) return;

    showView("login");
    setError("login-error", "");
    var btn = $("login-btn");
    setLoading(btn, true);

    var payload = {
      provider:              "magiclink",
      client_id:             oauthParams.client_id,
      scope:                 oauthParams.scope,
      state:                 oauthParams.state,
      response_type:         oauthParams.response_type,
      redirect_uri:          oauthParams.redirect_uri,
      nonce:                 oauthParams.nonce,
      code_challenge:        oauthParams.code_challenge,
      code_challenge_method: oauthParams.code_challenge_method,
      credential:            { email: email, code: token },
    };
    savedLoginPayload = payload;

    fetch(loginURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json().then(function(d){ return {status:r.status,data:d}; }); })
    .then(function(res) {
      setLoading(btn, false);
      if (res.status === 200 && !res.data.error) {
        handleSuccess(res.data);
        return;
      }
      // Falls through to the normal, still-usable login form on any error
      // (expired/already-used link, missing client_id, ...) — the user can
      // retry via password/OTP without reloading.
      handleLoginError(res.data, "login-error", btn);
    })
    .catch(function() {
      setLoading(btn, false);
      setError("login-error", i18n.t("login.networkError"));
    });
  })();

  // --- Populate provider selector if >1 option ---
  var providerSel = $("provider");
  // The SPA starts with only "password"; real provider list comes from a
  // probe request. Only shown if the selector has >1 option after population.
  (function initProvider() {
    if (oauthParams.provider && oauthParams.provider !== "password") {
      var opt = document.createElement("option");
      opt.value = oauthParams.provider;
      opt.textContent = oauthParams.provider.replace(/_/g," ");
      providerSel.appendChild(opt);
    }
    providerSel.value = oauthParams.provider || "password";
    if (providerSel.options.length > 1) {
      $("field-provider").style.display = "";
    }
  })();

  // --- White-label branding (async, best-effort) ---
  // Theme the page from the tenant's per-host /branding response. Honors
  // primary_color (CSS var driving the button + logo mark), logo_url (swaps
  // the default mark for the tenant logo), and brand_name (tab title). Any
  // failure or empty response silently keeps the default theme.
  (function loadBranding() {
    fetch(brandingURL, {headers: {"Accept": "application/json"}})
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        var b = data && data.branding;
        if (!b) return;
        if (b.primary_color) {
          document.documentElement.style.setProperty("--brand-primary", b.primary_color);
          document.documentElement.style.setProperty("--brand-primary-hover", b.primary_color);
        }
        if (b.logo_url) {
          var img = $("brand-logo"), mark = $("brand-mark");
          img.onload = function() { mark.style.display = "none"; img.style.display = "inline-block"; };
          img.src = b.logo_url;
          img.alt = b.brand_name || "";
        }
        if (b.brand_name) {
          document.title = i18n.t("app.title") + " · " + b.brand_name;
        }
      })
      .catch(function() { /* keep default theme */ });
  })();

  // --- Probe for available providers (async, best-effort) ---
  (function probeProviders() {
    if (!oauthParams.client_id) return;
    fetch(loginURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({client_id: oauthParams.client_id})
    })
    .then(function(r){ return r.json(); })
    .then(function(data) {
      // Home-realm discovery (B2B, opt-in): the probe may resolve the caller's
      // email domain to an enterprise connection and instruct the UI to route
      // through that org's upstream IdP rather than offer the provider list. A
      // normal response without connection_required falls through unchanged.
      if (data && data.connection_required) {
        showHomeRealm(data);
        return;
      }
      var providers = data.providers;
      if (!Array.isArray(providers) || providers.length === 0) return;
      // Rebuild the selector.
      while (providerSel.options.length > 0) providerSel.remove(0);
      providers.forEach(function(p) {
        var opt = document.createElement("option");
        opt.value = p;
        opt.textContent = p.charAt(0).toUpperCase() + p.slice(1).replace(/_/g," ");
        providerSel.appendChild(opt);
      });
      providerSel.value = oauthParams.provider || providers[0];
      if (providers.length > 1) {
        $("field-provider").style.display = "";
      }
    })
    .catch(function(){});
  })();

  // --- Conditional Mediation (Passkey Autofill) ---
  // If the browser supports it, initiate a conditional mediation WebAuthn
  // ceremony on page load. This lets the browser show available passkeys in
  // the username field's autofill dropdown WITHOUT a modal dialog. The user
  // can select a passkey directly and complete authentication seamlessly.
  // If the browser doesn't support it, or no passkeys are available, the
  // normal password login form remains fully functional.
  //
  // The conditional path uses a separate /webauthn/login/conditional/begin
  // endpoint that does NOT require a username — the authenticator resolves
  // the credential from its resident-key store (discoverable credentials).
  // The finish endpoint resolves the user identity from the authenticator's
  // userHandle, then issues tokens the same way as the regular flow.

  // WebAuthn helper: convert an ArrayBuffer to a base64url-encoded string.
  function arrayBufferToBase64URL(buf) {
    var bytes = new Uint8Array(buf);
    var str = "";
    for (var i = 0; i < bytes.length; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  // WebAuthn helper: convert a PublicKeyCredential (containing ArrayBuffer
  // fields) to a JSON-serializable object the server expects.
  function publicKeyCredentialToJSON(cred) {
    var resp = cred.response;
    return {
      id: cred.id,
      rawId: arrayBufferToBase64URL(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: arrayBufferToBase64URL(resp.clientDataJSON),
        authenticatorData: arrayBufferToBase64URL(resp.authenticatorData),
        signature: arrayBufferToBase64URL(resp.signature),
        userHandle: resp.userHandle ? arrayBufferToBase64URL(resp.userHandle) : null,
      },
    };
  }

  (function initConditionalMediation() {
    // Detect browser support.
    if (!window.PublicKeyCredential ||
        !PublicKeyCredential.isConditionalMediationAvailable) {
      return;
    }
    PublicKeyCredential.isConditionalMediationAvailable().then(function(avail) {
      if (!avail) return;
      // Fetch the conditional-mediation challenge.
      fetch(conditionalBeginURL, {method: "POST"})
        .then(function(r) { return r.json().then(function(d) { return {status: r.status, data: d}; }); })
        .then(function(res) {
          if (res.status !== 200 || !res.data.options) return;
          var opts = res.data.options;
          var sessionID = res.data.session_id;
          // opts is the full CredentialAssertion JSON from go-webauthn:
          //   { publicKey: { challenge, rpId, ... }, mediation: "conditional" }
          // Pass it directly to navigator.credentials.get().
          return navigator.credentials.get(opts).then(function(assertion) {
            // Serialize the PublicKeyCredential to JSON for the server.
            var body = JSON.stringify(publicKeyCredentialToJSON(assertion));
            // Send the assertion to the conditional finish endpoint.
            var finishURL = conditionalFinishURL + "?session_id=" + encodeURIComponent(sessionID);
            var clientID = oauthParams.client_id;
            if (clientID) finishURL += "&client_id=" + encodeURIComponent(clientID);
            return fetch(finishURL, {
              method: "POST",
              headers: {"Content-Type":"application/json"},
              body: body
            }).then(function(r2) { return r2.json().then(function(d2) { return {status: r2.status, data: d2}; }); });
          }).then(function(res2) {
            if (res2.status === 200 && !res2.data.error) {
              handleSuccess(res2.data);
            }
          });
        })
        .catch(function() {
          // Conditional mediation failed silently — user can still use the
          // regular login form. This is expected when no passkey is
          // registered or the user closes the autofill without selecting one.
        });
    }).catch(function() { /* ignore detection errors */ });
  })();

  // --- Home-realm discovery notice (B2B) ---
  // The org resolved to an enterprise connection; surface a notice that routes
  // the user to their organization's identity provider. The actual upstream
  // hand-off is server-side (the resolved connection drives the federated flow);
  // here we only present the routing decision using the connection's metadata.
  function showHomeRealm(data) {
    var org = data.display_name || i18n.t("hr.defaultOrg");
    var notice = $("hr-notice");
    notice.innerHTML = "";
    var p = document.createElement("p");
    p.style.marginBottom = "10px";
    p.textContent = i18n.t("hr.continueWithOrgNotice", {org: org});
    notice.appendChild(p);
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-primary";
    btn.textContent = i18n.t("hr.continueWithOrgButton", {org: org});
    btn.addEventListener("click", function() {
      // Resolved-connection hand-off is performed by the server when the login
      // payload carries the connection. Re-submitting the normal login form
      // hits the same /auth/login the connection routing is wired into.
      $("login-form").requestSubmit
        ? $("login-form").requestSubmit()
        : $("login-btn").click();
    });
    notice.appendChild(btn);
    notice.classList.add("visible");
  }

  // --- Build login payload ---
  function buildPayload(extra) {
    var provider = providerSel.value || "password";
    var payload = {
      provider:              provider,
      client_id:             oauthParams.client_id,
      scope:                 oauthParams.scope,
      state:                 oauthParams.state,
      response_type:         oauthParams.response_type,
      redirect_uri:          oauthParams.redirect_uri,
      nonce:                 oauthParams.nonce,
      code_challenge:        oauthParams.code_challenge,
      code_challenge_method: oauthParams.code_challenge_method,
    };
    if (oauthParams.resource && oauthParams.resource.length > 0) {
      payload.resource = oauthParams.resource;
    }
    var username = $("username").value.trim();
    var password = $("password").value;
    payload.credential = { username: username, password: password };
    return Object.assign(payload, extra || {});
  }

  // --- Handle a successful auth response ---
  function handleSuccess(data) {
    var redirectURI = oauthParams.redirect_uri;

    if (data.code) {
      if (redirectURI) {
        var u = new URL(redirectURI);
        u.searchParams.set("code", data.code);
        if (data.state || oauthParams.state) {
          u.searchParams.set("state", data.state || oauthParams.state);
        }
        if (data.iss) u.searchParams.set("iss", data.iss);
        location.replace(u.toString());
        return;
      }
    }

    if (data.access_token) {
      if (redirectURI) {
        // OAuth 2.0 §4.2.2: implicit-flow tokens MUST be delivered in the
        // URL fragment (#), not query string (?), so the token does not
        // leak via server logs, Referer headers, or browser history.
        var fragment = new URLSearchParams();
        fragment.set("access_token", data.access_token);
        fragment.set("token_type",   data.token_type || "Bearer");
        if (data.expires_in) fragment.set("expires_in", data.expires_in);
        if (oauthParams.state) fragment.set("state", oauthParams.state);
        if (data.iss) fragment.set("iss", data.iss);
        location.replace(redirectURI + "#" + fragment.toString());
        return;
      }
    }

    showView("success");
  }

  // --- Handle structured errors from /auth/login ---
  function handleLoginError(data, errBoxId, btn) {
    setLoading(btn, false);

    var code = data.error;

    if (code === "mfa_required") {
      currentMFAChallengeID = data.mfa_challenge_id || "";
      currentMFAMethods     = data.mfa_methods || [];
      renderMFAView(currentMFAMethods);
      showView("mfa");
      setError("login-error", "");
      return;
    }

    if (code === "consent_required") {
      savedConsentChallengeID = data.consent_challenge_id || "";
      // The server may enrich the response with the app's display name and
      // per-scope descriptions so the screen reads better than raw IDs.
      consentClientName = data.client_name || "";
      consentScopeDescriptions = {};
      if (Array.isArray(data.scopes)) {
        data.scopes.forEach(function (s) {
          if (s && s.scope && s.description) consentScopeDescriptions[s.scope] = s.description;
        });
      }
      renderConsentView();
      showView("consent");
      setError("login-error", "");
      return;
    }

    var msg = code || i18n.t("login.genericError");
    setError(errBoxId, msg);
  }

  // --- Login form submit ---
  $("login-form").addEventListener("submit", function(e) {
    e.preventDefault();
    var btn = $("login-btn");
    setError("login-error", "");
    setLoading(btn, true);

    var payload = buildPayload();
    savedLoginPayload = payload;

    fetch(loginURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json().then(function(d){ return {status:r.status,data:d}; }); })
    .then(function(res) {
      setLoading(btn, false);
      if (res.status === 200 && !res.data.error) {
        handleSuccess(res.data);
        return;
      }
      handleLoginError(res.data, "login-error", btn);
    })
    .catch(function(err) {
      setLoading(btn, false);
      setError("login-error", i18n.t("login.networkError"));
    });
  });

  // --- MFA view ---
  function renderMFAView(methods) {
    var container = $("mfa-methods");
    container.innerHTML = "";
    methods.forEach(function(m) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "mfa-method-btn";
      btn.textContent = methodLabel(m);
      btn.dataset.method = m;
      btn.addEventListener("click", function() {
        document.querySelectorAll(".mfa-method-btn").forEach(function(b) {
          b.classList.remove("selected");
        });
        btn.classList.add("selected");
        selectedMFAMethod = m;
        // Show TOTP code field only for TOTP-style methods.
        var isTOTP = (m === "totp" || m === "otp");
        $("mfa-totp-field").style.display = isTOTP ? "" : "none";
        $("mfa-btn").style.display = "";
      });
      container.appendChild(btn);
    });
    // Auto-select if only one method.
    if (methods.length === 1) {
      container.firstChild.click();
    }
    // Show trust-device checkbox for all MFA methods.
    $("mfa-trust-field").style.display = "";
    $("mfa-totp-field").style.display = "none";
    $("mfa-btn").style.display = methods.length === 1 ? "" : "none";
  }

  function methodLabel(m) {
    var labels = {
      totp:     i18n.t("mfa.method.totp"),
      otp:      i18n.t("mfa.method.otp"),
      webauthn: i18n.t("mfa.method.webauthn"),
      push:     i18n.t("mfa.method.push"),
      sms:      i18n.t("mfa.method.sms"),
    };
    return labels[m] || m.charAt(0).toUpperCase() + m.slice(1).replace(/_/g," ");
  }

  $("mfa-btn").addEventListener("click", function() {
    var btn = $("mfa-btn");
    setError("mfa-error", "");
    if (!selectedMFAMethod) {
      setError("mfa-error", i18n.t("mfa.selectMethod"));
      return;
    }
    var code = $("mfa-code").value.trim();
    if ((selectedMFAMethod === "totp" || selectedMFAMethod === "otp") && !code) {
      setError("mfa-error", i18n.t("mfa.enterCode"));
      return;
    }
    setLoading(btn, true);
    var trustDevice = $("mfa-trust-device") && $("mfa-trust-device").checked;
    var body = {
      mfa_challenge_id: currentMFAChallengeID,
      mfa_method:       selectedMFAMethod,
      code:             code,
      trust_device:     trustDevice || false
    };
    fetch(mfaURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body)
    })
    .then(function(r){ return r.json().then(function(d){ return {status:r.status,data:d}; }); })
    .then(function(res) {
      setLoading(btn, false);
      if (res.status === 200 && !res.data.error) {
        handleSuccess(res.data);
        return;
      }
      setError("mfa-error", res.data.error || i18n.t("mfa.verifyFailed"));
    })
    .catch(function() {
      setLoading(btn, false);
      setError("mfa-error", i18n.t("mfa.networkError"));
    });
  });

  $("mfa-back").addEventListener("click", function() {
    setError("mfa-error", "");
    $("mfa-code").value = "";
    $("mfa-trust-device").checked = false;
    showView("login");
  });

  // --- Consent view ---
  function renderConsentView() {
    $("consent-client").textContent = consentClientName || oauthParams.client_id || i18n.t("consent.defaultClientName");
    var list = $("consent-scopes");
    list.innerHTML = "";
    var scopes = oauthParams.scope.filter(function(s){ return s && s !== "openid"; });
    if (scopes.length === 0) scopes = ["openid"];
    scopes.forEach(function(s) {
      var li = document.createElement("li");
      li.textContent = scopeLabel(s);
      list.appendChild(li);
    });
  }

  function scopeLabel(s) {
    // Operator-provided description (from consent_required) wins; otherwise fall
    // back to the built-in label for well-known scopes, then the raw name.
    if (consentScopeDescriptions[s]) return consentScopeDescriptions[s];
    var labels = {
      openid:  i18n.t("consent.scope.openid"),
      profile: i18n.t("consent.scope.profile"),
      email:   i18n.t("consent.scope.email"),
      offline_access: i18n.t("consent.scope.offline_access"),
    };
    return labels[s] || s;
  }

  $("consent-allow-btn").addEventListener("click", function() {
    if (!savedLoginPayload) return;
    var btn = $("consent-allow-btn");
    setError("consent-error", "");
    setLoading(btn, true);
    var payload = Object.assign({}, savedLoginPayload, { consent_challenge_id: savedConsentChallengeID });
    fetch(loginURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(payload)
    })
    .then(function(r){ return r.json().then(function(d){ return {status:r.status,data:d}; }); })
    .then(function(res) {
      setLoading(btn, false);
      if (res.status === 200 && !res.data.error) {
        handleSuccess(res.data);
        return;
      }
      handleLoginError(res.data, "consent-error", btn);
    })
    .catch(function() {
      setLoading(btn, false);
      setError("consent-error", i18n.t("consent.networkError"));
    });
  });

  $("consent-deny-btn").addEventListener("click", function() {
    if (oauthParams.redirect_uri) {
      var u = new URL(oauthParams.redirect_uri);
      u.searchParams.set("error", "access_denied");
      if (oauthParams.state) u.searchParams.set("state", oauthParams.state);
      location.replace(u.toString());
    } else {
      showView("login");
    }
  });

  // --- Self-service panels (forgot password / signup) ---
  // Both panels live inside the login view; toggling them swaps the inline form
  // for the panel without leaving the view. Each panel resets its state on open.
  function togglePanel(panelId, open) {
    $(panelId).classList.toggle("active", open);
  }

  function setSuccess(boxId, msg) {
    var box = $(boxId);
    if (msg) {
      box.textContent = msg;
      box.classList.add("visible");
    } else {
      box.textContent = "";
      box.classList.remove("visible");
    }
  }

  $("forgot-link").addEventListener("click", function() {
    setError("forgot-error", "");
    setSuccess("forgot-success", "");
    $("forgot-identifier").value = $("username").value;
    togglePanel("signup-panel", false);
    togglePanel("forgot-panel", true);
  });

  $("forgot-back").addEventListener("click", function() {
    togglePanel("forgot-panel", false);
  });

  $("signup-link").addEventListener("click", function() {
    setError("signup-error", "");
    // Clear any prior signup confirmation when re-opening the panel.
    var prior = $("signup-confirm");
    if (prior) prior.classList.remove("visible");
    var form = $("signup-form");
    if (form) form.style.display = "";
    togglePanel("forgot-panel", false);
    togglePanel("signup-panel", true);
  });

  $("signup-back").addEventListener("click", function() {
    togglePanel("signup-panel", false);
  });

  // Forgot-password submit (POST /auth/forgot-password, body {identifier}).
  // The endpoint is intentionally always-200 for anti-enumeration: on any 2xx
  // we show the SAME generic message regardless of whether the account exists.
  // A 404 means the feature is not mounted — disclose that and hide the form.
  $("forgot-form").addEventListener("submit", function(e) {
    e.preventDefault();
    var btn = $("forgot-btn");
    setError("forgot-error", "");
    setSuccess("forgot-success", "");
    var identifier = $("forgot-identifier").value.trim();
    if (!identifier) {
      setError("forgot-error", i18n.t("forgot.emptyIdentifier"));
      return;
    }
    setLoading(btn, true);
    fetch(forgotURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({identifier: identifier})
    })
    .then(function(r) {
      setLoading(btn, false);
      if (r.status === 404) {
        $("forgot-form").style.display = "none";
        setError("forgot-error", i18n.t("forgot.notEnabled"));
        return;
      }
      if (r.status >= 200 && r.status < 300) {
        setSuccess("forgot-success", i18n.t("forgot.successMessage"));
        return;
      }
      setError("forgot-error", i18n.t("forgot.genericError"));
    })
    .catch(function() {
      setLoading(btn, false);
      setError("forgot-error", i18n.t("forgot.networkError"));
    });
  });

  // Signup submit (POST /auth/register, body {username, password, email?}).
  // 201 -> created (return to sign in). 409 -> account exists. 404 -> feature
  // not mounted (disclose + hide form). Any other status -> generic error.
  $("signup-form").addEventListener("submit", function(e) {
    e.preventDefault();
    var btn = $("signup-btn");
    setError("signup-error", "");
    var username = $("signup-username").value.trim();
    var password = $("signup-password").value;
    var email    = $("signup-email").value.trim();
    if (!username || !password) {
      setError("signup-error", i18n.t("signup.emptyFields"));
      return;
    }
    var body = {username: username, password: password};
    if (email) body.email = email;
    setLoading(btn, true);
    fetch(registerURL, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body)
    })
    .then(function(r) {
      setLoading(btn, false);
      if (r.status === 404) {
        $("signup-form").style.display = "none";
        setError("signup-error", i18n.t("signup.notEnabled"));
        return;
      }
      if (r.status === 409) {
        setError("signup-error", i18n.t("signup.conflict"));
        return;
      }
      if (r.status >= 200 && r.status < 300) {
        // Prefill the sign-in username, close the panel, and confirm in the
        // login view. The confirmation reuses the success-box styling, surfaced
        // in-place above the login form.
        $("username").value = username;
        $("signup-password").value = "";
        togglePanel("signup-panel", false);
        setError("login-error", "");
        showSignupConfirmation();
        return;
      }
      setError("signup-error", i18n.t("signup.genericError"));
    })
    .catch(function() {
      setLoading(btn, false);
      setError("signup-error", i18n.t("signup.networkError"));
    });
  });

  // Confirm a fresh signup in the login view. The login markup has no static
  // success box, so we insert one once (idempotent) right after the login-error
  // box and reuse the shared success-box styling.
  function showSignupConfirmation() {
    var note = $("signup-confirm");
    if (!note) {
      note = document.createElement("div");
      note.id = "signup-confirm";
      note.className = "success-box";
      var anchor = $("login-error");
      anchor.parentNode.insertBefore(note, anchor.nextSibling);
    }
    note.textContent = i18n.t("signup.confirmation");
    note.classList.add("visible");
  }
})();
