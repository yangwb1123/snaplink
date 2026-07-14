(function (global) {
  "use strict";

  // Minimal, zero-dependency i18n runtime shared by the hosted-login SPA.
  // Deliberately app-agnostic (no login-specific strings or DOM knowledge)
  // so it can be reused byte-for-byte by the other hosted SPAs (admin/
  // portal/developer) — copy this file into that SPA's directory rather
  // than reimplementing it. It isn't shared via a single physical file
  // today because each hosted SPA is embedded and served from its OWN
  // isolated filesystem root (see cmd/sso-server/serverassets/*_assets.go,
  // each doing fs.Sub(web.XFS, "x")); there is no cross-SPA static mount
  // for a file living at interfaces/web/ top level to be reachable from,
  // say, /admin/. See interfaces/web/login/app.js for the wiring example.

  var state = {
    locale: "en",
    defaultLocale: "en",
    dict: {},        // active-locale strings, keyed by message key
    defaultDict: {},  // default-locale strings — the fallback dictionary
  };

  // resolveLocale walks navigator.languages (preference order; falls back
  // to the single navigator.language) through a three-step chain per
  // candidate tag: exact match ("en-GB") -> language-only match ("en" from
  // "en-GB") -> the caller's configured default. Never throws — an absent
  // navigator.language simply falls through to defaultLocale.
  function resolveLocale(supported, defaultLocale) {
    var nav = global.navigator || {};
    var candidates = [];
    if (Array.isArray(nav.languages)) candidates = candidates.concat(nav.languages);
    if (nav.language) candidates.push(nav.language);

    for (var i = 0; i < candidates.length; i++) {
      var tag = String(candidates[i] || "").toLowerCase();
      if (supported.indexOf(tag) !== -1) return tag;
    }
    for (var j = 0; j < candidates.length; j++) {
      var lang = String(candidates[j] || "").split("-")[0].toLowerCase();
      if (supported.indexOf(lang) !== -1) return lang;
    }
    return defaultLocale;
  }

  // fetchBundle never rejects: a missing/malformed bundle resolves to {}
  // so t() below degrades to key-fallback instead of taking down the page.
  function fetchBundle(basePath, locale) {
    return global.fetch(basePath + locale + ".json", { headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; });
  }

  // init(options) resolves the active locale and loads its bundle plus the
  // default-locale bundle (used as the fallback dictionary in t()). Returns
  // a Promise<string> of the resolved locale; always resolves, never rejects.
  //
  //   options.basePath      directory the bundles live in, e.g. "locales/"
  //   options.supported     locale codes with a bundle file, e.g. ["en","es"]
  //   options.defaultLocale fallback locale, e.g. "en"
  function init(options) {
    options = options || {};
    var basePath = options.basePath || "locales/";
    var supported = options.supported || ["en"];
    var defaultLocale = options.defaultLocale || "en";

    state.defaultLocale = defaultLocale;
    state.locale = resolveLocale(supported, defaultLocale);

    var defaultFetch = fetchBundle(basePath, defaultLocale);
    var activeFetch = state.locale === defaultLocale
      ? defaultFetch
      : fetchBundle(basePath, state.locale);

    return Promise.all([defaultFetch, activeFetch]).then(function (results) {
      state.defaultDict = results[0] || {};
      state.dict = results[1] || {};
      return state.locale;
    });
  }

  // t(key, params) looks up key in the active bundle, then the default-locale
  // bundle, then falls back to the raw key — so a missing translation or a
  // bundle-load failure shows a (readable) key instead of blank/broken text.
  // params does simple "{name}" interpolation; an unmatched placeholder is
  // left as-is rather than blanked, to make a caller bug visible.
  function t(key, params) {
    var has = Object.prototype.hasOwnProperty;
    var str = has.call(state.dict, key) ? state.dict[key]
      : has.call(state.defaultDict, key) ? state.defaultDict[key]
      : key;
    if (params) {
      str = str.replace(/\{(\w+)\}/g, function (whole, name) {
        return has.call(params, name) ? params[name] : whole;
      });
    }
    return str;
  }

  // applyDOM re-paints already-rendered static markup: elements tagged
  // data-i18n get textContent replaced; data-i18n-placeholder gets their
  // placeholder attribute replaced. The pre-enhancement markup is the
  // default-locale (English) copy, so a slow/failed bundle fetch just
  // leaves correct English text on screen rather than a blank element.
  function applyDOM(root) {
    root = root || global.document;
    var els = root.querySelectorAll("[data-i18n]");
    for (var i = 0; i < els.length; i++) {
      els[i].textContent = t(els[i].getAttribute("data-i18n"));
    }
    var placeholders = root.querySelectorAll("[data-i18n-placeholder]");
    for (var j = 0; j < placeholders.length; j++) {
      placeholders[j].placeholder = t(placeholders[j].getAttribute("data-i18n-placeholder"));
    }
  }

  global.i18n = {
    init: init,
    t: t,
    applyDOM: applyDOM,
    get locale() { return state.locale; },
  };
})(window);
