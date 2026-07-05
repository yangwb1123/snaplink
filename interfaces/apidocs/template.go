package apidocs

import (
	"html/template"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// pageData feeds pageTemplate. SpecJSON carries the openapi document
// already encoded by encoding/json — which HTML-escapes '<', '>', '&' to
// <-style sequences by default specifically so JSON is safe to place
// verbatim inside a <script> element — as template.JS, so html/template
// does not ALSO try to re-escape a value that is already safe.
type pageData struct {
	Title    string
	Version  string
	SpecJSON template.JS
	Nonce    string
}

// handleUI returns the core.HandlerFunc that renders pageTemplate. Headers
// mirror the SDK's other hand-rolled HTML responses (see
// protocols/oidc/oidcsupport/form_post.go): no-store because the page
// embeds the live server's full endpoint + schema inventory, X-Frame-
// Options: DENY as belt-and-suspenders against clickjacking on an
// admin-bearer-gated page.
func handleUI(specJSON []byte, title, version string) core.HandlerFunc {
	return func(ctx core.HandlerContext) {
		w := ctx.ResponseWriter()
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_ = pageTemplate.Execute(w, pageData{
			Title:    title,
			Version:  version,
			SpecJSON: template.JS(specJSON),
			Nonce:    core.CSPNonceFromContext(ctx.Request().Context()),
		})
	}
}

// pageTemplate is the entire viewer: HTML + CSS (inline <style>, allowed
// unquoted-nonce under the default CSP's "style-src 'self' 'unsafe-inline'" —
// see internal/handler/security_headers.go's DefaultSecurityHeadersPolicy
// doc) + a small vanilla-JS renderer (inline <script>, nonce-gated — CSP's
// script-src carries NO 'unsafe-inline', so the nonce is what lets this
// element run when WithSecurityHeaders is wired). The spec is inlined as
// JSON rather than fetched from a second endpoint so a saved copy of this
// page (curl -H "Authorization: Bearer $TOKEN" .../docs -o d.html) is
// immediately, fully usable offline — no second authenticated request to
// replay.
var pageTemplate = template.Must(template.New("apidocs").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Title}}{{.Title}}{{else}}API Reference{{end}}{{if .Version}} v{{.Version}}{{end}}</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: Canvas; color: CanvasText; }
header { padding: 1.25rem 1.5rem; border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }
header h1 { margin: 0 0 .25rem; font-size: 1.25rem; }
header p { margin: 0; opacity: .75; max-width: 60rem; white-space: pre-wrap; }
.toolbar { padding: .75rem 1.5rem; border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent);
  position: sticky; top: 0; background: Canvas; z-index: 1; }
#search { width: 100%; max-width: 28rem; padding: .4rem .6rem; font: inherit;
  border: 1px solid color-mix(in srgb, CanvasText 25%, transparent); border-radius: .35rem;
  background: Canvas; color: CanvasText; }
main { padding: 0 1.5rem 3rem; }
.tag-group { margin-top: 1.5rem; }
.tag-group h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: .03em; opacity: .6; }
details.op { border: 1px solid color-mix(in srgb, CanvasText 15%, transparent); border-radius: .4rem;
  margin-bottom: .5rem; }
details.op > summary { list-style: none; cursor: pointer; padding: .5rem .75rem;
  display: flex; gap: .6rem; align-items: baseline; }
details.op > summary::-webkit-details-marker { display: none; }
.method { display: inline-block; min-width: 3.2rem; text-align: center; font-weight: 700;
  font-size: .72rem; padding: .1rem .3rem; border-radius: .25rem; color: #fff; }
.method.get { background: #2f6fed; }
.method.post { background: #1f9d55; }
.method.put, .method.patch { background: #b7791f; }
.method.delete { background: #c53030; }
.op .path { font-family: ui-monospace, Menlo, Consolas, monospace; }
.op .opsummary { opacity: .75; }
.op-body { padding: 0 .9rem .9rem; border-top: 1px solid color-mix(in srgb, CanvasText 10%, transparent); }
.op-body h4 { margin: .9rem 0 .3rem; font-size: .8rem; opacity: .7; }
.op-description { white-space: pre-wrap; opacity: .85; }
table.params { border-collapse: collapse; width: 100%; font-size: .85rem; }
table.params th, table.params td { text-align: left; padding: .25rem .5rem .25rem 0; vertical-align: top; }
table.params th { opacity: .6; font-weight: 600; }
.fields { list-style: none; margin: 0; padding-left: 1rem; font-size: .85rem; }
.fields .fields { border-left: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }
code { font-family: ui-monospace, Menlo, Consolas, monospace; }
.type-ref { color: #7c4dff; }
.type-prim { opacity: .8; }
.field-desc { opacity: .6; }
.response-code { font-weight: 600; margin-top: .6rem; }
.hint { opacity: .55; font-size: .8rem; padding: .75rem 1.5rem; }
</style>
</head>
<body>
<header>
<h1>{{if .Title}}{{.Title}}{{else}}API Reference{{end}}{{if .Version}} <small>v{{.Version}}</small>{{end}}</h1>
<p id="info-description"></p>
</header>
<div class="toolbar">
<input id="search" type="search" placeholder="Filter by path, summary, or tag&hellip;" autofocus>
</div>
<main id="main"></main>
<p class="hint">Read-only embedded viewer (sso.WithAPIDocsUI) &mdash; generated from the same
docs/openapi.yaml as the machine-readable companion at this same path's
<code>/openapi.json</code> ... (fetch it directly, or see docs/sdks/{typescript,python} for
generated consumer clients).</p>
<script{{if .Nonce}} nonce="{{.Nonce}}"{{end}}>
var SPEC = {{.SpecJSON}};

function el(tag, className, text) {
  var e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

function firstLines(text, n) {
  return (text || '').split(/\n/).slice(0, n || 1).join(' ').trim();
}

function resolveRef(ref, bucket) {
  var name = ref.split('/').pop();
  return (SPEC.components && SPEC.components[bucket] && SPEC.components[bucket][name]) || null;
}

function resolveResponse(r) {
  if (r && r['$ref']) { return resolveRef(r['$ref'], 'responses') || r; }
  return r;
}

function resolveParam(p) {
  if (p && p['$ref']) { return resolveRef(p['$ref'], 'parameters') || p; }
  return p;
}

// renderSchema builds a compact DOM tree describing schema. depth bounds
// recursion through named $refs (some schemas are self-referential, e.g.
// MenuItem.children -> MenuItem) so the tree can never grow unbounded.
function renderSchema(schema, depth) {
  if (!schema) return el('code', 'type-prim', 'any');
  if (schema['$ref']) {
    var name = schema['$ref'].split('/').pop();
    var target = resolveRef(schema['$ref'], 'schemas');
    var wrap = el('span', null, null);
    wrap.appendChild(el('code', 'type-ref', name));
    if (target && depth < 4) { wrap.appendChild(renderSchema(target, depth + 1)); }
    return wrap;
  }
  if (schema.oneOf || schema.anyOf) {
    var variants = schema.oneOf || schema.anyOf;
    var span = el('span', null, null);
    variants.forEach(function (v, i) {
      if (i > 0) span.appendChild(document.createTextNode(' | '));
      span.appendChild(renderSchema(v, depth));
    });
    return span;
  }
  if (schema.allOf && schema.allOf.length === 1) { return renderSchema(schema.allOf[0], depth); }
  if (schema.type === 'array') {
    var awrap = el('span', null, 'array of ');
    awrap.appendChild(renderSchema(schema.items || {}, depth));
    return awrap;
  }
  if (schema.type === 'object' || schema.properties) {
    if (depth >= 4) { return el('em', null, 'object {…}'); }
    var ul = el('ul', 'fields', null);
    var required = schema.required || [];
    var props = schema.properties || {};
    Object.keys(props).forEach(function (name) {
      var li = el('li', null, null);
      li.appendChild(el('code', null, name + (required.indexOf(name) >= 0 ? '' : '?')));
      li.appendChild(document.createTextNode(': '));
      li.appendChild(renderSchema(props[name], depth + 1));
      var desc = firstLines(props[name].description, 1);
      if (desc) { li.appendChild(el('span', 'field-desc', ' — ' + desc)); }
      ul.appendChild(li);
    });
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      var ali = el('li', null, '[key: string]: ');
      ali.appendChild(renderSchema(schema.additionalProperties, depth + 1));
      ul.appendChild(ali);
    }
    return ul;
  }
  var prim = el('code', 'type-prim', schema.type || 'any');
  if (schema.enum) { prim.textContent += ' (' + schema.enum.join(' | ') + ')'; }
  return prim;
}

function paramsTable(params) {
  var table = el('table', 'params', null);
  var thead = el('thead', null, null);
  var htr = el('tr', null, null);
  ['Name', 'In', 'Type', '', 'Description'].forEach(function (h) { htr.appendChild(el('th', null, h)); });
  thead.appendChild(htr);
  table.appendChild(thead);
  var tbody = el('tbody', null, null);
  params.forEach(function (raw) {
    var p = resolveParam(raw);
    var tr = el('tr', null, null);
    tr.appendChild(el('td', null, p.name));
    tr.appendChild(el('td', null, p['in']));
    var typeTd = el('td', null, null);
    typeTd.appendChild(renderSchema(p.schema || {}, 0));
    tr.appendChild(typeTd);
    tr.appendChild(el('td', null, p.required ? 'required' : ''));
    tr.appendChild(el('td', null, firstLines(p.description, 1)));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

function contentSchema(content) {
  if (!content) return null;
  var ct = content['application/json'] || content[Object.keys(content)[0]];
  return (ct && ct.schema) || null;
}

function operationBody(op) {
  var box = el('div', 'op-body', null);
  var desc = firstLines(op.description, 4);
  if (desc) { box.appendChild(el('p', 'op-description', desc)); }
  if (op.parameters && op.parameters.length) {
    box.appendChild(el('h4', null, 'Parameters'));
    box.appendChild(paramsTable(op.parameters));
  }
  if (op.requestBody) {
    var reqSchema = contentSchema(op.requestBody.content);
    if (reqSchema) {
      box.appendChild(el('h4', null, 'Request body' + (op.requestBody.required ? ' (required)' : ' (optional)')));
      box.appendChild(renderSchema(reqSchema, 0));
    }
  }
  var responses = op.responses || {};
  var codes = Object.keys(responses).sort();
  if (codes.length) {
    box.appendChild(el('h4', null, 'Responses'));
    codes.forEach(function (code) {
      var r = resolveResponse(responses[code]);
      box.appendChild(el('div', 'response-code', code + ' — ' + firstLines(r.description, 1)));
      var schema = contentSchema(r.content);
      if (schema) { box.appendChild(renderSchema(schema, 0)); }
    });
  }
  return box;
}

function operationDetails(method, path, op) {
  var d = document.createElement('details');
  d.className = 'op';
  var haystack = [method, path, op.operationId || '', op.summary || ''].concat(op.tags || []).join(' ').toLowerCase();
  d.setAttribute('data-search', haystack);
  var summary = el('summary', null, null);
  summary.appendChild(el('span', 'method ' + method, method.toUpperCase()));
  summary.appendChild(el('span', 'path', path));
  summary.appendChild(el('span', 'opsummary', op.summary || op.operationId || ''));
  d.appendChild(summary);
  d.appendChild(operationBody(op));
  return d;
}

function render() {
  document.getElementById('info-description').textContent =
    firstLines((SPEC.info && SPEC.info.description) || '', 3);

  var byTag = {};
  var methods = ['get', 'post', 'put', 'patch', 'delete'];
  Object.keys(SPEC.paths || {}).sort().forEach(function (path) {
    var item = SPEC.paths[path];
    methods.forEach(function (method) {
      var op = item[method];
      if (!op) return;
      var tag = (op.tags && op.tags[0]) || 'other';
      (byTag[tag] = byTag[tag] || []).push({ method: method, path: path, op: op });
    });
  });

  var main = document.getElementById('main');
  Object.keys(byTag).sort().forEach(function (tag) {
    var group = el('div', 'tag-group', null);
    group.setAttribute('data-tag', tag);
    group.appendChild(el('h2', null, tag));
    byTag[tag].forEach(function (entry) {
      group.appendChild(operationDetails(entry.method, entry.path, entry.op));
    });
    main.appendChild(group);
  });

  document.getElementById('search').addEventListener('input', function (e) {
    var q = e.target.value.toLowerCase();
    document.querySelectorAll('.tag-group').forEach(function (group) {
      var anyVisible = false;
      group.querySelectorAll('.op').forEach(function (op) {
        var match = q === '' || op.getAttribute('data-search').indexOf(q) >= 0;
        op.style.display = match ? '' : 'none';
        if (match) anyVisible = true;
      });
      group.style.display = anyVisible ? '' : 'none';
    });
  });
}

render();
</script>
</body>
</html>
`))
