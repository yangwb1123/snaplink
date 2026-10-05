// Cross-language conformance for the permission-holding rule.
//
// The cases in `ops/build/sdk-conformance/authorization.json` are the shared
// contract. A client rule that disagrees with the server is worse than no rule
// at all: it hides controls the server would grant and shows controls it would
// deny, so the rule is implemented once here and asserted against one fixture.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { holds, isNodeVisible, permittedActions, readAuthorization, visibleMenus } from "./index.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(
    join(HERE, "..", "..", "ops", "build", "sdk-conformance", "authorization.json"),
    "utf-8",
  ),
);

test("fixture is reachable and populated", () => {
  assert.ok(fixture.cases.length > 0, "the shared fixture must not be empty");
});

test("every rule case matches the contract", () => {
  for (const entry of fixture.cases) {
    assert.equal(
      holds(entry.held, entry.required),
      entry.expect,
      `${entry.id}: holds(${JSON.stringify(entry.held)}, ${JSON.stringify(entry.required)})`,
    );
  }
});

test("the fixture is exhaustive about the wildcard boundary", () => {
  // These are the cases a hand-rolled rule gets wrong, so their presence is
  // itself the assertion.
  const ids = fixture.cases.map((entry) => entry.id);
  for (const required of [
    "exact_match",
    "absent_permission_is_denied",
    "domain_wildcard_does_not_match_a_similar_looking_domain",
    "a_bare_star_grants_everything",
    "an_unqualified_permission_is_never_a_prefix",
    "an_empty_requirement_is_always_granted",
  ]) {
    assert.ok(ids.includes(required), `fixture must keep the ${required} case`);
  }
});

test("a node with no permission is always visible", () => {
  assert.ok(isNodeVisible({ id: "a", name: "A" }, []));
  assert.ok(isNodeVisible({ id: "a", name: "A", permission: "" }, []));
});

test("a node is visible when its permission is held, directly or by wildcard", () => {
  assert.ok(isNodeVisible({ id: "a", name: "A", permission: "panel:read" }, ["panel:read"]));
  assert.ok(isNodeVisible({ id: "a", name: "A", permission: "panel:config:apply" }, ["panel:*"]));
  assert.ok(!isNodeVisible({ id: "a", name: "A", permission: "panel:write" }, ["panel:read"]));
});

test("buttons are filtered by the same rule as their node", () => {
  const node = {
    id: "users",
    name: "Users",
    buttons: [
      { code: "create", name: "New", permission: "panel:inbound:write" },
      { code: "delete", name: "Delete", permission: "panel:*" },
      { code: "help", name: "Help" },
    ],
  };
  assert.deepEqual(
    permittedActions(node, ["panel:inbound:write"]).map((button) => button.code),
    ["create", "help"],
    "a narrower grant still shows the button with no permission",
  );
  assert.deepEqual(
    permittedActions(node, ["panel:*"]).map((button) => button.code),
    ["create", "delete", "help"],
  );
  assert.deepEqual(permittedActions(node, []).map((button) => button.code), ["help"]);
});

test("a hidden parent takes its children with it", () => {
  const tree = [
    {
      id: "admin",
      name: "Admin",
      permission: "panel:*",
      children: [{ id: "audit", name: "Audit", permission: "panel:read" }],
    },
    {
      id: "portal",
      name: "Portal",
      children: [{ id: "me", name: "Me" }],
    },
  ];
  assert.deepEqual(
    visibleMenus(tree, []).map((node) => node.id),
    ["portal"],
    "a parent whose own permission is denied is dropped with its children",
  );
  assert.deepEqual(
    visibleMenus(tree, ["panel:*"]).map((node) => node.id),
    ["admin", "portal"],
  );
  assert.deepEqual(
    visibleMenus(visibleMenus(tree, ["panel:*"]), ["panel:*"])[0].children.map((n) => n.id),
    ["audit"],
  );
});

test("identity, permissions, roles, and menus are read together and scoped", async () => {
  const seen = [];
  const bodies = {
    "/userinfo": { sub: "user-alice", email: "alice@example.test", name: "Alice" },
    "/permissions/me": { permissions: [{ code: "panel:read" }, "panel:config:apply", { code: "" }] },
    "/roles/me": { roles: [{ code: "panel-viewer" }] },
    "/menus/me": { menus: [{ id: "m", name: "Inbounds", permission: "panel:read" }] },
  };
  const request = async (path, query) => {
    seen.push({ path, query });
    return bodies[path];
  };

  const authorization = await readAuthorization(request, "singbox-panel");
  assert.equal(authorization.subject, "user-alice");
  assert.equal(authorization.email, "alice@example.test");
  assert.deepEqual(authorization.permissions, ["panel:read", "panel:config:apply"]);
  assert.deepEqual(authorization.roles, ["panel-viewer"]);
  assert.equal(authorization.menus.length, 1);

  // Every projection must be scoped to the application, or one subject's grants
  // for another application would be read silently.
  for (const call of seen) {
    if (call.path === "/userinfo") continue;
    assert.deepEqual(call.query, { client_id: "singbox-panel" }, call.path);
  }
  assert.deepEqual(
    seen.map((call) => call.path).sort(),
    ["/menus/me", "/permissions/me", "/roles/me", "/userinfo"],
  );
});

test("a response with no subject is rejected rather than trusted", async () => {
  const request = async (path) =>
    path === "/userinfo" ? { email: "nobody@example.test" } : {};
  await assert.rejects(() => readAuthorization(request, "app"), /no subject/);
});

test("an unreadable list is empty rather than a grant", async () => {
  const authorization = await readAuthorization(
    async (path) => (path === "/userinfo" ? { sub: "u" } : null),
    "app",
  );
  assert.deepEqual(authorization.permissions, []);
  assert.deepEqual(authorization.roles, []);
  assert.deepEqual(authorization.menus, []);
});