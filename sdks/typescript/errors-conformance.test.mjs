import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { SSOClient, SSOError, UNCLASSIFIED_ERROR } from "./index.ts";

const fixture = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "ops", "build", "sdk-conformance", "errors.json"),
    "utf8",
  ),
);

function clientReturning(status, body) {
  return new SSOClient({
    baseUrl: "https://sso.example.test",
    clientId: "spa-client",
    fetch: async () =>
      new Response(body, { status, headers: { "content-type": "application/json" } }),
  });
}

test("every fixture error code survives verbatim", async () => {
  for (const entry of fixture.cases) {
    if (!entry.status) continue; // a locally originated case, never a wire response
    const body = JSON.stringify({ error: entry.code, error_description: "any wording" });
    await assert.rejects(
      clientReturning(entry.status, body).postToken({ grant_type: "refresh_token" }),
      (error) => {
        assert.ok(error instanceof SSOError);
        assert.equal(error.error, entry.code);
        assert.equal(error.status, entry.status);
        assert.equal(error.errorDescription, "any wording");
        return true;
      },
    );
  }
});

test("a response without a code is never invented into a server code", async () => {
  for (const body of ["{}", '{"error_description":"no code here"}', "not json at all", ""]) {
    await assert.rejects(
      clientReturning(500, body).postToken({ grant_type: "refresh_token" }),
      (error) => {
        assert.ok(error instanceof SSOError);
        assert.equal(error.error, fixture.shape.fallback.code);
        assert.equal(error.error, UNCLASSIFIED_ERROR);
        assert.notEqual(error.error, "invalid_grant");
        assert.equal(error.status, 500);
        return true;
      },
    );
  }
});

test("a pre-flight failure keeps the zero status", async () => {
  const client = new SSOClient({ baseUrl: "https://sso.example.test" });
  await assert.rejects(
    client.login("alice", "secret"),
    (error) => {
      assert.ok(error instanceof SSOError);
      assert.equal(error.status, 0);
      assert.equal(error.error, "invalid_request");
      assert.notEqual(error.error, UNCLASSIFIED_ERROR);
      return true;
    },
  );
});
