import assert from "node:assert/strict";
import test from "node:test";

import {
  SSOClient,
  SnaplinkUserPreferencesClient,
  buildLoginPreferenceHandoff,
} from "./index.ts";

function response(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

test("preference facade maps application fields to the Snaplink wire contract", async () => {
  const calls = [];
  const client = new SSOClient({
    baseUrl: "https://sso.example.test",
    getAccessToken: () => "access-token",
    fetch: async (input, init) => {
      calls.push({ url: String(input), init });
      if (init.method === "PUT") return response({ status: "ok" });
      return response({ locale: "zh-CN", "sverp:theme_mode": "dark" });
    },
  });
  const preferences = new SnaplinkUserPreferencesClient(client);

  assert.deepEqual(await preferences.getMyPreferences(), {
    locale: "zh-CN",
    themeMode: "dark",
  });
  await preferences.updateMyPreferences({ locale: "en-US", themeMode: "light" });

  assert.equal(calls[0].init.headers.Authorization, "Bearer access-token");
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    locale: "en-US",
    "sverp:theme_mode": "light",
  });
});

test("login handoff contains only explicitly supplied presentation changes", () => {
  assert.deepEqual(
    buildLoginPreferenceHandoff({ locale: "en-US" }),
    { presentation_locale: "en-US" },
  );
  assert.deepEqual(
    buildLoginPreferenceHandoff({ themeMode: "dark" }),
    { presentation_theme_mode: "dark" },
  );
  assert.deepEqual(buildLoginPreferenceHandoff({}), {});
});
