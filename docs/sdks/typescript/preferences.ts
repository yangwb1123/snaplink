import type {
  LoginRequest,
  MyPreferences,
  MyPreferencesUpdateRequest,
  PreferenceUpdateResponse,
  SSOClient,
} from "./client.js";

/** Presentation theme values shared by Snaplink-hosted applications. */
export type PresentationThemeMode = "light" | "dark" | "auto";

/**
 * Application-facing presentation preferences.
 *
 * The wire key `sverp:theme_mode` deliberately does not appear here. Keep
 * protocol naming and application naming separate; the adapter below owns
 * that compatibility mapping.
 */
export interface PresentationPreferences {
  locale?: string;
  themeMode?: PresentationThemeMode;
}

/** A partial update; an empty value removes the corresponding preference. */
export interface PresentationPreferencesPatch {
  locale?: string;
  themeMode?: PresentationThemeMode | "";
}

/** Login-query fields accepted by the hosted-login handoff. */
export type LoginPreferenceHandoff = Pick<
  LoginRequest,
  "presentation_locale" | "presentation_theme_mode"
>;

const localePattern = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;
const themeModes = new Set<PresentationThemeMode>(["light", "dark", "auto"]);

function assertLocale(value: string, allowEmpty: boolean): void {
  if (allowEmpty && value === "") return;
  if (value.length > 32 || !localePattern.test(value)) {
    throw new TypeError("locale must be a valid BCP 47 language tag");
  }
}

function assertThemeMode(
  value: PresentationThemeMode | "",
  allowEmpty: boolean,
): void {
  if (allowEmpty && value === "") return;
  if (!themeModes.has(value as PresentationThemeMode)) {
    throw new TypeError("themeMode must be light, dark, or auto");
  }
}

/** Convert the generated Snaplink wire response into application fields. */
export function fromMyPreferences(
  value: MyPreferences,
): PresentationPreferences {
  const result: PresentationPreferences = {};
  if (value.locale !== undefined) {
    assertLocale(value.locale, false);
    result.locale = value.locale;
  }
  const themeMode = value["sverp:theme_mode"];
  if (themeMode !== undefined) {
    assertThemeMode(themeMode, false);
    result.themeMode = themeMode;
  }
  return result;
}

/** Convert application fields into the generated Snaplink PUT body. */
export function toMyPreferencesUpdateRequest(
  value: PresentationPreferencesPatch,
): MyPreferencesUpdateRequest {
  const result: MyPreferencesUpdateRequest = {};
  if (value.locale !== undefined) {
    assertLocale(value.locale, true);
    result.locale = value.locale;
  }
  if (value.themeMode !== undefined) {
    assertThemeMode(value.themeMode, true);
    result["sverp:theme_mode"] = value.themeMode;
  }
  return result;
}

/**
 * Build only the login preference values explicitly supplied by the caller.
 * The application tracks whether a value changed during this login-page
 * session; omitted fields remain omitted and therefore do not overwrite the
 * user's stored preference.
 */
export function buildLoginPreferenceHandoff(
  value: PresentationPreferencesPatch,
): LoginPreferenceHandoff {
  const result: LoginPreferenceHandoff = {};
  if (value.locale !== undefined) {
    assertLocale(value.locale, false);
    result.presentation_locale = value.locale;
  }
  if (value.themeMode !== undefined && value.themeMode !== "") {
    assertThemeMode(value.themeMode, false);
    result.presentation_theme_mode = value.themeMode;
  }
  return result;
}

/**
 * Typed preference facade for the generated HTTP client.
 *
 * It owns protocol mapping and validation; callers retain ownership of UI
 * state, caching, and storage.
 */
export class SnaplinkUserPreferencesClient {
  constructor(
    private readonly client: Pick<
      SSOClient,
      "getMyPreferences" | "putMyPreferences"
    >,
  ) {}

  async getMyPreferences(): Promise<PresentationPreferences> {
    return fromMyPreferences(await this.client.getMyPreferences());
  }

  async updateMyPreferences(
    value: PresentationPreferencesPatch,
  ): Promise<PreferenceUpdateResponse> {
    return this.client.putMyPreferences(toMyPreferencesUpdateRequest(value));
  }
}
