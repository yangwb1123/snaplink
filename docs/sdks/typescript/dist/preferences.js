const localePattern = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;
const themeModes = new Set(["light", "dark", "auto"]);
function assertLocale(value, allowEmpty) {
    if (allowEmpty && value === "")
        return;
    if (value.length > 32 || !localePattern.test(value)) {
        throw new TypeError("locale must be a valid BCP 47 language tag");
    }
}
function assertThemeMode(value, allowEmpty) {
    if (allowEmpty && value === "")
        return;
    if (!themeModes.has(value)) {
        throw new TypeError("themeMode must be light, dark, or auto");
    }
}
/** Convert the generated Snaplink wire response into application fields. */
export function fromMyPreferences(value) {
    const result = {};
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
export function toMyPreferencesUpdateRequest(value) {
    const result = {};
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
export function buildLoginPreferenceHandoff(value) {
    const result = {};
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
    client;
    constructor(client) {
        this.client = client;
    }
    async getMyPreferences() {
        return fromMyPreferences(await this.client.getMyPreferences());
    }
    async updateMyPreferences(value) {
        return this.client.putMyPreferences(toMyPreferencesUpdateRequest(value));
    }
}
