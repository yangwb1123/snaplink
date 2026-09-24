import type { LoginRequest, MyPreferences, MyPreferencesUpdateRequest, PreferenceUpdateResponse, SSOClient } from "./client.js";
/** Presentation theme values shared by Snaplink-hosted applications. */
export type PresentationThemeMode = "light" | "dark" | "auto";
/**
 * Application-facing presentation preferences.
 *
 * Wire keys deliberately do not appear here. The adapter owns the
 * application-neutral `theme_mode` mapping and its legacy
 * `sverp:theme_mode` fallback.
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
export type LoginPreferenceHandoff = Pick<LoginRequest, "presentation_locale" | "presentation_theme_mode">;
/** Convert the generated Snaplink wire response into application fields. */
export declare function fromMyPreferences(value: MyPreferences): PresentationPreferences;
/** Convert application fields into the generated Snaplink PUT body. */
export declare function toMyPreferencesUpdateRequest(value: PresentationPreferencesPatch): MyPreferencesUpdateRequest;
/**
 * Build only the login preference values explicitly supplied by the caller.
 * The application tracks whether a value changed during this login-page
 * session; omitted fields remain omitted and therefore do not overwrite the
 * user's stored preference.
 */
export declare function buildLoginPreferenceHandoff(value: PresentationPreferencesPatch): LoginPreferenceHandoff;
/**
 * Typed preference facade for the generated HTTP client.
 *
 * It owns protocol mapping and validation; callers retain ownership of UI
 * state, caching, and storage.
 */
export declare class SnaplinkUserPreferencesClient {
    private readonly client;
    constructor(client: Pick<SSOClient, "getMyPreferences" | "putMyPreferences">);
    getMyPreferences(): Promise<PresentationPreferences>;
    updateMyPreferences(value: PresentationPreferencesPatch): Promise<PreferenceUpdateResponse>;
}
