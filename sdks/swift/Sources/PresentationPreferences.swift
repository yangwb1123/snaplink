import Foundation

/// A theme selection shared by Snaplink-hosted applications.
public enum SnaplinkThemeMode: String, CaseIterable, Sendable {
    case light
    case dark
    /// Follow the operating system.
    case auto
}

/// Why a preference value was rejected.
public enum SnaplinkPreferenceError: Error, Sendable, Equatable, LocalizedError {
    /// The locale is not a well-formed BCP 47 tag.
    case invalidLocale
    /// The theme value is outside the allowlist.
    case invalidThemeMode
    /// The response carried both theme aliases with different values.
    case conflictingThemeAliases

    public var errorDescription: String? {
        switch self {
        case .invalidLocale: "locale must be a valid BCP 47 language tag"
        case .invalidThemeMode: "theme_mode must be light, dark, or auto"
        case .conflictingThemeAliases: "conflicting theme preference aliases"
        }
    }
}

/// Application-facing presentation preferences.
///
/// Wire keys deliberately do not appear in these types; the mapping to the
/// hosted-login query fields and the legacy `sverp:theme_mode` alias lives in
/// this module, so a protocol rename stays a one-line change here instead of
/// rippling through call sites.
public struct SnaplinkPresentationPreferences: Sendable, Equatable {
    /// BCP 47 language tag, absent when unset.
    public let locale: String?
    /// Theme selection, absent when unset.
    public let themeMode: SnaplinkThemeMode?

    public init(locale: String? = nil, themeMode: SnaplinkThemeMode? = nil) {
        self.locale = locale
        self.themeMode = themeMode
    }
}

/// A partial update.
///
/// An empty `locale` removes the stored value. `themeMode` has no empty value,
/// so removal is expressed by omitting the field.
public struct SnaplinkPresentationPreferencesPatch: Sendable, Equatable {
    public let locale: String?
    public let themeMode: SnaplinkThemeMode?

    public init(locale: String? = nil, themeMode: SnaplinkThemeMode? = nil) {
        self.locale = locale
        self.themeMode = themeMode
    }
}

public enum SnaplinkPresentationPreferencesCodec {
    /// The longest locale the server accepts, matching the OpenAPI `maxLength`.
    static let maximumLocaleLength = 32

    /// Maps a stored preference response to application fields.
    ///
    /// A response whose two theme aliases disagree is refused rather than
    /// resolved by precedence: picking one silently would hide a server that
    /// still has a stale alias in the profile.
    public static func fromStored(_ raw: Data) throws -> SnaplinkPresentationPreferences {
        let object: [String: Any]
        do {
            object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] ?? [:]
        } catch {
            throw SnaplinkPreferenceError.invalidThemeMode
        }
        if let locale = object["locale"] {
            guard let text = locale as? String else { throw SnaplinkPreferenceError.invalidLocale }
            try validate(locale: text, allowEmpty: false)
        }
        let current = try theme(from: object["theme_mode"])
        let legacy = try theme(from: object["sverp:theme_mode"])
        if let current, let legacy, current != legacy {
            throw SnaplinkPreferenceError.conflictingThemeAliases
        }
        return SnaplinkPresentationPreferences(
            locale: object["locale"] as? String,
            themeMode: current ?? legacy
        )
    }

    /// Maps a patch to the `PUT /me/preferences` request body.
    public static func toUpdateRequest(
        _ patch: SnaplinkPresentationPreferencesPatch
    ) throws -> [String: String] {
        var body: [String: String] = [:]
        if let locale = patch.locale {
            try validate(locale: locale, allowEmpty: true)
            body["locale"] = locale
        }
        if let themeMode = patch.themeMode {
            body["theme_mode"] = themeMode.rawValue
        }
        return body
    }

    /// Builds the hosted-login handoff: only explicitly changed, non-empty
    /// values, keyed by the login query field that carries them.
    ///
    /// A handoff is a presentation hint, not an authorization or tenant
    /// parameter: the server persists it as the authenticated user's allowlisted
    /// preference only after a successful authentication. Absent fields are
    /// omitted rather than sent empty, so a handoff never clears a preference
    /// the application did not mean to touch.
    public static func buildLoginHandoff(
        _ patch: SnaplinkPresentationPreferencesPatch
    ) throws -> [String: String] {
        var handoff: [String: String] = [:]
        if let locale = patch.locale {
            try validate(locale: locale, allowEmpty: false)
            handoff["presentation_locale"] = locale
        }
        if let themeMode = patch.themeMode {
            handoff["presentation_theme_mode"] = themeMode.rawValue
        }
        return handoff
    }

    private static func theme(from value: Any?) throws -> SnaplinkThemeMode? {
        guard let value else { return nil }
        guard let text = value as? String, let mode = SnaplinkThemeMode(rawValue: text) else {
            throw SnaplinkPreferenceError.invalidThemeMode
        }
        return mode
    }

    /// A pragmatic BCP 47 subset: a 2-3 letter primary subtag followed by
    /// alphanumeric subtags of 2-8 characters. This mirrors the server's own
    /// pattern and is deliberately not a full RFC 5646 parser.
    static func validate(locale: String, allowEmpty: Bool) throws {
        if allowEmpty && locale.isEmpty { return }
        guard !locale.isEmpty, locale.utf8.count <= maximumLocaleLength else {
            throw SnaplinkPreferenceError.invalidLocale
        }
        let parts = locale.split(separator: "-", omittingEmptySubsequences: false)
        guard let primary = parts.first,
              (2...3).contains(primary.count),
              primary.allSatisfy({ $0.isASCII && $0.isLetter }) else {
            throw SnaplinkPreferenceError.invalidLocale
        }
        for part in parts.dropFirst() {
            guard (2...8).contains(part.count),
                  part.allSatisfy({ $0.isASCII && $0.isLetter || $0.isASCII && $0.isNumber }) else {
                throw SnaplinkPreferenceError.invalidLocale
            }
        }
    }
}
