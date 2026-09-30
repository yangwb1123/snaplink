import Foundation
import XCTest
@testable import SnaplinkSSO

final class PresentationPreferencesTests: XCTestCase {
    func testMapsStoredPreferencesIncludingTheLegacyThemeAlias() throws {
        let stored = try SnaplinkPresentationPreferencesCodec.fromStored(
            Data(#"{"locale":"zh-CN","sverp:theme_mode":"dark"}"#.utf8)
        )
        XCTAssertEqual(stored.locale, "zh-CN")
        XCTAssertEqual(stored.themeMode, .dark)
    }

    func testRefusesConflictingThemeAliases() throws {
        let raw = Data(#"{"theme_mode":"dark","sverp:theme_mode":"light"}"#.utf8)
        XCTAssertThrowsError(try SnaplinkPresentationPreferencesCodec.fromStored(raw)) { error in
            XCTAssertEqual(error as? SnaplinkPreferenceError, .conflictingThemeAliases)
        }
    }

    func testRefusesAnUnknownThemeValue() throws {
        let raw = Data(#"{"theme_mode":"solarized"}"#.utf8)
        XCTAssertThrowsError(try SnaplinkPresentationPreferencesCodec.fromStored(raw)) { error in
            XCTAssertEqual(error as? SnaplinkPreferenceError, .invalidThemeMode)
        }
    }

    func testAbsentPreferencesDecodeAsUnset() throws {
        let stored = try SnaplinkPresentationPreferencesCodec.fromStored(Data("{}".utf8))
        XCTAssertNil(stored.locale)
        XCTAssertNil(stored.themeMode)
    }

    func testUpdateRequestCarriesOnlySetFields() throws {
        let body = try SnaplinkPresentationPreferencesCodec.toUpdateRequest(
            SnaplinkPresentationPreferencesPatch(locale: "en-US", themeMode: .auto)
        )
        XCTAssertEqual(body, ["locale": "en-US", "theme_mode": "auto"])

        let empty = try SnaplinkPresentationPreferencesCodec.toUpdateRequest(
            SnaplinkPresentationPreferencesPatch()
        )
        XCTAssertTrue(empty.isEmpty)
    }

    func testEmptyLocaleIsADeletionInAnUpdateButNotInAHandoff() throws {
        let deletion = try SnaplinkPresentationPreferencesCodec.toUpdateRequest(
            SnaplinkPresentationPreferencesPatch(locale: "")
        )
        XCTAssertEqual(deletion, ["locale": ""])

        XCTAssertThrowsError(
            try SnaplinkPresentationPreferencesCodec.buildLoginHandoff(
                SnaplinkPresentationPreferencesPatch(locale: "")
            )
        )
    }

    func testLoginHandoffUsesTheLoginFieldNames() throws {
        let handoff = try SnaplinkPresentationPreferencesCodec.buildLoginHandoff(
            SnaplinkPresentationPreferencesPatch(locale: "zh-CN", themeMode: .dark)
        )
        XCTAssertEqual(handoff, ["presentation_locale": "zh-CN", "presentation_theme_mode": "dark"])
    }

    func testLocaleValidationMatchesTheServerPattern() {
        for valid in ["en", "eng", "zh-CN", "en-US", "zh-Hans-CN", "es-419"] {
            XCTAssertNoThrow(
                try SnaplinkPresentationPreferencesCodec.validate(locale: valid, allowEmpty: false),
                "\(valid) should be accepted"
            )
        }
        for invalid in ["", "e", "english-language-tag", "en_US", "en-", "-en", "en-C", "en-ABCDEFGHI", "en-US-"] {
            XCTAssertThrowsError(
                try SnaplinkPresentationPreferencesCodec.validate(locale: invalid, allowEmpty: false),
                "\(invalid) should be rejected"
            )
        }
        let tooLong = String(repeating: "a", count: 33)
        XCTAssertThrowsError(try SnaplinkPresentationPreferencesCodec.validate(locale: tooLong, allowEmpty: false))
        // allowEmpty only widens the empty string; an over-long tag is still
        // rejected, matching the sibling SDKs and the server's maxLength.
        XCTAssertThrowsError(try SnaplinkPresentationPreferencesCodec.validate(locale: tooLong, allowEmpty: true))
    }

    func testUpdateRequestRejectsAnInvalidThemeBeforeTheNetwork() {
        XCTAssertThrowsError(
            try SnaplinkPresentationPreferencesCodec.toUpdateRequest(
                SnaplinkPresentationPreferencesPatch(locale: "not a locale", themeMode: .dark)
            )
        ) { error in
            XCTAssertEqual(error as? SnaplinkPreferenceError, .invalidLocale)
        }
    }
}
