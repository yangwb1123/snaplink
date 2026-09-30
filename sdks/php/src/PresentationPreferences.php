<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * Application-facing presentation preferences for Snaplink clients.
 *
 * The wire keys deliberately do not appear in the application-facing fields.
 * This class owns the mapping to the hosted-login query fields and to the
 * allowlisted /me/preferences body, including the legacy `sverp:theme_mode`
 * alias, so a protocol rename stays a change in one place.
 *
 * A handoff is a presentation hint, not an authorization or tenant parameter:
 * the server persists it as the authenticated user's preference only after a
 * successful authentication.
 */
final class PresentationPreferences
{
    /** The server's theme allowlist. */
    public const THEME_MODES = ['light', 'dark', 'auto'];

    /** The pre-rename alias still served during migration. */
    public const LEGACY_THEME_MODE_KEY = 'sverp:theme_mode';

    /** Matches the OpenAPI maxLength for presentation_locale. */
    private const MAX_LOCALE_LENGTH = 32;

    private function __construct(
        public readonly ?string $locale = null,
        public readonly ?string $themeMode = null,
    ) {
    }

    /**
     * Build a stored-value view. An empty patch is what an unset preference
     * looks like on the wire.
     *
     * @param array<string,mixed> $raw
     */
    public static function fromMyPreferences(array $raw): self
    {
        $locale = $raw['locale'] ?? null;
        if ($locale !== null) {
            $locale = self::requireLocale($locale, false);
        }
        return new self($locale, self::resolveThemeMode($raw));
    }

    /**
     * Map a partial update to the PUT body. An empty string removes the
     * stored value; an omitted field is not sent at all.
     *
     * @param array<string,string|null> $patch
     * @return array<string,string>
     */
    public static function toMyPreferencesUpdateRequest(array $patch): array
    {
        $body = [];
        if (($patch['locale'] ?? null) !== null) {
            $body['locale'] = self::requireLocale($patch['locale'], true);
        }
        if (($patch['theme_mode'] ?? null) !== null) {
            $body['theme_mode'] = self::requireThemeMode($patch['theme_mode'], true);
        }
        return $body;
    }

    /**
     * Return only explicitly changed, non-empty login hints.
     *
     * Spread the result into login() as `presentation_locale` and
     * `presentation_theme_mode`. Omitted fields stay omitted so a handoff
     * never clears a preference the application did not mean to touch.
     *
     * @param array<string,string|null> $patch
     * @return array<string,string>
     */
    public static function buildLoginPreferenceHandoff(array $patch): array
    {
        $handoff = [];
        if (($patch['locale'] ?? null) !== null) {
            $handoff['presentation_locale'] = self::requireLocale($patch['locale'], false);
        }
        $themeMode = $patch['theme_mode'] ?? null;
        if ($themeMode !== null && $themeMode !== '') {
            $handoff['presentation_theme_mode'] = self::requireThemeMode($themeMode, false);
        }
        return $handoff;
    }

    /**
     * @param array<string,mixed> $raw
     */
    private static function resolveThemeMode(array $raw): ?string
    {
        $generic = $raw['theme_mode'] ?? null;
        $legacy = $raw[self::LEGACY_THEME_MODE_KEY] ?? null;
        if ($generic !== null && $legacy !== null && $generic !== $legacy) {
            throw new SSOError(0, 'invalid_response', 'conflicting theme preference aliases');
        }
        $value = $generic ?? $legacy;
        return $value === null ? null : self::requireThemeMode($value, false);
    }

    /**
     * A pragmatic BCP 47 subset: a 2-3 letter primary subtag followed by
     * alphanumeric subtags of 2-8 characters, mirroring the server's own
     * pattern rather than implementing RFC 5646.
     */
    private static function requireLocale(mixed $value, bool $allowEmpty): string
    {
        if (!is_string($value)) {
            throw new SSOError(0, 'invalid_request', 'locale must be a string');
        }
        if ($allowEmpty && $value === '') {
            return '';
        }
        $parts = explode('-', $value);
        $invalid = $value === '' || strlen($value) > self::MAX_LOCALE_LENGTH
            || !self::isAlpha($parts[0]) || strlen($parts[0]) < 2 || strlen($parts[0]) > 3;
        foreach (array_slice($parts, 1) as $part) {
            $invalid = $invalid || strlen($part) < 2 || strlen($part) > 8 || !self::isAlphaNumeric($part);
        }
        if ($invalid) {
            throw new SSOError(0, 'invalid_request', 'locale must be a valid BCP 47 language tag');
        }
        return $value;
    }

    private static function requireThemeMode(mixed $value, bool $allowEmpty): string
    {
        if (!is_string($value)) {
            throw new SSOError(0, 'invalid_request', 'theme_mode must be a string');
        }
        if ($allowEmpty && $value === '') {
            return '';
        }
        if (!in_array($value, self::THEME_MODES, true)) {
            throw new SSOError(0, 'invalid_request', 'theme_mode must be light, dark, or auto');
        }
        return $value;
    }

    private static function isAlpha(string $value): bool
    {
        return $value !== '' && preg_match('/^[A-Za-z]+$/', $value) === 1;
    }

    private static function isAlphaNumeric(string $value): bool
    {
        return $value !== '' && preg_match('/^[A-Za-z0-9]+$/', $value) === 1;
    }
}
