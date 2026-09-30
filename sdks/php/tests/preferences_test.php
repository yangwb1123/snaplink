<?php

declare(strict_types=1);

// Presentation preference handoff: the mapping to /me/preferences and to the
// hosted-login query fields, including the legacy theme alias. The same
// contract is asserted in the other hosted-login SDKs; a change here is a
// change in every language.

require __DIR__ . '/../src/PresentationPreferences.php';
require __DIR__ . '/../src/SnaplinkClient.php';

use Snaplink\MemoryStateStore;
use Snaplink\PresentationPreferences;
use Snaplink\SnaplinkClient;
use Snaplink\SnaplinkError;

$failures = 0;
$checks = 0;

function check(string $name, bool $condition, string $detail = ''): void
{
    global $failures, $checks;
    $checks++;
    if ($condition) {
        echo "  ok   $name\n";
        return;
    }
    $failures++;
    echo "  FAIL $name" . ($detail === '' ? '' : ": $detail") . "\n";
}

function rejects(string $name, callable $action, string $expected): void
{
    try {
        $action();
        check($name, false, 'no error was raised');
    } catch (SnaplinkError $error) {
        check($name, $error->error === $expected, $error->error . ' ' . (string) $error);
    }
}

$stored = PresentationPreferences::fromMyPreferences(['locale' => 'zh-CN', 'theme_mode' => 'dark']);
check('a stored response maps to application fields', $stored->locale === 'zh-CN' && $stored->themeMode === 'dark');
$legacy = PresentationPreferences::fromMyPreferences([PresentationPreferences::LEGACY_THEME_MODE_KEY => 'auto']);
check('the legacy theme alias stays readable', $legacy->themeMode === 'auto' && $legacy->locale === null);
$empty = PresentationPreferences::fromMyPreferences([]);
check('an empty response yields no preferences', $empty->locale === null && $empty->themeMode === null);
rejects(
    'conflicting theme aliases are refused',
    static fn() => PresentationPreferences::fromMyPreferences([
        'theme_mode' => 'dark',
        PresentationPreferences::LEGACY_THEME_MODE_KEY => 'light',
    ]),
    'invalid_response'
);
foreach (['english-language-tag', 'en_US', 'e', 'en-US-', str_repeat('en-', 10) . 'abc'] as $locale) {
    rejects(
        "locale $locale is refused",
        static fn() => PresentationPreferences::fromMyPreferences(['locale' => $locale]),
        'invalid_request'
    );
}
rejects(
    'an unknown theme value is refused',
    static fn() => PresentationPreferences::fromMyPreferences(['theme_mode' => 'sepia']),
    'invalid_request'
);
rejects(
    'a non-string locale is refused',
    static fn() => PresentationPreferences::fromMyPreferences(['locale' => 42]),
    'invalid_request'
);

$exact = str_repeat('en-', 10) . 'ab';
check('a 32-character locale is accepted', strlen($exact) === 32 && PresentationPreferences::fromMyPreferences(['locale' => $exact])->locale === $exact);

$body = PresentationPreferences::toMyPreferencesUpdateRequest(['theme_mode' => 'dark']);
check('an untouched field is not sent', $body === ['theme_mode' => 'dark']);
$removal = PresentationPreferences::toMyPreferencesUpdateRequest(['locale' => '']);
check('an empty value removes a stored preference', $removal === ['locale' => '']);
rejects(
    'an invalid update value is refused',
    static fn() => PresentationPreferences::toMyPreferencesUpdateRequest(['theme_mode' => 'sepia']),
    'invalid_request'
);

$handoff = PresentationPreferences::buildLoginPreferenceHandoff(['locale' => 'en-US', 'theme_mode' => 'dark']);
check(
    'a handoff carries only explicit values',
    $handoff === ['presentation_locale' => 'en-US', 'presentation_theme_mode' => 'dark']
);
$localeOnly = PresentationPreferences::buildLoginPreferenceHandoff(['locale' => 'en-US']);
check('an omitted field stays omitted', $localeOnly === ['presentation_locale' => 'en-US']);
$emptyTheme = PresentationPreferences::buildLoginPreferenceHandoff(['theme_mode' => '']);
check('an empty theme hint clears nothing', $emptyTheme === []);
rejects(
    'a handoff refuses a value outside the allowlist',
    static fn() => PresentationPreferences::buildLoginPreferenceHandoff(['theme_mode' => 'sepia']),
    'invalid_request'
);

$jsonCalls = [];
$client = new SnaplinkClient(
    new MemoryStateStore(),
    static fn(string $endpoint, array $form): array => [
        'access_token' => 'access-1',
        'expires_in' => 900,
        'refresh_token' => 'refresh-1',
        'token_type' => 'Bearer',
    ],
    static function (string $method, string $endpoint, ?array $body, ?string $bearer) use (&$jsonCalls): array {
        $jsonCalls[] = [$method, $endpoint, $body, $bearer];
        if ($method === 'GET') {
            return ['locale' => 'zh-CN', 'theme_mode' => 'dark'];
        }
        return ['locale' => 'en-US', 'theme_mode' => 'light'];
    },
);
$loginOptions = [
    'base_url' => 'https://sso.example.test',
    'client_id' => 'spa-client',
    'redirect_uri' => 'https://app.example.test/auth/callback',
];
$started = $client->login($loginOptions);
$loginQuery = [];
parse_str((string) (parse_url((string) $started->redirectUrl())['query'] ?? ''), $loginQuery);
$client->login($loginOptions + [
    'callback_url' => $loginOptions['redirect_uri']
        . '?code=code-1&state=' . rawurlencode((string) $loginQuery['state'])
        . '&iss=' . rawurlencode($loginOptions['base_url']),
]);

$read = PresentationPreferences::fromMyPreferences($client->getMyPreferences());
check(
    'reading preferences is bearer-authenticated',
    $jsonCalls[0][0] === 'GET'
        && str_ends_with($jsonCalls[0][1], '/me/preferences')
        && $jsonCalls[0][3] === 'access-1'
);
check(
    'the typed read maps the stored response',
    $read->locale === 'zh-CN' && $read->themeMode === 'dark'
);
$client->updateMyPreferences(['locale' => 'en-US']);
$write = $jsonCalls[1];
check(
    'writing preferences sends only the supplied field',
    $write[0] === 'PUT' && $write[2] === ['locale' => 'en-US'] && $write[3] === 'access-1'
);

// A login URL is only built while no session is held, so the hint checks use a
// client that has not completed login.
$hintClient = new SnaplinkClient(new MemoryStateStore());
$hintStarted = $hintClient->login($loginOptions + $handoff);
parse_str((string) (parse_url((string) $hintStarted->redirectUrl())['query'] ?? ''), $hintQuery);
check(
    'the handoff reaches the login URL',
    ($hintQuery['presentation_locale'] ?? '') === 'en-US'
        && ($hintQuery['presentation_theme_mode'] ?? '') === 'dark'
);
$staleStarted = $hintClient->login([
    'base_url' => 'https://sso.example.test',
    'client_id' => 'spa-client',
    'redirect_uri' => 'https://app.example.test/auth/callback',
    'login_page_url' => 'https://sso.example.test/login/?keep=1&presentation_locale=de-DE',
]);
parse_str((string) (parse_url((string) $staleStarted->redirectUrl())['query'] ?? ''), $staleQuery);
check(
    'a stale hint in the login-page URL is replaced, not inherited',
    ($staleQuery['keep'] ?? '') === '1' && !isset($staleQuery['presentation_locale'])
);
rejects(
    'a whitespace-bearing hint is refused',
    static fn() => $hintClient->login($loginOptions + ['presentation_locale' => 'en US']),
    'invalid_request'
);
$anonymous = new SnaplinkClient(new MemoryStateStore());
rejects('reading preferences without a session is refused', static fn() => $anonymous->getMyPreferences(), 'login_required');
rejects(
    'writing preferences without a session is refused',
    static fn() => $anonymous->updateMyPreferences(['locale' => 'en-US']),
    'login_required'
);

echo "$checks checks, $failures failures\n";
exit($failures === 0 ? 0 : 1);
