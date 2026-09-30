<?php

declare(strict_types=1);

// The error taxonomy is a cross-language contract: a caller branches on the
// code, so every SDK must classify the same response identically. The cases
// come from the shared fixture rather than a local list, which is what makes
// drift detectable.

require __DIR__ . '/conformance_corpus.php';
require __DIR__ . '/../src/Entitlement.php';
require __DIR__ . '/../src/StateStore.php';
require __DIR__ . '/../src/MemoryStateStore.php';
require __DIR__ . '/../src/LoginResult.php';
require __DIR__ . '/../src/SSOError.php';
require __DIR__ . '/../src/SSOClient.php';

use Snaplink\MemoryStateStore;
use Snaplink\SSOClient;
use Snaplink\SSOError;

snaplinkSkipWithoutConformanceCorpus('error taxonomy conformance');

$fixture = json_decode(
    (string) file_get_contents(snaplinkConformanceFixture('errors.json')),
    true,
);
if (!is_array($fixture) || !isset($fixture['cases'], $fixture['shape']['fallback']['code'])) {
    fwrite(STDERR, "the shared error fixture is unreadable\n");
    exit(1);
}

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

/** A client whose JSON transport always answers with this status and body. */
function failingClient(int $status, string $body): SSOClient
{
    return new SSOClient(
        new MemoryStateStore(),
        static fn(string $endpoint, array $form): array => [
            'access_token' => 'access-1',
            'refresh_token' => 'refresh-1',
            'token_type' => 'Bearer',
        ],
        static function (string $method, string $endpoint, ?array $request, ?string $bearer) use ($status, $body): array {
            return ['status' => $status, 'body' => $body];
        },
    );
}

/** Log a client in so the account-context call carries a bearer. */
function login(SSOClient $client): void
{
    $options = [
        'base_url' => 'https://sso.example.test',
        'client_id' => 'spa-client',
        'redirect_uri' => 'https://app.example.test/auth/callback',
    ];
    $started = $client->login($options);
    $query = [];
    parse_str((string) (parse_url((string) $started->redirectUrl())['query'] ?? ''), $query);
    $client->login($options + [
        'callback_url' => $options['redirect_uri']
            . '?code=code-1&state=' . rawurlencode((string) $query['state'])
            . '&iss=' . rawurlencode($options['base_url']),
    ]);
}

foreach ($fixture['cases'] as $case) {
    if (!is_int($case['status'] ?? null) || $case['status'] === 0) {
        // A locally originated case is never a wire response.
        continue;
    }
    $body = json_encode([
        'error' => $case['code'],
        'error_description' => 'any wording',
    ]);
    $client = failingClient($case['status'], $body);
    login($client);
    try {
        $client->getAccountContext('pro');
        check("code {$case['code']} is reported", false, 'no error was raised');
    } catch (SSOError $error) {
        check(
            "code {$case['code']} survives verbatim",
            $error->error === $case['code'] && $error->status === $case['status'],
            $error->error . ' @ ' . $error->status
        );
    }
}

$fallback = $fixture['shape']['fallback']['code'];
foreach ([
    'an empty object' => '{}',
    'a description without a code' => '{"error_description":"no code"}',
    'a non-JSON body' => 'not json at all',
    'an empty body' => '',
] as $label => $body) {
    $client = failingClient(500, $body);
    login($client);
    try {
        $client->getAccountContext('pro');
        check("$label is reported as unclassified", false, 'no error was raised');
    } catch (SSOError $error) {
        check(
            "$label is reported as unclassified",
            $error->error === $fallback && $error->error !== 'invalid_grant' && $error->status === 500,
            $error->error . ' @ ' . $error->status
        );
    }
}

try {
    (new SSOClient())->refresh();
    check('a pre-flight failure keeps the zero status', false, 'no error was raised');
} catch (SSOError $error) {
    check(
        'a pre-flight failure keeps the zero status',
        $error->status === 0 && $error->error === 'login_required',
        $error->error . ' @ ' . $error->status
    );
}

echo "$checks checks, $failures failures\n";
exit($failures === 0 ? 0 : 1);
