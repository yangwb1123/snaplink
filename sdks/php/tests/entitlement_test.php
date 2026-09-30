<?php

declare(strict_types=1);

// Cross-language conformance for the entitlement layer.
//
// The cases in ops/build/sdk-conformance/entitlement.json are the shared
// contract, so a change to the fixture changes what every SDK is held to. The
// fixture stores Unix seconds and string-keyed maps to stay readable from any
// language; Entitlement::fromWire is the only place that mapping happens.

// The package is PSR-4 autoloaded in real use; this suite uses plain requires,
// so name the typed entitlement classes explicitly.
require __DIR__ . '/../src/Entitlement.php';
require __DIR__ . '/../src/LicenseState.php';
require __DIR__ . '/../src/StateStore.php';
require __DIR__ . '/../src/MemoryStateStore.php';
require __DIR__ . '/../src/LoginResult.php';
require __DIR__ . '/../src/SSOError.php';
require __DIR__ . '/../src/SSOClient.php';
require __DIR__ . '/conformance_corpus.php';

use Snaplink\Entitlement;
use Snaplink\LicenseState;

const REFERENCE_NOW = 1_700_000_000;

$failures = 0;
$checks = 0;

function check(string $name, bool $condition, string $detail = ''): void
{
    global $failures, $checks;
    $checks++;
    if ($condition) {
        echo "  ok   {$name}\n";
        return;
    }
    $failures++;
    echo "  FAIL {$name}" . ($detail === '' ? '' : ": {$detail}") . "\n";
}

function fixturePath(): string
{
    return snaplinkConformanceFixture('entitlement.json');
}

function loadFixture(): array
{
    $raw = file_get_contents(fixturePath());
    if ($raw === false) {
        throw new RuntimeException('cannot read the shared fixture');
    }
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}

function contextFor(array $case): array
{
    return [
        'product_id' => 'product-a',
        'tenant_id' => 'tenant-a',
        'entitlement' => $case['entitlement'],
    ];
}

function nowOf(array $case): int
{
    return $case['now'] ?? REFERENCE_NOW;
}

function findCase(array $cases, string $id): array
{
    foreach ($cases as $case) {
        if ($case['id'] === $id) {
            return $case;
        }
    }
    throw new RuntimeException("the fixture must contain {$id}");
}

snaplinkSkipWithoutConformanceCorpus('entitlement conformance');

$fixture = loadFixture();
$cases = $fixture['cases'];

check('fixture is reachable and populated', $cases !== []);

foreach ($cases as $case) {
    $state = LicenseState::fromAccountContext(contextFor($case), nowOf($case));
    check(
        "{$case['id']} classifies as {$case['expect_state']}",
        $state['kind'] === $case['expect_state'],
        "got {$state['kind']}",
    );
    if (isset($case['expect_inactive_reason'])) {
        check(
            "{$case['id']} reports reason {$case['expect_inactive_reason']}",
            ($state['reason'] ?? null) === $case['expect_inactive_reason'],
            'got ' . ($state['reason'] ?? 'none'),
        );
    }
}

foreach ($cases as $case) {
    $entitlement = LicenseState::entitlementFromAccountContext(contextFor($case));
    $present = $entitlement !== null;
    $grants = $entitlement !== null && $entitlement->stateAt(nowOf($case))['kind'] === LicenseState::ACTIVE;
    check(
        "{$case['id']} presence does not imply a grant",
        !($present && !$grants && $case['expect_state'] === LicenseState::ACTIVE),
    );
}

$boundary = findCase($cases, 'exactly_at_expiry');
$expiresAt = $boundary['entitlement']['expires_at'];
$entitlement = LicenseState::entitlementFromAccountContext(contextFor($boundary));
check('one second before expiry still grants', $entitlement->stateAt($expiresAt - 1)['kind'] === LicenseState::ACTIVE);
check('the expiry second itself does not grant', $entitlement->stateAt($expiresAt)['kind'] !== LicenseState::ACTIVE);

foreach ($cases as $case) {
    $entitlement = LicenseState::entitlementFromAccountContext(contextFor($case));
    foreach ($case['expect_features'] ?? [] as $key => $want) {
        $got = $entitlement !== null && $entitlement->has($key, nowOf($case));
        check("{$case['id']}/{$key} feature grant", $got === $want, 'got ' . ($got ? 'true' : 'false'));
    }
    foreach ($case['expect_limits'] ?? [] as $key => $want) {
        $grant = $entitlement?->limit($key, nowOf($case));
        if ($grant === null) {
            check(
                "{$case['id']}/{$key} limit loss is explained",
                $entitlement === null || $entitlement->stateAt(nowOf($case))['kind'] !== LicenseState::ACTIVE,
            );
            continue;
        }
        check("{$case['id']}/{$key} limit soft", $grant['soft'] === ($want['soft'] ?? 0));
        check("{$case['id']}/{$key} limit hard", $grant['hard'] === ($want['hard'] ?? 0));
        check("{$case['id']}/{$key} limit unlimited", $grant['unlimited'] === ($want['unlimited'] ?? false));
    }
}

$empty = ['product_id' => 'p', 'tenant_id' => 't', 'entitlement' => null];
check('an absent entitlement is never activated', LicenseState::fromAccountContext($empty, REFERENCE_NOW)['kind'] === LicenseState::NOT_ACTIVATED);
check('an absent entitlement grants nothing', !LicenseState::hasFeature($empty, 'core_sso', REFERENCE_NOW));

check('the server defines ten feature keys', count(Entitlement::FEATURES) === 10);
check('the server defines six limit keys', count(Entitlement::LIMITS) === 6);

$base = ['active' => true, 'features' => [], 'limits' => []];
$fromString = Entitlement::fromWire($base + [
    'effective_at' => '2023-11-14T22:13:19Z',
    'expires_at' => '2023-11-14T22:13:20Z',
]);
$fromNumber = Entitlement::fromWire($base + ['effective_at' => 1699999999, 'expires_at' => 1700000000]);
check('RFC 3339 and Unix seconds agree on effective_at', $fromString->effectiveAt === $fromNumber->effectiveAt);
check('RFC 3339 and Unix seconds agree on expires_at', $fromString->expiresAt === $fromNumber->expiresAt);

check('a missing expiry is absent', Entitlement::fromWire($base)->expiresAt === null);
check('a malformed expiry is absent', Entitlement::fromWire($base + ['expires_at' => 'nonsense'])->expiresAt === null);
check('a null effective_at is zero', Entitlement::fromWire($base + ['effective_at' => null])->effectiveAt === 0);

$unknown = Entitlement::fromWire([
    'active' => true,
    'effective_at' => 1_600_000_000,
    'features' => ['core_sso' => true, 'telemetry_magic' => true],
    'limits' => [],
]);
check('an unrecognised key is preserved', $unknown->unknownFeatures() === ['telemetry_magic']);
check('known keys still resolve', $unknown->has('core_sso', REFERENCE_NOW));
check('an unrecognised key grants nothing', !$unknown->has('telemetry_magic', REFERENCE_NOW));

echo "\n{$checks} checks, {$failures} failures\n";
exit($failures === 0 ? 0 : 1);
