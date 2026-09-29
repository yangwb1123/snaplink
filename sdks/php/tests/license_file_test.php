<?php

declare(strict_types=1);

// Cross-language conformance for entitlement-file verification.
//
// The cases in ops/build/sdk-conformance/license_file.json are the shared
// contract. The verifier here is deterministic and injected, deliberately not a
// vendor key: these tests are about the verification outcome, not the provenance
// of the trust root.

require __DIR__ . '/../src/Entitlement.php';
require __DIR__ . '/../src/EntitlementFile.php';
require __DIR__ . '/../src/LicenseError.php';
require __DIR__ . '/../src/LicenseFile.php';
require __DIR__ . '/../src/LicenseState.php';

use Snaplink\LicenseError;
use Snaplink\LicenseState;
use Snaplink\LicenseFile;

const REFERENCE_NOW = 1_700_000_000;
const KEY_ID = 'vendor-2026';

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

/** A deterministic stand-in: accepts only the exact payload it was bound to. */
function verifierFor(string $signed, array &$calls): callable
{
    return static function (string $publicKey, string $payload, string $signature) use ($signed, &$calls): bool {
        $calls[] = $payload;
        return $payload === $signed;
    };
}

function publicKey(): string
{
    return base64_encode(str_repeat("\x01", LicenseFile::PUBLIC_KEY_BYTES));
}

function signature(): string
{
    return base64_encode(str_repeat("\x02", LicenseFile::SIGNATURE_BYTES));
}

function payload(?int $expiresAt = null): string
{
    $value = [
        'tenant_id' => 'tenant-a',
        'subscription_id' => 'sub-a',
        'plan' => ['id' => 'enterprise', 'version' => 1],
        'revision' => 1,
        'active' => true,
        'features' => ['core_sso' => true, 'scim' => true, 'high_availability' => true],
        'limits' => ['storage_bytes' => ['soft' => 0, 'hard' => 0, 'unlimited' => true]],
        'effective_at' => 1600000000,
        'generated_at' => 1600000000,
    ];
    if ($expiresAt !== null) {
        $value['expires_at'] = $expiresAt;
    }
    return json_encode($value, JSON_THROW_ON_ERROR);
}

function envelope(
    string $body,
    string $sig = null,
    string $keyId = KEY_ID,
    string $algorithm = LicenseFile::ALGORITHM,
    int $version = LicenseFile::VERSION,
): string {
    return json_encode([
        'version' => $version,
        'algorithm' => $algorithm,
        'key_id' => $keyId,
        'payload' => base64_encode($body),
        'signature' => $sig ?? signature(),
    ], JSON_THROW_ON_ERROR);
}

function trustFor(string $signed, string $keyId = KEY_ID, array &$calls = null): LicenseFile
{
    $calls ??= [];
    return LicenseFile::trustFromKey($keyId, publicKey(), verifierFor($signed, $calls));
}

function expectCode(string $name, callable $action, string $want): void
{
    try {
        $action();
        check($name, false, 'expected ' . $want . ', got success');
    } catch (LicenseError $error) {
        check($name, $error->error === $want, 'expected ' . $want . ', got ' . $error->error);
    }
}

$body = payload(1900000000);
$calls = [];
$trust = trustFor($body, KEY_ID, $calls);
$file = $trust->verify(envelope($body));
check('a correctly signed file verifies offline', $file->keyId === KEY_ID);
check('the verifier is consulted exactly once', count($calls) === 1, 'got ' . count($calls));
check('an active file grants', $file->stateAt(REFERENCE_NOW)['kind'] === LicenseState::ACTIVE);
check('scim is granted', $file->entitlement->has('scim', REFERENCE_NOW));

$signed = payload(1900000000);
$tampered = str_replace('"scim"', '"SCIM"', $signed);
check('the tampering actually changed the payload', $signed !== $tampered);
expectCode(
    'a tampered payload never verifies',
    fn() => trustFor($signed)->verify(envelope($tampered)),
    'license_signature_invalid',
);

expectCode(
    'an untrusted key is refused',
    fn() => trustFor($body)->verify(envelope($body, null, 'someone-elses-key')),
    'license_untrusted_key',
);

$oem = trustFor($body, 'oem-2026');
check('a caller pinned key is accepted', $oem->verify(envelope($body, null, 'oem-2026'))->keyId === 'oem-2026');

$expiring = payload(1800000000);
$expired = trustFor($expiring)->verify(envelope($expiring));
check('an expired file is inactive', $expired->stateAt(1800000001)['kind'] === LicenseState::INACTIVE);
check('an expired file reports expired', $expired->stateAt(1800000001)['reason'] === LicenseState::EXPIRED);
check('one second earlier it granted', $expired->stateAt(1799999999)['kind'] === LicenseState::ACTIVE);

foreach (['', 'not json', '{}', '{"version":1}', '[]'] as $malformed) {
    expectCode(
        'a malformed envelope is an error: ' . var_export($malformed, true),
        fn() => trustFor($body)->verify($malformed),
        'license_malformed',
    );
}

$algorithmCalls = [];
$algorithmTrust = trustFor($body, KEY_ID, $algorithmCalls);
foreach (['none', 'HS256', 'Ed448', ''] as $algorithm) {
    expectCode(
        "an unsupported algorithm is refused: {$algorithm}",
        fn() => $algorithmTrust->verify(envelope($body, null, KEY_ID, $algorithm)),
        'license_algorithm_unsupported',
    );
}
check('no signature work happens before the algorithm gate', $algorithmCalls === []);

expectCode(
    'an unsupported envelope version is refused',
    fn() => trustFor($body)->verify(envelope($body, null, KEY_ID, LicenseFile::ALGORITHM, 99)),
    'license_algorithm_unsupported',
);

expectCode(
    'an empty trust root never verifies',
    fn() => LicenseFile::emptyTrust(static fn() => true)->verify(envelope($body)),
    'license_trust_unconfigured',
);
expectCode(
    'an unknown key id is refused',
    fn() => LicenseFile::trustFromKey('other', publicKey(), static fn() => true)->verify(envelope($body)),
    'license_untrusted_key',
);
expectCode('the vendor root is unconfigured', fn() => LicenseFile::vendorPinnedTrust(), 'license_trust_unconfigured');

expectCode('a non-base64 trust key is rejected', fn() => LicenseFile::trustFromKey('bad', 'not base64!!', static fn() => true), 'license_malformed');
expectCode('a short trust key is rejected', fn() => LicenseFile::trustFromKey('short', base64_encode('12345678'), static fn() => true), 'license_malformed');

expectCode(
    'a verifier returning false is treated as not verified',
    fn() => LicenseFile::trustFromKey(KEY_ID, publicKey(), static fn() => false)->verify(envelope($body)),
    'license_signature_invalid',
);

check('trust diagnostics expose only key ids', trustFor($body)->keyIds() === [KEY_ID]);
check(
    'a rejected key does not widen trust',
    (static function (): bool {
        $calls = [];
        $trust = LicenseFile::trustFromKey(KEY_ID, publicKey(), verifierFor('', $calls));
        try {
            $trust->addBase64Key('bad', 'not base64!!');
        } catch (LicenseError) {
        }
        return $trust->keyIds() === [KEY_ID];
    })(),
);

$fixture = json_decode(
    (string) file_get_contents(__DIR__ . '/../../../ops/build/sdk-conformance/license_file.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
$implemented = [
    'valid_signature', 'tampered_payload', 'signature_from_wrong_key',
    'caller_pinned_key', 'expired_entitlement', 'malformed_envelope',
    'unsupported_algorithm',
];
$ids = array_column($fixture['cases'], 'id');
foreach ($ids as $id) {
    check("fixture case {$id} is implemented here", in_array($id, $implemented, true));
}

if (function_exists('sodium_crypto_sign_verify_detached')) {
    check('the bundled sodium verifier is constructible', is_callable(LicenseFile::sodiumVerifier()));
} else {
    echo "  skip sodium verifier (ext-sodium unavailable)\n";
}

echo "\n{$checks} checks, {$failures} failures\n";
exit($failures === 0 ? 0 : 1);
