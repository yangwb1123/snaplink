<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * Local verification of a signed commercial entitlement file.
 *
 * docs/commercial-model.md requires that offline and private deployments gate
 * paid features from a signed file, and that authentication never calls a vendor
 * licensing service on a login path. The second clause is only satisfiable if
 * the SDK can verify the file itself: without a local verifier an air-gapped
 * deployment has to call /api/v1/me/account-context, which puts a vendor on the
 * login path and violates the rule this file exists to satisfy.
 *
 * Verification is entirely local. It performs no network I/O on any path,
 * including login.
 *
 * The signing private key never enters this package, the repository, or CI, and
 * is never transmitted here; only the payload and its signature are. A trust
 * root is always supplied by the caller, which is what makes OEM and private-CA
 * deployments possible. vendorPinnedTrust() is the slot for Snaplink's own root
 * and reports license_trust_unconfigured until a release populates it, rather
 * than carrying a placeholder key that would read as vendor authority while
 * verifying nothing.
 *
 * Only one step needs a primitive: checking a signature. Everything else --
 * envelope parsing, the algorithm and version gate, the key-id lookup, the
 * no-downgrade policy, and the three-state classification -- is identical in
 * every SDK and is what the shared conformance fixture pins.
 *
 * A LicenseVerifier is a callable (publicKey, payload, signature): bool. The
 * bundled sodiumVerifier() uses ext-sodium when it is loaded and throws
 * otherwise, so the package declares no hard extension requirement. Any other
 * implementation may be supplied instead.
 */
final class LicenseFile
{
    /** The only algorithm this build accepts. */
    public const ALGORITHM = 'Ed25519';
    /** The only envelope version this build accepts. */
    public const VERSION = 1;
    /** Raw Ed25519 public key length in bytes. */
    public const PUBLIC_KEY_BYTES = 32;
    /** Raw Ed25519 signature length in bytes. */
    public const SIGNATURE_BYTES = 64;

    /** @var list<string> */
    private const REQUIRED_FIELDS = ['version', 'algorithm', 'key_id', 'payload', 'signature'];

    /**
     * Key id to base64-encoded public key.
     *
     * Deliberately not readonly: rotation adds a key through
     * addBase64Key(), which validates before storing so a rejected key can
     * never widen trust.
     *
     * @var array<string,string>
     */
    private array $keys;

    /**
     * @param array<string,string> $keys
     * @param callable(string,string,string):bool $verifier
     */
    private function __construct(
        array $keys,
        private readonly mixed $verifier,
    ) {
        $this->keys = $keys;
    }

    /**
     * An empty trust root. Every file is rejected with
     * license_trust_unconfigured until a key is added, which is the same
     * starting point the other SDKs expose.
     *
     * @param callable(string,string,string):bool $verifier
     */
    public static function emptyTrust(callable $verifier): self
    {
        return new self([], $verifier);
    }

    /**
     * Build a trust root holding a single base64-encoded public key.
     *
     * @param callable(string,string,string):bool $verifier
     */
    public static function trustFromKey(string $keyId, string $publicKey, callable $verifier): self
    {
        $trust = self::emptyTrust($verifier);
        $trust->addBase64Key($keyId, $publicKey);
        return $trust;
    }

    /**
     * Trust another key, for rotation.
     *
     * A key that fails to decode is rejected rather than stored, so a typo
     * cannot silently widen or narrow trust.
     */
    public function addBase64Key(string $keyId, string $encoded): void
    {
        if ($keyId === '') {
            throw self::malformed('key id is required');
        }
        $raw = base64_decode(trim($encoded), true);
        if ($raw === false) {
            throw self::malformed("key {$keyId} is not base64");
        }
        if (strlen($raw) !== self::PUBLIC_KEY_BYTES) {
            throw self::malformed("key {$keyId} is not " . self::PUBLIC_KEY_BYTES . ' bytes');
        }
        $this->keys[$keyId] = $encoded;
    }

    /**
     * Snaplink's own pinned trust root.
     *
     * Deliberately not a placeholder key: a hardcoded constant that verifies
     * nothing would read as vendor authority while granting nothing.
     */
    public static function vendorPinnedTrust(): self
    {
        throw new LicenseError('license_trust_unconfigured', 'no vendor trust root is configured in this build');
    }

    public function isEmpty(): bool
    {
        return $this->keys === [];
    }

    /** @return list<string> */
    public function keyIds(): array
    {
        $ids = array_keys($this->keys);
        sort($ids);
        return $ids;
    }

    /**
     * Verify $raw against this trust root and decode the entitlement it carries.
     *
     * The declared algorithm and version are checked before any signature work,
     * so "none" and friends are refused rather than tolerated. Any failure
     * throws; this method never returns an inactive or free-tier entitlement in
     * place of a rejected file.
     */
    public function verify(string $raw): EntitlementFile
    {
        if ($this->isEmpty()) {
            throw new LicenseError('license_trust_unconfigured', 'no trust root was supplied');
        }
        $envelope = json_decode($raw, true);
        if (!is_array($envelope) || array_is_list($envelope)) {
            throw self::malformed('envelope must be an object');
        }
        $missing = array_values(array_filter(self::REQUIRED_FIELDS, static fn (string $f): bool => !array_key_exists($f, $envelope)));
        if ($missing !== []) {
            throw self::malformed('envelope is missing ' . implode(', ', $missing));
        }
        if ($envelope['version'] !== self::VERSION) {
            throw self::unsupported('envelope version ' . var_export($envelope['version'], true));
        }
        if ($envelope['algorithm'] !== self::ALGORITHM) {
            throw self::unsupported((string) $envelope['algorithm']);
        }
        $keyId = (string) $envelope['key_id'];
        $key = $this->keys[$keyId] ?? null;
        if ($key === null) {
            throw new LicenseError('license_untrusted_key', $keyId);
        }
        $payload = self::decodeBase64($envelope['payload'], 'payload');
        $signature = self::decodeBase64($envelope['signature'], 'signature');
        if (strlen($signature) !== self::SIGNATURE_BYTES) {
            throw self::malformed('signature is not ' . self::SIGNATURE_BYTES . ' bytes');
        }

        $verified = ($this->verifier)($key, $payload, $signature);
        if ($verified !== true) {
            throw new LicenseError('license_signature_invalid', 'signature did not verify');
        }

        $decoded = json_decode($payload, true);
        if (!is_array($decoded)) {
            throw self::malformed('payload is not an entitlement');
        }
        return new EntitlementFile(Entitlement::fromWire($decoded), $keyId);
    }

    /**
     * A verifier backed by ext-sodium.
     *
     * Returns false for a bad signature and throws only when the extension is
     * unavailable, so a caller can detect the missing dependency up front.
     *
     * @return callable(string,string,string):bool
     */
    public static function sodiumVerifier(): callable
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new LicenseError(
                'license_trust_unconfigured',
                'ext-sodium is not available; supply a LicenseVerifier instead',
            );
        }
        return static function (string $publicKey, string $payload, string $signature): bool {
            $key = base64_decode(trim($publicKey), true);
            if ($key === false) {
                return false;
            }
            return sodium_crypto_sign_verify_detached($signature, $payload, $key);
        };
    }

    private static function decodeBase64(mixed $value, string $name): string
    {
        if (!is_string($value)) {
            throw self::malformed("{$name} must be a string");
        }
        $raw = base64_decode(trim($value), true);
        if ($raw === false) {
            throw self::malformed("{$name} is not base64");
        }
        return $raw;
    }

    private static function malformed(string $message): LicenseError
    {
        return new LicenseError('license_malformed', $message);
    }

    private static function unsupported(string $message): LicenseError
    {
        return new LicenseError('license_algorithm_unsupported', $message);
    }
}
