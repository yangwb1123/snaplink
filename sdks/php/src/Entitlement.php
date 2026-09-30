<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * Application-facing commercial entitlement for the Snaplink PHP SDK.
 *
 * The server is always the authority on what a tenant may do. This file exists
 * so a caller never has to know the wire shape of an entitlement in order to
 * decide whether a feature is available, and so a lapsed entitlement is never
 * mistaken for a live one.
 *
 * Entitlement::stateAt() reproduces commerce.EntitlementSnapshot.effective
 * exactly: an entitlement is effective only when 'active' is set, $now is not
 * before effective_at, and expires_at is null or strictly after $now. A
 * presence check cannot make that distinction, which is why LicenseState has
 * three kinds rather than a nullable entitlement.
 */
final class Entitlement
{
    /** The feature keys the server currently defines, in declaration order. */
    public const FEATURES = [
        'core_sso', 'multi_tenant', 'audit_governance', 'notifications', 'im',
        'account', 'vault', 'scim', 'federation', 'high_availability',
    ];

    /** The limit keys the server currently defines, in declaration order. */
    public const LIMITS = [
        'users', 'clients', 'sessions', 'token_rate', 'storage_bytes', 'storage_objects',
    ];

    public function __construct(
        public readonly string $tenantId = '',
        public readonly string $subscriptionId = '',
        public readonly string $planId = '',
        public readonly int $planVersion = 0,
        public readonly int $revision = 0,
        public readonly bool $active = false,
        /** @var array<string,bool> */
        public readonly array $features = [],
        /** @var array<string,array{soft:int,hard:int,unlimited:bool}> */
        public readonly array $limits = [],
        public readonly int $effectiveAt = 0,
        public readonly ?int $expiresAt = null,
        public readonly int $generatedAt = 0,
    ) {
    }

    /**
     * Build from the 'entitlement' object of an account-context response.
     *
     * Timestamps arrive as RFC 3339 because that is what Go's time.Time
     * serialises; a Unix-seconds integer is also accepted so a fixture or a
     * hand-written entitlement file works unchanged.
     */
    public static function fromWire(mixed $raw): self
    {
        if (!is_array($raw)) {
            throw new SSOError(0, 'invalid_response', 'entitlement must be an object');
        }
        $features = [];
        foreach (($raw['features'] ?? []) as $key => $flag) {
            $features[(string) $key] = $flag === true;
        }
        $limits = [];
        foreach (($raw['limits'] ?? []) as $key => $grant) {
            $limits[(string) $key] = [
                'soft' => is_array($grant) && is_int($grant['soft'] ?? null) ? $grant['soft'] : 0,
                'hard' => is_array($grant) && is_int($grant['hard'] ?? null) ? $grant['hard'] : 0,
                'unlimited' => is_array($grant) && ($grant['unlimited'] ?? false) === true,
            ];
        }
        $plan = is_array($raw['plan'] ?? null) ? $raw['plan'] : [];
        return new self(
            tenantId: is_string($raw['tenant_id'] ?? null) ? $raw['tenant_id'] : '',
            subscriptionId: is_string($raw['subscription_id'] ?? null) ? $raw['subscription_id'] : '',
            planId: is_string($plan['id'] ?? null) ? $plan['id'] : '',
            planVersion: is_int($plan['version'] ?? null) ? $plan['version'] : 0,
            revision: is_int($raw['revision'] ?? null) ? $raw['revision'] : 0,
            active: ($raw['active'] ?? false) === true,
            features: $features,
            limits: $limits,
            effectiveAt: self::parseTimestamp($raw['effective_at'] ?? null) ?? 0,
            expiresAt: self::parseTimestamp($raw['expires_at'] ?? null),
            generatedAt: self::parseTimestamp($raw['generated_at'] ?? null) ?? 0,
        );
    }

    /** Current time in Unix seconds, the clock the state helpers expect. */
    public static function unixNow(): int
    {
        return time();
    }

    private static function parseTimestamp(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value)) {
            return null;
        }
        $text = trim($value);
        if ($text === '') {
            return null;
        }
        if (preg_match('/^-?\d+$/', $text) === 1) {
            return (int) $text;
        }
        $parsed = strtotime($text);
        return $parsed === false ? null : $parsed;
    }

    /**
     * Classify the entitlement at $now.
     *
     * Mirrors commerce.EntitlementSnapshot.effective exactly: the expires_at
     * boundary is exclusive, so an entitlement whose window closes at t is
     * already inactive at t.
     *
     * @return array{kind:string,reason?:string,until?:int|null}
     */
    public function stateAt(int $now): array
    {
        if (!$this->active) {
            return ['kind' => LicenseState::INACTIVE, 'reason' => LicenseState::SUSPENDED, 'until' => $this->expiresAt];
        }
        if ($now < $this->effectiveAt) {
            return ['kind' => LicenseState::INACTIVE, 'reason' => LicenseState::NOT_YET_EFFECTIVE];
        }
        if ($this->expiresAt !== null && $now >= $this->expiresAt) {
            return ['kind' => LicenseState::INACTIVE, 'reason' => LicenseState::EXPIRED, 'until' => $this->expiresAt];
        }
        return ['kind' => LicenseState::ACTIVE];
    }

    /**
     * Whether $feature is granted at $now.
     *
     * Returns false for an inactive entitlement regardless of what the map
     * says, and false for a key this build does not recognise: PHP cannot stop
     * a caller passing an arbitrary string, so the check is explicit.
     */
    public function has(string $feature, int $now): bool
    {
        if ($this->stateAt($now)['kind'] !== LicenseState::ACTIVE) {
            return false;
        }
        if (!in_array($feature, self::FEATURES, true)) {
            return false;
        }
        return $this->features[$feature] === true;
    }

    /**
     * The grant for $limit at $now, or null when inactive, absent, or unknown.
     *
     * @return array{soft:int,hard:int,unlimited:bool}|null
     */
    public function limit(string $limit, int $now): ?array
    {
        if ($this->stateAt($now)['kind'] !== LicenseState::ACTIVE) {
            return null;
        }
        if (!in_array($limit, self::LIMITS, true)) {
            return null;
        }
        return $this->limits[$limit] ?? null;
    }

    /**
     * Feature keys the server sent that this build does not recognise, so an
     * operator can see a plan grants something the SDK cannot yet gate.
     *
     * @return list<string>
     */
    public function unknownFeatures(): array
    {
        return array_values(array_diff(array_keys($this->features), self::FEATURES));
    }

    /**
     * Limit keys the server sent that this build does not recognise.
     *
     * @return list<string>
     */
    public function unknownLimits(): array
    {
        return array_values(array_diff(array_keys($this->limits), self::LIMITS));
    }
}
