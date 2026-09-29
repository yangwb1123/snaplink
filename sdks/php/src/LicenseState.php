<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * The three states a product licence can be in.
 *
 * A nullable entitlement cannot tell "never activated" from "activated once but
 * lapsed", and those need different copy and different follow-up actions.
 */
final class LicenseState
{
    public const NOT_ACTIVATED = 'not_activated';
    public const INACTIVE = 'inactive';
    public const ACTIVE = 'active';

    /** Why an entitlement is present but not usable. Presentation only. */
    public const NOT_YET_EFFECTIVE = 'not_yet_effective';
    public const EXPIRED = 'expired';
    public const SUSPENDED = 'suspended';

    /**
     * Classify an account-context response at $now.
     *
     * Returns null for the never-activated case, so a caller can tell it apart
     * from an entitlement that exists and has lapsed.
     */
    public static function fromAccountContext(?array $context, int $now): array
    {
        $entitlement = self::entitlementFromAccountContext($context);
        if ($entitlement === null) {
            return ['kind' => self::NOT_ACTIVATED];
        }
        return $entitlement->stateAt($now);
    }

    /**
     * The typed entitlement carried by an account-context response.
     *
     * Null means the product was never activated, which is a different state
     * from an expired Entitlement.
     */
    public static function entitlementFromAccountContext(?array $context): ?Entitlement
    {
        $raw = $context['entitlement'] ?? null;
        if ($raw === null) {
            return null;
        }
        return Entitlement::fromWire($raw);
    }

    /** Whether a state grants anything. The only question a gate should ask. */
    public static function isActive(array $state): bool
    {
        return $state['kind'] === self::ACTIVE;
    }

    /**
     * Whether $feature is granted at $now for this account context.
     */
    public static function hasFeature(?array $context, string $feature, int $now): bool
    {
        $entitlement = self::entitlementFromAccountContext($context);
        return $entitlement !== null && $entitlement->has($feature, $now);
    }
}
