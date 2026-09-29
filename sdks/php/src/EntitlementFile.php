<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * A verified commercial entitlement read from a local file.
 */
final class EntitlementFile
{
    public function __construct(
        public readonly Entitlement $entitlement,
        public readonly string $keyId,
    ) {
    }

    /**
     * Classify at $now.
     *
     * The three-state classification is identical to the online path, so a
     * deployment that moves between the two does not change behaviour.
     *
     * @return array{kind:string,reason?:string,until?:int|null}
     */
    public function stateAt(int $now): array
    {
        return $this->entitlement->stateAt($now);
    }
}
