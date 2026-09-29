<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * An entitlement-file verification failure.
 *
 * These codes originate in the SDK, never on the wire, and are namespaced so a
 * caller cannot confuse them with a network failure. None is recoverable by
 * retrying. The property is named $error rather than $code because Exception
 * already declares a non-readonly $code, and the wire vocabulary names it that
 * way elsewhere in the package.
 */
final class LicenseError extends \RuntimeException
{
    public function __construct(
        public readonly string $error,
        public readonly ?string $description = null,
    ) {
        parent::__construct($description === null ? $error : "{$error}: {$description}");
    }
}
