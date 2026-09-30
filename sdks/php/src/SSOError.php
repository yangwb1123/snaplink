<?php

declare(strict_types=1);

namespace Snaplink;

final class SSOError extends \RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $error,
        public readonly ?string $description = null,
    ) {
        parent::__construct($description ?: $error);
    }
}
