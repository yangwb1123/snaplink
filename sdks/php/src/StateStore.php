<?php

declare(strict_types=1);

namespace Snaplink;

interface StateStore
{
    public function take(string $key): ?string;

    public function save(string $key, string $value): void;
}
