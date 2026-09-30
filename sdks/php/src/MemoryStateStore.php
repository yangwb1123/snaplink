<?php

declare(strict_types=1);

namespace Snaplink;

final class MemoryStateStore implements StateStore
{
    private array $values = [];

    public function take(string $key): ?string
    {
        $value = $this->values[$key] ?? null;
        unset($this->values[$key]);
        return $value;
    }

    public function save(string $key, string $value): void
    {
        $this->values[$key] = $value;
    }
}
