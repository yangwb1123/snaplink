<?php

declare(strict_types=1);

namespace Snaplink;

final class LoginResult
{
    public function __construct(
        public readonly ?string $redirect_url = null,
        public readonly ?array $tokens = null,
        public readonly ?string $return_to = null,
    ) {
    }

    public function isComplete(): bool
    {
        return $this->tokens !== null;
    }

    public function redirectUrl(): ?string
    {
        return $this->redirect_url;
    }

    public function accessToken(): ?string
    {
        $token = $this->tokens['access_token'] ?? null;
        return is_string($token) ? $token : null;
    }
}
