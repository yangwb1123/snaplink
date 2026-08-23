<?php

declare(strict_types=1);

require __DIR__ . '/../src/SnaplinkClient.php';

use Snaplink\MemoryStateStore;
use Snaplink\SnaplinkClient;
use Snaplink\SnaplinkError;

$captured = [];
$client = new SnaplinkClient(
    new MemoryStateStore(),
    static function (string $endpoint, array $form) use (&$captured): array {
        $captured = [$endpoint, $form];
        return [
            'access_token' => 'access-1',
            'expires_in' => 900,
            'token_type' => 'Bearer',
        ];
    },
);

$options = [
    'base_url' => 'https://sso.example.test',
    'client_id' => 'spa-client',
    'redirect_uri' => 'https://app.example.test/auth/callback',
    'return_to' => 'https://app.example.test/dashboard',
];
$started = $client->login($options);
$login = parse_url((string) $started->redirectUrl());
parse_str((string) ($login['query'] ?? ''), $query);
if (($login['path'] ?? '') !== '/login/' || ($query['code_challenge_method'] ?? '') !== 'S256') {
    throw new RuntimeException('hosted-login redirect was not built correctly');
}

$completed = $client->login($options + [
    'callback_url' => $options['redirect_uri']
        . '?code=code-1&state=' . rawurlencode((string) $query['state'])
        . '&iss=' . rawurlencode($options['base_url']),
]);
if ($completed->accessToken() !== 'access-1' || $completed->return_to !== $options['return_to']) {
    throw new RuntimeException('hosted-login callback did not complete');
}
if (($captured[1]['grant_type'] ?? '') !== 'authorization_code' || isset($captured[1]['client_secret'])) {
    throw new RuntimeException('token request contained the wrong credentials');
}
if (!isset($captured[1]['code_verifier']) || strlen($captured[1]['code_verifier']) < 43) {
    throw new RuntimeException('token request did not contain PKCE');
}

$mismatch = new SnaplinkClient(new MemoryStateStore(), static fn(): array => []);
$mismatch->login($options);
try {
    $mismatch->login($options + [
        'callback_url' => $options['redirect_uri']
            . '?code=code-1&state=wrong&iss=' . rawurlencode($options['base_url']),
    ]);
    throw new RuntimeException('state mismatch was accepted');
} catch (SnaplinkError $error) {
    if ($error->error !== 'invalid_request') {
        throw $error;
    }
}

$activationCalls = [];
$activationClient = new SnaplinkClient(
    new MemoryStateStore(),
    static fn(string $endpoint, array $form): array => [
        'access_token' => 'access-setup',
        'expires_in' => 900,
        'token_type' => 'Bearer',
    ],
    static function (string $method, string $endpoint, ?array $body, ?string $bearer) use (&$activationCalls): array {
        $activationCalls[] = [$method, $endpoint, $body, $bearer];
        if (str_ends_with($endpoint, '/api/v1/activation/prepare')) {
            return ['activation_ticket' => 'ticket-1', 'expires_in' => 300, 'product_id' => 'pro'];
        }
        return ['context' => ['product_id' => 'pro', 'tenant_id' => 'tenant-1']];
    },
);
$activationOptions = [
    'base_url' => 'https://sso.example.test',
    'client_id' => 'spa-client',
    'redirect_uri' => 'https://app.example.test/auth/callback',
];
$activationClient->setup($activationOptions + ['product_id' => 'pro', 'license_key' => 'paid-secret']);
$activationStarted = $activationClient->login($activationOptions);
$activationLogin = parse_url((string) $activationStarted->redirectUrl());
parse_str((string) ($activationLogin['query'] ?? ''), $activationQuery);
$activationCompleted = $activationClient->login($activationOptions + [
    'callback_url' => $activationOptions['redirect_uri']
        . '?code=code-setup&state=' . rawurlencode((string) $activationQuery['state'])
        . '&iss=' . rawurlencode($activationOptions['base_url']),
]);
if ($activationCompleted->accessToken() !== 'access-setup') {
    throw new RuntimeException('activation login did not complete');
}
$claim = array_values(array_filter($activationCalls, static fn(array $call): bool => str_ends_with($call[1], '/api/v1/me/activation/claim')))[0] ?? null;
if ($claim === null || $claim[2]['activation_ticket'] !== 'ticket-1' || $claim[3] !== 'access-setup') {
    throw new RuntimeException('activation claim was not bearer-authenticated');
}
if ($activationClient->getAccountContext()['tenant_id'] !== 'tenant-1') {
    throw new RuntimeException('account context was not returned');
}

echo "hosted login tests passed\n";
