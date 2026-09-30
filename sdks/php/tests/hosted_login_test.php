<?php

declare(strict_types=1);

require __DIR__ . '/../src/StateStore.php';
require __DIR__ . '/../src/MemoryStateStore.php';
require __DIR__ . '/../src/LoginResult.php';
require __DIR__ . '/../src/SSOError.php';
require __DIR__ . '/../src/SSOClient.php';

use Snaplink\MemoryStateStore;
use Snaplink\SSOClient;
use Snaplink\SSOError;

$captured = [];
$logoutCalls = [];
$logoutStatus = 200;
$client = new SSOClient(
    new MemoryStateStore(),
    static function (string $endpoint, array $form) use (&$captured): array {
        $captured = [$endpoint, $form];
        return [
            'access_token' => ($form['grant_type'] ?? '') === 'refresh_token' ? 'access-2' : 'access-1',
            'expires_in' => 900,
            'refresh_token' => ($form['grant_type'] ?? '') === 'refresh_token' ? null : 'refresh-1',
            'token_type' => 'Bearer',
        ];
    },
    static function (string $method, string $endpoint, ?array $body, ?string $bearer) use (&$logoutCalls, &$logoutStatus): array {
        $logoutCalls[] = [$method, $endpoint, $body, $bearer];
        return [
            'status' => $logoutStatus,
            'body' => $logoutStatus < 300 ? '{}' : '{"error":"server_error"}',
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

$refreshed = $client->refresh();
if (
    $refreshed['access_token'] !== 'access-2'
    || $refreshed['refresh_token'] !== 'refresh-1'
    || $client->accessToken() !== 'access-2'
) {
    throw new RuntimeException('refresh did not adopt access token or retain the unrotated refresh token');
}
if (
    ($captured[1]['grant_type'] ?? '') !== 'refresh_token'
    || isset($captured[1]['code_verifier'])
    || isset($captured[1]['client_secret'])
) {
    throw new RuntimeException('refresh request did not use the isolated refresh-token grant');
}
try {
    (new SSOClient())->refresh();
    throw new RuntimeException('refresh without a session was accepted');
} catch (SSOError $error) {
    if ($error->error !== 'login_required') {
        throw $error;
    }
}
$client->clear();
if ($client->isLoggedIn() || $logoutCalls !== []) {
    throw new RuntimeException('clear must forget local state without contacting Snaplink');
}

$logoutStarted = $client->login($options);
$logoutLogin = parse_url((string) $logoutStarted->redirectUrl());
parse_str((string) ($logoutLogin['query'] ?? ''), $logoutQuery);
$client->login($options + [
    'callback_url' => $options['redirect_uri']
        . '?code=code-logout&state=' . rawurlencode((string) $logoutQuery['state'])
        . '&iss=' . rawurlencode($options['base_url']),
]);
$client->logout();
if (
    $client->isLoggedIn()
    || count($logoutCalls) !== 1
    || $logoutCalls[0][0] !== 'POST'
    || !str_ends_with($logoutCalls[0][1], '/logout')
    || $logoutCalls[0][2] !== null
    || $logoutCalls[0][3] !== 'access-1'
) {
    throw new RuntimeException('logout did not revoke server-side and clear local state');
}
$logoutStarted = $client->login($options);
$logoutLogin = parse_url((string) $logoutStarted->redirectUrl());
parse_str((string) ($logoutLogin['query'] ?? ''), $logoutQuery);
$client->login($options + [
    'callback_url' => $options['redirect_uri']
        . '?code=code-logout-failure&state=' . rawurlencode((string) $logoutQuery['state'])
        . '&iss=' . rawurlencode($options['base_url']),
]);
$logoutStatus = 500;
try {
    $client->logout();
    throw new RuntimeException('failed server logout was hidden');
} catch (SSOError $error) {
    if ($error->error !== 'server_error' || $client->isLoggedIn()) {
        throw $error;
    }
}

$mismatch = new SSOClient(new MemoryStateStore(), static fn(): array => []);
$mismatch->login($options);
try {
    $mismatch->login($options + [
        'callback_url' => $options['redirect_uri']
            . '?code=code-1&state=wrong&iss=' . rawurlencode($options['base_url']),
    ]);
    throw new RuntimeException('state mismatch was accepted');
} catch (SSOError $error) {
    if ($error->error !== 'invalid_request') {
        throw $error;
    }
}

$activationCalls = [];
$activationClient = new SSOClient(
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
