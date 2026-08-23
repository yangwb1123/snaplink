<?php

declare(strict_types=1);

namespace Snaplink;

interface StateStore
{
    public function take(string $key): ?string;

    public function save(string $key, string $value): void;
}

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

final class SnaplinkError extends \RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $error,
        public readonly ?string $description = null,
    ) {
        parent::__construct($description ?: $error);
    }
}

final class SnaplinkClient
{
    private StateStore $store;
    private $transport;
    private $jsonTransport;
    private ?array $tokens = null;
    private ?string $baseUrl = null;
    private ?string $clientId = null;
    private ?array $pendingSetup = null;
    private ?array $accountContext = null;

    public function __construct(
        ?StateStore $store = null,
        ?callable $transport = null,
        ?callable $jsonTransport = null,
    )
    {
        $this->store = $store ?? new MemoryStateStore();
        $this->transport = $transport;
        $this->jsonTransport = $jsonTransport;
    }

    public function login(array $options): LoginResult
    {
        self::rejectSecrets($options);
        $resolved = self::resolveOptions($options);
        $this->configureSession($resolved['base_url'], $resolved['client_id']);

        $callback = self::option($options, 'callback_url', 'callbackUrl');
        if ((!is_string($callback) || $callback === '') && array_key_exists('setup', $options)) {
            if (!is_array($options['setup'])) {
                throw new SnaplinkError(0, 'invalid_request', 'setup must be an array');
            }
            $this->prepareSetup($resolved['base_url'], $resolved['client_id'], $options['setup']);
        }
        if (is_string($callback) && $callback !== '') {
            return $this->finish($resolved, $callback);
        }
        if ($this->tokens !== null) {
            $this->claimPending($resolved['base_url'], $resolved['client_id']);
            return new LoginResult(null, $this->tokens, $resolved['return_to']);
        }

        $verifier = self::randomUrlSafe(64);
        $transaction = [
            'base_url' => self::canonicalUrl($resolved['base_url']),
            'client_id' => $resolved['client_id'],
            'code_verifier' => $verifier,
            'created_at' => time(),
            'redirect_uri' => $resolved['redirect_uri'],
            'return_to' => $resolved['return_to'],
            'state' => self::randomUrlSafe(32),
        ];
        if ($this->pendingSetup !== null) {
            $transaction['activation_ticket'] = $this->pendingSetup['activation_ticket'];
            $transaction['product_id'] = $this->pendingSetup['product_id'];
        }
        $key = self::storeKey($resolved['client_id']);
        $this->store->save($key, json_encode($transaction, JSON_THROW_ON_ERROR));
        try {
            $loginUrl = self::buildLoginUrl($resolved, $transaction['state'], self::pkceChallenge($verifier));
        } catch (\Throwable $error) {
            $this->store->take($key);
            throw $error;
        }
        return new LoginResult($loginUrl, null, $resolved['return_to']);
    }

    public function setup(array $options): array
    {
        self::rejectSecrets($options);
        $allowInsecure = (bool) (self::option($options, 'allow_insecure_http_for_development', 'allowInsecureHttpForDevelopment') ?? false);
        $baseUrl = self::normalizeUrl(self::required($options, 'base_url', 'baseUrl'), 'base_url', false, false, $allowInsecure);
        $clientId = self::required($options, 'client_id', 'clientId');
        $this->configureSession($baseUrl, $clientId);
        return $this->prepareSetup($baseUrl, $clientId, $options);
    }

    public function getAccountContext(?string $productId = null): array
    {
        if ($this->tokens === null || !is_string($this->tokens['access_token'] ?? null)) {
            throw new SnaplinkError(401, 'login_required', 'login is required');
        }
        $product = $productId ?? ($this->accountContext['product_id'] ?? null);
        if (!is_string($product) || trim($product) === '') {
            throw new SnaplinkError(0, 'invalid_request', 'product_id is required');
        }
        $endpoint = rtrim((string) $this->baseUrl, '/') . '/api/v1/me/account-context?product_id=' . rawurlencode($product);
        $response = $this->jsonRequest('GET', $endpoint, null, (string) $this->tokens['access_token']);
        $context = $response['context'] ?? null;
        if (!is_array($context)) {
            throw new SnaplinkError(0, 'invalid_response', 'account context response was invalid');
        }
        $this->accountContext = $context;
        return $context;
    }

    public function accessToken(): ?string
    {
        $token = $this->tokens['access_token'] ?? null;
        return is_string($token) ? $token : null;
    }

    public function tokens(): ?array
    {
        return $this->tokens;
    }

    public function isLoggedIn(): bool
    {
        return $this->accessToken() !== null && $this->accessToken() !== '';
    }

    public function clear(): void
    {
        $this->tokens = null;
        $this->accountContext = null;
    }

    public function logout(): void
    {
        $this->clear();
    }

    private function finish(array $options, string $callbackUrl): LoginResult
    {
        $callback = self::parseCallback($callbackUrl, $options['redirect_uri'], $options['allow_insecure']);
        $raw = $this->store->take(self::storeKey($options['client_id']));
        if ($raw === null) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login transaction is missing or expired');
        }
        try {
            $transaction = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login transaction is invalid');
        }
        if (!is_array($transaction) || !isset($transaction['created_at'])) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login transaction is invalid');
        }
        if (max(0, time() - (int) $transaction['created_at']) > $options['ttl']) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login transaction is missing or expired');
        }
        if (
            ($transaction['client_id'] ?? null) !== $options['client_id']
            || ($transaction['base_url'] ?? null) !== self::canonicalUrl($options['base_url'])
        ) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login transaction belongs to another client');
        }
        if (($callback['state'] ?? '') !== ($transaction['state'] ?? '')) {
            throw new SnaplinkError(0, 'invalid_request', 'hosted-login state did not match');
        }
        if (
            ($callback['iss'] ?? '') === ''
            || self::canonicalUrl((string) $callback['iss']) !== (string) $transaction['base_url']
        ) {
            throw new SnaplinkError(0, 'invalid_request', 'authorization issuer did not match Snaplink');
        }
        if (($callback['code'] ?? null) !== null && ($callback['error'] ?? null) !== null) {
            throw new SnaplinkError(0, 'invalid_request', 'authorization response contained both code and error');
        }
        if (($callback['error'] ?? '') !== '') {
            throw new SnaplinkError(
                0,
                (string) $callback['error'],
                isset($callback['error_description']) ? (string) $callback['error_description'] : null,
            );
        }
        $code = $callback['code'] ?? '';
        if (!is_string($code) || $code === '') {
            throw new SnaplinkError(0, 'invalid_request', 'authorization response did not contain a code');
        }
        $tokens = $this->exchange($options, $transaction, $code);
        $this->tokens = $tokens;
        try {
            if (is_string($transaction['activation_ticket'] ?? null) && is_string($transaction['product_id'] ?? null)) {
                $this->claimActivation(
                    $options['base_url'],
                    $options['client_id'],
                    $transaction['activation_ticket'],
                    $transaction['product_id'],
                );
            }
        } catch (\Throwable $error) {
            $this->tokens = null;
            throw $error;
        }
        return new LoginResult(null, $tokens, (string) $transaction['return_to']);
    }

    private function configureSession(string $baseUrl, string $clientId): void
    {
        if ($this->baseUrl === $baseUrl && $this->clientId === $clientId) {
            return;
        }
        $this->tokens = null;
        $this->pendingSetup = null;
        $this->accountContext = null;
        $this->baseUrl = $baseUrl;
        $this->clientId = $clientId;
    }

    private function prepareSetup(string $baseUrl, string $clientId, array $setup): array
    {
        self::rejectSecrets($setup);
        $body = self::activationRequest($clientId, $setup);
        $response = $this->jsonRequest('POST', rtrim($baseUrl, '/') . '/api/v1/activation/prepare', $body, null);
        $ticket = $response['activation_ticket'] ?? null;
        $product = $response['product_id'] ?? null;
        if (!is_string($ticket) || $ticket === '' || !is_string($product) || $product === '') {
            throw new SnaplinkError(0, 'invalid_response', 'activation endpoint returned an invalid ticket');
        }
        $this->pendingSetup = [
            'activation_ticket' => $ticket,
            'base_url' => $baseUrl,
            'client_id' => $clientId,
            'product_id' => $product,
        ];
        return $response;
    }

    private function claimPending(string $baseUrl, string $clientId): void
    {
        if (
            $this->pendingSetup === null
            || $this->pendingSetup['base_url'] !== $baseUrl
            || $this->pendingSetup['client_id'] !== $clientId
        ) {
            return;
        }
        $this->claimActivation($baseUrl, $clientId, $this->pendingSetup['activation_ticket'], $this->pendingSetup['product_id']);
    }

    private function claimActivation(string $baseUrl, string $clientId, string $ticket, string $productId): void
    {
        $token = $this->tokens['access_token'] ?? null;
        if (!is_string($token) || $token === '') {
            throw new SnaplinkError(401, 'login_required', 'login is required');
        }
        $response = $this->jsonRequest(
            'POST',
            rtrim($baseUrl, '/') . '/api/v1/me/activation/claim',
            ['activation_ticket' => $ticket, 'product_id' => $productId],
            $token,
        );
        if (!is_array($response['context'] ?? null)) {
            throw new SnaplinkError(0, 'invalid_response', 'activation claim response was invalid');
        }
        $this->accountContext = $response['context'];
        if (
            $this->pendingSetup !== null
            && $this->pendingSetup['activation_ticket'] === $ticket
            && $this->pendingSetup['client_id'] === $clientId
        ) {
            $this->pendingSetup = null;
        }
    }

    private function exchange(array $options, array $transaction, string $code): array
    {
        $form = [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $transaction['client_id'],
            'code' => $code,
            'code_verifier' => (string) $transaction['code_verifier'],
            'redirect_uri' => (string) $transaction['redirect_uri'],
        ];
        $endpoint = rtrim($options['base_url'], '/') . '/token';
        $response = $this->transport !== null
            ? ($this->transport)($endpoint, $form)
            : $this->defaultTokenRequest($endpoint, $form);
        if (!is_array($response)) {
            throw new SnaplinkError(0, 'network_error', 'token request returned an invalid response');
        }
        if (array_key_exists('status', $response) && array_key_exists('body', $response)) {
            $status = (int) $response['status'];
            $body = is_string($response['body']) ? $response['body'] : '';
            $decoded = json_decode($body, true);
            if ($status < 200 || $status >= 300) {
                self::oauthError($status, is_array($decoded) ? $decoded : []);
            }
            $response = $decoded;
        }
        if (
            !is_array($response)
            || !is_string($response['access_token'] ?? null)
            || !is_string($response['token_type'] ?? null)
        ) {
            throw new SnaplinkError(0, 'invalid_response', 'token endpoint returned an invalid token response');
        }
        return $response;
    }

    private function jsonRequest(string $method, string $endpoint, ?array $body, ?string $bearer): array
    {
        $response = $this->jsonTransport !== null
            ? ($this->jsonTransport)($method, $endpoint, $body, $bearer)
            : $this->defaultJsonRequest($method, $endpoint, $body, $bearer);
        if (!is_array($response)) {
            throw new SnaplinkError(0, 'network_error', 'JSON request returned an invalid response');
        }
        if (array_key_exists('status', $response) && array_key_exists('body', $response)) {
            $status = (int) $response['status'];
            $decoded = json_decode(is_string($response['body']) ? $response['body'] : '', true);
            if ($status < 200 || $status >= 300) {
                self::oauthError($status, is_array($decoded) ? $decoded : []);
            }
            $response = $decoded;
        }
        if (!is_array($response)) {
            throw new SnaplinkError(0, 'invalid_response', 'JSON endpoint returned an invalid response');
        }
        return $response;
    }

    private function defaultJsonRequest(string $method, string $endpoint, ?array $body, ?string $bearer): array
    {
        $headers = "Accept: application/json\r\n"
            . "Cache-Control: no-store\r\n"
            . "Pragma: no-cache\r\n";
        if ($body !== null) {
            $headers .= "Content-Type: application/json\r\n";
        }
        if ($bearer !== null && $bearer !== '') {
            $headers .= 'Authorization: Bearer ' . $bearer . "\r\n";
        }
        $request = ['method' => $method, 'header' => $headers, 'ignore_errors' => true];
        if ($body !== null) {
            $request['content'] = json_encode($body, JSON_THROW_ON_ERROR);
        }
        $context = stream_context_create(['http' => $request]);
        $bodyValue = @file_get_contents($endpoint, false, $context);
        $headersValue = $http_response_header ?? [];
        $status = 0;
        if (isset($headersValue[0]) && preg_match('/\s([0-9]{3})\s/', $headersValue[0], $matches) === 1) {
            $status = (int) $matches[1];
        }
        if ($bodyValue === false) {
            throw new SnaplinkError($status, 'network_error', 'JSON request failed');
        }
        return ['status' => $status, 'body' => $bodyValue];
    }

    private function defaultTokenRequest(string $endpoint, array $form): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Accept: application/json\r\n"
                    . "Cache-Control: no-store\r\n"
                    . "Content-Type: application/x-www-form-urlencoded\r\n",
                'content' => http_build_query($form, '', '&', PHP_QUERY_RFC3986),
                'ignore_errors' => true,
            ],
        ]);
        $body = @file_get_contents($endpoint, false, $context);
        $headers = $http_response_header ?? [];
        $status = 0;
        if (isset($headers[0]) && preg_match('/\s([0-9]{3})\s/', $headers[0], $matches) === 1) {
            $status = (int) $matches[1];
        }
        if ($body === false) {
            throw new SnaplinkError($status, 'network_error', 'token request failed');
        }
        return ['status' => $status, 'body' => $body];
    }

    private static function resolveOptions(array $options): array
    {
        $allowInsecure = (bool) (self::option($options, 'allow_insecure_http_for_development', 'allowInsecureHttpForDevelopment') ?? false);
        $base = self::normalizeUrl(self::required($options, 'base_url', 'baseUrl'), 'base_url', false, false, $allowInsecure);
        $clientId = self::required($options, 'client_id', 'clientId');
        $redirect = self::normalizeUrl(self::required($options, 'redirect_uri', 'redirectUri'), 'redirect_uri', true, false, $allowInsecure);
        $returnToValue = self::option($options, 'return_to', 'returnTo');
        $returnTo = $returnToValue === null
            ? $redirect
            : self::normalizeUrl((string) $returnToValue, 'return_to', true, true, $allowInsecure);
        if (self::origin($returnTo) !== self::origin($redirect)) {
            throw new SnaplinkError(0, 'invalid_request', 'return_to must use the redirect URI origin');
        }
        $loginPageValue = self::option($options, 'login_page_url', 'loginPageUrl');
        $loginPage = $loginPageValue === null
            ? self::loginPageFromBase($base)
            : self::normalizeUrl((string) $loginPageValue, 'login_page_url', true, false, $allowInsecure);
        $scope = self::values(self::option($options, 'scope'), ['openid', 'profile', 'email'], 'scope', true);
        $resource = self::values(self::option($options, 'resource'), [], 'resource', false);
        $ttlValue = self::option($options, 'transaction_ttl_seconds', 'transactionTtlSeconds') ?? 600;
        if (!is_int($ttlValue) || $ttlValue <= 0) {
            throw new SnaplinkError(0, 'invalid_request', 'transaction_ttl_seconds must be positive');
        }
        $maxAge = self::option($options, 'max_age', 'maxAge');
        if ($maxAge !== null && (!is_int($maxAge) || $maxAge < 0)) {
            throw new SnaplinkError(0, 'invalid_request', 'max_age must be non-negative');
        }
        return [
            'base_url' => $base,
            'client_id' => $clientId,
            'login_page_url' => $loginPage,
            'redirect_uri' => $redirect,
            'return_to' => $returnTo,
            'scope' => $scope,
            'resource' => $resource,
            'prompt' => self::optionalSpaceValue(self::option($options, 'prompt')),
            'max_age' => $maxAge,
            'login_hint' => self::optionalSpaceValue(self::option($options, 'login_hint', 'loginHint')),
            'acr_values' => self::optionalSpaceValue(self::option($options, 'acr_values', 'acrValues')),
            'ui_locales' => self::optionalSpaceValue(self::option($options, 'ui_locales', 'uiLocales')),
            'ttl' => $ttlValue,
            'allow_insecure' => $allowInsecure,
        ];
    }

    private static function buildLoginUrl(array $options, string $state, string $challenge): string
    {
        $parts = parse_url($options['login_page_url']);
        if ($parts === false) {
            throw new SnaplinkError(0, 'invalid_request', 'login_page_url is invalid');
        }
        $managed = [
            'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope',
            'state', 'code_challenge', 'code_challenge_method', 'resource', 'prompt',
            'max_age', 'login_hint', 'acr_values', 'ui_locales',
        ];
        $pairs = [];
        foreach (self::queryPairs($parts['query'] ?? null) as $pair) {
            if (!in_array($pair[0], $managed, true)) {
                $pairs[] = $pair;
            }
        }
        foreach ([
            ['client_id', $options['client_id']],
            ['redirect_uri', $options['redirect_uri']],
            ['response_type', 'code'],
            ['response_mode', 'query'],
            ['scope', implode(' ', $options['scope'])],
            ['state', $state],
            ['code_challenge', $challenge],
            ['code_challenge_method', 'S256'],
        ] as $pair) {
            $pairs[] = $pair;
        }
        foreach ($options['resource'] as $resource) {
            $pairs[] = ['resource', $resource];
        }
        foreach (['prompt', 'login_hint', 'acr_values', 'ui_locales'] as $key) {
            if ($options[$key] !== null) {
                $pairs[] = [$key, $options[$key]];
            }
        }
        if ($options['max_age'] !== null) {
            $pairs[] = ['max_age', (string) $options['max_age']];
        }
        $parts['query'] = self::encodePairs($pairs);
        $parts['fragment'] = null;
        return self::buildUrl($parts);
    }

    private static function parseCallback(string $raw, string $redirect, bool $allowInsecure): array
    {
        $callback = self::normalizeUrl($raw, 'callback_url', true, false, $allowInsecure);
        if (self::canonicalUrl($callback) !== self::canonicalUrl($redirect)) {
            throw new SnaplinkError(0, 'invalid_request', 'callback_url does not match redirect_uri');
        }
        $parts = parse_url($callback);
        $values = [];
        foreach (self::queryPairs($parts['query'] ?? null) as [$key, $value]) {
            $values[$key] ??= $value;
        }
        return $values;
    }

    private static function normalizeUrl(
        string $raw,
        string $name,
        bool $allowQuery,
        bool $allowFragment,
        bool $allowInsecure,
    ): string {
        if (trim($raw) === '') {
            throw new SnaplinkError(0, 'invalid_request', $name . ' is required');
        }
        $parts = parse_url($raw);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must be an absolute HTTP(S) URL');
        }
        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must not contain credentials');
        }
        $loopbackHttp = $scheme === 'http' && self::isLoopback($host);
        if ($scheme !== 'https' && !($loopbackHttp || ($allowInsecure && $scheme === 'http'))) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must use HTTPS or loopback HTTP');
        }
        if (!$allowQuery && isset($parts['query'])) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must not contain a query');
        }
        if (!$allowFragment && isset($parts['fragment'])) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must not contain a fragment');
        }
        $parts['scheme'] = $scheme;
        $parts['host'] = $host;
        return self::buildUrl($parts);
    }

    private static function loginPageFromBase(string $base): string
    {
        $parts = parse_url($base);
        $path = rtrim((string) ($parts['path'] ?? ''), '/') . '/login/';
        $parts['path'] = $path;
        return self::buildUrl($parts);
    }

    private static function buildUrl(array $parts): string
    {
        $url = (string) $parts['scheme'] . '://' . (string) $parts['host'];
        if (isset($parts['port'])) {
            $url .= ':' . (int) $parts['port'];
        }
        $url .= (string) ($parts['path'] ?? '');
        if (isset($parts['query']) && $parts['query'] !== null && $parts['query'] !== '') {
            $url .= '?' . (string) $parts['query'];
        }
        if (isset($parts['fragment']) && $parts['fragment'] !== null && $parts['fragment'] !== '') {
            $url .= '#' . (string) $parts['fragment'];
        }
        return $url;
    }

    private static function queryPairs(?string $query): array
    {
        if ($query === null || $query === '') {
            return [];
        }
        $pairs = [];
        foreach (explode('&', $query) as $part) {
            if ($part === '') {
                continue;
            }
            $bits = explode('=', $part, 2);
            $pairs[] = [
                rawurldecode(str_replace('+', ' ', $bits[0])),
                rawurldecode(str_replace('+', ' ', $bits[1] ?? '')),
            ];
        }
        return $pairs;
    }

    private static function encodePairs(array $pairs): string
    {
        return implode('&', array_map(
            static fn(array $pair): string => rawurlencode((string) $pair[0]) . '=' . rawurlencode((string) $pair[1]),
            $pairs,
        ));
    }

    private static function values(mixed $value, array $default, string $name, bool $required): array
    {
        if ($value === null) {
            return $default;
        }
        if (is_string($value)) {
            $value = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
        }
        if (!is_array($value) || ($required && $value === [])) {
            throw new SnaplinkError(0, 'invalid_request', $name . ' must contain values');
        }
        $result = [];
        foreach ($value as $item) {
            if (!is_string($item) || $item === '' || preg_match('/\s/', $item) === 1) {
                throw new SnaplinkError(0, 'invalid_request', $name . ' values must be non-empty and whitespace-free');
            }
            $result[] = $item;
        }
        return $result;
    }

    private static function optionalSpaceValue(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_string($value)) {
            return $value;
        }
        if (is_array($value)) {
            $result = self::values($value, [], 'option', true);
            return implode(' ', $result);
        }
        throw new SnaplinkError(0, 'invalid_request', 'optional login values must be strings or arrays');
    }

    private static function required(array $options, string $snake, string $camel): string
    {
        $value = self::option($options, $snake, $camel);
        if (!is_string($value) || trim($value) === '') {
            throw new SnaplinkError(0, 'invalid_request', $snake . ' is required');
        }
        return $value;
    }

    private static function activationRequest(string $clientId, array $setup): array
    {
        $productId = self::required($setup, 'product_id', 'productId');
        $licenseKey = self::option($setup, 'license_key', 'licenseKey');
        $invitationCode = self::option($setup, 'invitation_code', 'invitationCode');
        $licenseKey = is_string($licenseKey) ? $licenseKey : '';
        $invitationCode = is_string($invitationCode) ? $invitationCode : '';
        if (($licenseKey === '') === ($invitationCode === '')) {
            throw new SnaplinkError(0, 'invalid_request', 'exactly one of license_key or invitation_code is required');
        }
        $body = ['client_id' => $clientId, 'product_id' => $productId];
        if ($licenseKey !== '') {
            $body['license_key'] = $licenseKey;
        }
        if ($invitationCode !== '') {
            $body['invitation_code'] = $invitationCode;
        }
        foreach ([
            ['tenant_hint', 'tenantHint'],
            ['locale', 'locale'],
            ['app_version', 'appVersion'],
        ] as [$snake, $camel]) {
            $value = self::option($setup, $snake, $camel);
            if (is_string($value) && $value !== '') {
                $body[$snake] = $value;
            }
        }
        return $body;
    }

    private static function option(array $options, string $snake, ?string $camel = null): mixed
    {
        if (array_key_exists($snake, $options)) {
            return $options[$snake];
        }
        return $camel !== null && array_key_exists($camel, $options) ? $options[$camel] : null;
    }

    private static function rejectSecrets(array $options): void
    {
        if (array_key_exists('client_secret', $options) || array_key_exists('clientSecret', $options)) {
            throw new \InvalidArgumentException('hosted browser login does not accept client secrets');
        }
    }

    private static function randomUrlSafe(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private static function pkceChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function storeKey(string $clientId): string
    {
        return 'snaplink.login.v1:' . rawurlencode($clientId);
    }

    private static function origin(string $raw): string
    {
        $parts = parse_url($raw);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
        return $scheme . '://' . $host . ':' . $port;
    }

    private static function canonicalUrl(string $raw): string
    {
        $parts = parse_url($raw);
        if ($parts === false) {
            return '';
        }
        $parts['path'] = rtrim((string) ($parts['path'] ?? ''), '/');
        unset($parts['query'], $parts['fragment']);
        return self::buildUrl($parts);
    }

    private static function isLoopback(string $host): bool
    {
        return in_array(trim(strtolower($host), '[]'), ['localhost', '127.0.0.1', '::1'], true);
    }

    private static function oauthError(int $status, array $body): never
    {
        throw new SnaplinkError(
            $status,
            is_string($body['error'] ?? null) ? $body['error'] : 'invalid_grant',
            is_string($body['error_description'] ?? null) ? $body['error_description'] : null,
        );
    }
}
