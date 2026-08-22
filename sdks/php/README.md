# snaplink/sso-client — PHP SDK

This package provides a framework-neutral hosted-login facade for a public
Snaplink client. It uses the existing Console /login/ page, Authorization
Code + S256 PKCE, and an atomic short-lived state transaction. It does not
require a separate BFF and it never accepts a client secret.

Install it with Composer:

~~~text
composer require snaplink/sso-client
~~~

The first call returns a URL for the framework to issue as a 302. The callback
call validates state and issuer, exchanges the code, and keeps the token in
the client instance:

~~~php
use Snaplink\SnaplinkClient;

$snaplink = new SnaplinkClient();

$started = $snaplink->login([
    'base_url' => 'https://sso.example.com',
    'client_id' => 'my-public-app',
    'redirect_uri' => 'https://app.example.com/auth/callback',
    'return_to' => 'https://app.example.com/dashboard',
]);

return new RedirectResponse($started->redirectUrl());

// On the registered callback route:
$completed = $snaplink->login([
    'base_url' => 'https://sso.example.com',
    'client_id' => 'my-public-app',
    'redirect_uri' => 'https://app.example.com/auth/callback',
    'callback_url' => $request->getUri(),
]);

$accessToken = $completed->accessToken();
~~~

Use a durable StateStore implementation for multi-worker deployments;
MemoryStateStore is intended for development and single-process examples.
The default token transport uses PHP's standard-library HTTP streams. Tests
and applications may inject a callable transport as the second constructor
argument.
