# snaplink/sso-client — PHP SDK

This package provides a framework-neutral hosted-login facade for a public
Snaplink client. It uses the existing Console /login/ page, Authorization
Code + S256 PKCE, and an atomic short-lived state transaction. It does not
require a separate BFF and it never accepts a client secret.

This package is not currently listed on public Packagist. For local development,
add a path repository to the consuming application's `composer.json` (replace
the URL with the path to this checkout), then require the checked-in package
version:

~~~json
{
  "repositories": [
    {
      "type": "path",
      "url": "../snaplink/sdks/php",
      "options": { "symlink": true }
    }
  ]
}
~~~

After adding the repository entry, run:

~~~sh
composer require snaplink/sso-client:0.3.0
~~~

PHP CI runs this installation flow in a temporary consumer with Packagist
network access disabled.

Once a Packagist release exists, consumers can install it without the path
repository:

~~~sh
composer require snaplink/sso-client
~~~

## Packagist release preparation

`.github/workflows/sdk-php-release.yml` verifies protected source tags named
`sdk-php-v<composer-version>`, then waits at the `php-packagist` GitHub
environment before publishing. The workflow uses `git subtree split` to push
only `sdks/php` history to a standalone repository and creates the corresponding
`v<version>` tag there. No package was published by adding this workflow.

Before the first release, create an empty target GitHub repository, configure
the `php-packagist` environment with required reviewers, set its
`PHP_SDK_REPOSITORY` variable to `owner/repository`, and add a fine-grained
`PHP_SDK_PUBLISH_TOKEN` secret with contents write access only to that target.
Protect the `sdk-php-v*` source tag pattern. Finally, verify ownership of the
`snaplink` Packagist vendor namespace and configure Packagist to monitor the
standalone target repository. Until then, local path installation above is the
supported Composer installation route.

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

For a paid or invited product, prepare activation before the redirect. The
credential is sent only in the HTTPS JSON body; the login transaction carries
only the short-lived ticket and the callback claims it with the bearer:

~~~php
$snaplink->setup([
    'base_url' => 'https://sso.example.com',
    'client_id' => 'my-public-app',
    'product_id' => 'pro',
    'license_key' => 'license-from-your-checkout',
]);
// Call login with the same options; the callback performs the claim.
$account = $snaplink->getAccountContext('pro');
~~~

The one-call form is `login([... 'setup' => ['product_id' => 'pro',
'license_key' => '...']])`. Use `invitation_code` for invitations. The server
derives the tenant, plan, features, and limits; credentials are never put in a
URL or OAuth state.

The client exposes the explicit lifecycle shared by the hosted-login SDKs:
`refresh()` performs the refresh-token grant, `clear()` only forgets local
state, and `logout()` calls the server before clearing local state even when
revocation fails.

For shared presentation settings, `PresentationPreferences` maps the wire
shape, validates values, and builds the login hints:

~~~php
$preferences = PresentationPreferences::fromMyPreferences($snaplink->getMyPreferences());
$snaplink->updateMyPreferences(['theme_mode' => 'dark']);

$handoff = PresentationPreferences::buildLoginPreferenceHandoff([
    'locale' => 'en-US',
    'theme_mode' => 'dark',
]);
$started = $snaplink->login($options + $handoff);
~~~

A handoff carries only values the application explicitly set, so it never
clears a stored preference. `locale` is a BCP 47 language tag and `theme_mode`
is one of light, dark, or auto; anything else is rejected before a request is
made. These are presentation hints, not authorization or tenant parameters.

Use a durable StateStore implementation for multi-worker deployments;
MemoryStateStore is intended for development and single-process examples.
The default token transport uses PHP's standard-library HTTP streams. Tests
and applications may inject a callable transport as the second constructor
argument; activation JSON calls may use the optional third constructor
argument with `(method, endpoint, body, bearer)` parameters.
