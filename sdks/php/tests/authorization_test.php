<?php

declare(strict_types=1);

// Cross-language conformance for the permission-holding rule.
//
// The cases in ops/build/sdk-conformance/authorization.json are the shared
// contract. A client rule that disagrees with the server is worse than no rule
// at all, so the rule is implemented once here and asserted against one fixture.

require __DIR__ . '/../src/Authorization.php';
require __DIR__ . '/../src/SSOError.php';

use Snaplink\Authorization;
use Snaplink\MenuButton;
use Snaplink\MenuNode;

$failures = 0;
$checks = 0;

function check(string $name, bool $condition, string $detail = ''): void
{
    global $failures, $checks;
    $checks++;
    if ($condition) {
        return;
    }
    $failures++;
    echo "  FAIL {$name}" . ($detail === '' ? '' : ": {$detail}") . "\n";
}

$fixture = json_decode(
    (string) file_get_contents(__DIR__ . '/../../../ops/build/sdk-conformance/authorization.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
check('fixture is populated', ($fixture['cases'] ?? []) !== []);

foreach ($fixture['cases'] as $case) {
    $got = Authorization::holds($case['held'], $case['required']);
    check(
        "rule {$case['id']}",
        $got === $case['expect'],
        'got ' . var_export($got, true) . ' want ' . var_export($case['expect'], true),
    );
}

$ids = array_column($fixture['cases'], 'id');
foreach ([
    'exact_match',
    'absent_permission_is_denied',
    'domain_wildcard_does_not_match_a_similar_looking_domain',
    'a_bare_star_grants_everything',
    'an_unqualified_permission_is_never_a_prefix',
    'an_empty_requirement_is_always_granted',
] as $required) {
    check("fixture keeps {$required}", in_array($required, $ids, true));
}

$node = new MenuNode(
    id: 'users',
    name: 'Users',
    buttons: [
        new MenuButton('create', 'New', 'panel:inbound:write'),
        new MenuButton('delete', 'Delete', 'panel:*'),
        new MenuButton('help', 'Help', ''),
    ],
);
$codes = static fn (array $permissions): array => array_map(
    static fn (MenuButton $b): string => $b->code,
    $node->actions($permissions),
);
check('a node with no permission is visible with no grants', (new MenuNode())->isVisible([]));
check('buttons use the narrow grant', $codes(['panel:inbound:write']) === ['create', 'help'], json_encode($codes(['panel:inbound:write'])));
check('buttons use the wildcard grant', $codes(['panel:*']) === ['create', 'delete', 'help']);
check('buttons with no grant keep only the unconditional one', $codes([]) === ['help']);

$tree = [
    new MenuNode('admin', 'Admin', permission: 'panel:*', children: [
        new MenuNode('audit', 'Audit', permission: 'panel:read'),
    ]),
    new MenuNode('portal', 'Portal', children: [new MenuNode('me', 'Me')]),
];
$viewer = new Authorization(subject: 'u', menus: $tree);
$visible = $viewer->visibleMenus();
check('a denied parent is dropped with its children', array_map(static fn (MenuNode $n): string => $n->id, $visible) === ['portal']);

$owner = new Authorization(subject: 'u', permissions: ['panel:*'], menus: $tree);
$visible = $owner->visibleMenus();
check('a wildcard owner keeps both nodes', array_map(static fn (MenuNode $n): string => $n->id, $visible) === ['admin', 'portal']);
check('the surviving child is kept', array_map(static fn (MenuNode $n): string => $n->id, $visible[0]->children) === ['audit']);

check('allows uses the same rule', $owner->allows('panel:config:apply'));
check('allows denies an unrelated code', !$owner->allows('other:read'));
check('allows grants an empty requirement', $owner->allows(''));

// A code list with no readable entry grants nothing.
check('an empty code is dropped', Authorization::codes([['code' => ''], ['description' => 'none'], 'panel:read']) === ['panel:read']);
check('an unreadable list is empty', Authorization::codes(null) === []);

$asked = [];
$request = static function (string $path) use (&$asked): array {
    $asked[] = $path;
    return match (true) {
        str_starts_with($path, '/userinfo') => ['sub' => 'user-alice', 'email' => 'alice@example.test'],
        str_starts_with($path, '/permissions/me') => ['permissions' => [['code' => 'panel:read']]],
        str_starts_with($path, '/roles/me') => ['roles' => [['code' => 'panel-viewer']]],
        default => ['menus' => [['id' => 'm', 'name' => 'Inbounds', 'permission' => 'panel:read']]],
    };
};
$authorization = Authorization::read($request, 'singbox-panel');
check('identity is read', $authorization->subject === 'user-alice');
check('permissions are read', $authorization->permissions === ['panel:read']);
check('roles are read', $authorization->roles === ['panel-viewer']);
check('menus are read', count($authorization->menus) === 1);
check('all four projections are read', count($asked) === 4);
foreach ($asked as $path) {
    check(
        "projection {$path} is scoped",
        $path === '/userinfo' || str_contains($path, 'client_id=singbox-panel'),
    );
}

try {
    Authorization::read(static fn (string $p): array => ['sub' => 'u'], '  ');
    check('a blank client id is refused', false);
} catch (Snaplink\SSOError $error) {
    check('a blank client id is refused', $error->error === 'invalid_request');
}

try {
    Authorization::read(static fn (string $p): array => ['email' => 'nobody@example.test'], 'app');
    check('a response with no subject is rejected', false);
} catch (Snaplink\SSOError $error) {
    check('a response with no subject is rejected', $error->error === 'invalid_response');
}

echo "{$checks} checks, {$failures} failures\n";
exit($failures === 0 ? 0 : 1);