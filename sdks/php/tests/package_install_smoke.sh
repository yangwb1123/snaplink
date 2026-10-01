#!/usr/bin/env bash
set -euo pipefail

# The package root is this script's parent. Deriving it from the script rather
# than from a fixed monorepo path keeps the check working in the standalone
# repository the subtree split produces, which is where Composer consumers and
# anyone auditing the published source actually land.
package_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_name="$(php -r '$manifest = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR); echo $manifest["name"] ?? "";' "${package_dir}/composer.json")"
package_version="$(php -r '$manifest = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR); echo $manifest["version"] ?? "";' "${package_dir}/composer.json")"
[[ -n "${package_name}" && -n "${package_version}" ]]

consumer_dir="$(mktemp -d)"
trap 'rm -rf "${consumer_dir}"' EXIT
php -r '
$packageDir = $argv[1];
$consumerDir = $argv[2];
$manifest = [
    "repositories" => [
        ["type" => "path", "url" => $packageDir, "options" => ["symlink" => false]],
        ["packagist.org" => false],
    ],
];
file_put_contents(
    $consumerDir . "/composer.json",
    json_encode($manifest, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n",
);
' "${package_dir}" "${consumer_dir}"

(
    cd "${consumer_dir}"
    COMPOSER_DISABLE_NETWORK=1 composer require "${package_name}:${package_version}" \
        --no-interaction --no-progress
)
php -r '
require $argv[1];
// Every shipped type must be reachable through PSR-4 on its own. A class that
// only loads because another file happened to require it first is not part of
// the published surface, so the check autoloads each name independently.
$types = preg_split("/\s+/", trim($argv[2] ?? ""), -1, PREG_SPLIT_NO_EMPTY);
if ($types === false || $types === []) {
    fwrite(STDERR, "smoke check received no class names\n");
    exit(1);
}
$missing = [];
foreach ($types as $type) {
    if (!class_exists($type) && !interface_exists($type)) {
        $missing[] = $type;
    }
}
if ($missing !== []) {
    fwrite(STDERR, "Composer autoload did not expose: " . implode(", ", $missing) . "\n");
    exit(1);
}
' "${consumer_dir}/vendor/autoload.php" \
    "$(cd "${package_dir}/src" && printf '%s\n' *.php | sed 's/\.php$//; s#^#Snaplink\\#' | tr '\n' ' ')"
echo "PASS: local Composer path install (${package_name} ${package_version})"
