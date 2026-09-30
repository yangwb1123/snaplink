#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
package_dir="${repo_root}/sdks/php"
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
if (!class_exists("Snaplink\\SnaplinkClient")) {
    fwrite(STDERR, "Composer autoload did not expose SnaplinkClient.\n");
    exit(1);
}
' "${consumer_dir}/vendor/autoload.php"
echo "PASS: local Composer path install (${package_name} ${package_version})"
