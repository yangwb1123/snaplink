<?php

declare(strict_types=1);

/**
 * Locate the shared cross-SDK conformance corpus.
 *
 * These cases live in ops/build/sdk-conformance/ and are deliberately shared:
 * one file is the contract every SDK is checked against, which is what makes
 * drift between languages detectable. They are therefore NOT part of this
 * package, and the published Composer distribution must not carry a second
 * copy that could diverge from the original.
 *
 * That means the conformance tests have two legitimate contexts:
 *
 *   - a monorepo checkout, where the corpus is present and the real
 *     cross-language comparison runs;
 *   - the standalone package repository this subtree split produces, where the
 *     corpus is absent and the test cannot do its job.
 *
 * In the second case the test skips and says so. Copying the fixture to make the
 * test pass would defeat the purpose of a shared fixture, and exiting non-zero
 * would leave the distributed repository with a permanently red suite for a
 * condition that is expected rather than broken.
 */

function snaplinkConformanceCorpusAvailable(): bool
{
    return is_dir(__DIR__ . '/../../../ops/build/sdk-conformance');
}

function snaplinkConformanceFixture(string $name): string
{
    return __DIR__ . '/../../../ops/build/sdk-conformance/' . $name;
}

/**
 * Skip the calling test when the shared corpus is not part of this checkout.
 * Returns true when the caller should exit without running its checks.
 */
function snaplinkSkipWithoutConformanceCorpus(string $testName): bool
{
    if (snaplinkConformanceCorpusAvailable()) {
        return false;
    }
    echo "SKIP $testName: the shared cross-SDK conformance corpus is not part of this "
        . "distribution; it runs in the monorepo checkout\n";
    exit(0);
}
