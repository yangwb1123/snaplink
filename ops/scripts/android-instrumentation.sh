#!/usr/bin/env bash
# Run the Android Keystore instrumentation test on a booted emulator.
#
# Why this script exists rather than a bare gradle invocation:
#
# `connectedAndroidTest` installs the test APK through `pm`. A freshly created
# emulator can report sys.boot_completed=1 before the system server is actually
# serving the package manager, and installing into that window fails with
#
#   'package install-create -r -t -S <id>' returns error
#   'Unknown failure: cmd: Can't find service: package'
#
# which surfaces as "Starting 0 tests" - no test ever runs, and the build failure
# looks like a test problem rather than a timing one. The action's boot wait only
# covers the boot-completed property, so the package service is polled here, where
# the failure can be named: if the manager never answers, this says so instead of
# leaving the caller to interpret an install stack trace.
#
# The script locates itself, so the caller's working directory does not matter
# and the Gradle wrapper is always invoked from the directory that holds it.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
gradle_workspace="${repo_root}/sdks"

# Long enough for a cold image to finish booting, short enough that a genuinely
# dead emulator is reported rather than waited on for the whole CI job.
readonly READY_TIMEOUT_SECONDS="${ANDROID_READY_TIMEOUT_SECONDS:-600}"
readonly POLL_INTERVAL_SECONDS=3

log() { printf '[android-instrumentation] %s\n' "$*" >&2; }

device_id="$(adb devices | awk 'NR > 1 && $2 == "device" { print $1; exit }')"
if [[ -z "$device_id" ]]; then
    log "no device in 'adb devices'; the emulator did not start or is offline"
    adb devices >&2 || true
    exit 1
fi
log "using device ${device_id}"

waited=0
until [[ "$(adb -s "${device_id}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
    (( waited += POLL_INTERVAL_SECONDS ))
    if (( waited >= READY_TIMEOUT_SECONDS )); then
        log "sys.boot_completed never reached 1 within ${READY_TIMEOUT_SECONDS}s"
        exit 1
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
done
log "boot completed"

# The window this script exists for: boot_completed is set, package is not up.
waited=0
until adb -s "${device_id}" shell 'pm path android' >/dev/null 2>&1; do
    (( waited += POLL_INTERVAL_SECONDS ))
    if (( waited >= READY_TIMEOUT_SECONDS )); then
        log "the package manager never answered 'pm path android' within ${READY_TIMEOUT_SECONDS}s"
        log "an install now would fail with: Can't find service: package"
        exit 1
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
done
log "package manager ready"

# The boot animation keeps the device busy and can stall the install; animations
# are disabled by the emulator action too, and this covers a manual local run.
adb -s "${device_id}" shell settings put global window_animation_scale 0 >/dev/null 2>&1 || true
adb -s "${device_id}" shell settings put global transition_animation_scale 0 >/dev/null 2>&1 || true
adb -s "${device_id}" shell settings put global animator_duration_scale 0 >/dev/null 2>&1 || true

cd "${gradle_workspace}"
exec ./gradlew :snaplink:connectedDebugAndroidTest "$@"
