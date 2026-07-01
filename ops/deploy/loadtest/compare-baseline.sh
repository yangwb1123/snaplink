#!/usr/bin/env sh
# Compare current load test results against baseline.json
# Usage: ./compare-baseline.sh [baseline_file] [threshold_percent]
# Exit codes: 0 = within threshold, 1 = regression detected
set -eu

BASELINE="${1:-baseline.json}"
THRESHOLD="${2:-20}"  # Allow 20% degradation by default

if [ ! -f "$BASELINE" ]; then
  echo "ERROR: Baseline file not found: $BASELINE"
  echo "Run ./record-baseline.sh first to create a baseline"
  exit 1
fi

echo "==> Comparing against baseline: $BASELINE"
echo "    Threshold: ${THRESHOLD}% degradation allowed"
echo ""

# Run k6 and capture metrics
k6 run --summary-export=current.json ../loadtest/token.js 2>&1

if [ ! -f current.json ]; then
  echo "ERROR: current.json not generated"
  exit 1
fi

# Extract baseline metrics
BL_P95=$(jq -r '.metrics.http_req_duration.p95 // 0' "$BASELINE")
BL_P99=$(jq -r '.metrics.http_req_duration.p99 // 0' "$BASELINE")
BL_FAILED=$(jq -r '.metrics.http_req_failed.rate // 0' "$BASELINE")

# Extract current metrics
CUR_P95=$(jq -r '.metrics.http_req_duration["p(95)"] // 0' current.json)
CUR_P99=$(jq -r '.metrics.http_req_duration["p(99)"] // 0' current.json)
CUR_FAILED=$(jq -r '.metrics.http_req_failed.rate // 0' current.json)

echo "Metric          | Baseline | Current  | Change"
echo "----------------|----------|----------|--------"

# Calculate percentage changes
if [ "$BL_P95" -gt 0 ]; then
  P95_CHANGE=$(echo "scale=2; (($CUR_P95 - $BL_P95) / $BL_P95) * 100" | bc)
  printf "p95 latency (ms)| %-8s | %-8s | %s%%\n" "$BL_P95" "$CUR_P95" "$P95_CHANGE"
else
  P95_CHANGE=0
  printf "p95 latency (ms)| %-8s | %-8s | N/A\n" "$BL_P95" "$CUR_P95"
fi

if [ "$BL_P99" -gt 0 ]; then
  P99_CHANGE=$(echo "scale=2; (($CUR_P99 - $BL_P99) / $BL_P99) * 100" | bc)
  printf "p99 latency (ms)| %-8s | %-8s | %s%%\n" "$BL_P99" "$CUR_P99" "$P99_CHANGE"
else
  P99_CHANGE=0
  printf "p99 latency (ms)| %-8s | %-8s | N/A\n" "$BL_P99" "$CUR_P99"
fi

FAILED_CHANGE=$(echo "scale=4; $CUR_FAILED - $BL_FAILED" | bc)
printf "Failed rate     | %-8s | %-8s | %s\n" "$BL_FAILED" "$CUR_FAILED" "$FAILED_CHANGE"

echo ""

# Check for regressions
REGRESSION=0
if [ "$(echo "$P95_CHANGE > $THRESHOLD" | bc)" -eq 1 ]; then
  echo "FAIL: p95 latency regressed by ${P95_CHANGE}% (threshold: ${THRESHOLD}%)"
  REGRESSION=1
fi

if [ "$(echo "$P99_CHANGE > $THRESHOLD" | bc)" -eq 1 ]; then
  echo "FAIL: p99 latency regressed by ${P99_CHANGE}% (threshold: ${THRESHOLD}%)"
  REGRESSION=1
fi

if [ "$(echo "$CUR_FAILED > $BL_FAILED" | bc)" -eq 1 ]; then
  echo "FAIL: Failure rate increased from $BL_FAILED to $CUR_FAILED"
  REGRESSION=1
fi

if [ "$REGRESSION" -eq 0 ]; then
  echo "PASS: All metrics within threshold"
else
  echo "FAIL: Performance regression detected"
fi

# Cleanup
rm -f current.json

exit $REGRESSION
