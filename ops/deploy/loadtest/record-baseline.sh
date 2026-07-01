#!/usr/bin/env bash
# Record load test baseline metrics to baseline.json
# Usage: ./record-baseline.sh [iterations]
set -euo pipefail

BASELINE_FILE="${1:-baseline.json}"
ITERATIONS="${2:-3}"

echo "==> Recording load test baseline ($ITERATIONS iterations)..."

# Run k6 and capture JSON output
k6 run --out json=results.json ../loadtest/token.js 2>&1 | tee k6-output.txt

# Extract metrics from k6 JSON output
if [ -f results.json ]; then
  # Parse k6 results and create baseline
  cat > "$BASELINE_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "iterations": $ITERATIONS,
  "metrics": {
    "http_req_duration": {
      "avg": $(jq -r '.metrics.http_req_duration.avg // 0' results.json),
      "p95": $(jq -r '.metrics.http_req_duration["p(95)"] // 0' results.json),
      "p99": $(jq -r '.metrics.http_req_duration["p(99)"] // 0' results.json),
      "max": $(jq -r '.metrics.http_req_duration.max // 0' results.json)
    },
    "http_req_failed": {
      "rate": $(jq -r '.metrics.http_req_failed.rate // 0' results.json)
    },
    "http_reqs": {
      "rate": $(jq -r '.metrics.http_reqs.rate // 0' results.json),
      "count": $(jq -r '.metrics.http_reqs.count // 0' results.json)
    }
  }
}
EOF
  echo "==> Baseline recorded: $BASELINE_FILE"
  jq '.' "$BASELINE_FILE"
else
  echo "ERROR: results.json not found"
  exit 1
fi
