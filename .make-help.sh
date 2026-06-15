#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
echo "================================================================================"
echo "  snaplink/sso -- Engineering Make Targets"
echo "================================================================================"
echo ""
grep -E '^[a-zA-Z_-]+:.*##' Makefile | sort | while IFS= read -r line; do
  target=$(echo "$line" | awk -F':.*##' '{print $1}' | xargs)
  desc=$(echo "$line" | awk -F':.*##' '{print $2}' | xargs)
  printf "  %-28s %s\n" "$target" "$desc"
done
echo ""
echo "  Other targets (no help text):"
grep -E '^[a-zA-Z_-]+:' Makefile | grep -v '##' | awk -F: '{print $1}' | sort | while IFS= read -r t; do
  printf "  %-28s\n" "$t"
done
