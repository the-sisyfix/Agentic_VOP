#!/usr/bin/env bash
# Run one pipeline benchmark end-to-end and save a labeled scorecard.
#
# Usage:
#   ./run_bench.sh <stack> <per-scanner> [extra args...]
#
# Examples:
#   ./run_bench.sh openai 3                      # 9 scanners × 3 fixtures = 27 runs
#   ./run_bench.sh claude 2 --skip-done          # 2-per-scanner, skip completed
#   ./run_bench.sh gemini 3 --issue-slugs "a,b,c"
#
# What it does (in order):
#   1. Delete the default output path  (apps/benchmarks/scorecards/pipeline_<stack>.csv)
#   2. Run pipeline_runner.py with --stack <stack> --per-scanner <N> --sandbox + extras
#   3. Rename the finished scorecard to pipeline_<stack>_per_scanner_<N>.csv
#      (prior labeled file, if any, is backed up to .BACKUP-<timestamp>.csv)
#
# After running one per stack, aggregate with:
#   PYTHONPATH=../.. uv run python -m apps.benchmarks.compare_pipeline
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <openai|gemini|claude> <per-scanner-N> [extra pipeline_runner args...]" >&2
  exit 2
fi

STACK=$1
PER_SCANNER=$2
shift 2

case "$STACK" in
  openai|gemini|claude) ;;
  *)
    echo "ERROR: stack must be one of: openai, gemini, claude (got '$STACK')" >&2
    exit 2
    ;;
esac

if ! [[ "$PER_SCANNER" =~ ^[0-9]+$ ]]; then
  echo "ERROR: per-scanner must be a positive integer (got '$PER_SCANNER')" >&2
  exit 2
fi

# Resolve paths relative to this script so you can run it from any cwd.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." &> /dev/null && pwd)
API_DIR="$REPO_ROOT/apps/api"
SCORECARDS="$SCRIPT_DIR/scorecards"
DEFAULT_CSV="$SCORECARDS/pipeline_${STACK}.csv"
LABELED_CSV="$SCORECARDS/pipeline_${STACK}_per_scanner_${PER_SCANNER}.csv"

mkdir -p "$SCORECARDS"

# 1. Clear the default output so pipeline_runner starts fresh (append-prone).
if [[ -f "$DEFAULT_CSV" ]]; then
  echo "▶ Removing stale default: $DEFAULT_CSV"
  rm -f "$DEFAULT_CSV"
fi

# Back up any prior labeled scorecard before overwriting it at step 3.
if [[ -f "$LABELED_CSV" ]]; then
  BACKUP="$SCORECARDS/pipeline_${STACK}_per_scanner_${PER_SCANNER}.BACKUP-$(date +%Y%m%d-%H%M%S).csv"
  echo "▶ Backing up prior labeled scorecard → $(basename "$BACKUP")"
  mv "$LABELED_CSV" "$BACKUP"
fi

echo "▶ Running benchmark: stack=$STACK per_scanner=$PER_SCANNER $*"
echo

# 2. Run the benchmark. caffeinate keeps the mac awake during long runs.
cd "$API_DIR"
PYTHONPATH="$REPO_ROOT" caffeinate -d -i -s \
  uv run python -m apps.benchmarks.pipeline_runner \
    --stack "$STACK" \
    --sandbox \
    --per-scanner "$PER_SCANNER" \
    "$@"

echo
# 3. Rename default → labeled so compare_pipeline.py auto-detects it.
if [[ -f "$DEFAULT_CSV" ]]; then
  mv "$DEFAULT_CSV" "$LABELED_CSV"
  echo "▶ Scorecard saved: $LABELED_CSV"
else
  echo "⚠  No scorecard was written at $DEFAULT_CSV — benchmark may have failed early." >&2
  exit 1
fi
