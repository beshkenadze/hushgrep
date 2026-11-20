#!/usr/bin/env bash
set -euo pipefail
umask 077
dir=$(mktemp -d "$RUNNER_TEMP/hushgrep-output.XXXXXXXX")
measure=$(mktemp "$RUNNER_TEMP/hushgrep-rss.XXXXXXXX")
timings=$(mktemp "$RUNNER_TEMP/hushgrep-timing.XXXXXXXX")
trap 'rm -f -- "$measure" "$timings"' EXIT
# Resolve relative paths against the checkout even if a workflow sets a working-directory.
cd "$GITHUB_WORKSPACE"
rc=0
# stderr stays private even if a dependency prints a candidate or a sensitive filename.
/usr/bin/time -f '%e %M' -o "$measure" "$SCANNER" --timings --output "$dir/report.json" "$(realpath -- "$CHECKOUT")" 2>"$timings" || rc=$?
if [[ "$rc" != 0 && "$rc" != 2 ]]; then
  echo "::error::Hushgrep could not scan the checkout. Check that path is a Git root and the runner is compatible."
  exit 1
fi
python3 -I "$GITHUB_ACTION_PATH/action/report.py" render "$dir" "$measure" "$timings" "$rc"
