#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ "$(uname -sm)" != "Linux x86_64" ]]; then
  echo "::error::Hushgrep requires an x86-64 Linux runner. Use ubuntu-24.04."
  exit 1
fi
archive=hushgrep-linux-x86_64.tar.gz
tag=v0.1.0-alpha.3
digest=0aca46d8e4c9ec9eca7d952ffbc504465b3ba634f8a3cf651686fb0588a7ee03
dir=$(mktemp -d "$RUNNER_TEMP/hushgrep-install.XXXXXXXX")
cd "$dir"
url="https://github.com/beshkenadze/hushgrep/releases/download/$tag/$archive"
curl --silent --show-error --fail --location --retry 2 --connect-timeout 15 --max-time 300 -o "$archive" "$url"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --strict --check --status
tar -xzf "$archive"
rm -- "$archive"
printf 'binary=%s/hushgrep-linux-x86_64/hushgrep\n' "$dir" >> "$GITHUB_OUTPUT"
