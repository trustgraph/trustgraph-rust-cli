#!/usr/bin/env bash
# Publishes one npm package directory with pnpm, with provenance. Used by
# .github/workflows/npm.yml; see doc/releasing.md.
#
#   scripts/npm-publish.sh DIR [--dry-run]
#
# A version that is already on the registry is skipped, so a release that
# failed half way can simply be re-run. Authentication is npm trusted
# publishing (OIDC), or an NPM_TOKEN written to ~/.npmrc by the workflow.
set -euo pipefail

dir=${1:?usage: scripts/npm-publish.sh DIR [--dry-run]}
dry_run=${2:-}
manifest="$(cd "$dir" && pwd)/package.json"
name=$(node -p 'require(process.argv[1]).name' "$manifest")
version=$(node -p 'require(process.argv[1]).version' "$manifest")
spec="$name@$version"

if pnpm view "$spec" version >/dev/null 2>&1; then
  echo "$spec is already published, skipping"
  exit 0
fi

flags=(--access public --no-git-checks)
# Prereleases (1.0.0-rc.1) go to the `next` dist-tag, so `latest` stays stable.
case "$version" in *-*) flags+=(--tag next) ;; esac
if [ "$dry_run" = --dry-run ]; then
  flags+=(--dry-run)
else
  flags+=(--provenance)
fi

echo "publishing $spec from $dir ${dry_run}"
(cd "$dir" && pnpm publish "${flags[@]}")
