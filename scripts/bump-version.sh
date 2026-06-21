#!/usr/bin/env bash
# bump-version.sh <new-version>
#
# Sets every version field in the workspace to <new-version>:
#   - [workspace.package] version in the root Cargo.toml
#   - `version = "..."` in crate Cargo.toml files
#   - Intra-workspace path dependency versions
#
# Usage:
#   ./scripts/bump-version.sh 0.0.2

set -euo pipefail

NEW="${1:-}"
if [[ -z "$NEW" ]]; then
    echo "Usage: $0 <new-version>" >&2
    exit 1
fi

# Validate semver-ish format (e.g. 1.2.3 or 1.2.3-rc.1)
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9._-]+)?$ ]]; then
    echo "Invalid version format: '$NEW' (expected e.g. 1.2.3 or 1.2.3-rc.1)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# All Cargo.toml files (includes huginn-ebpf-xdp which is outside the workspace)
mapfile -t TOMLS < <(find . -name "Cargo.toml" -not -path "*/target/*")

for f in "${TOMLS[@]}"; do
    # 1. Any standalone `version = "x.y.z"` line (workspace package or per-crate)
    sed -i 's/^\(version\s*=\s*\)"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*[^"]*"/\1"'"$NEW"'"/' "$f"

    # 2. Intra-workspace path deps: { path = "../foo", version = "x.y.z" }
    sed -i 's/\(path\s*=\s*"\.\.\/[^"]*"[^,]*,\s*version\s*=\s*\)"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*[^"]*"/\1"'"$NEW"'"/g' "$f"
    # Also handles: { version = "x.y.z", path = "../foo" }
    sed -i 's/\(version\s*=\s*\)"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*[^"]*"\(\s*,\s*path\s*=\)/\1"'"$NEW"'"\2/g' "$f"
done

echo "Bumped all versions to $NEW"
echo "Next steps:"
echo "  cargo check"
echo "  git commit -am \"chore: bump version to $NEW\""
