#!/bin/bash
set -e

VERSION=$1

# Verify version format
if ! echo "$VERSION" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+$" > /dev/null; then
    echo "Version must be in format X.Y.Z"
    exit 1
fi

# Cross-platform sed command (macOS and Linux)
do_sed() {
    local file=$1
    local pattern=$2
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '.bak' "$pattern" "$file"
        rm "${file}.bak"
    else
        sed -i "$pattern" "$file"
    fi
}

# Update CHANGELOG.md - replace "## Unreleased" with version and date
CURRENT_DATE=$(date +%Y-%m-%d)
do_sed "CHANGELOG.md" "s/## Unreleased/## [${VERSION}] - ${CURRENT_DATE}/"

# Update workspace version
do_sed "Cargo.toml" "s/^version = \".*\"/version = \"${VERSION}\"/"

# Update versions in crate Cargo.toml files
for crate in common crypto serde class-hash; do
    file="crates/${crate}/Cargo.toml"
    echo "Updating dependencies for $file..."
    do_sed "$file" "s/pathfinder-common = { version = \"[^\"]*\"/pathfinder-common = { version = \"${VERSION}\"/"
    do_sed "$file" "s/pathfinder-crypto = { version = \"[^\"]*\"/pathfinder-crypto = { version = \"${VERSION}\"/"
    do_sed "$file" "s/pathfinder-serde = { version = \"[^\"]*\"/pathfinder-serde = { version = \"${VERSION}\"/"
done

# Update Cargo.lock
cargo update -p pathfinder-common -p pathfinder-crypto -p pathfinder-serde -p pathfinder-class-hash

# Verify everything still builds
cargo check --workspace

# Create and checkout new release branch
git checkout -b release/v${VERSION}

# Create git commit and tag
git add Cargo.toml Cargo.lock crates/*/Cargo.toml CHANGELOG.md
git commit -m "chore: bump version to ${VERSION}"
git tag -a "v${VERSION}" -m "Pathfinder v${VERSION}"

# Quik recap of what was done
echo -e "\nChanges made:"
echo "- Updated workspace version to ${VERSION}"
echo "- Updated CHANGELOG.md with version ${VERSION} and date ${CURRENT_DATE}"
echo "- Updated dependency versions in public crates:"
for crate in common crypto serde class-hash; do
    echo "  - crates/${crate}/Cargo.toml"
done

# Confirmation before pushing
echo -e "\nPush these changes to release/v${VERSION} and create a tag v${VERSION}? (Y/n)"
read -r answer
if [[ "$answer" == "n" ]] || [[ "$answer" == "N" ]]; then
    echo "Aborting push. Changes are committed locally."
    exit 1
fi

# Push changes
git push --set-upstream origin release/v${VERSION} && git push origin "v${VERSION}"
