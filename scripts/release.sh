#!/bin/bash

# Release script for envoy-avp-authorizer
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 1.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if version is provided
if [ $# -eq 0 ]; then
    print_error "Please provide a version number"
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

VERSION="$1"

# Validate version format (basic semver check)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    print_error "Invalid version format. Please use semantic versioning (e.g., 1.0.0, 1.0.0-alpha.1)"
    exit 1
fi

TAG="v$VERSION"

print_status "Starting release process for version $VERSION"

# Check if we're on the main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ] && [ "$CURRENT_BRANCH" != "master" ]; then
    print_warning "You are not on the main/master branch (current: $CURRENT_BRANCH)"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Release cancelled"
        exit 1
    fi
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    print_error "Working directory is not clean. Please commit or stash your changes."
    exit 1
fi

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    print_error "Tag $TAG already exists"
    exit 1
fi

# Update Cargo.toml version
print_status "Updating Cargo.toml version to $VERSION"
if command -v sed >/dev/null 2>&1; then
    # Use sed to update version in Cargo.toml
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    else
        # Linux
        sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    fi
else
    print_warning "sed not found. Please manually update the version in Cargo.toml to $VERSION"
    read -p "Press Enter after updating Cargo.toml..."
fi

# Verify the version was updated
if ! grep -q "version = \"$VERSION\"" Cargo.toml; then
    print_error "Failed to update version in Cargo.toml"
    exit 1
fi

print_status "Version updated in Cargo.toml"

# Update Cargo.lock
print_status "Updating Cargo.lock"
cargo check --quiet

# Commit the version change
print_status "Committing version change"
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to $VERSION"

# Create and push tag
print_status "Creating tag $TAG"
git tag -a "$TAG" -m "Release $VERSION"

print_status "Pushing changes and tag to origin"
git push origin HEAD
git push origin "$TAG"

print_status "Release $VERSION initiated successfully!"
print_status "GitHub Actions will now build and create the release automatically."
print_status "Check the Actions tab in your GitHub repository for progress."

echo ""
print_status "Release artifacts will be available at:"
echo "  - Binaries: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/releases/tag/$TAG"
echo "  - Docker: ghcr.io/$(git remote get-url origin | sed 's/.*github.com[:/]\([^/]*\).*/\1/')/envoy-avp-authorizer:$TAG"