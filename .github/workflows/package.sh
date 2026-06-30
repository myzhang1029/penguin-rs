#!/bin/bash

set -euo pipefail

TARGET="$1"
PROFILE="$2"
DELETE_OLD="$3"
REPO="myzhang1029/penguin-rs"
GIT_REV="$(git describe --tags --match='v[0-9\.]*' --long | cut -f2 -d-)"
if [ "$GIT_REV" -eq 0 ]; then
  PKG_REV="$((GIT_REV + 1)).gha"
else
  PKG_REV="$((GIT_REV + 1))~alpha.gha"
fi

mkdir packages

cargo deb --no-build --no-strip --package rusty-penguin \
  --deb-revision "$PKG_REV" \
  --target "$TARGET" --profile "$PROFILE"
cp -v target/"$TARGET"/debian/*.deb packages

cargo generate-rpm --package penguin \
  -s "release = \"$PKG_REV\"" \
  --target "$TARGET" --profile "$PROFILE"
cp -v target/"$TARGET"/generate-rpm/*.rpm packages

# Delete old packages
if [ "$GIT_REV" -ne 0 ] && [ "$DELETE_OLD" = true ]; then
  TAIL_PATTERN="$(ls packages | sed 's/.*gha\(.*\)/\1/' | sort | uniq | tr '\n' '|' | sed 's/\(.*\)|/(\1)/')"
  ASSET_IDS="$(gh api -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2026-03-10" \
    "/repos/$REPO/releases" | jq "map(select(.tag_name==\"nightly\"))[0] | .assets | map(select(.name | test(\"^rusty-penguin.*$TAIL_PATTERN\$\")) | .id) | .[]")"
  for asset_id in $ASSET_IDS; do
    echo "DELETE /repos/$REPO/releases/assets/$asset_id"
    gh api --method DELETE -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2026-03-10" \
      "/repos/$REPO/releases/assets/$asset_id"
  done
fi
