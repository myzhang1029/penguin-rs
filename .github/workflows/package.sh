#!/bin/bash
TARGET="$1"
PROFILE="$2"
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
