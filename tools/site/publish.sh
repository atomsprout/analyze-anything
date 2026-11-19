#!/bin/bash
# Publishes the website: puts the files of site/ on the gh-pages branch, which GitHub Pages serves.
#
#   tools/site/publish.sh
#
# The branch holds one commit, replaced each time; its history is the history of site/ on main.
set -euo pipefail
cd "$(dirname "$0")/../.."
REMOTE=$(git remote get-url origin)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R site/. "$WORK/"
# No Jekyll: the files are served as they are.
touch "$WORK/.nojekyll"
git -C "$WORK" init -q -b gh-pages
git -C "$WORK" add -A
git -C "$WORK" -c user.name="$(git config user.name)" -c user.email="$(git config user.email)" \
    commit -qm "The website, from site/ at $(git rev-parse --short HEAD)"
git -C "$WORK" push -q -f "$REMOTE" gh-pages
echo "published; GitHub Pages takes a minute to show it"
