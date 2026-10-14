#!/bin/sh
# 配る zip を作って、R2 の非公開の置き場（preflight-downloads）に置く。
# 使い方（signup/ で）: ./upload-zip.sh [タグかコミット]   省略すると v$(cat ../VERSION)
#   1. 指定の版から zip を作る（signup/ や tests/ は入れない。.gitattributes の export-ignore）
#   2. versions/Preflight-<版>.zip として残し、latest/Preflight.zip を置き換える
#   受け口は latest/Preflight.zip を渡す（wrangler.toml の DOWNLOAD_KEY）。
set -eu
cd "$(dirname "$0")"
root=..
ref="${1:-v$(cat "$root/VERSION")}"
git -C "$root" rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "版が見つかりません: $ref" >&2; exit 1; }
case "$ref" in v[0-9]*) ver="${ref#v}" ;; *) ver="$(git -C "$root" rev-parse --short "$ref")" ;; esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
zip="$tmp/Preflight-$ver.zip"
git -C "$root" archive --worktree-attributes --format=zip --prefix=Preflight/ -o "$zip" "$ref"
unzip -l "$zip" | grep -q " Preflight/Preflight.command$" || { echo "zip に Preflight.command がありません" >&2; exit 1; }
if unzip -l "$zip" | grep -q " Preflight/signup/"; then echo "zip に signup/ が入っています" >&2; exit 1; fi
echo "作った zip: Preflight-$ver.zip（$(wc -c <"$zip" | tr -d ' ') バイト）"

if [ "${DRY_RUN:-}" = 1 ]; then cp "$zip" "./Preflight-$ver.zip"; echo "DRY_RUN=1 なので置かずに、ここに残しました"; exit 0; fi
npx wrangler r2 object put "preflight-downloads/versions/Preflight-$ver.zip" --file="$zip" --content-type=application/zip --remote
npx wrangler r2 object put "preflight-downloads/latest/Preflight.zip" --file="$zip" --content-type=application/zip --remote
echo "置きました: versions/Preflight-$ver.zip と latest/Preflight.zip"
