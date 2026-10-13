#!/bin/bash
# 初回の準備: CyberRiskScape（評価エンジン）を版を固定して取得・ビルドし、台帳のひな形を置く。
# 何度実行してもよい（取得済み・作成済みのものはそのまま残す）。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="${RISKSCAPE_HOME:-$HOME/.riskscape}"

# 評価エンジンの版。上げるときは両方を同時に書き換え、テストを通してから。
CRS_REPO="https://github.com/takashi-ohmoto-git/CyberRiskScape.git"
CRS_TAG="v0.6.0"
CRS_COMMIT="71834024f8f7ad9c1bc134dfbe2ea330316dbcd6"
DEST="$HERE/vendor/CyberRiskScape"

for c in git node npm; do
  command -v "$c" >/dev/null || { echo "$c が見つかりません。先にインストールしてください。" >&2; exit 1; }
done

if [ -n "${CRS_CLI:-}" ]; then
  echo "CRS_CLI が指定されているので、CyberRiskScape の取得は省略します: $CRS_CLI"
else
  if [ ! -d "$DEST/.git" ]; then
    git clone --depth 1 --branch "$CRS_TAG" "$CRS_REPO" "$DEST"
  fi
  actual="$(git -C "$DEST" rev-parse HEAD)"
  if [ "$actual" != "$CRS_COMMIT" ]; then
    echo "取得した CyberRiskScape のコミットが想定と違います（想定 $CRS_COMMIT / 実際 $actual）。中止します。" >&2
    exit 1
  fi
  if [ ! -f "$DEST/dist-cli/main.js" ]; then
    (cd "$DEST" && npm ci && npm run build:cli)
  fi
  echo "CyberRiskScape $CRS_TAG: $DEST/dist-cli/main.js"
fi

mkdir -p "$DATA"
chmod 700 "$DATA"
if [ ! -f "$DATA/inventory.json" ]; then
  cp "$HERE/examples/inventory.example.json" "$DATA/inventory.json"
  chmod 600 "$DATA/inventory.json"
  echo "台帳のひな形を置きました: $DATA/inventory.json（自分の環境に合わせて書き換えてください）"
else
  echo "台帳はそのまま使います: $DATA/inventory.json"
fi
