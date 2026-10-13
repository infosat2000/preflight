#!/bin/bash
# 初回の準備: CyberRiskScape（評価エンジン）を版を固定して取得・ビルドし、台帳のひな形を置く。
# 何度実行してもよい（取得済み・作成済みのものはそのまま残す）。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="${BB_PREFLIGHT_HOME:-$HOME/.bb-preflight}"

# 評価エンジンの版。上げるときは両方を同時に書き換え、テストを通してから。
CRS_REPO="https://github.com/takashi-ohmoto-git/CyberRiskScape.git"
CRS_TAG="v0.6.0"
CRS_COMMIT="71834024f8f7ad9c1bc134dfbe2ea330316dbcd6"
DEST="$HERE/vendor/CyberRiskScape"
# このツールの版（VERSION ファイルが唯一の置き場所）
VERSION="$(tr -d '[:space:]' < "$HERE/VERSION")"
echo "Blackbox Blast Preflight v$VERSION"

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
    # パッケージの install スクリプトは動かさない（npm のサプライチェーン攻撃は多くがここから入る）
    (cd "$DEST" && npm ci --ignore-scripts && npm run build:cli)
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

# 起動ボタン: アイコン付きの「Blackbox Blast Preflight.app」を ~/Applications に置く（sudo 不要）。
# Finder の「アプリケーション」・Launchpad・Spotlight から開ける。中身は Preflight.command をターミナルで開くだけ。
# 置きたくない場合は BB_PREFLIGHT_NO_SHORTCUT=1 で実行する。何度実行しても同じものを上書きする。
if [ -z "${BB_PREFLIGHT_NO_SHORTCUT:-}" ]; then
  APPS="${BB_PREFLIGHT_APPS_DIR:-$HOME/Applications}"
  APP="$APPS/Blackbox Blast Preflight.app"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  # 本体の場所を埋め込む（フォルダを移したら setup.sh をもう一度実行する）
  printf '#!/bin/bash\nTARGET=%q\nexec open -a Terminal "$TARGET"\n' "$HERE/Preflight.command" > "$APP/Contents/MacOS/launcher"
  chmod 755 "$APP/Contents/MacOS/launcher"
  cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Blackbox Blast Preflight</string>
  <key>CFBundleDisplayName</key><string>Blackbox Blast Preflight</string>
  <key>CFBundleIdentifier</key><string>com.blackboxblast.preflight</string>
  <key>CFBundleExecutable</key><string>launcher</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
  # アイコン: リポジトリの 1024px PNG から、macOS 標準の sips と iconutil で .icns を作る
  ICONSET="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$HERE/assets/icon-1024.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$HERE/assets/icon-1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
  touch "$APP"  # Finder にアイコンの更新を知らせる
  echo "起動ボタンを置きました: $APP"
fi
