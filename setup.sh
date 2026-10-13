#!/bin/bash
# 初回の準備: 台帳のひな形と起動ボタンを置く。必要なのは macOS に入っている python3 だけ。
# ./setup.sh --with-engine（または BB_PREFLIGHT_ENGINE=1）のときだけ、専門家向けの評価エンジン CyberRiskScape を
# 版を固定して取得・ビルドする（git・Node.js・npm が必要）。一度入れたエンジンは、次からも使う。
# 何度実行してもよい（取得済み・作成済みのものはそのまま残す）。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="${BB_PREFLIGHT_HOME:-$HOME/.bb-preflight}"

# 評価エンジンの版。上げるときは両方を同時に書き換え、テストを通してから。
# Diagram.command がブラウザ版に構成図を読み込めるかも確かめる（diagram.py の説明を参照）。
CRS_REPO="https://github.com/takashi-ohmoto-git/CyberRiskScape.git"
CRS_TAG="v0.6.0"
CRS_COMMIT="71834024f8f7ad9c1bc134dfbe2ea330316dbcd6"
DEST="$HERE/vendor/CyberRiskScape"
# このツールの版（VERSION ファイルが唯一の置き場所）
VERSION="$(tr -d '[:space:]' < "$HERE/VERSION")"
echo "Blackbox Blast Preflight v$VERSION"

WITH_ENGINE="${BB_PREFLIGHT_ENGINE:-}"
[ "${1:-}" = "--with-engine" ] && WITH_ENGINE=1
[ -f "$DEST/dist-cli/main.js" ] && WITH_ENGINE=1

# python3 は macOS に入っている。初めて使う Mac では「コマンドライン・デベロッパ・ツール」を入れる画面が出ることがある
if [ -x /usr/bin/python3 ]; then PY=/usr/bin/python3; else PY=python3; fi
if ! "$PY" -c "import sys; sys.exit(sys.version_info < (3, 9))" 2>/dev/null; then
  echo "python3（3.9 以上）が使えません。画面に「コマンドライン・デベロッパ・ツール」をインストールする案内が出ていたら、インストールしてから、もう一度開いてください。" >&2
  exit 1
fi

if [ -z "$WITH_ENGINE" ] && [ -z "${CRS_CLI:-}" ]; then
  echo "評価エンジンは入れません（点検とレポートには不要です。専門家向けの一覧が要るときは ./setup.sh --with-engine）。"
elif [ -n "${CRS_CLI:-}" ]; then
  echo "CRS_CLI が指定されているので、CyberRiskScape の取得は省略します: $CRS_CLI"
else
  for c in git node npm; do
    command -v "$c" >/dev/null || { echo "評価エンジンを入れるには $c が必要です。先にインストールしてください。" >&2; exit 1; }
  done
  if [ ! -d "$DEST/.git" ]; then
    git clone --depth 1 --branch "$CRS_TAG" "$CRS_REPO" "$DEST"
  fi
  actual="$(git -C "$DEST" rev-parse HEAD)"
  if [ "$actual" != "$CRS_COMMIT" ]; then
    echo "取得した CyberRiskScape のコミットが想定と違います（想定 $CRS_COMMIT / 実際 $actual）。中止します。" >&2
    exit 1
  fi
  if [ ! -f "$DEST/dist-cli/main.js" ] || [ ! -f "$DEST/dist/index.html" ]; then
    # パッケージの install スクリプトは動かさない（npm のサプライチェーン攻撃は多くがここから入る）
    # dist-cli は評価に、dist は構成図を開くブラウザ版（Diagram.command）に使う
    (cd "$DEST" && { [ -d node_modules ] || npm ci --ignore-scripts; } && npm run build:cli && npm run build)
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

# 起動ボタン: アイコン付きの .app を「アプリケーション」に置く（sudo 不要）。
# 管理者のユーザーなら /Applications（Finder のサイドバーの「アプリケーション」）に、そうでなければ ~/Applications に置く。
# Launchpad・Spotlight からも開ける。中身は起動ファイル（.command）をターミナルで開くだけ。
# 置きたくない場合は BB_PREFLIGHT_NO_SHORTCUT=1 で実行する。何度実行しても同じものを上書きする。
# 使い方: make_app "アプリ名" 起動ファイル バンドルID アイコンの1024pxPNG
make_app() {
  local name="$1" target="$2" bundle="$3" icon="$4"
  local app="$APPS/$name.app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  # 本体の場所を埋め込む（フォルダを移したら setup.sh をもう一度実行する）
  printf '#!/bin/bash\nTARGET=%q\nexec open -a Terminal "$TARGET"\n' "$target" > "$app/Contents/MacOS/launcher"
  chmod 755 "$app/Contents/MacOS/launcher"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleDisplayName</key><string>$name</string>
  <key>CFBundleIdentifier</key><string>$bundle</string>
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
  local iconset s d
  iconset="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$iconset"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$icon" --out "$iconset/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z "$d" "$d" "$icon" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"
  touch "$app"  # Finder にアイコンの更新を知らせる
  echo "起動ボタンを置きました: $app"
}

# 前の版が ~/Applications に置いた起動ボタンは、この setup.sh が作ったものだけ片付ける（同じものが2つ並ばないように）
remove_old_app() {
  local old="$1" bundle="$2"
  [ "$old" != "$APPS/$(basename "$old")" ] || return 0
  [ -f "$old/Contents/Info.plist" ] || return 0
  if [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$old/Contents/Info.plist" 2>/dev/null)" = "$bundle" ]; then
    rm -rf "$old"
    echo "前の場所の起動ボタンを片付けました: $old"
  fi
}

if [ -z "${BB_PREFLIGHT_NO_SHORTCUT:-}" ]; then
  if [ -n "${BB_PREFLIGHT_APPS_DIR:-}" ]; then
    APPS="$BB_PREFLIGHT_APPS_DIR"
  elif [ -w /Applications ]; then
    APPS=/Applications
  else
    APPS="$HOME/Applications"
  fi
  main_app="$APPS/Blackbox Blast Preflight.app"
  first_time=""
  [ -e "$main_app" ] || first_time=1
  make_app "Blackbox Blast Preflight" "$HERE/Preflight.command" com.blackboxblast.preflight "$HERE/assets/icon-1024.png"
  remove_old_app "$HOME/Applications/Blackbox Blast Preflight.app" com.blackboxblast.preflight
  # 専門家向け: 評価エンジンを入れた Mac にだけ、構成図を開く起動ボタンも置く
  if [ -f "$DEST/dist/index.html" ]; then
    make_app "Blackbox Blast Preflight Diagram" "$HERE/Diagram.command" com.blackboxblast.preflight.diagram "$HERE/assets/icon-diagram-1024.png"
    remove_old_app "$HOME/Applications/Blackbox Blast Preflight Diagram.app" com.blackboxblast.preflight.diagram
  fi
  echo "Dock にドラッグしておくと、次からはそこから開けます。"
  # 初めて置いたときだけ、置いた場所を Finder で見せる
  if [ -n "$first_time" ] && [ -z "${CI:-}" ] && [ -z "${BB_PREFLIGHT_NO_BROWSER:-}" ]; then
    open -R "$main_app" || true
  fi
fi
