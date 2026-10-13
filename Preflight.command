#!/bin/bash
# Finder でダブルクリックして使う起動ファイル。
# 初回はセットアップして台帳を開き、2回目以降は実測してレポートを開く。
set -uo pipefail
cd "$(dirname "$0")" || exit 1
DATA="${BB_PREFLIGHT_HOME:-$HOME/.bb-preflight}"

finish() {
  echo
  read -r -n 1 -p "何かキーを押すと閉じます…" _
  exit "$1"
}

echo "== Preflight（FOREST LIFE*）Blackbox Blast Edition =="
if [ ! -f "$DATA/inventory.json" ]; then
  echo "初回のセットアップをします。"
  ./setup.sh || { echo "セットアップに失敗しました。上のメッセージを確認してください。"; finish 1; }
fi
if cmp -s examples/inventory.example.json "$DATA/inventory.json"; then
  echo
  echo "台帳（inventory.json）がひな形のままです。テキストエディットで開くので、自分の環境に合わせて書き換えて保存し、もう一度この起動ファイルを開いてください。"
  open -e "$DATA/inventory.json"
  finish 0
fi

echo "実測しています。このMacの設定は変更しません。ふつうは1〜3分ほどかかります（Mac が重いときは、もっとかかります）。"
log="$(mktemp)"
if ./run.sh 2>&1 | tee "$log"; then
  report="$(sed -n 's/^レポート: //p' "$log" | tail -1)"
  rm -f "$log"
  if [ -n "$report" ] && [ -f "$report" ]; then
    echo "レポートを開きます: $report"
    open "$report"  # report.html を既定のブラウザで開く
  fi
  finish 0
else
  rm -f "$log"
  echo "実測に失敗しました。上のメッセージを確認してください。"
  finish 1
fi
