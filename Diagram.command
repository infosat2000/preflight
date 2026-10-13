#!/bin/bash
# Finder でダブルクリックして使う、専門家向けの起動ファイル。
# 最新の構成図を、評価エンジンのブラウザ版で開く（./setup.sh --with-engine で入れたときだけ使える）。
cd "$(dirname "$0")" || exit 1
if [ -x /usr/bin/python3 ]; then PY=/usr/bin/python3; else PY=python3; fi
"$PY" diagram.py
code=$?
if [ "$code" -ne 0 ]; then
  echo
  read -r -n 1 -p "何かキーを押すと閉じます…" _
fi
exit "$code"
