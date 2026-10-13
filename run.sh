#!/bin/bash
# 実測 → 構成図 JSON 生成 → CyberRiskScape で評価 → 前回との差分、を1回で回す。
# 個人データ（台帳・構成図・レポート）はコードの外、$BB_PREFLIGHT_HOME（既定 ~/.bb-preflight）に置く。
set -euo pipefail
umask 077  # レポートは自分の弱点の地図なので、本人以外は読めないようにする
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="${BB_PREFLIGHT_HOME:-$HOME/.bb-preflight}"
CRS="${CRS_CLI:-$HERE/vendor/CyberRiskScape/dist-cli/main.js}"
if [ -n "${PYTHON:-}" ]; then PY="$PYTHON"; elif [ -x /usr/bin/python3 ]; then PY=/usr/bin/python3; else PY=python3; fi
INV="$DATA/inventory.json"
MODEL="$DATA/model.json"

[ -f "$INV" ] || { echo "台帳がありません: $INV（先に ./setup.sh を実行し、台帳を自分の環境に合わせて書き換えてください）" >&2; exit 1; }
[ -f "$CRS" ] || { echo "CyberRiskScape の CLI がありません: $CRS（先に ./setup.sh を実行してください）" >&2; exit 1; }

STAMP="$(date +%Y-%m-%d_%H%M%S)"
OUT="$DATA/out/$STAMP"
mkdir -p "$OUT"

[ -f "$MODEL" ] && cp "$MODEL" "$OUT/prev-model.json"

"$PY" "$HERE/collect.py" "$INV" "$OUT/facts.json"
"$PY" "$HERE/build.py" "$INV" "$OUT/facts.json" "$MODEL"
cp "$MODEL" "$OUT/model.json"

node "$CRS" checklist "$MODEL" --id ipa-alert-2026-10 --format csv --out "$OUT/ipa-checklist.csv"
node "$CRS" checklist "$MODEL" --id ipa-alert-2026-10 --format md --out "$OUT/ipa-checklist.md"
node "$CRS" analyze "$MODEL" --format json --out "$OUT/threats.json"
if [ -f "$OUT/prev-model.json" ]; then
  node "$CRS" diff "$OUT/prev-model.json" "$MODEL" --format md --out "$OUT/diff.md" || true
fi
"$PY" "$HERE/report.py" "$OUT"
echo "レポート: $OUT/report.md"
