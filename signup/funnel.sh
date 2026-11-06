#!/bin/sh
# 申し込みの流れを週ごとに数える（読むだけ。名簿も記録も変えない）。
# 使い方（signup/ で）: ./funnel.sh            直近8週
#                      WEEKS=12 ./funnel.sh   直近12週
#                      EXCLUDE="me@example.com,test@example.com" ./funnel.sh   自分の試験用アドレスを数えない
# 出すのは件数だけ。メールアドレスは表示しない。
# BB の案内と紹介ページの「見えた」「押された」は hits 表から週ごとに出す（件数だけ。誰が見たかは残していない）。
set -eu
cd "$(dirname "$0")"
weeks="${WEEKS:-8}"
case "$weeks" in *[!0-9]*|'') echo "WEEKS は数字で指定してください" >&2; exit 1 ;; esac

# 除外するアドレスは SQL の文字列として埋め込むので、使える文字を限る
not_in=""
if [ -n "${EXCLUDE:-}" ]; then
  for a in $(printf '%s' "$EXCLUDE" | tr ',' ' '); do
    a="$(printf '%s' "$a" | tr 'A-Z' 'a-z')"
    case "$a" in *[!a-z0-9@._+-]*) echo "EXCLUDE に使えない文字があります" >&2; exit 1 ;; esac
    not_in="$not_in${not_in:+,}'$a'"
  done
  not_in="AND email NOT IN ($not_in)"
fi

sql="SELECT strftime('%Y-W%W', at) AS week,
  SUM(kind='signup') AS signup, SUM(kind='confirm') AS confirm, SUM(kind='download') AS download,
  SUM(kind='relink') AS relink, SUM(kind='unsubscribe') AS unsubscribe,
  COUNT(DISTINCT CASE WHEN kind='download' THEN email END) AS people_downloaded
FROM events WHERE at >= date('now', '-$((weeks * 7)) days') $not_in
GROUP BY week ORDER BY week"

npx wrangler d1 execute preflight-signup --remote --json --command "$sql" 2>/dev/null | python3 -c '
import json, sys
rows = json.load(sys.stdin)[0]["results"]
cols = ["week", "signup", "confirm", "download", "people_downloaded", "relink", "unsubscribe"]
head = ["週", "申し込み", "確認", "DL回数", "DLした人", "再発行", "停止"]
print("  ".join("%-9s" % h for h in head))
for r in rows:
    print("  ".join("%-9s" % (r.get(c) or 0) for c in cols))
if not rows:
    print("（この期間の記録はありません）")
'

hits="SELECT strftime('%Y-W%W', day) AS week,
  SUM(CASE WHEN kind='view' AND place IN ('hero','article') THEN n ELSE 0 END) AS promo_view,
  SUM(CASE WHEN kind='click' AND place IN ('hero','article') THEN n ELSE 0 END) AS promo_click,
  SUM(CASE WHEN kind='view' AND place='page' THEN n ELSE 0 END) AS page_view
FROM hits WHERE day >= date('now', '-$((weeks * 7)) days') GROUP BY week ORDER BY week"
echo
echo "BB の案内と紹介ページ（自分の閲覧も含む）"
npx wrangler d1 execute preflight-signup --remote --json --command "$hits" 2>/dev/null | python3 -c '
import json, sys
rows = json.load(sys.stdin)[0]["results"]
cols = ["week", "promo_view", "promo_click", "page_view"]
head = ["週", "案内が見えた", "案内が押された", "紹介ページ"]
print("  ".join("%-9s" % h for h in head))
for r in rows:
    print("  ".join("%-9s" % (r.get(c) or 0) for c in cols))
if not rows:
    print("（まだ記録はありません）")
'
