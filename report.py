#!/usr/bin/env python3
"""out/<日時>/ の実測結果と CyberRiskScape の評価を、日本語の1枚レポート report.md にまとめる。"""
import collections
import csv
import json
import os
import sys


def main():
    out = sys.argv[1]
    with open(os.path.join(out, "facts.json"), encoding="utf-8") as f:
        facts = json.load(f)
    with open(os.path.join(out, "threats.json"), encoding="utf-8") as f:
        threats = json.load(f)[0]["threats"]
    with open(os.path.join(out, "ipa-checklist.csv"), encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    summary = next((r[1] for r in rows if r and r[0] == "集計"), "")
    head = next(i for i, r in enumerate(rows) if r and r[0] == "グループ")
    items = [dict(zip(rows[head], r)) for r in rows[head + 1:] if len(r) > 3]

    L = []
    L.append("# 実測点検レポート（%s）" % facts["measuredAt"].replace("T", " "))
    L.append("")
    L.append("## 1. 実測でしか分からないこと（このMac・公開URL）")
    L.append("")
    fw = facts["firewall"]
    L.append("- ファイアウォール: **%s**（ステルスモード %s）" % ("有効" if fw["enabled"] else "無効 ← 要対処",
                                                     "オン" if fw["stealth"] else "オフ"))
    wide = [l for l in facts["listeners"] if l["scope"] in ("all", "lan")]
    tail = [l for l in facts["listeners"] if l["scope"] == "tailscale"]
    loop = [l for l in facts["listeners"] if l["scope"] == "loopback"]
    L.append("- 待ち受け: 全インターフェース/LAN **%d 件**・Tailscale のみ %d 件・127.0.0.1 のみ %d 件" % (
        len(wide), len(tail), len(loop)))
    for l in wide:
        L.append("  - ⚠ `%s`（PID %s）が `%s` で待ち受け — LAN の他機器から届く可能性" % (l["process"], l["pid"], l["addr"]))
    L.append("- 公開URL（未認証でアクセスした結果）:")
    mark = {"open": "公開", "auth_required": "認証あり", "unreachable": "応答なし", "other": "その他"}
    for u in facts["urls"]:
        warn = ""
        if u["id"].startswith("old-") and u["verdict"] != "unreachable":
            warn = " ⚠ 解約済みのはずが応答"
        if "admin" in u["id"] and u["verdict"] == "open":
            warn = " ⚠ 管理画面が認証なしで開く"
        L.append("  - %s: HTTP %s → %s%s" % (u["url"], u["code"], mark.get(u["verdict"], u["verdict"]), warn))
    lp = [x for x in facts.get("lanProbe", []) if x["open"]]
    if lp:
        L.append("- ⚠ LAN 側の IP（%s）で待ち受けている遠隔管理・共有系ポート: **%s**（同じMacからの試験のためファイアウォールは通っていない。他機器から届くかは別途確認。システム設定 → 一般 → 共有）" % (
            lp[0]["ip"], ", ".join(str(x["port"]) for x in lp)))
    else:
        L.append("- LAN 側の遠隔管理・共有系ポート: すべて閉")
    if facts["secrets"]:
        L.append("- ⚠ 平文の鍵らしき文字列: **%d ファイル**（値は記録していない）" % len(facts["secrets"]))
        for h in facts["secrets"]:
            L.append("  - `%s`（%s）" % (h["file"], ", ".join(h["kinds"])))
    else:
        L.append("- 平文の鍵らしき文字列: 検出なし（対象は API キー形式と秘密鍵のみ。平文パスワードは検出できない）")
    ag = facts["agents"]
    L.append("- AIエージェント: ローカル MCP %s / claude を呼ぶ定期ジョブ %d 本（%s。別のスクリプトを挟む多段呼び出しは未計上）" % (
        ", ".join(ag["local_mcp_servers"]) or "なし", len(ag["claude_launchd_jobs"]), ", ".join(ag["claude_launchd_jobs"])))
    L.append("")

    L.append("## 2. 前回との差分")
    L.append("")
    d = os.path.join(out, "diff.md")
    if os.path.exists(d):
        with open(d, encoding="utf-8") as f:
            body = f.read().strip()
        # 見出しを 2 段下げて、このレポートの節の中に収める
        for line in body.splitlines():
            L.append("##" + line if line.startswith("#") else line)
    else:
        L.append("初回のため差分はありません。次回の実行から、増えた入口・消えた入口がここに出ます。")
    L.append("")

    L.append("---")
    L.append("")
    L.append("以下は補助の情報です。CyberRiskScape の脅威ルールは、構成要素の**種類**から一般的に想定される脅威を並べます。"
             "このMacで確かめた問題ではないため、件数の多さは危険度を表しません。上の 1・2 節を優先してください。")
    L.append("")
    L.append("## 3. 参考: IPA 注意喚起 17 項目（CyberRiskScape の判定）")
    L.append("")
    L.append("集計: %s" % summary)
    L.append("")
    L.append("| 項目 | 状態 | 要対応の脅威 | 未入力 |")
    L.append("|---|---|---|---|")
    for it in items:
        L.append("| %s %s | %s | %s | %s |" % (it.get("項目 No"), it.get("項目"), it.get("状態"),
                                          it.get("要対応（脅威検出数）"), it.get("未入力（脅威検出数）")))
    L.append("")
    L.append("「未入力」は台帳か実測で値が埋まっていない属性です。分からない値をもっともらしく埋めることはしていません。")
    L.append("「問題なし」「対象なし」は、該当する要素を図に描いていないだけの場合があります（例: ipa-09 は委託先、ipa-13 はシャドー IT を台帳に載せていない）。実測で確かめた結果ではありません。")
    L.append("")

    L.append("## 4. 参考: 重大度 High 以上で、まだ対応方針が決まっていない脅威（対象ごと・一般論）")
    L.append("")
    by = collections.OrderedDict()
    for t in threats:
        if t.get("effectiveSeverity", t.get("severity")) in ("Critical", "High") and t.get("status") in ("", "未対応", None):
            by.setdefault(t["asset"], []).append(t["name"])
    # 同じ脅威の組み合わせを持つ対象はまとめる（定期ジョブ・コネクタ・ログイン線などが並ぶため）
    groups = collections.OrderedDict()
    for asset, names in by.items():
        groups.setdefault(tuple(sorted(set(names))), []).append(asset)
    for names, assets in groups.items():
        who = assets[0] if len(assets) == 1 else "%s ほか計 %d 件" % (assets[0], len(assets))
        L.append("- **%s**: %s" % (who, " / ".join(names)))
        if len(assets) > 1:
            L.append("  - 対象: %s" % "、".join(a.split(" ", 1)[-1] if a.startswith("C") else a for a in assets))
    L.append("")

    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
