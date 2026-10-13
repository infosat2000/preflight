#!/usr/bin/env python3
"""out/<日時>/ の実測結果と CyberRiskScape の評価を、1枚レポートにまとめる。

日本語の report.md と、英語の report.en.md を書く。
CyberRiskScape が出す脅威名・IPA 項目名・差分（diff.md）は本家の日本語のまま載せる。
"""
import collections
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def version():
    """このツールの版。VERSION ファイルが唯一の置き場所。"""
    with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
        return f.read().strip()


def build(out, lang):
    J = lang == "ja"

    def T(ja, en):
        return ja if J else en

    with open(os.path.join(out, "facts.json"), encoding="utf-8") as f:
        facts = json.load(f)
    with open(os.path.join(out, "threats.json"), encoding="utf-8") as f:
        threats = json.load(f)[0]["threats"]
    with open(os.path.join(out, "ipa-checklist.csv"), encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    summary = next((r[1] for r in rows if r and r[0] == "集計"), "")
    head = next(i for i, r in enumerate(rows) if r and r[0] == "グループ")
    items = [dict(zip(rows[head], r)) for r in rows[head + 1:] if len(r) > 3]
    sep = "、" if J else ", "

    L = []
    L.append(T("# 実測点検レポート（%s）", "# Measured check report (%s)") % facts["measuredAt"].replace("T", " "))
    L.append(T("Blackbox Blast Preflight v%s で作成", "Made with Blackbox Blast Preflight v%s") % version())
    L.append("")
    if not J:
        L.append("Names that come from the evaluation engine (threats, IPA checklist items, the diff) are kept in the original Japanese.")
        L.append("")
    L.append(T("## 1. 実測でしか分からないこと（このMac・公開URL）", "## 1. What only measurement can tell (this Mac, public URLs)"))
    L.append("")
    fw = facts["firewall"]
    L.append(T("- ファイアウォール: **%s**（ステルスモード %s）", "- Firewall: **%s** (stealth mode %s)") % (
        T("有効", "on") if fw["enabled"] else T("無効 ← 要対処", "off ← fix this"),
        T("オン", "on") if fw["stealth"] else T("オフ", "off")))
    wide = [l for l in facts["listeners"] if l["scope"] in ("all", "lan")]
    tail = [l for l in facts["listeners"] if l["scope"] == "tailscale"]
    loop = [l for l in facts["listeners"] if l["scope"] == "loopback"]
    L.append(T("- 待ち受け: 全インターフェース/LAN **%d 件**・Tailscale のみ %d 件・127.0.0.1 のみ %d 件",
               "- Listening: all interfaces/LAN **%d**, Tailscale only %d, 127.0.0.1 only %d") % (len(wide), len(tail), len(loop)))
    for l in wide:
        L.append(T("  - ⚠ `%s`（PID %s）が `%s` で待ち受け — LAN の他機器から届く可能性",
                   "  - ⚠ `%s` (PID %s) listens on `%s` — other devices on the LAN may reach it") % (l["process"], l["pid"], l["addr"]))
    L.append(T("- 公開URL（未認証でアクセスした結果）:", "- Public URLs (result of an unauthenticated request):"))
    mark = {"open": T("公開", "open"), "auth_required": T("認証あり", "login required"),
            "unreachable": T("応答なし", "no response"), "other": T("その他", "other")}
    for u in facts["urls"]:
        warn = ""
        if u["id"].startswith("old-") and u["verdict"] != "unreachable":
            warn = T(" ⚠ 解約済みのはずが応答", " ⚠ retired but still answers")
        if "admin" in u["id"] and u["verdict"] == "open":
            warn = T(" ⚠ 管理画面が認証なしで開く", " ⚠ admin page opens without login")
        L.append("  - %s: HTTP %s → %s%s" % (u["url"], u["code"], mark.get(u["verdict"], u["verdict"]), warn))
    lp = [x for x in facts.get("lanProbe", []) if x["open"]]
    if lp:
        L.append(T("- ⚠ LAN 側の IP（%s）で待ち受けている遠隔管理・共有系ポート: **%s**（同じMacからの試験のためファイアウォールは通っていない。他機器から届くかは別途確認。システム設定 → 一般 → 共有）",
                   "- ⚠ Remote-admin/sharing ports listening on the LAN IP (%s): **%s** (tested from this Mac, so the firewall was not in the path; check separately whether other devices can reach them. System Settings → General → Sharing)") % (
            lp[0]["ip"], ", ".join(str(x["port"]) for x in lp)))
    else:
        L.append(T("- LAN 側の遠隔管理・共有系ポート: すべて閉", "- Remote-admin/sharing ports on the LAN side: all closed"))
    if facts["secrets"]:
        L.append(T("- ⚠ 平文の鍵らしき文字列: **%d ファイル**（値は記録していない）",
                   "- ⚠ Strings that look like plain-text keys: **%d files** (values not recorded)") % len(facts["secrets"]))
        for h in facts["secrets"]:
            L.append(T("  - `%s`（%s）", "  - `%s` (%s)") % (h["file"], ", ".join(h["kinds"])))
    else:
        L.append(T("- 平文の鍵らしき文字列: 検出なし（対象は API キー形式と秘密鍵のみ。平文パスワードは検出できない）",
                   "- Plain-text keys: none found (only API-key formats and private keys are detected; plain passwords are not)"))
    ag = facts["agents"]
    none = T("なし", "none")
    L.append(T("- AIエージェント: ローカル MCP %s / claude を呼ぶ定期ジョブ %d 本（%s。別のスクリプトを挟む多段呼び出しは未計上）",
               "- AI agents: local MCP %s / scheduled jobs that call claude: %d (%s; calls through another script are not counted)") % (
        ", ".join(ag["local_mcp_servers"]) or none, len(ag["claude_launchd_jobs"]), ", ".join(ag["claude_launchd_jobs"]) or none))
    L.append("")

    L.append(T("## 2. 前回との差分", "## 2. Changes since the last run"))
    L.append("")
    d = os.path.join(out, "diff.md")
    if os.path.exists(d):
        with open(d, encoding="utf-8") as f:
            body = f.read().strip()
        # 見出しを 2 段下げて、このレポートの節の中に収める
        for line in body.splitlines():
            L.append("##" + line if line.startswith("#") else line)
    else:
        L.append(T("初回のため差分はありません。次回の実行から、増えた入口・消えた入口がここに出ます。",
                   "This is the first run, so there is no diff yet. From the next run, new and removed entry points appear here."))
    L.append("")

    L.append("---")
    L.append("")
    L.append(T("以下は補助の情報です。評価エンジンの脅威ルールは、構成要素の**種類**から一般的に想定される脅威を並べます。"
               "このMacで確かめた問題ではないため、件数の多さは危険度を表しません。上の 1・2 節を優先してください。",
               "What follows is supporting information. The evaluation engine's threat rules list threats generally expected for each **kind** of component. "
               "They were not confirmed on this Mac, so a high count does not mean high risk. Give sections 1 and 2 priority."))
    L.append("")
    L.append(T("## 3. 参考: IPA 注意喚起 17 項目（評価エンジンの判定）", "## 3. Reference: IPA alert, 17 items (evaluation engine's verdict)"))
    L.append("")
    L.append(T("集計: %s", "Summary: %s") % summary)
    L.append("")
    L.append(T("| 項目 | 状態 | 要対応の脅威 | 未入力 |", "| Item | Status | Threats to handle | Not entered |"))
    L.append("|---|---|---|---|")
    for it in items:
        L.append("| %s %s | %s | %s | %s |" % (it.get("項目 No"), it.get("項目"), it.get("状態"),
                                          it.get("要対応（脅威検出数）"), it.get("未入力（脅威検出数）")))
    L.append("")
    L.append(T("「未入力」は台帳か実測で値が埋まっていない属性です。分からない値をもっともらしく埋めることはしていません。",
               "\"Not entered\" means an attribute that neither the inventory nor the measurement filled in. Unknown values are never guessed."))
    L.append(T("「問題なし」「対象なし」は、該当する要素を図に描いていないだけの場合があります（例: ipa-09 は委託先、ipa-13 はシャドー IT を台帳に載せていない）。実測で確かめた結果ではありません。",
               "\"No issue\" or \"not applicable\" can simply mean the element is not in the diagram (e.g. ipa-09 needs contractors and ipa-13 needs shadow IT in the inventory). It is not a measured result."))
    L.append("")

    L.append(T("## 4. 参考: 重大度 High 以上で、まだ対応方針が決まっていない脅威（対象ごと・一般論）",
               "## 4. Reference: High or Critical threats with no decision yet (per component, general)"))
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
        who = assets[0] if len(assets) == 1 else T("%s ほか計 %d 件", "%s and %d in total") % (assets[0], len(assets))
        L.append("- **%s**: %s" % (who, " / ".join(names)))
        if len(assets) > 1:
            L.append(T("  - 対象: %s", "  - Components: %s") % sep.join(a.split(" ", 1)[-1] if a.startswith("C") else a for a in assets))
    L.append("")
    return "\n".join(L) + "\n"


def main():
    out = sys.argv[1]
    for lang, name in (("ja", "report.md"), ("en", "report.en.md")):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(build(out, lang))


if __name__ == "__main__":
    main()
