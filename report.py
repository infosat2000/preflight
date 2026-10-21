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


def threat_lines(facts, L, T):
    """1.2.0 で足した実測（居座り・偽装・開くだけで動く仕掛け・AI ツールの鍵と版・拡張機能）の要約。値や行の中身は出さない。"""
    a = facts.get("autostart")
    if a is not None:
        flagged = [x for x in a.get("items", []) if set(x.get("flags", [])) - {"claudeJob", "disabled", "pkg", "apple", "missing", "oclp"}]
        L.append(T("- 自動で起動するもの: plist %d 件・アプリ内の部品 %d 件（印の付いたもの %d 件。ログイン項目の一覧そのものは sudo なしでは読めない）",
                   "- Things that start on their own: %d plists, %d helpers inside apps (%d flagged; the login items list itself can't be read without sudo)") % (
            a.get("total", 0), a.get("bundled", 0), len(flagged)))
        for x in flagged:
            L.append("  - `%s` → `%s`: %s / %s" % (x["label"], x.get("program", ""), ", ".join(x["flags"]), (x.get("sign") or {}).get("kind") or "-"))
    d = facts.get("disguise")
    if d is not None:
        L.append(T("- 偽装・痕跡（照らした一覧: %s 時点）: 名乗りと署名が合わない %d 件・既知の痕跡 %d 件・一時置き場から動く %d 件・改ざんされたウォレット %d 件",
                   "- Disguise and traces (list as of %s): name/signature mismatch %d, known traces %d, running from temp %d, tampered wallets %d") % (
            d.get("iocUpdated") or "-", len(d.get("fakes", [])), len(d.get("ioc", [])), len(d.get("running", [])),
            len([w for w in d.get("wallets", []) if w.get("tampered")])))
        for x in d.get("fakes", []) + d.get("running", []):
            L.append("  - `%s`: %s / %s %s" % (x["file"], x.get("claim") or "-", (x.get("sign") or {}).get("kind") or "-", (x.get("sign") or {}).get("team") or ""))
        for x in d.get("ioc", []):
            L.append("  - `%s` (%s)" % (x["file"], x.get("source", "")))
    sh = facts.get("shell")
    if sh is not None:
        hits = ["%s:%d (%s)" % (f["file"], h["line"], ", ".join(h["kinds"])) for f in sh.get("files", []) for h in f.get("hits", [])]
        L.append(T("- シェルの起動ファイル: %s", "- Shell startup files: %s") % (", ".join(hits) or T("気になる行なし", "nothing suspicious")))
        for g in sh.get("git", []):
            L.append("  - git %s = `%s`: %s" % (g["setting"], g["dir"], ", ".join(g.get("hooks", [])) or "-"))
    o = facts.get("openToRun")
    if o is not None:
        L.append(T("- 開くだけで動く仕掛け: Claude のフック %d 件・folderOpen のタスク %d 件・ワームのファイル名 %d 件・見えない文字 %d 件（~/.claude の全体フック %d 個は数えるだけ）",
                   "- Open-to-run: Claude hooks %d, folderOpen tasks %d, worm file names %d, hidden characters %d (%d global hooks in ~/.claude only counted)") % (
            len(o.get("hooks", [])), len(o.get("tasks", [])), len(o.get("ioc", [])), len(o.get("hidden", [])), o.get("globalHooks", 0)))
    k = facts.get("aiKeys")
    if k:
        L.append(T("- AI ツールの鍵と版: 鍵のファイル %d 個・MCP %d 個（平文の鍵あり %d・http %d・版を固定しない %d）・%s",
                   "- AI tool keys and versions: key files %d, MCP servers %d (plain keys %d, http %d, unpinned %d), %s") % (
            len(k.get("credFiles", [])), len(k.get("mcp", [])), len([m for m in k.get("mcp", []) if m.get("secretValues")]),
            len([m for m in k.get("mcp", []) if m.get("insecureUrl")]), len([m for m in k.get("mcp", []) if m.get("unpinned")]),
            ", ".join("%s %s%s" % (c["name"], c["version"], T("（%s 未満 %s）" % (c["fixed"], c["cve"]), " (< %s %s)" % (c["fixed"], c["cve"])) if c.get("old") else "")
                      for c in k.get("cli", [])) or "-"))
    e = facts.get("extensions")
    if e:
        L.append(T("- ブラウザの拡張機能: %d 個（ストア外 %d・既知の悪いもの %d）", "- Browser extensions: %d (off-store %d, known bad %d)") % (
            e.get("total", 0), len([x for x in e.get("items", []) if not x.get("store")]), len([x for x in e.get("items", []) if x.get("bad")])))


def build(out, lang):
    J = lang == "ja"

    def T(ja, en):
        return ja if J else en

    def proc(name):
        # 名前が分からないものは、collect.py が日本語の印を入れている
        if not J and name.startswith("（root"):
            return "(root-owned, name unknown)"
        if not J and name.startswith("（"):
            return "(unknown name)"
        return name

    with open(os.path.join(out, "facts.json"), encoding="utf-8") as f:
        facts = json.load(f)
    # 評価エンジン（CyberRiskScape）は入れなくても動く。入れていなければ 3・4 節を出さない
    engine = os.path.exists(os.path.join(out, "threats.json")) and os.path.exists(os.path.join(out, "ipa-checklist.csv"))
    threats, items, summary = [], [], ""
    if engine:
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
    L.append(T("BB Preflight（FOREST LIFE*）v%s で作成", "Made with BB Preflight by FOREST LIFE* v%s") % version())
    L.append("")
    if not J and engine:
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
                   "  - ⚠ `%s` (PID %s) listens on `%s` — other devices on the LAN may reach it") % (proc(l["process"]), l["pid"], l["addr"]))
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
    n = facts.get("npm")
    if n and n.get("used"):
        g = n.get("guard")
        L.append(T("- npm: ignore-scripts %s / supply-chain-guard %s",
                   "- npm: ignore-scripts %s / supply-chain-guard %s") % (
            {True: "true", False: "false"}.get(n.get("ignoreScripts"), T("不明", "unknown")),
            T("未導入", "not installed") if not g else T("最後の走査 %s・未確認 重大 %d 件・注意 %d 件%s",
                                                     "last scan %s, unchecked: %d serious, %d to check%s") % (
                g.get("lastScanAt", "").replace("T", " ") or "-", g.get("high", 0), g.get("medium", 0),
                T("・日次が止まっている", ", daily scan stopped") if g.get("stale") else "")))
        if n.get("version"):
            L.append(T("  - npm の版: %s（12 以上は install スクリプトが標準で止まる: %s）", "  - npm version: %s (12+ blocks install scripts by default: %s)") % (
                n["version"], T("はい", "yes") if n.get("scriptsOffByDefault") else T("いいえ", "no")))
    threat_lines(facts, L, T)
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
    elif previous_changes(out):
        ch = previous_changes(out)
        for key, label in (("better", T("良くなったこと", "Better")), ("worse", T("悪くなったこと", "Worse"))):
            if ch[key]:
                L.append("### " + label)
                L.extend("- " + x[lang] for x in ch[key])
                L.append("")
        if not (ch["better"] or ch["worse"]):
            L.append(T("前回から変わったことはありません。", "Nothing changed since the last run."))
    else:
        L.append(T("初回のため差分はありません。次回の実行から、増えた入口・消えた入口がここに出ます。",
                   "This is the first run, so there is no diff yet. From the next run, new and removed entry points appear here."))
    L.append("")

    if not engine:
        L.append(T("IPA 注意喚起 17 項目の判定と、構成要素ごとの脅威の一覧は、評価エンジンを入れたときだけ出ます"
                   "（`./setup.sh --with-engine`。Node.js と npm が必要です）。",
                   "The IPA 17-item verdict and the per-component threat list appear only when the evaluation engine is installed "
                   "(`./setup.sh --with-engine`; needs Node.js and npm)."))
        L.append("")
        return "\n".join(L) + "\n"

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


def previous_changes(out):
    """評価エンジンの diff.md がないときの差分。前回の facts.json と比べる。"""
    import easy_report
    prev = easy_report.previous_facts(out)
    if not prev:
        return None
    with open(os.path.join(out, "facts.json"), encoding="utf-8") as f:
        return easy_report.changes(prev, json.load(f))


def main():
    out = sys.argv[1]
    for lang, name in (("ja", "report.md"), ("en", "report.en.md")):
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(build(out, lang))


if __name__ == "__main__":
    main()
