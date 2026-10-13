#!/usr/bin/env python3
"""out/<日時>/facts.json を、Mac に詳しくない人でも読める1枚の HTML（report.html）にする。

判定は決まったルールだけで行い、AI や外部には何も送らない。
見た目は report_page.html（外部の読み込みなし）で、ここではその中にデータを埋め込むだけ。
専門的な一覧（report.md）は「詳しい情報」として末尾に折りたたんで入れる。
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RED, YELLOW, GREEN = "red", "yellow", "green"

# 点検する6つの項目（画面のチェックリストの並び）
CHECKS = [
    ("fw", "ファイアウォール"),
    ("ports", "遠隔操作・共有の入口"),
    ("apps", "外から届くアプリ"),
    ("sites", "公開しているサイト"),
    ("keys", "API キーなどの鍵"),
    ("ai", "AI の自動実行"),
]

# 遠隔操作・共有系のポート。名前・何が困るか・直し方
PORTS = {
    22: ("リモートログイン（SSH）", "同じネットワークにいる人が、パスワードを当てればこのMacを遠隔で操作できます。",
         "システム設定 → 一般 → 共有 → 「リモートログイン」をオフ"),
    3283: ("リモートマネージメント", "同じネットワークの人が、このMacを遠隔で管理できる入口です。",
           "システム設定 → 一般 → 共有 → 「リモートマネージメント」をオフ"),
    5900: ("画面共有", "同じネットワークの人が、このMacの画面を見たり操作したりできる入口です。",
           "システム設定 → 一般 → 共有 → 「画面共有」をオフ"),
    445: ("ファイル共有", "同じネットワークの人が、このMacのファイルを読みに来られる入口です。",
          "システム設定 → 一般 → 共有 → 「ファイル共有」をオフ"),
    548: ("ファイル共有（古い方式）", "同じネットワークの人が、このMacのファイルを読みに来られる入口です。",
          "システム設定 → 一般 → 共有 → 「ファイル共有」をオフ"),
    88: ("共有機能の認証（Kerberos）", "ファイル共有や画面共有に付いてくる入口です。",
         "システム設定 → 一般 → 共有 → 「ファイル共有」「画面共有」をオフにすると閉じます"),
    631: ("プリンタ共有", "同じネットワークの人が、このMacにつないだプリンタを使える入口です。",
          "システム設定 → 一般 → 共有 → 「プリンタ共有」をオフ"),
}

# 外から届く状態で待ち受けていても普通な、Apple 純正の部品
NORMAL_APPS = {
    "rapportd": "AirDrop・Handoff など Apple 製品どうしの連携",
    "ControlCe": "AirPlay の受信",
    "ControlCenter": "AirPlay の受信",
    "sharingd": "AirDrop などの共有機能",
    "mDNSResponder": "ネットワーク上の機器を見つける仕組み",
    "identityservicesd": "iMessage・FaceTime の連携",
    "remoted": "Apple 製品どうしの連携",
}

SECRET_KINDS = {
    "anthropic": "Anthropic（Claude）の API キー",
    "github": "GitHub のトークン",
    "stripe_live": "Stripe の本番キー",
    "aws": "AWS のアクセスキー",
    "groq": "Groq の API キー",
    "private_key": "秘密鍵",
}


def finding(cat, level, title, what, why, how):
    return {"cat": cat, "level": level, "title": title, "what": what, "why": why, "how": how}


def wide_listeners(facts):
    """LAN の他の機器から届きうる待ち受けを、アプリごとにまとめる。"""
    apps = {}
    for l in facts.get("listeners", []):
        if l.get("scope") in ("all", "lan"):
            apps.setdefault(l.get("process") or "（名前不明）", set()).add(l.get("port"))
    return apps


def open_admin_ports(facts):
    return sorted({x["port"] for x in facts.get("lanProbe", []) if x.get("open")})


def port_info(p):
    return PORTS.get(p, ("番号 %s の入口" % p, "同じネットワークの人がつながれる入口です。",
                         "システム設定 → 一般 → 共有 で、使っていない共有をオフ"))


def analyze(facts):
    """facts から、やること（赤・黄）と、確認できて問題なかったこと（緑）を作る。

    戻り値: (todo, ok)。ok は {"cat", "text"} の並び。
    """
    todo, ok = [], []

    def good(cat, text):
        ok.append({"cat": cat, "text": text})

    if facts.get("firewall", {}).get("enabled"):
        good("fw", "ファイアウォール（外から勝手につながれるのを防ぐ壁）は有効です。")
    else:
        todo.append(finding(
            "fw", RED, "ファイアウォールが切れています",
            "外から勝手につながれるのを防ぐ、Mac に最初から入っている壁がオフになっています。",
            "同じ Wi-Fi にいる人（カフェ・ホテル・コワーキングなど）から、このMacの入口に直接つながれます。",
            "システム設定 → ネットワーク → ファイアウォール → オン"))

    ports = open_admin_ports(facts)
    for p in ports:
        name, why, how = port_info(p)
        todo.append(finding(
            "ports", RED, "%sが、同じネットワークから使える状態です" % name,
            "このMacの「%s」が、Wi-Fi や LAN の側からつながる状態で開いています。" % name,
            why + "使っていないなら閉じておくのが安全です。", how))
    if facts.get("lanProbe") and not ports:
        good("ports", "リモートログイン・画面共有・ファイル共有などの遠隔操作の入口は、すべて閉じています。")

    unknown, normal, nameless = [], [], 0
    for app, ps in sorted(wide_listeners(facts).items()):
        if ps <= set(PORTS):
            continue  # 遠隔操作の入口として上で扱う
        if app.startswith("（root"):
            nameless += len(ps)  # 権限なしでは名前が見えない。多くは macOS 自身
        elif app in NORMAL_APPS:
            normal.append("%s（%s）" % (app, NORMAL_APPS[app]))
        else:
            unknown.append(app)
    if unknown:
        todo.append(finding(
            "apps", YELLOW, "外からつながれる状態のアプリが %d 個あります" % len(unknown),
            "次のアプリが、同じネットワークの他の機器からつながる状態で待ち受けています: " + "、".join(unknown),
            "多くはスマホ連携などの便利機能で、すぐ危ないわけではありません。"
            "ただ、心当たりのないアプリや、ログインなしで動く自作のサーバーがあると、他人に使われるおそれがあります。",
            "心当たりのないものは、そのアプリの設定で「ネットワーク」「リモート」「スマホ連携」などをオフにします。"
            "自作のサーバーなら、待ち受け先を 127.0.0.1（このMacの中だけ）に変えます。"
            + ("ほかに、名前が見えない待ち受けが %d 件あります（多くは macOS 自身の部品です）。" % nameless if nameless else "")))
    elif "listeners" in facts:
        good("apps", "外からつながれる状態の、心当たりのないアプリはありませんでした。")
    inner = [l for l in facts.get("listeners", []) if l.get("scope") in ("loopback", "tailscale")]
    if inner:
        good("apps", "%d 件の待ち受けは、このMacの中か Tailscale の中だけに閉じています。" % len(inner))
    if normal:
        good("apps", "Apple の標準機能の待ち受けは普通の動きです: " + "、".join(normal))

    site_issue = False
    for u in facts.get("urls", []):
        uid, url, v = u.get("id", ""), u.get("url", ""), u.get("verdict")
        if "admin" in uid and v == "open":
            site_issue = True
            todo.append(finding(
                "sites", RED, "管理画面が、ログインなしで開きます",
                "%s が、ログインしていない状態でも開きました。" % url,
                "誰でも管理画面に入れると、サイトの書き換えやお客さまの情報の持ち出しができてしまいます。",
                "管理画面にパスワードと二段階認証をかけるか、Cloudflare Access などで自分だけが入れるようにします。"))
        elif uid.startswith("old-") and v != "unreachable":
            site_issue = True
            todo.append(finding(
                "sites", YELLOW, "やめたはずのサイトが、まだ応答しています",
                "%s は使っていないはずですが、アクセスすると応答がありました。" % url,
                "放っておいた古いサイトは更新されず、乗っ取りや偽サイトの入口になりやすいです。",
                "サーバーやドメインの管理画面で、そのサイトを止めるか削除します。"))
        elif "admin" in uid and v == "auth_required":
            good("sites", "%s は、ログインしないと開けません。" % url)
        elif uid.startswith("old-"):
            good("sites", "やめたサイト %s は、もう応答しません。" % url)
    if facts.get("urls") and not site_issue and not any(o["cat"] == "sites" for o in ok):
        good("sites", "登録した公開サイトに、気になる応答はありませんでした。")

    secrets = facts.get("secrets", [])
    if secrets:
        kinds = sorted({SECRET_KINDS.get(k, k) for h in secrets for k in h.get("kinds", [])})
        files = [h["file"] for h in secrets]
        todo.append(finding(
            "keys", RED, "大事な鍵（API キーなど）が、ふつうのファイルに書かれています",
            "%s が、次のファイルにそのまま書かれています: %s（鍵の中身はこのレポートに書いていません）" % (
                "、".join(kinds), "、".join(files)),
            "ファイルがうっかり共有・公開されたり、AI ツールに読まれたりすると、他人に鍵を使われて料金を請求されることがあります。",
            "使っていない鍵は、そのサービスの管理画面で無効にします。使う鍵はパスワード管理アプリやキーチェーンに移し、ファイルからは消します。"))
    else:
        good("keys", "API キーなどの鍵が、調べた範囲のファイルにそのまま書かれてはいませんでした。")

    jobs = facts.get("agents", {}).get("claude_launchd_jobs", [])
    if jobs:
        todo.append(finding(
            "ai", YELLOW, "AI が自動で動く仕組みが %d 個あります" % len(jobs),
            "決まった時刻などに Claude を呼び出す仕組みが登録されています: " + "、".join(jobs),
            "自分で作ったものなら問題ありません。覚えのないものは、知らないうちに AI がファイルを読んだり外へ送ったりしているかもしれません。",
            "覚えのないものがあれば、~/Library/LaunchAgents の中の同じ名前のファイルを確かめ、不要なら止めます。"))
    else:
        good("ai", "AI を自動で呼び出す仕組みは、見つかりませんでした。")

    order = {RED: 0, YELLOW: 1}
    todo.sort(key=lambda f: order[f["level"]])
    return todo, ok


def checks(todo):
    """6つの項目それぞれの信号（いちばん悪いもの）。"""
    res = []
    for cat, label in CHECKS:
        levels = {f["level"] for f in todo if f["cat"] == cat}
        res.append({"cat": cat, "label": label,
                    "level": RED if RED in levels else YELLOW if YELLOW in levels else GREEN})
    return res


def previous_facts(out):
    """同じフォルダの並びで、今回より前の最新の facts.json を読む。"""
    here = os.path.basename(os.path.normpath(out))
    parent = os.path.dirname(os.path.normpath(out))
    prev = sorted(d for d in glob.glob(os.path.join(parent, "*", "facts.json"))
                  if os.path.basename(os.path.dirname(d)) < here)
    if not prev:
        return None
    with open(prev[-1], encoding="utf-8") as f:
        return json.load(f)


def changes(prev, cur):
    """前回と今回を、ふつうの言葉で比べる。"""
    better, worse = [], []
    a, b = prev.get("firewall", {}).get("enabled"), cur.get("firewall", {}).get("enabled")
    if a != b:
        (better if b else worse).append("ファイアウォールが" + ("オンになりました" if b else "オフになりました"))
    a, b = set(open_admin_ports(prev)), set(open_admin_ports(cur))
    better += ["%sが閉じました" % port_info(p)[0] for p in sorted(a - b)]
    worse += ["%sが開きました" % port_info(p)[0] for p in sorted(b - a)]
    a, b = set(wide_listeners(prev)), set(wide_listeners(cur))
    better += ["%s が外から届かなくなりました" % x for x in sorted(a - b)]
    worse += ["%s が外から届く状態になりました" % x for x in sorted(b - a)]
    a = {h["file"] for h in prev.get("secrets", [])}
    b = {h["file"] for h in cur.get("secrets", [])}
    better += ["鍵が書かれたファイルが片付きました: %s" % x for x in sorted(a - b)]
    worse += ["鍵が書かれたファイルが増えました: %s" % x for x in sorted(b - a)]
    return {"better": better, "worse": worse}


def build_data(facts, prev=None, detail=""):
    todo, ok = analyze(facts)
    reds = sum(1 for f in todo if f["level"] == RED)
    return {
        "measuredAt": facts.get("measuredAt", "").replace("T", " "),
        "verdict": RED if reds else YELLOW if todo else GREEN,
        "counts": {"red": reds, "yellow": len(todo) - reds, "ok": len(ok)},
        "checks": checks(todo),
        "todo": todo,
        "ok": [o["text"] for o in ok],
        "diff": changes(prev, facts) if prev else None,
        "detail": detail,
    }


def page(data, standalone=True):
    """report_page.html にデータを埋め込む。standalone なら html/head/body で包む。"""
    with open(os.path.join(HERE, "report_page.html"), encoding="utf-8") as f:
        tpl = f.read()
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    body = tpl.replace("__PREFLIGHT_DATA__", blob)
    if not standalone:
        return body
    return ('<!doctype html>\n<html lang="ja"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            "</head><body>\n%s\n</body></html>\n" % body)


def main():
    out = sys.argv[1]
    with open(os.path.join(out, "facts.json"), encoding="utf-8") as f:
        facts = json.load(f)
    detail = ""
    md = os.path.join(out, "report.md")
    if os.path.exists(md):
        with open(md, encoding="utf-8") as f:
            detail = f.read()
    data = build_data(facts, previous_facts(out), detail)
    with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f:
        f.write(page(data))


if __name__ == "__main__":
    main()
