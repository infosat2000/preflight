#!/usr/bin/env python3
"""out/<日時>/facts.json を、Mac に詳しくない人でも読める1枚の HTML（report.html）にする。

判定は決まったルールだけで行い、AI や外部には何も送らない。
見た目は report_page.html（外部の読み込みなし）で、ここではその中にデータを埋め込むだけ。
専門的な一覧（report.md）は「詳しい情報」として末尾に折りたたんで入れる。
画面に出す文はすべて {"ja": ..., "en": ...} の形で持ち、ページ側で言語を切り替える。
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RED, YELLOW, GREEN = "red", "yellow", "green"


def t(ja, en):
    """日本語と英語の対になった文。"""
    return {"ja": ja, "en": en}


def same(s):
    """ファイル名やアプリ名など、どちらの言語でも同じ文字列。"""
    return t(s, s)


def join(items):
    """t() の並びを、日本語は「、」、英語は「, 」でつなぐ。"""
    return t("、".join(x["ja"] for x in items), ", ".join(x["en"] for x in items))


def cat_text(*parts):
    """t() と ふつうの文字列を、言語ごとにつなげる。"""
    ja, en = [], []
    for p in parts:
        if isinstance(p, dict):
            ja.append(p["ja"])
            en.append(p["en"])
        else:
            ja.append(p)
            en.append(p)
    return t("".join(ja), "".join(en))


# 点検する6つの項目（画面のチェックリストの並び）
CHECKS = [
    ("fw", t("ファイアウォール", "Firewall")),
    ("ports", t("遠隔操作・共有の入口", "Remote access and sharing")),
    ("apps", t("外から届くアプリ", "Apps reachable from outside")),
    ("sites", t("公開しているサイト", "Your public websites")),
    ("keys", t("API キーなどの鍵", "API keys and other secrets")),
    ("ai", t("AI の自動実行", "AI running on its own")),
]

_SHARING_JA = "システム設定 → 一般 → 共有 → "
_SHARING_EN = "System Settings → General → Sharing → "

# 遠隔操作・共有系のポート。名前・何が困るか・直し方
PORTS = {
    22: (t("リモートログイン（SSH）", "Remote Login (SSH)"),
         t("同じネットワークにいる人が、パスワードを当てればこのMacを遠隔で操作できます。",
           "Someone on the same network could control this Mac from afar if they guess your password."),
         t(_SHARING_JA + "「リモートログイン」をオフ", _SHARING_EN + "turn off Remote Login")),
    3283: (t("リモートマネージメント", "Remote Management"),
           t("同じネットワークの人が、このMacを遠隔で管理できる入口です。",
             "It lets people on the same network manage this Mac from afar."),
           t(_SHARING_JA + "「リモートマネージメント」をオフ", _SHARING_EN + "turn off Remote Management")),
    5900: (t("画面共有", "Screen Sharing"),
           t("同じネットワークの人が、このMacの画面を見たり操作したりできる入口です。",
             "It lets people on the same network see and control this Mac's screen."),
           t(_SHARING_JA + "「画面共有」をオフ", _SHARING_EN + "turn off Screen Sharing")),
    445: (t("ファイル共有", "File Sharing"),
          t("同じネットワークの人が、このMacのファイルを読みに来られる入口です。",
            "It lets people on the same network read files on this Mac."),
          t(_SHARING_JA + "「ファイル共有」をオフ", _SHARING_EN + "turn off File Sharing")),
    548: (t("ファイル共有（古い方式）", "File Sharing (old method)"),
          t("同じネットワークの人が、このMacのファイルを読みに来られる入口です。",
            "It lets people on the same network read files on this Mac."),
          t(_SHARING_JA + "「ファイル共有」をオフ", _SHARING_EN + "turn off File Sharing")),
    88: (t("共有機能の認証（Kerberos）", "Sign-in for sharing (Kerberos)"),
         t("ファイル共有や画面共有に付いてくる入口です。",
           "It comes with File Sharing and Screen Sharing."),
         t(_SHARING_JA + "「ファイル共有」「画面共有」をオフにすると閉じます",
           _SHARING_EN + "turn off File Sharing and Screen Sharing to close it")),
    631: (t("プリンタ共有", "Printer Sharing"),
          t("同じネットワークの人が、このMacにつないだプリンタを使える入口です。",
            "It lets people on the same network use the printer connected to this Mac."),
          t(_SHARING_JA + "「プリンタ共有」をオフ", _SHARING_EN + "turn off Printer Sharing")),
}

# 外から届く状態で待ち受けていても普通な、Apple 純正の部品
NORMAL_APPS = {
    "rapportd": t("AirDrop・Handoff など Apple 製品どうしの連携",
                  "lets your Apple devices work together, like AirDrop and Handoff"),
    "ControlCe": t("AirPlay の受信", "receives AirPlay"),
    "ControlCenter": t("AirPlay の受信", "receives AirPlay"),
    "sharingd": t("AirDrop などの共有機能", "sharing features like AirDrop"),
    "mDNSResponder": t("ネットワーク上の機器を見つける仕組み", "finds other devices on the network"),
    "identityservicesd": t("iMessage・FaceTime の連携", "connects iMessage and FaceTime"),
    "remoted": t("Apple 製品どうしの連携", "lets your Apple devices work together"),
}

SECRET_KINDS = {
    "anthropic": t("Anthropic（Claude）の API キー", "Anthropic (Claude) API key"),
    "github": t("GitHub のトークン", "GitHub token"),
    "stripe_live": t("Stripe の本番キー", "Stripe live key"),
    "aws": t("AWS のアクセスキー", "AWS access key"),
    "groq": t("Groq の API キー", "Groq API key"),
    "private_key": t("秘密鍵", "private key"),
}

UNKNOWN_APP = "（名前不明）"


def app_name(app):
    """アプリ名をそのまま両言語で。名前が分からないものだけ訳す。"""
    if app == UNKNOWN_APP:
        return t(UNKNOWN_APP, "(unknown name)")
    if app.startswith("（root"):
        return t(app, "(name hidden, owned by the system)")
    return same(app)


def key_kinds(hits):
    kinds = {k for h in hits for k in h.get("kinds", [])}
    return sorted((SECRET_KINDS.get(k) or same(k) for k in kinds), key=lambda x: x["ja"])


def why_loose(hits):
    if any(h.get("gitIgnored") is False for h in hits):
        return t("Git で管理しているフォルダにあり、GitHub などに上がるおそれがあります",
                 "It is in a folder tracked by Git, so it could end up on GitHub or similar sites")
    if any(h.get("private") is False for h in hits):
        return t("このMacのほかのユーザーやアプリからも読める設定です",
                 "Other users and apps on this Mac can read it")
    return t("パスワード管理アプリなどではなく、ふつうのファイルに置かれています",
             "It is kept in a plain file, not in a password manager")


def finding(cat, level, title, what, why, how):
    return {"cat": cat, "level": level, "title": title, "what": what, "why": why, "how": how}


def wide_listeners(facts):
    """LAN の他の機器から届きうる待ち受けを、アプリごとにまとめる。"""
    apps = {}
    for l in facts.get("listeners", []):
        if l.get("scope") in ("all", "lan"):
            apps.setdefault(l.get("process") or UNKNOWN_APP, set()).add(l.get("port"))
    return apps


def open_admin_ports(facts):
    return sorted({x["port"] for x in facts.get("lanProbe", []) if x.get("open")})


def port_info(p):
    return PORTS.get(p, (t("番号 %s の入口" % p, "Port %s" % p),
                         t("同じネットワークの人がつながれる入口です。",
                           "People on the same network can connect to it."),
                         t("システム設定 → 一般 → 共有 で、使っていない共有をオフ",
                           "System Settings → General → Sharing → turn off any sharing you don't use")))


def analyze(facts):
    """facts から、やること（赤・黄）と、確認できて問題なかったこと（緑）を作る。

    戻り値: (todo, ok)。ok は {"cat", "text"} の並び（text は {"ja", "en"}）。
    """
    todo, ok = [], []

    def good(cat, text):
        ok.append({"cat": cat, "text": text})

    if facts.get("firewall", {}).get("enabled"):
        good("fw", t("ファイアウォール（外から勝手につながれるのを防ぐ壁）は有効です。",
                     "The firewall (a wall that stops others from connecting without asking) is on."))
    else:
        todo.append(finding(
            "fw", RED, t("ファイアウォールが切れています", "The firewall is off"),
            t("外から勝手につながれるのを防ぐ、Mac に最初から入っている壁がオフになっています。",
              "Your Mac has a built-in wall that stops others from connecting without asking. It is turned off."),
            t("同じ Wi-Fi にいる人（カフェ・ホテル・コワーキングなど）から、このMacの入口に直接つながれます。",
              "People on the same Wi-Fi (at a cafe, hotel or shared office) can connect straight to this Mac."),
            t("システム設定 → ネットワーク → ファイアウォール → オン",
              "System Settings → Network → Firewall → turn it on")))

    ports = open_admin_ports(facts)
    for p in ports:
        name, why, how = port_info(p)
        todo.append(finding(
            "ports", RED,
            t("%sが、同じネットワークから使える状態です" % name["ja"],
              "%s can be used from your network" % name["en"]),
            t("このMacの「%s」が、Wi-Fi や LAN の側からつながる状態で開いています。" % name["ja"],
              "%s on this Mac is open, so others on your Wi-Fi or local network can connect to it." % name["en"]),
            t(why["ja"] + "使っていないなら閉じておくのが安全です。",
              why["en"] + " If you don't use it, it is safer to turn it off."),
            how))
    if facts.get("lanProbe") and not ports:
        good("ports", t("リモートログイン・画面共有・ファイル共有などの遠隔操作の入口は、すべて閉じています。",
                        "Remote Login, Screen Sharing, File Sharing and other ways in from afar are all closed."))

    unknown, normal, nameless = [], [], 0
    for app, ps in sorted(wide_listeners(facts).items()):
        if ps <= set(PORTS):
            continue  # 遠隔操作の入口として上で扱う
        if app.startswith("（root"):
            nameless += len(ps)  # 権限なしでは名前が見えない。多くは macOS 自身
        elif app in NORMAL_APPS:
            normal.append(t("%s（%s）" % (app, NORMAL_APPS[app]["ja"]),
                            "%s (%s)" % (app, NORMAL_APPS[app]["en"])))
        else:
            unknown.append(app_name(app))
    if unknown:
        extra = t("", "")
        if nameless:
            extra = t("ほかに、名前が見えない待ち受けが %d 件あります（多くは macOS 自身の部品です）。" % nameless,
                      " There %s also %d more whose name%s can't be seen (most are parts of macOS itself)." % (
                          "is" if nameless == 1 else "are", nameless, "" if nameless == 1 else "s"))
        todo.append(finding(
            "apps", YELLOW,
            t("外からつながれる状態のアプリが %d 個あります" % len(unknown),
              "%d app%s can be reached from outside" % (len(unknown), "" if len(unknown) == 1 else "s")),
            cat_text(t("次のアプリが、同じネットワークの他の機器からつながる状態で待ち受けています: ",
                       "These apps are waiting for connections from other devices on your network: "),
                     join(unknown)),
            t("多くはスマホ連携などの便利機能で、すぐ危ないわけではありません。"
              "ただ、心当たりのないアプリや、ログインなしで動く自作のサーバーがあると、他人に使われるおそれがあります。",
              "Most are handy features, like linking to your phone, and are not an urgent danger. "
              "But an app you don't recognize, or a server you built that needs no login, could be used by someone else."),
            cat_text(t("心当たりのないものは、そのアプリの設定で「ネットワーク」「リモート」「スマホ連携」などをオフにします。"
                       "自作のサーバーなら、待ち受け先を 127.0.0.1（このMacの中だけ）に変えます。",
                       "For any you don't recognize, open that app's settings and turn off options like "
                       "\"network\", \"remote\" or \"phone link\". "
                       "If it is a server you built, make it listen on 127.0.0.1 (this Mac only)."),
                     extra)))
    elif "listeners" in facts:
        good("apps", t("外からつながれる状態の、心当たりのないアプリはありませんでした。",
                       "No unfamiliar apps can be reached from outside."))
    inner = [l for l in facts.get("listeners", []) if l.get("scope") in ("loopback", "tailscale")]
    if inner:
        good("apps", t("%d 件の待ち受けは、このMacの中か Tailscale（自分の機器どうしだけをつなぐ VPN）の中だけに閉じています。" % len(inner),
                       "%d listening service%s stay%s inside this Mac or inside Tailscale "
                       "(a VPN that links only your own devices)." % (
                           len(inner), "" if len(inner) == 1 else "s", "s" if len(inner) == 1 else "")))
    if normal:
        good("apps", cat_text(t("Apple の標準機能の待ち受けは普通の動きです: ",
                                "These built-in Apple features are working normally: "), join(normal)))

    site_issue = False
    for u in facts.get("urls", []):
        uid, url, v = u.get("id", ""), u.get("url", ""), u.get("verdict")
        if "admin" in uid and v == "open":
            site_issue = True
            todo.append(finding(
                "sites", RED, t("管理画面が、ログインなしで開きます", "Your admin page opens without a login"),
                t("%s が、ログインしていない状態でも開きました。" % url,
                  "%s opened even without logging in." % url),
                t("誰でも管理画面に入れると、サイトの書き換えやお客さまの情報の持ち出しができてしまいます。",
                  "If anyone can get into the admin page, they can change your site or take your customers' information."),
                t("管理画面にパスワードと二段階認証をかけるか、Cloudflare Access などで自分だけが入れるようにします。",
                  "Protect the admin page with a password and two-step sign-in, "
                  "or use a service like Cloudflare Access so only you can get in.")))
        elif uid.startswith("old-") and v != "unreachable":
            site_issue = True
            todo.append(finding(
                "sites", YELLOW, t("やめたはずのサイトが、まだ応答しています", "A site you stopped using still responds"),
                t("%s は使っていないはずですが、アクセスすると応答がありました。" % url,
                  "%s should no longer be in use, but it still answers when visited." % url),
                t("放っておいた古いサイトは更新されず、乗っ取りや偽サイトの入口になりやすいです。",
                  "Old sites that are left alone don't get updates. They are easy to take over or turn into fake sites."),
                t("サーバーやドメインの管理画面で、そのサイトを止めるか削除します。",
                  "Stop or delete the site in your server or domain control panel.")))
        elif "admin" in uid and v == "auth_required":
            good("sites", t("%s は、ログインしないと開けません。" % url,
                            "%s can't be opened without logging in." % url))
        elif uid.startswith("old-"):
            good("sites", t("やめたサイト %s は、もう応答しません。" % url,
                            "The old site %s no longer responds." % url))
        elif v == "open":
            good("sites", t("%s は誰でも見られます（公開用のサイトなら正常です）。" % url,
                            "Anyone can see %s (this is fine for a public site)." % url))
    if facts.get("urls") and not site_issue and not any(o["cat"] == "sites" for o in ok):
        good("sites", t("登録した公開サイトに、気になる応答はありませんでした。",
                        "Your listed public sites showed nothing worrying."))

    secrets = facts.get("secrets", [])
    # .env 系で、本人しか読めず、Git に載らない置き方なら、開発ではふつう（確認だけ）。それ以外は赤
    tidy = [h for h in secrets if os.path.basename(h["file"]).startswith(".env")
            and h.get("private") and h.get("gitIgnored") is not False]
    loose = [h for h in secrets if h not in tidy]
    if loose:
        kinds, files, why = join(key_kinds(loose)), join([same(h["file"]) for h in loose]), why_loose(loose)
        todo.append(finding(
            "keys", RED,
            t("大事な鍵（API キーなど）が、人に見られやすい置き方になっています",
              "Important keys (like API keys) are stored where others could see them"),
            t("%s が、次のファイルにそのまま書かれています: %s。%s（鍵の中身はこのレポートに書いていません）" % (
                kinds["ja"], files["ja"], why["ja"]),
              "These files have keys written in plain text (%s): %s. %s. (This report does not show the keys themselves.)" % (
                kinds["en"], files["en"], why["en"])),
            t("ファイルがうっかり共有・公開されたり、GitHub に上がったり、AI ツールに読まれたりすると、他人に鍵を使われて料金を請求されることがあります。",
              "If the file is shared or published by mistake, pushed to GitHub, or read by an AI tool, "
              "someone else could use the key and you could be charged for it."),
            t("使っていない鍵は、そのサービスの管理画面で無効にします。使う鍵はパスワード管理アプリやキーチェーンに移し、ファイルからは消します。"
              "GitHub に上げたことがある鍵は、作り直してください。",
              "Turn off keys you don't use in that service's dashboard. Move keys you do use into a password manager "
              "or Keychain, and delete them from the file. "
              "If a key was ever pushed to GitHub, make a new one.")))
    if tidy:
        kinds, files = join(key_kinds(tidy)), join([same(h["file"]) for h in tidy])
        todo.append(finding(
            "keys", YELLOW,
            t("API キーが、設定ファイル（.env）に書かれています", "API keys are written in a settings file (.env)"),
            t("%s が、次のファイルに書かれています: %s。本人しか読めない設定で、Git にも載らないようになっています。" % (
                kinds["ja"], files["ja"]),
              "These files have keys written in them (%s): %s. Only you can read them, and Git is set to ignore them." % (
                kinds["en"], files["en"])),
            t("開発ではよくある置き方で、すぐ危ないわけではありません。ただ、ファイルごとコピーしたり、AI ツールにフォルダを読ませたりすると、鍵も一緒に渡ります。",
              "This is common when building software and is not an urgent danger. "
              "But if you copy the file or let an AI tool read the folder, the key goes along with it."),
            t("使っていない鍵は、そのサービスの管理画面で無効にします。大事な鍵は、パスワード管理アプリやキーチェーンに移すとより安全です。",
              "Turn off keys you don't use in that service's dashboard. "
              "Important keys are safer in a password manager or Keychain.")))
    if not secrets:
        good("keys", t("API キーなどの鍵が、調べた範囲のファイルにそのまま書かれてはいませんでした。",
                       "No API keys or other secrets were found written in plain text in the files we checked."))

    jobs = facts.get("agents", {}).get("claude_launchd_jobs", [])
    if jobs:
        todo.append(finding(
            "ai", YELLOW,
            t("AI が自動で動く仕組みが %d 個あります" % len(jobs),
              "%d automatic AI task%s found" % (len(jobs), " was" if len(jobs) == 1 else "s were")),
            cat_text(t("決まった時刻などに Claude を呼び出す仕組みが登録されています: ",
                       "These are set up to start Claude on their own, for example at set times: "),
                     join([same(j) for j in jobs])),
            t("自分で作ったものなら問題ありません。覚えのないものは、知らないうちに AI がファイルを読んだり外へ送ったりしているかもしれません。",
              "If you set them up yourself, that's fine. If you don't recognize one, an AI may be reading your files "
              "or sending them out without you knowing."),
            t("覚えのないものがあれば、~/Library/LaunchAgents の中の同じ名前のファイルを確かめ、不要なら止めます。",
              "If you don't recognize one, look for the file with the same name in ~/Library/LaunchAgents, "
              "and turn it off if you don't need it.")))
    else:
        good("ai", t("AI を自動で呼び出す仕組みは、見つかりませんでした。",
                     "Nothing was found that starts AI on its own."))

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
        (better if b else worse).append(
            t("ファイアウォールが" + ("オンになりました" if b else "オフになりました"),
              "The firewall was turned " + ("on" if b else "off")))
    a, b = set(open_admin_ports(prev)), set(open_admin_ports(cur))
    for p in sorted(a - b):
        n = port_info(p)[0]
        better.append(t("%sが閉じました" % n["ja"], "%s is now closed" % n["en"]))
    for p in sorted(b - a):
        n = port_info(p)[0]
        worse.append(t("%sが開きました" % n["ja"], "%s is now open" % n["en"]))
    a, b = set(wide_listeners(prev)), set(wide_listeners(cur))
    for x in sorted(a - b):
        n = app_name(x)
        better.append(t("%s が外から届かなくなりました" % n["ja"], "%s can no longer be reached from outside" % n["en"]))
    for x in sorted(b - a):
        n = app_name(x)
        worse.append(t("%s が外から届く状態になりました" % n["ja"], "%s can now be reached from outside" % n["en"]))
    a = {h["file"] for h in prev.get("secrets", [])}
    b = {h["file"] for h in cur.get("secrets", [])}
    better += [t("鍵が書かれたファイルが片付きました: %s" % x, "A file with a key in it was cleaned up: %s" % x)
               for x in sorted(a - b)]
    worse += [t("鍵が書かれたファイルが増えました: %s" % x, "A new file with a key in it was found: %s" % x)
              for x in sorted(b - a)]
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
        "ok": ok,
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
    # 先頭の <title> と <style> は head に置く
    cut = body.index("</style>") + len("</style>")
    return ('<!doctype html>\n<html lang="ja"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            "%s\n</head><body>\n%s\n</body></html>\n" % (body[:cut], body[cut:]))


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
    if detail:
        data["detailPath"] = os.path.abspath(md)
    path = os.path.join(out, "report.html")
    # 中身は自分の弱点の地図なので、run.sh の外から呼ばれても本人しか読めないようにする
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(page(data))
    os.chmod(path, 0o600)


if __name__ == "__main__":
    main()
