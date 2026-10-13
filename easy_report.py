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
    ("npm", t("npm の感染対策", "npm infection protection")),
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
    "npm": t("npm の公開用トークン", "npm publish token"),
    "private_key": t("秘密鍵", "private key"),
}

# 「システム設定 → 一般 → 共有」の中で、オフにするスイッチの名前
SWITCHES = {
    22: [t("リモートログイン", "Remote Login")],
    3283: [t("リモートマネージメント", "Remote Management")],
    5900: [t("画面共有", "Screen Sharing")],
    445: [t("ファイル共有", "File Sharing")],
    548: [t("ファイル共有", "File Sharing")],
    88: [t("ファイル共有", "File Sharing"), t("画面共有", "Screen Sharing")],
    631: [t("プリンタ共有", "Printer Sharing")],
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


# 直し方の難しさ。self は設定画面をたどるだけで本人ができるもの、help は開発やサーバーの知識がいるもの
SELF, HELP = "self", "help"

OPEN_SETTINGS = t("画面左上の Apple メニュー から「システム設定」を開きます",
                  "Open the Apple menu  at the top left and choose System Settings")
RECHECK = t("直したら、Preflight をもう一度開いて点検します。直っていれば「前回の点検から変わったこと」に出ます",
            "When you're done, open Preflight again to re-check. If it worked, it shows up under the changes since the last check")


STILL_LISTED = t("この方法では待ち受けそのものは残るので、次の点検でも「確認しておく」に出ます。ブロックしてあれば、それで大丈夫です",
                 "This leaves the app itself listening, so it will still appear under \"Check\" next time. Once it's blocked, that's fine")


def finding(cat, level, title, what, why, how, effort=HELP, steps=None, time=None, undo=None, keep=None, ask_ai=None):
    """1件の指摘。how は直し方の要約、steps は番号付きの手順、time は目安の時間、undo は元に戻す方法、
    keep は「このままでよい場合」、ask_ai は Claude Code などに貼る依頼文（鍵の値やファイルの中身は入れない）。"""
    f = {"cat": cat, "level": level, "title": title, "what": what, "why": why, "how": how, "effort": effort}
    for k, v in (("steps", steps), ("time", time), ("undo", undo), ("keep", keep), ("askAi", ask_ai)):
        if v:
            f[k] = v
    return f


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


def sharing_switch(p):
    names = SWITCHES.get(p)
    if not names:
        return t("使っていない共有のスイッチを、すべてオフにします", "Turn off every sharing switch you don't use")
    return t("「%s」のスイッチをオフにします" % "」と「".join(n["ja"] for n in names),
             "Turn off %s" % " and ".join(n["en"] for n in names))


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
              "System Settings → Network → Firewall → turn it on"),
            SELF, [OPEN_SETTINGS,
                   t("左の一覧で「ネットワーク」を選びます", "Choose Network in the list on the left"),
                   t("「ファイアウォール」を押して、スイッチをオンにします", "Click Firewall and turn the switch on"),
                   RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("同じスイッチをオフにすれば元に戻ります", "Turn the same switch off to undo it")))

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
            how, SELF, [OPEN_SETTINGS,
                        t("左の一覧で「一般」を選び、右の「共有」を押します",
                          "Choose General in the list on the left, then click Sharing"),
                        sharing_switch(p),
                        RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("同じスイッチをオンにすれば元に戻ります", "Turn the same switch back on to undo it"),
            keep=t("ほかの Mac から、この機能を自分で使っているなら、そのままで構いません",
                   "If you use this feature yourself from another Mac, you can leave it on")))
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
                     extra),
            SELF, [t("上のアプリ名を見て、使っていないアプリがないか確かめます",
                     "Look at the app names above and find any you don't use"),
                   t("使っていないアプリは終了して、「アプリケーション」フォルダからゴミ箱に入れます",
                     "Quit apps you don't use and drag them from the Applications folder to the Trash"),
                   t("使うけれど、ほかの機器からつながる必要はないアプリは、システム設定 → ネットワーク → ファイアウォール →「オプション…」を開きます",
                     "For apps you use but that don't need connections from other devices, open "
                     "System Settings → Network → Firewall → Options…"),
                   t("「＋」でそのアプリを追加し、「外部からの接続をブロック」にします",
                     "Click + to add the app, then set it to \"Block incoming connections\""),
                   STILL_LISTED],
            time=t("約5分", "About 5 min"),
            undo=t("同じ画面でアプリを選び「外部からの接続を許可」に戻します。ゴミ箱に入れたアプリは、ゴミ箱から戻せます",
                   "In the same window, set the app back to \"Allow incoming connections\". Apps in the Trash can be put back"),
            keep=t("スマホ連携など、ほかの機器から使う機能が必要なアプリは、そのままで大丈夫です",
                   "Apps whose features you use from other devices, like linking to your phone, are fine as they are"),
            ask_ai=t("このMacで、次のアプリが同じネットワークの他の機器から接続を受け付けています: %s。"
                     "それぞれ何のために待ち受けているか調べてください。自分で作ったサーバーなら、待ち受け先を 127.0.0.1 に変えて動作確認してください。"
                     "市販のアプリなら設定は変えずに、私が何をすればよいかだけ教えてください。" % join(unknown)["ja"],
                     "On this Mac, these apps accept connections from other devices on the network: %s. "
                     "Find out what each one is listening for. If one is a server I built, change it to listen on 127.0.0.1 "
                     "and check that it still works. If it is a regular app, don't change anything; just tell me what I should do." % join(unknown)["en"])))
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
                  "or use a service like Cloudflare Access so only you can get in."),
                time=t("30分〜", "30 min or more"),
                ask_ai=t("%s の管理画面が、ログインなしで開きます。どこで動いているサイトか調べ、"
                         "パスワードと二段階認証をかけるか、Cloudflare Access などで私だけが入れるようにする手順を、私の環境に合わせて教えてください。" % url,
                         "The admin page at %s opens without a login. Find out where the site is hosted, and tell me the steps, "
                         "for my setup, to protect it with a password and two-step sign-in or to let only me in with "
                         "something like Cloudflare Access." % url)))
        elif uid.startswith("old-") and v != "unreachable":
            site_issue = True
            todo.append(finding(
                "sites", YELLOW, t("やめたはずのサイトが、まだ応答しています", "A site you stopped using still responds"),
                t("%s は使っていないはずですが、アクセスすると応答がありました。" % url,
                  "%s should no longer be in use, but it still answers when visited." % url),
                t("放っておいた古いサイトは更新されず、乗っ取りや偽サイトの入口になりやすいです。",
                  "Old sites that are left alone don't get updates. They are easy to take over or turn into fake sites."),
                t("サーバーやドメインの管理画面で、そのサイトを止めるか削除します。",
                  "Stop or delete the site in your server or domain control panel."),
                time=t("15分〜", "15 min or more"),
                ask_ai=t("もう使っていないはずの %s が、まだ応答します。どのサーバーやサービスで動いているか調べ、"
                         "止める手順を教えてください。止める前に、残しておくべきデータがないかも確かめてください。" % url,
                         "%s should no longer be in use, but it still responds. Find out which server or service runs it and "
                         "tell me how to stop it. Before stopping it, check whether any data should be kept." % url)))
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
              "If a key was ever pushed to GitHub, make a new one."),
            time=t("30分〜", "30 min or more"),
            ask_ai=t("次のファイルに API キーなどの鍵がそのまま書かれています: %s。鍵の値は画面に表示しないでください。"
                     "使っている鍵は macOS のキーチェーンから読む形に変え、ファイルからは消してください。"
                     "そのファイルが Git に記録されたり GitHub に上がったりしたことがないかも確かめ、あれば鍵の作り直しが必要か教えてください。"
                     "最後に、元のプログラムが動くか確かめてください。" % files["ja"],
                     "These files have API keys or other secrets written in plain text: %s. Don't show the key values on screen. "
                     "For keys that are in use, change the code to read them from the macOS Keychain and remove them from the file. "
                     "Check whether the file was ever committed to Git or pushed to GitHub, and if so, tell me whether I need new keys. "
                     "Finally, check that the original program still works." % files["en"])))
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
              "Important keys are safer in a password manager or Keychain."),
            time=t("30分〜", "30 min or more"),
            keep=t("自分の開発用で、このフォルダをコピーしたり AI に丸ごと読ませたりしないなら、このままで構いません",
                   "If it's for your own development and you don't copy the folder or let an AI read all of it, you can leave it"),
            ask_ai=t("次の .env ファイルに API キーが書かれています: %s。鍵の値は画面に表示しないでください。"
                     "使っていない鍵があれば教えてください。使っている鍵は macOS のキーチェーンから読む形に変え、"
                     "変えたあとにプログラムが動くか確かめてください。" % files["ja"],
                     "These .env files have API keys in them: %s. Don't show the key values on screen. "
                     "Tell me if any key looks unused. For keys in use, change the code to read them from the macOS Keychain, "
                     "then check that the program still works." % files["en"])))
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
            t("覚えのないものは、システム設定 → 一般 → ログイン項目と機能拡張 で、バックグラウンドでの実行を止めます。",
              "For any you don't recognize, stop it from running in the background in "
              "System Settings → General → Login Items & Extensions."),
            SELF, [OPEN_SETTINGS,
                   t("左の一覧で「一般」を選び、右の「ログイン項目と機能拡張」を押します",
                     "Choose General in the list on the left, then click Login Items & Extensions"),
                   t("「バックグラウンドでの実行を許可」の一覧から、上の名前に近い項目を探します",
                     "In the \"Allow in the Background\" list, find the items that match the names above"),
                   t("覚えのないものは、スイッチをオフにします", "Turn off the switch for any you don't recognize"),
                   t("止めても設定ファイルは残るので、次の点検でも「確認しておく」に出ます。止めてあれば、それで大丈夫です",
                     "The setting file stays even after you turn it off, so it will still appear under \"Check\" next time. "
                     "Once it's off, that's fine")],
            time=t("約5分", "About 5 min"),
            undo=t("同じスイッチをオンにすれば元に戻ります", "Turn the same switch back on to undo it"),
            keep=t("自分で作った仕組みなら、そのままで大丈夫です", "If you set them up yourself, they are fine as they are"),
            ask_ai=t("このMacの ~/Library/LaunchAgents に、Claude を自動で呼び出す仕組みが登録されています: %s。"
                     "それぞれ、いつ・何を読んで・どこへ送っているかを調べて、ふつうの言葉で説明してください。止めるかどうかは私が決めるので、まだ何も変えないでください。"
                     % join([same(j) for j in jobs])["ja"],
                     "On this Mac, ~/Library/LaunchAgents has jobs that start Claude automatically: %s. "
                     "For each one, find out when it runs, what it reads and where it sends things, and explain it in plain words. "
                     "I will decide whether to stop them, so don't change anything yet." % join([same(j) for j in jobs])["en"])))
    else:
        good("ai", t("AI を自動で呼び出す仕組みは、見つかりませんでした。",
                     "Nothing was found that starts AI on its own."))

    npm_findings(facts.get("npm"), todo, good)

    order = {RED: 0, YELLOW: 1}
    todo.sort(key=lambda f: order[f["level"]])
    return todo, ok


def entry_map(facts, todo):
    """素人向けの「入口の地図」。このMacの中・同じ Wi-Fi/LAN・インターネットの3つの場所に、
    何がどんな状態で置かれているかを並べる。各項目の cat はレポートの説明カードへの飛び先。"""
    lvl = {f["cat"]: f["level"] for f in reversed(todo)}  # 同じ項目なら重い方（todo は赤が先）

    def item(cat, label, level):
        return {"cat": cat, "label": label, "level": level}

    mac, lan, net = [], [], []
    inner = [l for l in facts.get("listeners", []) if l.get("scope") in ("loopback", "tailscale")]
    if inner:
        mac.append(item("apps", t("中だけで動くサービス %d 件" % len(inner), "%d service%s kept inside" % (
            len(inner), "" if len(inner) == 1 else "s")), GREEN))
    secrets = facts.get("secrets", [])
    if secrets:
        mac.append(item("keys", t("鍵が書かれたファイル %d 件" % len(secrets), "%d file%s with keys" % (
            len(secrets), "" if len(secrets) == 1 else "s")), lvl.get("keys", YELLOW)))
    elif "secrets" in facts:
        mac.append(item("keys", t("鍵の置き忘れなし", "No stray keys"), GREEN))
    if (facts.get("npm") or {}).get("used"):
        mac.append(item("npm", t("npm の感染対策", "npm infection protection"), lvl.get("npm", GREEN)))

    for p in open_admin_ports(facts):
        lan.append(item("ports", port_info(p)[0], RED))
    if facts.get("lanProbe") and not open_admin_ports(facts):
        lan.append(item("ports", t("遠隔操作・共有の入口は閉", "Remote access and sharing closed"), GREEN))
    normal = 0
    for app, ps in sorted(wide_listeners(facts).items()):
        if ps <= set(PORTS) or app.startswith("（root"):
            continue
        if app in NORMAL_APPS:
            normal += 1
        else:
            lan.append(item("apps", app_name(app), YELLOW))
    if normal:
        lan.append(item("apps", t("Apple の標準機能 %d 件" % normal, "%d built-in Apple feature%s" % (
            normal, "" if normal == 1 else "s")), GREEN))

    for u in facts.get("urls", []):
        uid, url, v = u.get("id", ""), u.get("url", ""), u.get("verdict")
        host = url.split("//", 1)[-1].rstrip("/")
        if "admin" in uid and v == "open":
            level = RED
        elif uid.startswith("old-") and v != "unreachable":
            level = YELLOW
        elif uid.startswith("old-") or v in ("open", "auth_required"):
            level = GREEN
        else:
            continue
        net.append(item("sites", same(host), level))
    jobs = facts.get("agents", {}).get("claude_launchd_jobs", [])
    if jobs:
        net.append(item("ai", t("AI を自動で呼ぶ仕組み %d 件" % len(jobs), "%d automatic AI task%s" % (
            len(jobs), "" if len(jobs) == 1 else "s")), YELLOW))

    return {"firewall": bool(facts.get("firewall", {}).get("enabled")), "mac": mac, "lan": lan, "net": net}


GUARD_CMD = "python3 ~/.claude/supply-chain/scan.py --status"


def npm_findings(n, todo, good):
    """npm のサプライチェーン攻撃（パッケージに仕込まれたワームなど）への備え。npm を使っていなければ何も出さない。"""
    if not n or not n.get("used"):
        return
    g = n.get("guard")
    if g and (g.get("high") or g.get("medium")):
        hi, n_all = g.get("high", 0), g.get("high", 0) + g.get("medium", 0)
        todo.append(finding(
            "npm", RED if hi else YELLOW,
            t("npm の感染の疑いが %d 件出ています" % hi, "%d possible npm infection%s reported" % (hi, "" if hi == 1 else "s")) if hi else
            t("npm の見張りが、確認してほしいものを %d 件出しています" % n_all,
              "npm monitoring has %d item%s for you to check" % (n_all, "" if n_all == 1 else "s")),
            t("感染を見張る supply-chain-guard が、最後の走査（%s）で、まだ確認していないものを見つけています（重大 %d 件・注意 %d 件）。" % (
                g["lastScanAt"].replace("T", " "), hi, n_all - hi),
              "supply-chain-guard, which watches for infections, found items you haven't checked yet in its last scan (%s): "
              "%d serious, %d to check." % (g["lastScanAt"].replace("T", " "), hi, n_all - hi)),
            t("感染したパッケージは、このMacの鍵（GitHub・npm・クラウドなど）を盗んで外へ送り、ほかのプロジェクトにも広がることがあります。",
              "An infected package can steal keys on this Mac (GitHub, npm, cloud and so on), send them out, and spread to other projects."),
            t("ターミナルで %s を実行して内容を確かめ、supply-chain-guard の取扱説明書（MANUAL.md）の「警告が出たとき」に沿って対処します。" % GUARD_CMD,
              "Run %s in Terminal to see the details, then follow \"When a warning appears\" in the supply-chain-guard manual (MANUAL.md)." % GUARD_CMD),
            time=t("30分〜", "30 min or more"),
            ask_ai=t("このMacで supply-chain-guard が npm の感染の疑いを出しています。%s を実行して結果を読み、"
                     "何が見つかったのか、本当に危ないのかを、ふつうの言葉で説明してください。鍵や設定ファイルの中身は画面に出さず、"
                     "削除や作り直しなど元に戻せない操作は、私に確かめてから行ってください。" % GUARD_CMD,
                     "supply-chain-guard on this Mac reports a possible npm infection. Run %s, read the result, and explain in plain words "
                     "what was found and whether it is really dangerous. Don't show keys or the contents of settings files, and ask me "
                     "before doing anything that can't be undone, like deleting files or replacing keys." % GUARD_CMD)))
        return
    if g and g.get("stale"):
        todo.append(finding(
            "npm", YELLOW, t("npm の感染の見張りが止まっています", "npm infection monitoring has stopped"),
            t("supply-chain-guard は入っていますが、毎日の走査がしばらく動いていません（最後の走査: %s）。" % (
                g.get("lastScanAt", "").replace("T", " ") or "なし"),
              "supply-chain-guard is installed, but its daily scan hasn't run for a while (last scan: %s)." % (
                g.get("lastScanAt", "").replace("T", " ") or "none")),
            t("見張りが止まっている間に感染したパッケージが入っても、気づけません。",
              "If an infected package arrives while monitoring is stopped, you won't notice."),
            t("ターミナルで python3 ~/.claude/supply-chain/scan.py --quick を実行し、そのあと %s で日時が新しくなったか確かめます。"
              "直らなければ、supply-chain-guard の install.sh をもう一度実行します。" % GUARD_CMD,
              "Run python3 ~/.claude/supply-chain/scan.py --quick in Terminal, then check with %s that the date is new. "
              "If it doesn't help, run supply-chain-guard's install.sh again." % GUARD_CMD),
            SELF, time=t("約5分", "About 5 min")))
        return
    if g:
        good("npm", t("npm の感染の見張り（supply-chain-guard）は動いていて、最後の走査（%s）で異常はありませんでした。" % (
            g.get("lastScanAt", "").replace("T", " ")),
                      "npm infection monitoring (supply-chain-guard) is running, and its last scan (%s) found nothing." % (
            g.get("lastScanAt", "").replace("T", " "))))
        return
    if n.get("ignoreScripts"):
        good("npm", t("npm は、パッケージを入れるときにその中のプログラムを自動で動かさない設定です（感染の主な入口が閉じています）。",
                      "npm is set not to run programs inside packages when installing them (the main way infections get in is closed)."))
        return
    todo.append(finding(
        "npm", YELLOW, t("npm の感染対策が入っていません", "No protection against npm infections"),
        t("このMacでは npm を使っていますが、パッケージを入れるときに、その中のプログラムが自動で動く設定のままです。",
          "This Mac uses npm, and it still runs programs inside packages automatically when installing them."),
        t("乗っ取られたパッケージを1つ入れただけで、このMacの鍵（GitHub・npm・クラウドなど）を盗まれることがあります。"
          "AI に開発を任せていると、知らないうちにパッケージが入ることもあります。",
          "Installing just one hijacked package can let someone steal keys on this Mac (GitHub, npm, cloud and so on). "
          "When an AI does your coding, packages can be installed without you noticing."),
        t("ターミナルで npm config set ignore-scripts true を実行します。",
          "Run npm config set ignore-scripts true in Terminal."),
        SELF, [t("「アプリケーション」→「ユーティリティ」から「ターミナル」を開きます",
                 "Open Terminal from Applications → Utilities"),
               t("npm config set ignore-scripts true と入力して return を押します",
                 "Type npm config set ignore-scripts true and press return"),
               RECHECK],
        time=t("約1分", "About 1 min"),
        undo=t("npm config delete ignore-scripts で元に戻ります", "Run npm config delete ignore-scripts to undo it"),
        keep=t("入れたあとに動かなくなるパッケージがあれば、そのプロジェクトで npm rebuild --ignore-scripts=false パッケージ名 を実行します。"
               "感染を毎日見張るなら、supply-chain-guard を入れるとより安心です",
               "If a package stops working after you install it, run npm rebuild --ignore-scripts=false <package> in that project. "
               "To watch for infections every day, installing supply-chain-guard is safer still"),
        ask_ai=t("このMacの npm で、パッケージの install スクリプトを動かさない設定（ignore-scripts=true）にしたいです。"
                 "設定したあと、今のプロジェクトがビルドできるか確かめ、スクリプトが必要なパッケージがあれば、そのパッケージだけ動かす方法を教えてください。",
                 "I want npm on this Mac to stop running package install scripts (ignore-scripts=true). After setting it, check that my "
                 "current projects still build, and if a package needs its scripts, show me how to run them for that package only.")))


def checks(todo, skip=()):
    """6つの項目それぞれの信号（いちばん悪いもの）。"""
    res = []
    for cat, label in CHECKS:
        if cat in skip:
            continue
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


def version():
    """このツールの版。VERSION ファイルが唯一の置き場所。"""
    with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
        return f.read().strip()


def build_data(facts, prev=None, detail=""):
    todo, ok = analyze(facts)
    reds = sum(1 for f in todo if f["level"] == RED)
    return {
        "version": version(),
        "measuredAt": facts.get("measuredAt", "").replace("T", " "),
        "verdict": RED if reds else YELLOW if todo else GREEN,
        "counts": {"red": reds, "yellow": len(todo) - reds, "ok": len(ok)},
        "checks": checks(todo, () if (facts.get("npm") or {}).get("used") else ("npm",)),
        "map": entry_map(facts, todo),
        "todo": todo,
        "ok": ok,
        "diff": changes(prev, facts) if prev else None,
        "prevMeasuredAt": prev.get("measuredAt", "").replace("T", " ")[:16] if prev else "",
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
    # 詳しい情報は report.py が書いた日本語版と英語版を、言語ごとに入れる
    detail, where = {}, {}
    for lang, name in (("ja", "report.md"), ("en", "report.en.md")):
        md = os.path.join(out, name)
        if os.path.exists(md):
            with open(md, encoding="utf-8") as f:
                detail[lang] = f.read()
            where[lang] = os.path.abspath(md)
    data = build_data(facts, previous_facts(out), detail or "")
    if where:
        data["detailPath"] = where
    # 専門家向け: 自動で作った構成図を、評価エンジンのブラウザ版で開くための情報
    model = os.path.join(out, "model.json")
    if os.path.exists(model):
        data["modelPath"] = os.path.abspath(model)
        data["engineDir"] = os.path.join(HERE, "vendor", "CyberRiskScape")
    path = os.path.join(out, "report.html")
    # 中身は自分の弱点の地図なので、run.sh の外から呼ばれても本人しか読めないようにする
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(page(data))
    os.chmod(path, 0o600)


if __name__ == "__main__":
    main()
