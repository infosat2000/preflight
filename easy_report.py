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
import re
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
    ("aiperm", t("AI に与えた権限", "Permissions given to AI")),
    ("guard", t("Mac の守り", "Built-in protection")),
    ("update", t("更新の設定", "Update settings")),
    ("disk", t("ディスクの暗号化", "Disk encryption")),
    ("ssh", t("SSH の鍵", "SSH keys")),
    ("remote", t("遠隔操作アプリ", "Remote-control apps")),
    ("backup", t("バックアップ", "Backup")),
    ("autostart", t("自動で起動するもの", "Things that start on their own")),
    ("disguise", t("名前を偽ったアプリ", "Apps posing as Apple or Google")),
    ("shell", t("シェルと git への居座り", "Shell and git hooks")),
    ("repo", t("開くだけで動く仕掛け", "Code that runs when a folder opens")),
    ("aikeys", t("AI ツールの鍵と版", "AI tool keys and versions")),
    ("ext", t("ブラウザの拡張機能", "Browser extensions")),
]
# 実測できなかった（その Mac で読めなかった・対象がない）ときは、チェックリストに出さない項目
OPTIONAL = {"npm", "aiperm", "guard", "update", "disk", "ssh", "backup", "autostart", "disguise", "shell", "repo", "aikeys", "ext"}
# 1.2.0 で足した項目。どれも「このMacの中」に置くもの
THREAT_CATS = ("autostart", "disguise", "shell", "repo", "aikeys", "ext")

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
RECHECK = t("直したら、BB Preflight をもう一度開いて点検します。直っていれば「前回の点検から変わったこと」に出ます",
            "When you're done, open BB Preflight again to re-check. If it worked, it shows up under the changes since the last check")


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
    more_findings(facts, todo, good)
    guard_findings(facts, todo, good)
    update_findings(facts.get("updates"), todo, good)
    threat_findings(facts, todo, good)

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
    skip = present(facts)
    for cat, label in ((c, l) for c, l in CHECKS if c in ("npm", "aiperm", "guard", "update", "disk", "ssh", "backup") + THREAT_CATS):
        if cat not in skip:
            mac.append(item(cat, label, lvl.get(cat, GREEN)))
    if facts.get("remoteApps"):
        net.append(item("remote", cat_text(t("遠隔操作アプリ: ", "Remote control: "), join([same(a) for a in facts["remoteApps"]])), YELLOW))

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
    if n.get("scriptsOffByDefault") and not n.get("ignoreScripts"):
        good("npm", t("npm は %s です。12 からは、パッケージを入れるときにその中のプログラムが標準で動きません（感染の主な入口が閉じています）。" % n.get("version"),
                      "npm is %s. From version 12, programs inside packages don't run by default when installing them "
                      "(the main way infections get in is closed)." % n.get("version")))
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
        t("ターミナルで npm config set ignore-scripts true を実行します（npm を 12 以上にしても、同じように標準で止まります）。",
          "Run npm config set ignore-scripts true in Terminal (updating npm to version 12 or later also turns this off by default)."),
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


def more_findings(facts, todo, good):
    """AI の権限・ディスクの暗号化・SSH の鍵・遠隔操作アプリ・バックアップ。"""
    ap = facts.get("aiPermissions")
    if ap and ap.get("files"):
        anyc = [b for b in ap.get("broad", []) if b["kind"] == "any"]
        code = [b for b in ap.get("broad", []) if b["kind"] == "code"]
        where = join([same(f) for f in dict.fromkeys(ap.get("bypass", []) + [b["file"] for b in anyc])])
        if ap.get("bypass") or anyc:
            todo.append(finding(
                "aiperm", RED, t("AI が、確認なしで何でも実行できる設定です", "AI can run anything without asking you"),
                cat_text(t("Claude Code の設定で、確認を飛ばすモード（bypassPermissions）か、すべてのコマンドを許す指定（Bash(*) など）が入っています: ",
                           "Claude Code is set to skip confirmations (bypassPermissions), or allows every command (such as Bash(*)): "), where),
                t("読み込んだ Web ページやファイルに悪い指示が仕込まれていると（プロンプトインジェクション）、AI がファイルを消したり鍵を外へ送ったりしても止められません。",
                  "If a web page or file the AI reads contains hidden instructions (prompt injection), nothing stops the AI from deleting files "
                  "or sending your keys out."),
                t("Claude Code で /permissions を開いて、広すぎる許可を消します。設定ファイルの \"defaultMode\": \"bypassPermissions\" は消すか \"default\" にします。",
                  "Open /permissions in Claude Code and remove the overly broad rules. In the settings file, remove "
                  "\"defaultMode\": \"bypassPermissions\" or set it to \"default\"."),
                time=t("約10分", "About 10 min"),
                undo=t("消した許可は、/permissions からいつでも足し直せます", "You can add a rule back at any time from /permissions"),
                ask_ai=t("Claude Code の設定（%s）に、確認なしで何でも実行できる許可が入っています。私がふだん使う作業に必要な許可だけを、"
                         "具体的なコマンドに絞った形で提案してください。設定ファイルを書き換える前に、変更の案を見せて私に確かめてください。" % where["ja"],
                         "My Claude Code settings (%s) allow running anything without asking. Suggest a narrower set of rules, limited to "
                         "specific commands I actually use. Show me the proposed changes before editing any settings file." % where["en"])))
        wide = ap.get("mcpWide", [])
        if code or wide:
            rules = [same(b["rule"]) for b in code[:5]]
            parts = []
            if rules:
                parts.append(cat_text(t("プログラムを丸ごと実行できる許可: ", "rules that let it run any program: "), join(rules),
                                      t("（ほか %d 件）" % (len(code) - 5), " (and %d more)" % (len(code) - 5)) if len(code) > 5 else ""))
            if wide:
                parts.append(cat_text(t("ホームフォルダ全体を読める MCP: ", "MCP servers that can read your whole home folder: "),
                                      join([same(w) for w in wide])))
            todo.append(finding(
                "aiperm", YELLOW, t("AI に、広めの許可を与えています", "AI has fairly broad permissions"),
                cat_text(t("Claude Code に、次の許可を与えています。", "Claude Code has been given: "),
                         join(parts) if len(parts) > 1 else parts[0], t("", ".")),
                t("python3 や node を何でも実行してよい許可は、実質「何でもできる」許可と同じです。悪い指示を読み込んだときに、確認なしで動いてしまいます。",
                  "Permission to run any python3 or node command is, in practice, permission to do anything. If the AI reads hidden "
                  "instructions, it acts on them without asking."),
                t("許可を、決まったスクリプトだけに絞ります（例: Bash(python3:*) → Bash(python3 tests/run.py)）。MCP には作業用フォルダだけを渡します。",
                  "Narrow the rules to specific scripts (for example Bash(python3:*) → Bash(python3 tests/run.py)). Give MCP servers only "
                  "your work folder."),
                time=t("約15分", "About 15 min"),
                keep=t("自分しか触らないフォルダで、怪しいものを AI に読ませないなら、すぐ危ないわけではありません",
                       "If the AI only works in your own folders and never reads untrusted content, it is not an urgent danger"),
                ask_ai=t("Claude Code の許可リストに、python3 や node などを何でも実行できる広い許可があります。最近の作業で実際に使ったコマンドを調べ、"
                         "必要なものだけに絞った許可の案を出してください。書き換える前に、案を見せて私に確かめてください。",
                         "My Claude Code allow list has broad rules that let it run any python3 or node command. Look at the commands I "
                         "actually used recently and propose narrower rules. Show me the proposal before changing anything.")))
        if not (ap.get("bypass") or anyc or code or wide):
            good("aiperm", t("Claude Code の許可に、確認なしで何でもできるような広すぎるものはありませんでした（設定ファイル %d 件）。" % ap["files"],
                             "Claude Code's permissions include nothing broad enough to do anything without asking (%d settings file%s)."
                             % (ap["files"], "" if ap["files"] == 1 else "s")))

    fv = facts.get("fileVault")
    if fv and fv.get("on") is True:
        good("disk", t("ディスクは FileVault で暗号化されています。Mac をなくしても、中身は読まれません。",
                       "The disk is encrypted with FileVault. If the Mac is lost, its contents can't be read."))
    elif fv and fv.get("on") is False:
        steps = [OPEN_SETTINGS,
                 t("左の一覧で「プライバシーとセキュリティ」を選び、「FileVault」の「オンにする」を押します",
                   "Choose Privacy & Security on the left, then click Turn On next to FileVault"),
                 t("復旧キーは、紙に書くかパスワード管理アプリに保存し、Mac の外に置いておきます（なくすと中身を取り出せなくなります）",
                   "Write the recovery key down or save it in a password manager, somewhere off this Mac (if you lose it, you can't get your data back)"),
                 t("暗号化はそのまま使いながら裏で進みます。電源につないでおくと早く終わります",
                   "Encryption runs in the background while you keep working. It finishes faster on power")]
        if fv.get("oclp"):
            todo.append(finding(
                "disk", YELLOW, t("ディスクが暗号化されていません", "The disk is not encrypted"),
                t("FileVault がオフです。この Mac は OpenCore Legacy Patcher（OCLP）で動いています。",
                  "FileVault is off. This Mac runs with OpenCore Legacy Patcher (OCLP)."),
                t("Mac をなくしたり盗まれたりすると、ディスクを抜かれて、中のファイルや鍵をそのまま読まれます。",
                  "If the Mac is lost or stolen, someone can take the disk and read your files and keys as they are."),
                t("OCLP の Mac は、オンにする前に OCLP の資料で FileVault との相性を確かめ、Time Machine でバックアップを取ってから進めます。",
                  "On an OCLP Mac, first check OCLP's documentation for FileVault compatibility and make a Time Machine backup, then turn it on."),
                time=t("確認に30分〜", "30 min or more to check first"),
                keep=None if fv.get("laptop") else t("持ち歩かない机の Mac で、部屋の鍵がかかるなら、急ぎではありません",
                                                     "If it's a desk Mac that never leaves a locked room, it's not urgent"),
                ask_ai=t("この Mac は OpenCore Legacy Patcher（OCLP）で動いています。FileVault をオンにしても起動や OCLP のパッチに問題が出ないか、"
                         "OCLP の公式資料で確かめてください。macOS のアップデートは勧めないでください。オンにする場合は、先にバックアップを取る手順から案内してください。",
                         "This Mac runs with OpenCore Legacy Patcher (OCLP). Check OCLP's official documentation for whether turning on "
                         "FileVault could break booting or OCLP's patches. Don't suggest a macOS update. If it's safe, walk me through "
                         "making a backup first.")))
        else:
            todo.append(finding(
                "disk", RED, t("ディスクが暗号化されていません", "The disk is not encrypted"),
                t("FileVault（Mac に最初から入っているディスクの暗号化）がオフです。", "FileVault, the disk encryption built into your Mac, is off."),
                t("Mac をなくしたり盗まれたりすると、ディスクを抜かれて、中のファイルや鍵をそのまま読まれます。",
                  "If the Mac is lost or stolen, someone can take the disk and read your files and keys as they are."),
                t("システム設定 → プライバシーとセキュリティ → FileVault → オンにする",
                  "System Settings → Privacy & Security → FileVault → Turn On"),
                SELF, steps + [RECHECK], time=t("設定は約5分（暗号化は裏で数時間）", "About 5 min to set up (encryption runs for hours in the background)"),
                undo=t("同じ画面でオフにできます", "You can turn it off on the same screen")))

    keys = facts.get("sshKeys")
    if keys:
        plain = [k for k in keys if not k.get("encrypted")]
        if plain:
            names = join([same(k["file"]) for k in plain])
            first = plain[0]["file"]
            todo.append(finding(
                "ssh", YELLOW, t("パスフレーズのない SSH の鍵が %d 個あります" % len(plain),
                                 "%d SSH key%s ha%s no passphrase" % (len(plain), "" if len(plain) == 1 else "s", "s" if len(plain) == 1 else "ve")),
                cat_text(t("次の鍵は、ファイルを持っているだけで誰でも使えます: ", "Anyone who has these files can use them: "), names),
                t("鍵のファイルを1つ盗まれるだけで、サーバーや GitHub にあなたとして入られます。npm のワームなどが真っ先に狙うのが、こうした鍵です。",
                  "If one key file is stolen, someone can log in to your servers or GitHub as you. Worms in npm packages go after exactly these keys."),
                t("ターミナルで ssh-keygen -p -f %s を実行して、パスフレーズを付けます。" % first,
                  "Run ssh-keygen -p -f %s in Terminal to add a passphrase." % first),
                SELF, [t("「アプリケーション」→「ユーティリティ」から「ターミナル」を開きます", "Open Terminal from Applications → Utilities"),
                       t("ssh-keygen -p -f %s と入力して return を押し、新しいパスフレーズを2回入れます" % first,
                         "Type ssh-keygen -p -f %s, press return, and enter a new passphrase twice" % first),
                       t("毎回入れるのが面倒なら ssh-add --apple-use-keychain %s で、キーチェーンに覚えさせます" % first,
                         "To avoid typing it every time, run ssh-add --apple-use-keychain %s to save it in Keychain" % first),
                       t("鍵がほかにもあれば、同じ手順をくり返します", "Repeat for any other keys"),
                       RECHECK],
                time=t("約5分", "About 5 min"),
                undo=t("同じコマンドで、パスフレーズを空にすれば元に戻ります", "Run the same command and leave the passphrase empty to undo it"),
                keep=t("自動で動く処理（定期的な git push など）がこの鍵を使っているなら、パスフレーズを付けると止まることがあります。その鍵は、その処理専用にして、ほかでは使わないようにします",
                       "If an automatic job (like a scheduled git push) uses this key, adding a passphrase may stop it. Keep such a key only for that job")))
        else:
            good("ssh", t("SSH の鍵（%d 個）は、すべてパスフレーズで守られています。" % len(keys),
                          "All %d SSH key%s %s protected by a passphrase." % (len(keys), "" if len(keys) == 1 else "s",
                                                                             "is" if len(keys) == 1 else "are")))

    apps = facts.get("remoteApps")
    if apps:
        todo.append(finding(
            "remote", YELLOW, t("遠隔操作アプリが入っています", "Remote-control apps are installed"),
            cat_text(t("ほかの人がこのMacの画面を見たり操作したりできるアプリがあります: ",
                       "These apps let someone else see and control this Mac's screen: "), join([same(a) for a in apps])),
            t("「ウイルスに感染しました」などの偽の警告で電話をかけさせ、こうしたアプリを入れさせる「サポート詐欺」がよくあります。入ったままだと、知らない人に操作され続けるおそれがあります。",
              "In tech-support scams, a fake warning (\"your Mac is infected\") makes you call a number and install apps like these. "
              "Left installed, a stranger may keep controlling your Mac."),
            t("自分で入れて使っているもの以外は、アプリを終了して「アプリケーション」フォルダからゴミ箱に入れます。"
              "電話で言われて入れたなら、すぐネットを切って削除し、パスワードを変え、IPA の「情報セキュリティ安心相談窓口」に相談します。",
              "Unless you installed it yourself and use it, quit the app and move it from Applications to the Trash. "
              "If someone on the phone told you to install it, disconnect from the internet, delete it, change your passwords, "
              "and get help (in Japan, IPA's security consultation desk)."),
            SELF, time=t("約5分", "About 5 min"),
            keep=t("自分で入れて、家族のパソコンの手伝いなどに使っているなら、問題ありません",
                   "If you installed it yourself, for example to help family with their computers, that's fine")))
    elif apps is not None:
        good("remote", t("サポート詐欺で入れさせられることの多い遠隔操作アプリは、見つかりませんでした。",
                         "No remote-control apps of the kind used in tech-support scams were found."))

    tm = facts.get("timeMachine")
    if tm:
        last = tm.get("lastBackupAt")
        days = None
        if last and facts.get("measuredAt"):
            try:
                import datetime
                days = (datetime.datetime.fromisoformat(facts["measuredAt"][:16]) -
                        datetime.datetime.fromisoformat(last)).days
            except ValueError:
                days = None
        setup_steps = [t("外付けのディスクを Mac につなぎます", "Connect an external disk to the Mac"),
                       OPEN_SETTINGS,
                       t("左の一覧で「一般」を選び、「Time Machine」→「バックアップディスクを追加」でそのディスクを選びます",
                         "Choose General on the left, then Time Machine → Add Backup Disk, and pick that disk"),
                       t("最初のバックアップは数時間かかります。終わったら外付けディスクはつないだままにするか、こまめにつなぎます",
                         "The first backup takes a few hours. Keep the disk connected, or connect it often"),
                       RECHECK]
        if not tm.get("configured"):
            todo.append(finding(
                "backup", YELLOW, t("バックアップが設定されていません", "No backup is set up"),
                t("Time Machine（Mac に最初から入っているバックアップ）に、バックアップ先がありません。",
                  "Time Machine, the backup built into your Mac, has no backup disk."),
                t("故障やランサムウェア（ファイルを人質にする攻撃）にあうと、仕事のファイルを取り戻せません。",
                  "If the Mac breaks or ransomware locks your files, you can't get your work back."),
                t("外付けディスクをつなぎ、システム設定 → 一般 → Time Machine で設定します。",
                  "Connect an external disk and set it up in System Settings → General → Time Machine."),
                SELF, setup_steps, time=t("約10分（初回のバックアップは数時間）", "About 10 min (the first backup takes hours)"),
                keep=t("ほかの方法（クラウドなど）で、仕事のファイルを毎日バックアップしているなら、急ぎではありません",
                       "If you back up your work files every day another way (for example to the cloud), it's not urgent")))
        elif days is not None and days > 7:
            todo.append(finding(
                "backup", RED if days > 30 else YELLOW, t("最後のバックアップが %d 日前です" % days, "The last backup was %d days ago" % days),
                t("Time Machine の最後のバックアップは %s です。" % last.replace("T", " "),
                  "Time Machine's last backup was on %s." % last.replace("T", " ")),
                t("いま故障やランサムウェアにあうと、この %d 日分の作業は戻りません。" % days,
                  "If the Mac breaks or ransomware strikes now, the last %d days of work can't be recovered." % days),
                t("バックアップ先のディスクをつないで、メニューバーの Time Machine から「今すぐバックアップを作成」を選びます。",
                  "Connect the backup disk and choose Back Up Now from the Time Machine menu in the menu bar."),
                SELF, time=t("約5分（バックアップは裏で進みます）", "About 5 min (the backup runs in the background)")))
        elif days is not None:
            good("backup", t("Time Machine の最後のバックアップは %s です。" % last.replace("T", " "),
                             "Time Machine's last backup was on %s." % last.replace("T", " ")))
        else:
            good("backup", t("Time Machine は設定されています（最後のバックアップの日時は、この権限では読めませんでした）。",
                             "Time Machine is set up (the time of the last backup couldn't be read with these permissions)."))


def guard_findings(facts, todo, good):
    """SIP・Gatekeeper・自動ログイン。OCLP の Mac は SIP を一部ゆるめるのが前提なので、そのぶんを差し引いて判断する。"""
    g = facts.get("macGuard")
    if not g:
        return
    oclp = g.get("oclp")
    ok = []
    if g.get("gatekeeper") is False:
        todo.append(finding(
            "guard", RED, t("Gatekeeper がオフです", "Gatekeeper is off"),
            t("ダウンロードしたアプリを開く前の確認（Gatekeeper）が止まっています。",
              "The check macOS runs before opening downloaded apps (Gatekeeper) is turned off."),
            t("開発元が確かめられないアプリや、改ざんされたアプリも、警告なしで開いてしまいます。",
              "Apps from unknown developers, or apps that were tampered with, open without any warning."),
            t("ターミナルで sudo spctl --master-enable を実行して、元に戻します。",
              "Run sudo spctl --master-enable in Terminal to turn it back on."),
            SELF, [t("「アプリケーション」→「ユーティリティ」から「ターミナル」を開きます", "Open Terminal from Applications → Utilities"),
                   t("sudo spctl --master-enable と入力して return を押し、Mac のパスワードを入れます",
                     "Type sudo spctl --master-enable, press return, and enter your Mac password"),
                   RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("止められたアプリは、一度開こうとしたあと、システム設定 →「プライバシーとセキュリティ」の「このまま開く」で1つずつ許可できます",
                   "If an app is blocked, try opening it once, then allow just that app with Open Anyway in System Settings → Privacy & Security")))
    elif g.get("gatekeeper"):
        ok.append(t("Gatekeeper はオン", "Gatekeeper is on"))
    sip = g.get("sip")
    if sip == "on":
        ok.append(t("SIP（システムを書き換えから守る仕組み）はオン", "SIP (which protects system files) is on"))
    elif sip == "custom" and oclp:
        ok.append(t("SIP は OCLP に必要なぶんだけゆるめてあります（OCLP では普通の状態です）",
                    "SIP is relaxed only as far as OCLP needs (normal for OCLP)"))
    elif sip in ("custom", "off"):
        todo.append(finding(
            "guard", YELLOW if oclp else RED,
            t("SIP がオフになっています", "SIP is turned off") if sip == "off" else t("SIP が一部オフです", "SIP is partly off"),
            t("システムのファイルを書き換えから守る仕組み（SIP）が%s。" % ("止まっています" if sip == "off" else "一部ゆるめてあります"),
              "System Integrity Protection, which keeps system files from being changed, is %s." % ("off" if sip == "off" else "partly relaxed")),
            t("悪いプログラムが入り込んだとき、macOS の中まで書き換えて居座れるようになります。",
              "If malware gets in, it can rewrite parts of macOS itself and stay hidden."),
            t("OCLP が必要とする設定より広くゆるめていないか、OCLP の設定画面で確かめます。" if oclp else
              "復旧モード（リカバリー）で起動し、ターミナルで csrutil enable を実行してオンに戻します。",
              "Check in OCLP's settings that SIP isn't relaxed further than OCLP needs." if oclp else
              "Start up in Recovery mode, open Terminal there, and run csrutil enable to turn it back on."),
            time=t("約15分", "About 15 min"),
            keep=t("OCLP で動かしている Mac は、SIP を一部ゆるめないと起動やパッチが動きません。OCLP の推奨どおりなら、そのままにします",
                   "On an OCLP Mac, SIP has to be partly relaxed for booting and patches to work. If it matches OCLP's recommendation, leave it")
            if oclp else None))
    if g.get("autoLogin"):
        todo.append(finding(
            "guard", YELLOW, t("自動ログインがオンです", "Automatic login is on"),
            t("Mac を起動すると、パスワードを入れなくてもデスクトップまで進みます。",
              "When the Mac starts, it goes straight to the desktop without a password."),
            t("Mac を持ち去られると、電源を入れるだけで、メールやブラウザに保存したログインまで使われます。",
              "If someone takes the Mac, they only need to switch it on to use your mail and the logins saved in your browser."),
            t("システム設定 →「ユーザとグループ」→「自動ログイン」を「オフ」にします。",
              "System Settings → Users & Groups → set Automatically log in as to Off."),
            SELF, [OPEN_SETTINGS,
                   t("左の一覧で「ユーザとグループ」を選びます", "Choose Users & Groups on the left"),
                   t("「自動ログイン」を「オフ」にして、Mac のパスワードを入れます", "Set Automatically log in as to Off and enter your Mac password"),
                   RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("同じ画面で、いつでもオンに戻せます", "You can turn it back on from the same screen"),
            keep=t("持ち歩かない机の Mac で、部屋の鍵がかかるなら、急ぎではありません",
                   "If it's a desk Mac that never leaves a locked room, it's not urgent")))
    elif g.get("autoLogin") is False:
        ok.append(t("自動ログインはオフ", "automatic login is off"))
    if ok and not any(f["cat"] == "guard" for f in todo):
        good("guard", cat_text(join(ok), t("でした。", ".")))


def update_findings(u, todo, good):
    """守りのデータ（XProtect など）を自動で受け取る設定か。macOS 本体のアップデートは勧めない。
    OCLP の Mac は、更新を意図して止めていることが多いので、注意にせず状態だけを伝える。"""
    if not u:
        return
    if u.get("securityData"):
        good("update", t("ウイルス対策のデータ（XProtect など）は、自動で受け取る設定です。",
                         "Malware-protection data (such as XProtect) is set to install automatically."))
    elif u.get("oclp"):
        good("update", t("ウイルス対策のデータを自動で受け取る設定はオフです。OCLP の Mac では、更新を意図して止めていることがあります。"
                         "意図したものなら、そのままで構いません。",
                         "Automatic install of malware-protection data is off. OCLP Macs often turn updates off on purpose. "
                         "If that was intended, you can leave it."))
    else:
        todo.append(finding(
            "update", YELLOW, t("ウイルス対策のデータが自動で届きません", "Malware-protection data doesn't arrive automatically"),
            t("「セキュリティ対応とシステムファイルをインストール」がオフです。", "Install Security Responses and system files is off."),
            t("macOS に入っているウイルス対策（XProtect）が、新しいマルウェアを見分けるためのデータを受け取れません。",
              "macOS's built-in malware protection (XProtect) can't get the data it needs to recognise new malware."),
            t("システム設定 → 一般 → ソフトウェアアップデート → 自動アップデートの「i」→「セキュリティ対応とシステムファイルをインストール」をオン。",
              "System Settings → General → Software Update → the (i) next to Automatic Updates → turn on Install Security Responses and system files."),
            SELF, [OPEN_SETTINGS,
                   t("左の一覧で「一般」を選び、「ソフトウェアアップデート」を開きます", "Choose General on the left, then Software Update"),
                   t("「自動アップデート」の右の「i」を押し、「セキュリティ対応とシステムファイルをインストール」だけをオンにして「完了」を押します",
                     "Click the (i) next to Automatic Updates, turn on only Install Security Responses and system files, and click Done"),
                   RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("同じ画面で、いつでもオフに戻せます", "You can turn it off again on the same screen"),
            keep=t("macOS 本体のアップデートとは別の設定です。これをオンにしても、macOS の版は変わりません",
                   "This is separate from macOS upgrades. Turning it on doesn't change your macOS version")))


# --- 1.2.0: 居座り・偽装・開くだけで動く仕掛け・AI ツールの鍵と版・拡張機能 -------------------

# この印が1つでもあれば「今すぐ直す」。Apple や Google の本物の署名なら、そもそも印は付かない
AUTOSTART_RED = {"fakeApple", "fakeGoogle", "temp", "ioc", "invalidSig", "hiddenHomeFile", "downloadRun"}

FLAG_TEXT = {
    "fakeApple": t("Apple を名乗っているが、Apple の署名ではない", "uses an Apple name but isn't signed by Apple"),
    "fakeGoogle": t("Google を名乗っているが、Google の署名ではない", "uses a Google name but isn't signed by Google"),
    "temp": t("一時置き場やキャッシュから動く", "runs from a temporary or cache folder"),
    "ioc": t("マルウェアの報告にある名前", "has a name from a malware report"),
    "invalidSig": t("署名が壊れている（中身が書き換えられた）", "its signature is broken (the contents were changed)"),
    "hiddenHomeFile": t("ホームフォルダの隠しファイルから動く", "runs from a hidden file in your home folder"),
    "downloadRun": t("ネットから取ってきたものを、その場で実行する", "downloads something and runs it straight away"),
    "unsigned": t("署名がない（作り手が分からない）", "has no signature (the maker is unknown)"),
    "adhoc": t("仮の署名だけ（作り手が分からない）", "has only a makeshift signature (the maker is unknown)"),
    "hiddenDir": t("見慣れない隠しフォルダから動く", "runs from an unfamiliar hidden folder"),
    "shared": t("誰でも書ける共有フォルダ（/Users/Shared）から動く", "runs from the shared folder anyone can write to (/Users/Shared)"),
}

LINE_TEXT = {
    "downloadRun": t("ネットから取ってきて実行", "downloads and runs code"),
    "decodeRun": t("隠した文字列を戻して実行", "decodes hidden text and runs it"),
    "tempRun": t("一時置き場のものを実行", "runs something from a temporary folder"),
    "hiddenRun": t("見慣れない隠しファイルを実行", "runs an unfamiliar hidden file"),
    "osascript": t("AppleScript を実行", "runs AppleScript"),
    "background": t("裏で動き続けるものを起動", "starts something that keeps running in the background"),
}
LINE_RED = {"downloadRun", "decodeRun", "tempRun"}

MALWARE_STEPS = [
    t("Mac のパスワードや、ウォレットの復元フレーズを求める画面が出ても、入れないでください",
      "If a window asks for your Mac password or a wallet recovery phrase, don't enter it"),
    t("Wi-Fi を切るか LAN ケーブルを抜いて、ネットから外します（Mac の電源は切らずに、そのままにします）",
      "Turn off Wi-Fi or unplug the network cable (leave the Mac switched on)"),
    t("ファイルはまだ消さずに、下の「AI に頼む」か、詳しい人に見てもらいます。IPA の「情報セキュリティ安心相談窓口」にも相談できます",
      "Don't delete anything yet. Use \"Ask an AI\" below or ask an expert to look. In Japan you can also contact IPA's security consultation desk"),
    t("本物のマルウェアだと分かったら、ほかの機器から、メール・銀行・GitHub・クラウドなどのパスワードを変えます",
      "If it turns out to be malware, change the passwords for your email, bank, GitHub, cloud and so on from another device"),
]
NOT_AV = t("BB Preflight はウイルス対策ソフトの代わりではありません。見つかった痕跡を知らせるだけです",
           "BB Preflight is not antivirus software. It only reports the traces it finds")


def flags_text(flags):
    return join([FLAG_TEXT[f] for f in flags if f in FLAG_TEXT])


def listing(rows, limit=8):
    """「名前（理由）」を並べる。多いときは残りの件数だけを書く。"""
    shown = rows[:limit]
    text = join([cat_text(same(name), t("（", " ("), why, t("）", ")")) for name, why in shown])
    if len(rows) > limit:
        text = cat_text(text, t("、ほか %d 件" % (len(rows) - limit), ", and %d more" % (len(rows) - limit)))
    return text


def autostart_levels(items):
    red, yellow = [], []
    for it in items:
        fl = set(it.get("flags") or [])
        if fl & AUTOSTART_RED:
            red.append(it)
        elif fl & {"claudeJob", "disabled", "pkg", "oclp"}:
            continue  # claude を呼ぶジョブは「AI の自動実行」で扱う。OCLP 自身のものは OCLP の Mac に必要
        elif fl & {"unsigned", "adhoc", "hiddenDir", "shared"}:
            yellow.append(it)
    return red, yellow


def threat_findings(facts, todo, good):
    autostart_findings(facts.get("autostart"), todo, good)
    disguise_findings(facts.get("disguise"), facts.get("iocUpdated", ""), todo, good)
    shell_findings(facts.get("shell"), todo, good)
    repo_findings(facts.get("openToRun"), todo, good)
    aikeys_findings(facts.get("aiKeys"), todo, good)
    ext_findings(facts.get("extensions"), todo, good)


def autostart_findings(a, todo, good):
    if a is None:
        return
    red, yellow = autostart_levels(a.get("items") or [])
    if red:
        rows = [(it["label"], flags_text(sorted(set(it["flags"]) & AUTOSTART_RED))) for it in red]
        files = join([same(it["file"]) for it in red])
        todo.append(finding(
            "autostart", RED, t("自動で起動する、怪しいものがあります", "Something suspicious starts on its own"),
            cat_text(t("Mac の起動やログインのたびに動くように登録されています: ", "These are set to run every time the Mac starts or you log in: "),
                     listing(rows), t("。登録の場所: ", ". Where they are registered: "), files),
            t("マルウェアは、Apple や Google の名前を借りてここに居座り、パスワードや鍵、ウォレットを盗み続けます。",
              "Malware often hides here under an Apple or Google name, and keeps stealing passwords, keys and wallets."),
            t("まだ消さずに、ネットから外して、詳しい人か AI に見てもらいます。", "Don't delete anything yet. Go offline and have an expert or an AI look at it."),
            HELP, MALWARE_STEPS + [NOT_AV], time=t("30分〜", "30 min or more"),
            ask_ai=t("BB Preflight が、このMacで自動で起動する怪しいものを見つけました: %s。登録の場所: %s。"
                     "それぞれの plist と、それが動かすファイルの署名（codesign -dv）と中身を調べ、マルウェアかどうかを判断してください。"
                     "ファイルの削除や launchctl での停止など、元に戻せない操作は、私に確かめてから行ってください。鍵やパスワードの値は画面に出さないでください。"
                     % (", ".join(it["label"] for it in red), files["ja"]),
                     "BB Preflight found suspicious items that start on their own on this Mac: %s. Registered in: %s. "
                     "Check each plist and the signature (codesign -dv) and contents of the file it runs, and tell me whether it is malware. "
                     "Ask me before anything that can't be undone, such as deleting files or stopping it with launchctl. Don't show any key or password values."
                     % (", ".join(it["label"] for it in red), files["en"]))))
    if yellow:
        rows = [(it["label"], flags_text(sorted(set(it["flags"]) & {"unsigned", "adhoc", "hiddenDir", "shared"}))) for it in yellow]
        todo.append(finding(
            "autostart", YELLOW, t("作り手を確かめられない自動起動が %d 個あります" % len(yellow),
                                   "%d item%s start%s on their own without a known maker" % (
                                       len(yellow), "" if len(yellow) == 1 else "s", "s" if len(yellow) == 1 else "")),
            cat_text(t("次のものが自動で動くように登録されていますが、署名から作り手が分かりません: ",
                       "These are set to run on their own, but their signature doesn't show who made them: "), listing(rows)),
            t("自分で作った仕組みや、開発の道具なら問題ありません。覚えのないものは、知らないうちに入り込んだプログラムかもしれません。",
              "If you set it up yourself, or it comes from a developer tool, that's fine. If you don't recognise it, it may be a program that got in without you knowing."),
            t("覚えのないものは、システム設定 → 一般 → ログイン項目と機能拡張 で、バックグラウンドでの実行を止めます。",
              "For any you don't recognise, stop it from running in the background in System Settings → General → Login Items & Extensions."),
            SELF, [OPEN_SETTINGS,
                   t("左の一覧で「一般」を選び、右の「ログイン項目と機能拡張」を押します",
                     "Choose General in the list on the left, then click Login Items & Extensions"),
                   t("「バックグラウンドでの実行を許可」の一覧から、上の名前に近い項目を探し、覚えのないもののスイッチをオフにします",
                     "In the \"Allow in the Background\" list, find the items that match the names above and turn off any you don't recognise"),
                   t("止めても設定ファイルは残るので、次の点検でも出ます。止めてあれば、それで大丈夫です",
                     "The setting file stays after you turn it off, so it will still appear next time. Once it's off, that's fine")],
            time=t("約5分", "About 5 min"),
            undo=t("同じスイッチをオンにすれば元に戻ります", "Turn the same switch back on to undo it"),
            keep=t("自分で作ったものや、Homebrew などの開発の道具が入れたものなら、そのままで大丈夫です",
                   "If you made it yourself, or a developer tool such as Homebrew added it, it's fine as it is")))
    if not red and not yellow:
        good("autostart", t("自動で起動するもの（%d 件）に、名前を偽ったものや、一時置き場から動くものはありませんでした。" % a.get("total", 0),
                            "None of the %d things that start on their own use a fake name or run from a temporary folder." % a.get("total", 0)))


def disguise_findings(d, updated, todo, good):
    if d is None:
        return
    fakes = [x for x in (d.get("fakes") or []) + (d.get("running") or []) if x.get("claim")]
    traces = [x["file"] for x in d.get("ioc") or []] + [x["file"] for x in d.get("fakes") or [] if not x.get("claim")]
    running = [x for x in d.get("running") or [] if not x.get("claim")]
    wallets = [x for x in d.get("wallets") or [] if x.get("tampered")]
    updated = d.get("iocUpdated") or updated
    if fakes:
        rows = [(x["file"], FLAG_TEXT["fake" + x["claim"].capitalize()]) for x in fakes]
        files = ", ".join(x["file"] for x in fakes)
        todo.append(finding(
            "disguise", RED, t("Apple や Google を名乗る偽のアプリがあります", "An app is posing as Apple or Google"),
            cat_text(t("Apple や Google の名前なのに、本物の署名がないものが見つかりました: ",
                       "These use an Apple or Google name, but don't carry that company's real signature: "), listing(rows)),
            t("2026 年に報告された Mac の情報窃取型マルウェアのほとんどが、こうした偽の名前で隠れています。パスワード・ブラウザのログイン・暗号資産が盗まれます。",
              "Most Mac info-stealers reported in 2026 hide behind fake names like these. They steal passwords, browser logins and crypto wallets."),
            t("まだ消さずに、ネットから外して、詳しい人か AI に見てもらいます。", "Don't delete anything yet. Go offline and have an expert or an AI look at it."),
            HELP, MALWARE_STEPS + [NOT_AV], time=t("30分〜", "30 min or more"),
            ask_ai=t("BB Preflight が、Apple や Google を名乗っているのに本物の署名がないファイルを見つけました: %s。"
                     "それぞれ codesign -dv と spctl -a -vv で署名を確かめ、どこから来たか（xattr -l の com.apple.quarantine など）と、"
                     "自動で起動する登録（~/Library/LaunchAgents など）がないかを調べ、マルウェアかどうか判断してください。"
                     "削除など元に戻せない操作は、私に確かめてから行ってください。" % files,
                     "BB Preflight found files that use an Apple or Google name without that company's real signature: %s. "
                     "For each, check the signature with codesign -dv and spctl -a -vv, find out where it came from (for example the "
                     "com.apple.quarantine attribute in xattr -l), look for anything that starts it automatically (such as ~/Library/LaunchAgents), "
                     "and tell me whether it is malware. Ask me before anything that can't be undone, such as deleting files." % files)))
    if traces:
        names = join([same(x) for x in traces[:8]])
        todo.append(finding(
            "disguise", RED, t("マルウェアの報告にある痕跡が見つかりました", "Traces from malware reports were found"),
            cat_text(t("2026 年のマルウェアの報告に出てくる名前や場所に、ファイルがあります: ",
                       "Files exist under names or places that appear in 2026 malware reports: "), names,
                     t("（ほか %d 件）" % (len(traces) - 8), " (and %d more)" % (len(traces) - 8)) if len(traces) > 8 else ""),
            t("盗んだパスワードやファイルを、まとめて送る準備をしているおそれがあります。",
              "Malware may be collecting stolen passwords and files here to send them out."),
            t("まだ消さずに、ネットから外して、詳しい人か AI に見てもらいます。", "Don't delete anything yet. Go offline and have an expert or an AI look at it."),
            HELP, MALWARE_STEPS + [NOT_AV], time=t("30分〜", "30 min or more"),
            ask_ai=t("BB Preflight が、マルウェアの報告にある名前のファイルを見つけました: %s。"
                     "中身の鍵やパスワードは画面に出さずに、いつ作られたか、何のプログラムが作ったか、自動で起動する登録がないかを調べ、"
                     "マルウェアかどうか判断してください。削除など元に戻せない操作は、私に確かめてから行ってください。" % ", ".join(traces),
                     "BB Preflight found files whose names appear in malware reports: %s. Without showing any keys or passwords inside them, "
                     "find out when they were created, which program created them, and whether anything starts them automatically, "
                     "then tell me whether this is malware. Ask me before anything that can't be undone, such as deleting files." % ", ".join(traces))))
    if wallets:
        apps = join([same(x["app"]) for x in wallets])
        todo.append(finding(
            "disguise", RED, t("ウォレットのアプリが書き換えられています", "A wallet app has been modified"),
            cat_text(t("次の暗号資産ウォレットのアプリの署名が、作り手のものではなくなっています: ",
                       "These crypto wallet apps no longer carry their maker's signature: "), apps),
            t("マルウェアがウォレットのアプリを差し替え、復元フレーズや送金先を盗むことがあります。",
              "Malware sometimes replaces wallet apps to steal recovery phrases or redirect payments."),
            t("そのアプリは開かずに、作り手の公式サイトから入れ直します。資産は、別の安全な機器で新しいウォレットに移します。",
              "Don't open the app. Reinstall it from the maker's official site, and move your funds to a new wallet from another safe device."),
            HELP, MALWARE_STEPS, time=t("1時間〜", "1 hour or more")))
    if running:
        rows = [(x["file"], flags_text(x.get("flags") or [])) for x in running]
        todo.append(finding(
            "disguise", YELLOW, t("一時置き場から、署名のないプログラムが動いています", "An unsigned program is running from a temporary folder"),
            cat_text(t("今動いているプログラムのうち、次のものは一時置き場などにあり、署名から作り手が分かりません: ",
                       "These running programs sit in a temporary folder or similar, and their signature doesn't show who made them: "), listing(rows)),
            t("自分で作ったプログラムを試しているところなら問題ありません。覚えのないものは、ターミナルに貼り付けたコマンドで入り込んだものかもしれません。",
              "If you are testing a program you built, that's fine. If you don't recognise it, it may have got in through a command pasted into Terminal."),
            t("覚えがなければ、ネットから外して、詳しい人か AI に見てもらいます。", "If you don't recognise it, go offline and have an expert or an AI look at it."),
            HELP, time=t("15分〜", "15 min or more"),
            keep=t("自分で作ったり試したりしているプログラムなら、そのままで大丈夫です",
                   "If it is a program you are building or testing, it's fine")))
    if not (fakes or traces or wallets or running):
        good("disguise", t("Apple や Google を名乗る偽のアプリや、既知の痕跡（%s 時点の一覧）は見つかりませんでした。" % (updated or "-"),
                           "No apps posing as Apple or Google, and no known traces (list as of %s), were found." % (updated or "-")))


def shell_findings(s, todo, good):
    if s is None:
        return
    red, yellow = [], []
    for f in s.get("files") or []:
        if f.get("othersCanWrite"):
            red.append((f["file"], t("本人以外も書き換えられる", "others can change it")))
        for h in f.get("hits") or []:
            kinds = h.get("kinds") or []
            row = ("%s:%d" % (f["file"], h["line"]), join([LINE_TEXT[k] for k in kinds if k in LINE_TEXT]))
            (red if set(kinds) & LINE_RED else yellow).append(row)
    for g in s.get("git") or []:
        if not g.get("hooks"):
            continue
        row = ("%s → %s" % (g["setting"], g["dir"]), cat_text(t("すべてのリポジトリで動くフック: ", "hooks that run in every repository: "),
                                                             same(", ".join(g["hooks"]))))
        (red if g.get("flags") else yellow).append(row)
    if red:
        todo.append(finding(
            "shell", RED, t("ターミナルやgitを使うたびに、怪しいものが動きます", "Something suspicious runs every time you use Terminal or git"),
            cat_text(t("次の場所に、怪しい書き込みがあります（行の中身はこのレポートに書いていません）: ",
                       "These places contain suspicious entries (the lines themselves are not shown in this report): "), listing(red)),
            t("2026 年の MacSync や PamStealer は、~/.zshrc や git の全体フックに書き込んで、消されても戻ってくるようにしていました。",
              "In 2026, MacSync and PamStealer wrote into ~/.zshrc and global git hooks so they came back even after being removed."),
            t("まだ消さずに、ネットから外して、詳しい人か AI に見てもらいます。", "Don't delete anything yet. Go offline and have an expert or an AI look at it."),
            HELP, MALWARE_STEPS + [NOT_AV], time=t("30分〜", "30 min or more"),
            ask_ai=t("BB Preflight が、シェルの起動ファイルか git の全体フックに怪しい書き込みを見つけました: %s。"
                     "その行やフックが何をするかを、鍵やパスワードの値を画面に出さずに説明し、マルウェアかどうか判断してください。"
                     "書き換える前に、変更の案を見せて私に確かめてください。" % ", ".join(r[0] for r in red),
                     "BB Preflight found suspicious entries in shell startup files or global git hooks: %s. Explain what each line or hook does "
                     "without showing any key or password values, and tell me whether it is malware. Show me the proposed change before editing anything."
                     % ", ".join(r[0] for r in red))))
    if yellow:
        todo.append(finding(
            "shell", YELLOW, t("ターミナルやgitを使うたびに動くものがあります", "Some things run every time you use Terminal or git"),
            cat_text(t("次の場所に、使うたびに動く書き込みがあります（行の中身はこのレポートに書いていません）: ",
                       "These places run something every time (the lines themselves are not shown in this report): "), listing(yellow)),
            t("自分で書いたものなら問題ありません。覚えのないものは、知らないうちに書き足されたのかもしれません。",
              "If you wrote it yourself, that's fine. If you don't recognise it, it may have been added without you knowing."),
            t("テキストエディットなどでそのファイルを開き、書かれた行を確かめます。覚えのない行は、先頭に # を付けて止めます。",
              "Open the file in a text editor and look at that line. Put # at the start of any line you don't recognise to turn it off."),
            SELF, time=t("約10分", "About 10 min"),
            undo=t("付けた # を消せば元に戻ります", "Remove the # to undo it"),
            keep=t("自分で書いた行や、自分で設定したフックなら、そのままで大丈夫です",
                   "If you wrote the line or set up the hook yourself, it's fine as it is"),
            ask_ai=t("BB Preflight が、シェルの起動ファイルか git の全体設定に、使うたびに動く書き込みを見つけました: %s。"
                     "それぞれ何をしているか、ふつうの言葉で説明してください。鍵やパスワードの値は画面に出さず、まだ何も変えないでください。"
                     % ", ".join(r[0] for r in yellow),
                     "BB Preflight found entries in shell startup files or global git settings that run every time: %s. "
                     "Explain in plain words what each one does. Don't show key or password values, and don't change anything yet."
                     % ", ".join(r[0] for r in yellow))))
    if not red and not yellow:
        good("shell", t("シェルの起動ファイル（%d 個）と git の全体設定に、怪しい書き込みはありませんでした。" % len(s.get("files") or []),
                        "No suspicious entries in your shell startup files (%d) or global git settings." % len(s.get("files") or [])))


def repo_findings(r, todo, good):
    if r is None:
        return
    red = [(x["file"], t("ワームが置くファイルの名前", "a file name used by an npm worm")) for x in r.get("ioc") or []]
    red += [(x["file"], t("人の目に見えない指示", "instructions hidden from human eyes")) for x in r.get("hidden") or [] if "tags" in x["kinds"]]
    yellow = [(x["file"], cat_text(t("フック: ", "hooks: "), same(", ".join(x["events"])))) for x in r.get("hooks") or []]
    yellow += [(x["file"], t("フォルダを開くと動くタスク", "a task that runs when the folder opens")) for x in r.get("tasks") or []]
    yellow += [(x["file"], t("見えない文字や向きを変える文字", "invisible or direction-changing characters"))
               for x in r.get("hidden") or [] if "tags" not in x["kinds"]]
    if red:
        files = ", ".join(x[0] for x in red)
        todo.append(finding(
            "repo", RED, t("開くだけで動く、ワームの仕掛けがあります", "A worm's trap that runs when a folder opens"),
            cat_text(t("次のファイルが見つかりました: ", "These were found: "), listing(red)),
            t("2026 年の npm ワーム（Mini Shai-Hulud 系）は、AI エージェントやエディタでフォルダを開くだけで動き、GitHub や npm、クラウドの鍵を盗んで、ほかのリポジトリにも広がりました。npm install をしなくても動きます。",
              "In 2026, npm worms (the Mini Shai-Hulud family) ran as soon as a folder was opened in an AI agent or editor, stole GitHub, npm and cloud keys, "
              "and spread to other repositories. They run even without npm install."),
            t("そのフォルダを AI エージェントやエディタで開かずに、詳しい人か AI に、ほかの場所から見てもらいます。鍵は作り直します。",
              "Don't open that folder in an AI agent or editor. Have an expert or an AI look at it from elsewhere, and replace your keys."),
            HELP, [t("そのフォルダを Claude Code・Cursor・VS Code などで開かないでください", "Don't open that folder in Claude Code, Cursor, VS Code or similar")]
            + MALWARE_STEPS[1:] + [NOT_AV], time=t("1時間〜", "1 hour or more"),
            ask_ai=t("BB Preflight が、開くだけで動くワームの仕掛けらしいファイルを見つけました: %s。そのフォルダではなく、ホームフォルダから作業してください。"
                     "ファイルの中身を実行せずに読んで、何をするものか、git の履歴でいつ入ったかを調べてください。"
                     "鍵の値は画面に出さず、削除や鍵の作り直しは私に確かめてから行ってください。" % files,
                     "BB Preflight found files that look like a worm's open-to-run trap: %s. Work from my home folder, not from inside that folder. "
                     "Read the files without running them, explain what they do, and use git history to find when they arrived. "
                     "Don't show key values, and ask me before deleting files or replacing keys." % files)))
    if yellow:
        todo.append(finding(
            "repo", YELLOW, t("フォルダを開くと自動で動く設定があります", "Some folders run things automatically when opened"),
            cat_text(t("次のプロジェクトに、開いたときや AI の作業中に自動で動く設定があります: ",
                       "These projects have settings that run things when opened or while an AI is working: "), listing(yellow)),
            t("自分で入れた設定なら問題ありません。人から受け取ったリポジトリや、ダウンロードしたプロジェクトに入っていたなら、ワームの仕掛けかもしれません。",
              "If you added them yourself, that's fine. If they came in a repository someone sent you or a project you downloaded, they may be a worm's trap."),
            t("そのファイルを開いて、自分で入れた設定か確かめます。覚えのないものは、そのフォルダを AI エージェントやエディタで開く前に消します。",
              "Open the file and check that you added it. If you don't recognise it, remove it before opening the folder in an AI agent or editor."),
            SELF, time=t("約10分", "About 10 min"),
            keep=t("自分で作ったフックやタスクなら、そのままで大丈夫です", "If you made the hooks or tasks yourself, they're fine as they are"),
            ask_ai=t("BB Preflight が、フォルダを開くと自動で動く設定を見つけました: %s。それぞれ、何を実行するのか、"
                     "git の履歴でいつ・誰が入れたのかを、実行せずに調べて説明してください。まだ何も変えないでください。" % ", ".join(x[0] for x in yellow),
                     "BB Preflight found settings that run things when a folder opens: %s. Without running anything, explain what each one runs, "
                     "and use git history to find when and by whom it was added. Don't change anything yet." % ", ".join(x[0] for x in yellow))))
    if not red and not yellow:
        good("repo", t("走査範囲のプロジェクトに、開くだけで動く仕掛けや、AI への見えない指示はありませんでした。",
                       "No open-to-run traps or hidden AI instructions were found in the projects we checked."))


CRED_NAME = {"git": "Git", "npm": "npm", "gh": "GitHub CLI", "docker": "Docker", "netrc": ".netrc", "pypi": "PyPI",
             "aws": "AWS", "codex": "Codex", "gemini": "Gemini CLI", "copilot": "GitHub Copilot", "claude": "Claude Code"}
PLAIN_FIX = {
    "git": t("git config --global credential.helper osxkeychain にして、~/.git-credentials を消します",
             "Run git config --global credential.helper osxkeychain, then delete ~/.git-credentials"),
    "npm": t("~/.npmrc の _authToken を消し、npm login でやり直すか、${NPM_TOKEN} のように環境変数から読む形にします",
             "Remove _authToken from ~/.npmrc and log in again with npm login, or read it from an environment variable like ${NPM_TOKEN}"),
    "gh": t("gh auth logout のあと gh auth login でやり直すと、キーチェーンに保存されます",
            "Run gh auth logout, then gh auth login, so the token is stored in Keychain"),
    "docker": t("~/.docker/config.json に \"credsStore\": \"osxkeychain\" を入れて、docker login をやり直します",
                "Add \"credsStore\": \"osxkeychain\" to ~/.docker/config.json and run docker login again"),
    "netrc": t("~/.netrc のパスワードは、パスワード管理アプリかキーチェーンに移します", "Move the passwords in ~/.netrc to a password manager or Keychain"),
    "pypi": t("~/.pypirc のパスワードを消し、keyring を使う形にします", "Remove the password from ~/.pypirc and use keyring instead"),
}


def aikeys_findings(k, todo, good):
    if not k or not any(k.get(x) for x in ("credFiles", "mcp", "cli")):
        return
    creds = k.get("credFiles") or []
    # 鍵を入れるための置き場所（plain が None）か、平文の鍵が見つかったものだけ。鍵の無い設定ファイルは読めても困らない
    open_files = [c for c in creds if c.get("private") is False and c.get("plain") is not False]
    plain = [c for c in creds if c.get("plain") and c.get("private") is not False and c["kind"] in PLAIN_FIX]
    mcp = k.get("mcp") or []
    mcp_keys = [m for m in mcp if m.get("secretValues")]
    mcp_http = [m for m in mcp if m.get("insecureUrl")]
    old = [c for c in k.get("cli") or [] if c.get("old")]
    if open_files:
        files = join([same(c["file"]) for c in open_files])
        todo.append(finding(
            "aikeys", RED, t("鍵のファイルが、ほかのユーザーやアプリからも読めます", "Key files can be read by other users and apps"),
            cat_text(t("次のファイルは、AI ツールや開発の道具の鍵を入れる場所ですが、本人以外も読める設定です: ",
                       "These files hold keys for AI or developer tools, but people other than you can read them: "), files),
            t("npm ワームなどは、まさにこうしたファイルを読んで鍵を盗みます。",
              "npm worms and similar malware read exactly these files to steal keys."),
            t("ターミナルで chmod 600 ファイル名 を実行して、本人だけが読めるようにします。",
              "Run chmod 600 <file> in Terminal so only you can read it."),
            SELF, [t("「アプリケーション」→「ユーティリティ」から「ターミナル」を開きます", "Open Terminal from Applications → Utilities"),
                   t("chmod 600 %s と入力して return を押します" % " ".join(c["file"] for c in open_files),
                     "Type chmod 600 %s and press return" % " ".join(c["file"] for c in open_files)),
                   RECHECK],
            time=t("約1分", "About 1 min"),
            undo=t("chmod 644 ファイル名 で元に戻ります（戻す理由はふつうありません）", "chmod 644 <file> undoes it (there is usually no reason to)")))
    if plain or mcp_keys:
        rows = [(c["file"], cat_text(same(CRED_NAME.get(c["kind"], c["kind"])), t(" の鍵が平文", " key in plain text"))) for c in plain]
        rows += [("%s（%s）" % (m["name"], m["app"]), t("MCP の設定に鍵が直接", "key written straight into the MCP settings")) for m in mcp_keys]
        steps = [PLAIN_FIX[c["kind"]] for c in plain]
        if mcp_keys:
            steps.append(t("MCP の設定の env に書いた鍵は、キーチェーンや環境変数から読む形にします（例: \"${GITHUB_TOKEN}\"）",
                           "For keys in an MCP server's env settings, read them from Keychain or an environment variable instead (for example \"${GITHUB_TOKEN}\")"))
        todo.append(finding(
            "aikeys", YELLOW, t("AI ツールや開発の道具の鍵が、平文で置かれています", "Keys for AI and developer tools are stored in plain text"),
            cat_text(t("次の場所に、鍵がそのまま書かれています（鍵の値はこのレポートに書いていません）: ",
                       "Keys are written as they are in these places (the values are not shown in this report): "), listing(rows)),
            t("2026 年の npm ワームや情報窃取型マルウェアは、こうした設定ファイルを真っ先に読みます。MCP の設定から漏れた鍵も多く報告されています。",
              "In 2026, npm worms and info-stealers went straight for these settings files. Many keys have also leaked from MCP settings."),
            steps[0], SELF, steps + [RECHECK], time=t("約15分", "About 15 min"),
            keep=t("本人しか読めない設定で、AI に怪しいものを読ませないなら、すぐ危ないわけではありません",
                   "If only you can read it and your AI never reads untrusted content, it's not an urgent danger"),
            ask_ai=t("BB Preflight が、次の場所に平文の鍵を見つけました: %s。鍵の値は画面に出さずに、キーチェーンや環境変数から読む形に変える手順を、"
                     "私の環境に合わせて案内してください。書き換える前に、変更の案を見せて私に確かめてください。" % ", ".join(r[0] for r in rows),
                     "BB Preflight found plain-text keys in: %s. Without showing the key values, walk me through moving them to Keychain or environment "
                     "variables for my setup. Show me the proposed change before editing anything." % ", ".join(r[0] for r in rows))))
    if mcp_http:
        names = join([same("%s（%s）" % (m["name"], m["app"])) for m in mcp_http])
        todo.append(finding(
            "aikeys", YELLOW, t("暗号化されていない通信の MCP があります", "An MCP server uses an unencrypted connection"),
            cat_text(t("次の MCP サーバーは、インターネットの先に http（暗号化なし）でつながっています: ",
                       "These MCP servers connect over the internet with plain http (no encryption): "), names),
            t("通り道で中身やトークンを読まれたり、返事を書き換えられて AI に悪い指示を入れられたりします。",
              "Anyone along the way can read the traffic and tokens, or change the replies to slip bad instructions to your AI."),
            t("その MCP の URL を https に変えます。https に対応していないサーバーは使わないようにします。",
              "Change that MCP server's URL to https. Stop using servers that don't support https."),
            SELF, time=t("約5分", "About 5 min")))
    if old:
        rows = [(c["name"], t("%s（%s より前の版に既知の脆弱性 %s）" % (c["version"], c["fixed"], c["cve"]),
                              "%s (versions before %s have known flaw %s)" % (c["version"], c["fixed"], c["cve"]))) for c in old]
        todo.append(finding(
            "aikeys", YELLOW, t("AI ツールに、直った版があります", "A fixed version of an AI tool is available"),
            cat_text(t("次の AI ツールは、既知の脆弱性が直る前の版です: ", "These AI tools are older than the version that fixes a known flaw: "), listing(rows)),
            t("悪いリポジトリや設定を開いたとき、確認なしでコマンドを動かされたり、鍵を外へ送られたりするおそれがあります。",
              "Opening a malicious repository or settings file could make the tool run commands without asking, or send your keys out."),
            t("その AI ツールを最新の版にします（macOS 本体のアップデートとは別です）。",
              "Update that AI tool to the latest version (this is separate from macOS updates)."),
            SELF, time=t("約5分", "About 5 min"),
            keep=t("macOS の版は変わりません。AI ツールだけの更新です", "This doesn't change your macOS version. Only the AI tool is updated")))
    if not (open_files or plain or mcp_keys or mcp_http or old):
        unp = len([m for m in mcp if m.get("unpinned")])
        extra = t("（版を固定せずに毎回取ってくる MCP が %d 個あります。気になるなら版を固定します）" % unp,
                  " (%d MCP server%s fetch%s the latest version every time; pin the version if that worries you)" % (
                      unp, "" if unp == 1 else "s", "es" if unp == 1 else "")) if unp else t("", "")
        good("aikeys", cat_text(t("AI ツールや開発の道具の鍵の置き方、MCP の設定、AI ツールの版に、気になるものはありませんでした。",
                                  "Nothing worrying in how AI and developer tool keys are stored, in MCP settings, or in AI tool versions."), extra))


def ext_findings(e, todo, good):
    if not e:
        return
    items = e.get("items") or []
    bad = [x for x in items if x.get("bad")]
    side = [x for x in items if not x.get("bad")]
    if bad:
        names = join([same("%s（%s）" % (x["name"], x["browser"])) for x in bad])
        todo.append(finding(
            "ext", RED, t("AI の会話を盗むと報告された拡張機能が入っています", "An extension reported to steal AI chats is installed"),
            cat_text(t("次の拡張機能は、AI との会話を外へ送ると報告されたものです: ", "These extensions were reported to send your AI chats out: "), names),
            t("ChatGPT や Claude などとの会話の中身、そこに貼った鍵や仕事の情報が、知らない人に送られます。",
              "The contents of your chats with ChatGPT, Claude and others, including keys or work details you pasted, go to strangers."),
            t("ブラウザの拡張機能の管理画面（chrome://extensions など）で、その拡張機能を削除します。会話に貼ったことのある鍵は作り直します。",
              "Remove the extension in your browser's extension page (such as chrome://extensions). Replace any keys you ever pasted into a chat."),
            SELF, time=t("約10分", "About 10 min")))
    if side:
        rows = [(x["name"], cat_text(same(x["browser"]), t("・ストアの外から", ", not from the store"))) for x in side]
        todo.append(finding(
            "ext", YELLOW, t("ストアの外から入った拡張機能があります", "Some extensions didn't come from the store"),
            cat_text(t("次の拡張機能は、ブラウザの公式ストア以外から入っています: ", "These extensions came from somewhere other than the browser's store: "),
                     listing(rows)),
            t("マルウェアは、ブラウザに自分の拡張機能を入れて、ログインやウォレットを盗むことがあります。",
              "Malware sometimes adds its own browser extension to steal logins and wallets."),
            t("拡張機能の管理画面で、覚えのないものを削除します。", "Remove any you don't recognise in the browser's extension page."),
            SELF, time=t("約5分", "About 5 min"),
            keep=t("自分で作った拡張機能や、会社が入れたものなら、そのままで大丈夫です",
                   "Extensions you built yourself, or ones your company installed, are fine")))
    if not items:
        good("ext", t("ブラウザ（%s）の拡張機能 %d 個は、すべて公式ストアから入ったもので、既知の悪いものはありませんでした。" % (
            "・".join(e.get("browsers") or []), e.get("total", 0)),
            "All %d extensions in your browser%s (%s) came from the official store, and none are known to be bad." % (
                e.get("total", 0), "" if len(e.get("browsers") or []) == 1 else "s", ", ".join(e.get("browsers") or []))))


# 構成図の3列: だれが → 入口（このMac・サイト・AI）→ その先（データ・外部サービス・鍵）
DIAGRAM_COL = {"USER": 0, "SMARTPHONE": 0,
               "PC": 1, "FRONT_END_SERVER": 1, "PROCESS": 1, "AGENT": 1}
OUTSIDERS = ("n-lan-other", "n-internet")  # 本人以外がつないでくる起点


# 構成図のラベルは評価エンジン向けに日本語で作っている。ツールが付けた部分だけを英語に置き換える
# （台帳に自分で書いた名前は、そのまま残る）
LABEL_EN = [
    (r"^本人$", "You"),
    (r"^このMac", "This Mac"),
    (r"（ファイアウォール: 有効）", " (firewall on)"), (r"（ファイアウォール: 無効）", " (firewall off)"),
    (r"^同じLAN上の他の機器・来訪者$", "Other devices and visitors on the LAN"),
    (r"^本人の端末（Tailscale 経由）$", "Your devices (via Tailscale)"),
    (r"^インターネット上の利用者・第三者$", "People on the internet"),
    (r"随時変わるポート", "changing port"),
    (r"（127\.0\.0\.1のみ）", " (127.0.0.1 only)"), (r"（Tailscale のみ）", " (Tailscale only)"),
    (r"（全インターフェース）", " (all interfaces)"),
    (r"^解約済みのはずの入口が応答: ", "Retired but still answers: "),
    (r"^Claude Code（このMac・プラグイン (\d+) 個）", r"Claude Code (this Mac, \1 plugins)"),
    (r"^ローカル MCP: ", "Local MCP: "),
    (r"（送信・書き込み可）", " (can send and write)"),
    (r"^定期ジョブ: ", "Scheduled job: "),
    (r"^平文の鍵の疑い: (.*)（(.*)）$", r"Possible plain-text key: \1 (\2)"),
    (r"（root 所有・名前不明）", "(root-owned, name unknown)"),
    (r"（名前不明）", "(unknown name)"),
]
# 台帳の名前を置き換えたあとに、残った全角の括弧などをそろえる
LABEL_EN_LAST = [(r"（例）", " (example)"), (r"（(.*?)）", r" (\1)")]


# 台帳の portNames に書くことが多い名前の英語（portNamesEn がなければこれを使う）
PORT_NAMES_EN = {"22": "Remote Login (SSH)", "88": "Kerberos (for sharing)", "445": "File Sharing (SMB)",
                 "548": "File Sharing (AFP)", "631": "Printer Sharing (CUPS)", "3283": "Remote Management",
                 "5900": "Screen Sharing"}


def inventory_names_en(inv):
    """台帳に書いた名前の英語版（labelEn・portNamesEn）を、日本語→英語の組で返す。"""
    pairs = []
    if not inv:
        return pairs
    en_ports = dict(PORT_NAMES_EN, **(inv.get("portNamesEn") or {}))
    for port, ja in (inv.get("portNames") or {}).items():
        if en_ports.get(str(port)):
            pairs.append((ja, en_ports[str(port)]))
    items = list(inv.get("publicSites") or []) + list(inv.get("dataStores") or []) + list(inv.get("saas") or [])
    items += list((inv.get("aiConnectors") or {}).get("items") or [])
    items += [d["pii"] for d in inv.get("dataStores") or [] if isinstance(d.get("pii"), dict)]
    mac = inv.get("mac") or {}
    for x in items + [mac]:
        if isinstance(x, dict) and x.get("label") and x.get("labelEn"):
            pairs.append((x["label"], x["labelEn"]))
    return sorted(pairs, key=lambda p: -len(p[0]))


def label_en(ja, names=()):
    en = ja
    for pat, rep in LABEL_EN:
        en = re.sub(pat, rep, en)
    for a, b in names:
        if a and a in en:
            en = en.replace(a, b)
    for pat, rep in LABEL_EN_LAST:
        en = re.sub(pat, rep, en)
    return en


def diagram(model, names=()):
    """model.json（自動で作った構成図）を、レポートの中に描ける形にする。ラベルは構成図のまま。"""
    layer = ((model or {}).get("layers") or {}).get("L1") or {}
    nodes = [n for n in layer.get("nodes", []) if n.get("id")]
    if not nodes:
        return None
    ids = {n["id"] for n in nodes}
    edges = [e for e in layer.get("edges", []) if e.get("source") in ids and e.get("target") in ids]
    out = [{"id": n["id"], "label": t(str(n.get("label") or n["id"]), label_en(str(n.get("label") or n["id"]), names)),
            "type": n.get("type", ""),
            "col": DIAGRAM_COL.get(n.get("type"), 2)} for n in nodes]
    # 外の人がつながれる入口と、そこから先は「ほかの人が届く道」として色を変える
    reach, todo_ids = set(OUTSIDERS) & ids, list(set(OUTSIDERS) & ids)
    while todo_ids:
        cur = todo_ids.pop()
        for e in edges:
            if e["source"] == cur and e["target"] not in reach:
                reach.add(e["target"])
                todo_ids.append(e["target"])
    for n in out:
        n["outside"] = n["id"] in reach
    return {"nodes": out, "edges": [[e["source"], e["target"], e["source"] in reach] for e in edges]}


def present(facts):
    """チェックリストに出す項目。実測できなかったものは出さない。"""
    has = {
        "npm": (facts.get("npm") or {}).get("used"),
        "aiperm": (facts.get("aiPermissions") or {}).get("files"),
        "guard": any(v is not None for k, v in (facts.get("macGuard") or {}).items() if k in ("sip", "gatekeeper")),
        "update": bool(facts.get("updates")),
        "disk": (facts.get("fileVault") or {}).get("on") is not None,
        "ssh": bool(facts.get("sshKeys")),
        "backup": bool(facts.get("timeMachine")),
        "autostart": facts.get("autostart") is not None,
        "disguise": facts.get("disguise") is not None,
        "shell": facts.get("shell") is not None,
        "repo": facts.get("openToRun") is not None,
        "aikeys": any((facts.get("aiKeys") or {}).get(k) for k in ("credFiles", "mcp", "cli")),
        "ext": bool(facts.get("extensions")),
    }
    skip = [c for c in OPTIONAL if not has.get(c)]
    if "remoteApps" not in facts:
        skip.append("remote")
    return skip


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
    # 古い版はフルパス、今の版は ~/… で記録しているので、そろえて比べる
    home = lambda p: re.sub(r"^/Users/[^/]+", "~", p)
    a = {home(h["file"]) for h in prev.get("secrets", [])}
    b = {home(h["file"]) for h in cur.get("secrets", [])}
    better += [t("鍵が書かれたファイルが片付きました: %s" % x, "A file with a key in it was cleaned up: %s" % x)
               for x in sorted(a - b)]
    worse += [t("鍵が書かれたファイルが増えました: %s" % x, "A new file with a key in it was found: %s" % x)
              for x in sorted(b - a)]
    # 自動で起動するものは、前回も実測していたときだけ比べる（1.2.0 より前の結果と比べて全部「増えた」にしない）
    if prev.get("autostart") is not None and cur.get("autostart") is not None:
        a = {x["label"] for x in prev["autostart"].get("items", [])}
        b = {x["label"] for x in cur["autostart"].get("items", [])}
        worse += [t("自動で起動するものが増えました: %s" % x, "Something new starts on its own: %s" % x) for x in sorted(b - a)]
        better += [t("自動で起動するものが減りました: %s" % x, "Something no longer starts on its own: %s" % x) for x in sorted(a - b)]
    if prev.get("disguise") is not None and cur.get("disguise") is not None:
        sus = lambda d: {x["file"] for x in (d.get("fakes") or []) + (d.get("ioc") or [])}
        a, b = sus(prev["disguise"]), sus(cur["disguise"])
        worse += [t("怪しいファイルが見つかりました: %s" % x, "A suspicious file was found: %s" % x) for x in sorted(b - a)]
        better += [t("怪しいファイルがなくなりました: %s" % x, "A suspicious file is gone: %s" % x) for x in sorted(a - b)]
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
        "checks": checks(todo, present(facts)),
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
        # 台帳は out/<日時>/ の2つ上（~/.bb-preflight/inventory.json）にある
        inv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(out))), "inventory.json")
        inv = None
        if os.path.exists(inv_path):
            try:
                with open(inv_path, encoding="utf-8") as f:
                    inv = json.load(f)
            except ValueError:
                inv = None
        with open(model, encoding="utf-8") as f:
            data["diagram"] = diagram(json.load(f), inventory_names_en(inv))
    if os.path.exists(model) and os.path.isdir(os.path.join(HERE, "vendor", "CyberRiskScape", "node_modules")):
        data["modelPath"] = os.path.abspath(model)
        data["engineDir"] = os.path.join(HERE, "vendor", "CyberRiskScape")
        data["diagramCommand"] = os.path.join(HERE, "Diagram.command")
    path = os.path.join(out, "report.html")
    # 中身は自分の弱点の地図なので、run.sh の外から呼ばれても本人しか読めないようにする
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(page(data))
    os.chmod(path, 0o600)


if __name__ == "__main__":
    main()
