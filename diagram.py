"""最新の構成図（model.json）を、評価エンジン CyberRiskScape のブラウザ版で開く（専門家向け）。

評価エンジンは書き換えない。ビルド済みの画面（vendor/CyberRiskScape/dist）をこのMacの中だけ（127.0.0.1）で配り、
同じ場所に小さな読み込みページを足す。読み込みページは、ブラウザ版がふだん自動保存に使う場所（IndexedDB）へ
構成図を入れてから、ブラウザ版を開く。ブラウザ版で作業中だった図は、消さずに別名で残す。
ターミナルを閉じるか control + C で終わる。開きっぱなしにしないよう、30 分たつと自動で止まる。

構成図は「弱点の地図」なので、ほかのサイトや同じ Mac の別の人からは読めないようにする。
- Host が 127.0.0.1 / localhost でない要求は断る（悪意のあるサイトが DNS リバインディングで読みに来るのを防ぐ）。
- 起動ごとに合言葉（トークン）を作り、読み込みページと構成図の取得で照合する。合言葉はブラウザで開く URL にだけ載る。

読み込みページは、ブラウザ版の内部の保存形式に合わせている。評価エンジンの版（setup.sh の CRS_TAG）を上げるときは、
読み込めるかを確かめてからにする。読み込めなかったときも、作業中の図は残り、点検には影響しない。
"""
import functools
import hmac
import http.server
import json
import os
import secrets
import socketserver
import sys
import threading
import urllib.parse
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "vendor", "CyberRiskScape", "dist")
PORT = 4180  # 毎回同じ番号にして、ブラウザ版の保存場所（番号ごとに分かれる）をそろえる
STOP_AFTER = 30 * 60

# ブラウザ版の保存場所の名前（v0.6.0 の src/features/persistence/db.ts と同じ）
LOADER = """<!doctype html><meta charset="utf-8"><title>Preflight</title>
<body style="font:15px system-ui;background:#16191e;color:#e4e8ec;padding:24px">
<p id="m">構成図を読み込んでいます… / Loading the diagram…</p>
<script>
(async function () {
  var say = function (t) { document.getElementById("m").textContent = t; };
  try {
    var t = new URLSearchParams(location.search).get("t") || "";
    var res = await fetch("/__preflight/model.json?t=" + encodeURIComponent(t), { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    var model = await res.json();
    history.replaceState(null, "", location.pathname);  // 合言葉を履歴に残さない
    var open = function (v) { return new Promise(function (ok, ng) {
      var r = v ? indexedDB.open("cyberriskscape", v) : indexedDB.open("cyberriskscape");
      r.onupgradeneeded = function () { if (!r.result.objectStoreNames.contains("projects")) r.result.createObjectStore("projects"); };
      r.onsuccess = function () { ok(r.result); }; r.onerror = function () { ng(r.error); };
    }); };
    var db = await open();
    if (!db.objectStoreNames.contains("projects")) { var v = db.version + 1; db.close(); db = await open(v); }
    await new Promise(function (ok, ng) {
      var tx = db.transaction("projects", "readwrite"), st = tx.objectStore("projects");
      var g = st.get("default");
      g.onsuccess = function () {
        // ブラウザ版で作業中だった図は、別名で残してから置き換える
        if (g.result !== undefined) st.put(g.result, "backup-" + new Date().toISOString());
        st.put(model, "default");
      };
      tx.oncomplete = ok; tx.onerror = function () { ng(tx.error); };
    });
    db.close();
    location.replace("/");
  } catch (e) {
    say("読み込めませんでした / Could not load the diagram: " + e);
  }
})();
</script>"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, model=None, token="", **kw):
        self.model = model
        self.token = token
        super().__init__(*a, **kw)

    def host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in ("127.0.0.1:%d" % port, "localhost:%d" % port)

    def token_ok(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        given = (query.get("t") or [""])[0]
        return bool(self.token) and hmac.compare_digest(given.encode(), self.token.encode())

    def do_GET(self):
        if not self.host_ok():
            self.send_error(403)
            return
        if self.path.startswith("/__preflight/"):
            if not self.token_ok():
                self.send_error(403)
                return
            if self.path.startswith("/__preflight/model.json"):
                body, ctype = self.model, "application/json"
            else:
                body, ctype = LOADER.encode("utf-8"), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_HEAD(self):
        if not self.host_ok() or self.path.startswith("/__preflight/"):
            self.send_error(403)
            return
        super().do_HEAD()

    def log_message(self, *a):
        pass


def main():
    data = os.environ.get("BB_PREFLIGHT_HOME") or os.path.expanduser("~/.bb-preflight")
    model = os.path.join(data, "model.json")
    if not os.path.isfile(os.path.join(DIST, "index.html")):
        sys.exit("評価エンジンのブラウザ版がありません。先に ./setup.sh --with-engine を実行してください。")
    if not os.path.isfile(model):
        sys.exit("構成図がまだありません。先に点検（Preflight.command）を一度実行してください。")
    with open(model, "rb") as f:
        body = f.read()
    json.loads(body)  # 壊れていたらここで止める
    token = secrets.token_urlsafe(32)
    handler = functools.partial(Handler, directory=DIST, model=body, token=token)
    socketserver.TCPServer.allow_reuse_address = True
    try:
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), handler)
    except OSError:
        sys.exit("ポート %d が使われています。前に開いた構成図のターミナルを閉じてから、もう一度開いてください。" % PORT)
    url = "http://127.0.0.1:%d/__preflight/load.html?t=%s" % (PORT, token)
    print("構成図を開きます: %s" % url)
    print("このMacの中だけで配っています（ほかの機器からは見えません）。終わるときは、このウインドウを閉じます。", flush=True)
    if not os.environ.get("BB_PREFLIGHT_NO_BROWSER"):
        threading.Timer(0.5, webbrowser.open, [url]).start()
    stop = threading.Timer(STOP_AFTER, srv.shutdown)
    stop.daemon = True
    stop.start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    print("構成図の配信を止めました。")


if __name__ == "__main__":
    main()
