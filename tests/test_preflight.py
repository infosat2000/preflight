"""Preflight（FOREST LIFE*）の単体テスト。標準ライブラリだけで動く（macOS 標準の python3 3.9 を想定）。

実行: python3 -m unittest discover -s tests
CyberRiskScape の CLI があれば（vendor/ か CRS_CLI）、評価まで通す結合テストも走る。
"""
import copy
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import build  # noqa: E402
import collect  # noqa: E402
import report  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
EXAMPLE_INV = os.path.join(ROOT, "examples", "inventory.example.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def facts():
    return load(os.path.join(FIX, "facts.json"))


def inventory():
    return load(EXAMPLE_INV)


def nodes_by_id(m):
    return {n["id"]: n for n in m.nodes}


def risky_mac(f):
    """新しい点検項目を、すべて悪い側にした facts。"""
    f["aiPermissions"] = {"files": 2, "bypass": ["~/.claude/settings.json"],
                          "broad": [{"file": "~/.claude/settings.local.json", "rule": "Bash(*)", "kind": "any"},
                                    {"file": "~/.claude/settings.local.json", "rule": "Bash(python3:*)", "kind": "code"}],
                          "mcpWide": ["filesystem"]}
    f["fileVault"] = {"on": False, "oclp": False, "laptop": True}
    f["sshKeys"] = [{"file": "~/.ssh/id_ed25519", "encrypted": False}, {"file": "~/.ssh/work", "encrypted": True}]
    f["remoteApps"] = ["AnyDesk"]
    f["timeMachine"] = {"configured": True, "lastBackupAt": "2026-08-01T09:00"}
    f["macGuard"] = {"sip": "off", "gatekeeper": False, "autoLogin": True, "oclp": False}
    f["updates"] = {"check": False, "securityData": False, "oclp": False}
    return f


class ClassifyAddrTest(unittest.TestCase):
    def test_scopes(self):
        cases = {
            "*:22": "all",
            "0.0.0.0:80": "all",
            "[::]:443": "all",
            "127.0.0.1:5678": "loopback",
            "[::1]:5678": "loopback",
            "100.64.0.1:4880": "tailscale",
            "100.127.255.254:4880": "tailscale",
            "100.128.0.1:4880": "lan",
            "192.168.1.10:445": "lan",
            "localhost:80": "unknown",
        }
        for addr, want in cases.items():
            self.assertEqual(collect.classify_addr(addr), want, addr)


class PortProbeTest(unittest.TestCase):
    def test_open_and_closed_port(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(collect.port_open("127.0.0.1", port))
        finally:
            srv.close()
        self.assertFalse(collect.port_open("127.0.0.1", port, timeout=0.5))

    def test_lan_ips_are_lan_scope(self):
        for ip in collect.lan_ips():
            self.assertEqual(collect.classify_addr(ip + ":0"), "lan")


class SecretScanTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_detects_real_looking_keys_without_values(self):
        # 本物に見える文字列は実行時に組み立てる（リポジトリ自体が鍵スキャナに引っかからないように）
        key = "sk-" + "ant-" + "a1B2c3D4e5F6g7H8i9J0kLmNoPq"
        p = self.write("app/.env", "ANTHROPIC_API_KEY=%s\n" % key)
        hits = collect.secret_scan([self.root])
        self.assertEqual([{k: h[k] for k in ("file", "kinds")} for h in hits], [{"file": p, "kinds": ["anthropic"]}])
        self.assertEqual(set(hits[0]), {"file", "kinds", "private", "gitIgnored"})  # never the value
        self.assertNotIn(key, json.dumps(hits))

    def test_home_is_shortened_and_depth_is_limited(self):
        key = "sk-" + "ant-" + "a1B2c3D4e5F6g7H8i9J0kLmNoPq"
        self.write("app/.env", "ANTHROPIC_API_KEY=%s\n" % key)
        self.write("/".join("d%d" % i for i in range(collect.SCAN_DEPTH + 1)) + "/.env", "K=%s\n" % key)
        old = collect.HOME
        collect.HOME = self.root
        try:
            hits = collect.secret_scan([self.root])
        finally:
            collect.HOME = old
        self.assertEqual([h["file"] for h in hits], ["~/app/.env"])     # too-deep file skipped, no user name
        import easy_report
        prev = {"secrets": [{"file": "/Users/someone/app/.env"}]}
        self.assertEqual(easy_report.changes(prev, {"secrets": [{"file": "~/app/.env"}]}),
                         {"better": [], "worse": []})                  # older full paths still match

    def test_own_folder_is_skipped(self):
        # このツールのテストには偽の鍵があるので、ツール自身のフォルダは見ない
        key = "sk-" + "ant-" + "a1B2c3D4e5F6g7H8i9J0kLmNoPq"
        self.write("tool/tests/fixture.py", "K = '%s'\n" % key)
        self.write("app/.env", "K=%s\n" % key)
        old = collect.TOOL_DIR
        collect.TOOL_DIR = os.path.realpath(os.path.join(self.root, "tool"))
        try:
            hits = collect.secret_scan([self.root])
        finally:
            collect.TOOL_DIR = old
        self.assertEqual([os.path.basename(h["file"]) for h in hits], [".env"])

    def test_scanning_this_tool_finds_nothing(self):
        # ツールを ~/Claude の下などに置き、鍵の検索範囲に入っても、自分自身は見つからない
        self.assertEqual(collect.secret_scan([collect.TOOL_DIR]), [])
        old = collect.TOOL_DIR
        collect.TOOL_DIR = "/nonexistent"
        try:
            # 除外を外しても、このツールのコードとテストには鍵と見えるものがない
            self.assertEqual([h["file"] for h in collect.secret_scan([old])], [])
        finally:
            collect.TOOL_DIR = old

    def test_results_folder_is_skipped(self):
        key = "sk-" + "ant-" + "a1B2c3D4e5F6g7H8i9J0kLmNoPq"
        self.write("bb/out/1/facts.txt", "K=%s\n" % key)
        old = os.environ.get("BB_PREFLIGHT_HOME")
        os.environ["BB_PREFLIGHT_HOME"] = os.path.join(self.root, "bb")
        try:
            self.assertEqual(collect.secret_scan([self.root]), [])
        finally:
            if old is None:
                del os.environ["BB_PREFLIGHT_HOME"]
            else:
                os.environ["BB_PREFLIGHT_HOME"] = old

    def test_npm_token(self):
        tok = "npm" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        self.write(".npmrc", "//registry.npmjs.org/:_authToken=%s\n" % tok)
        self.assertEqual([h["kinds"] for h in collect.secret_scan([self.root])], [["npm"]])

    def test_ignores_placeholders_and_skipped_dirs(self):
        self.write("app/.env.example", "KEY=sk-" + "ant-xxxxxxxxxxxxxxxxxxxxxxxxxx\n")
        self.write("app/README.md", "KEY=sk-" + "ant-your-key-goes-here-0000000000\n")
        self.write("node_modules/pkg/.env", "KEY=sk-" + "ant-a1B2c3D4e5F6g7H8i9J0kLmNoPq\n")
        self.write("vendor/x/.env", "KEY=gsk_" + "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV\n")
        self.assertEqual(collect.secret_scan([self.root]), [])

    def test_private_key(self):
        head = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
        self.write("keys/id.txt", head + "\n" + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB" + "\n")
        self.write("docs/howto.md", "Look for a line like `" + head + "` in the file.\n")   # heading only: not a key
        self.write("code/check.py", "if %r in text:\n    pass\n" % head)
        hits = collect.secret_scan([self.root])
        self.assertEqual([(os.path.basename(h["file"]), h["kinds"]) for h in hits], [("id.txt", ["private_key"])])


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.m = build.build(inventory(), facts())
        self.nodes = nodes_by_id(self.m)
        self.edges = {(e["source"], e["target"]): e for e in self.m.edges}

    def test_node_ids_come_from_measurements(self):
        # 固定ポートはポート番号、随時変わるポートはプロセス名から ID を作る
        for nid in ("n-all-22", "n-all-4870", "n-all-helper-app", "n-tailscale-4880", "n-loopback-5678"):
            self.assertIn(nid, self.nodes)

    def test_same_input_gives_same_ids(self):
        again = build.build(inventory(), facts())
        self.assertEqual([n["id"] for n in self.m.nodes], [n["id"] for n in again.nodes])
        self.assertEqual([e["id"] for e in self.m.edges], [e["id"] for e in again.edges])

    def test_loopback_has_no_incoming_edge(self):
        self.assertEqual(self.nodes["n-loopback-5678"]["type"], "PROCESS")
        self.assertFalse([e for e in self.m.edges if e["target"] == "n-loopback-5678"])

    def test_lan_listener_is_reachable_from_lan(self):
        e = self.edges[("n-lan-other", "n-all-4870")]
        self.assertEqual((e["auth"], e["encryption"]), ("None", "Plain"))
        surf = self.nodes["n-all-22"]["attackSurface"]
        self.assertIs(surf["hasRemoteAccessRestriction"], False)  # 22 は遠隔管理ポート
        self.assertNotIn("hasRemoteAccessRestriction", self.nodes["n-all-4870"]["attackSurface"])

    def test_port_names_from_inventory(self):
        self.assertTrue(self.nodes["n-all-22"]["label"].startswith("リモートログイン(SSH) :22"))
        self.assertIn("随時変わるポート", self.nodes["n-all-helper-app"]["label"])

    def test_open_admin_page_is_unauthenticated(self):
        n = self.nodes["n-site-shop-admin"]
        self.assertIs(n["attackSurface"]["hasUserAuthentication"], False)
        self.assertEqual(self.edges[("n-internet", "n-site-shop-admin")]["auth"], "None")

    def test_protected_admin_page_uses_inventory_auth(self):
        f = facts()
        f["urls"][1]["verdict"] = "auth_required"
        m = build.build(inventory(), f)
        n = nodes_by_id(m)["n-site-shop-admin"]
        self.assertIs(n["attackSurface"]["hasUserAuthentication"], True)
        e = [e for e in m.edges if e["target"] == "n-site-shop-admin"][0]
        self.assertEqual(e["auth"], "Password")

    def test_retired_endpoint_that_answers_is_flagged(self):
        self.assertIn("n-site-old-campaign", self.nodes)
        f = facts()
        f["urls"][2]["verdict"] = "unreachable"
        self.assertNotIn("n-site-old-campaign", nodes_by_id(build.build(inventory(), f)))

    def test_agents_and_secrets(self):
        self.assertIn("n-mcp-local-fs", self.nodes)
        self.assertIn("n-job-com-example-nightly", self.nodes)
        self.assertIn(("n-job-com-example-nightly", "n-saas-anthropic"), self.edges)
        secret = [n for n in self.m.nodes if n["type"] == "CREDENTIAL"][0]
        self.assertEqual(secret["parentId"], "n-mac")

    def test_edges_point_to_existing_nodes(self):
        for e in self.m.edges:
            self.assertIn(e["source"], self.nodes, e["id"])
            self.assertIn(e["target"], self.nodes, e["id"])

    def test_no_owner_specific_text(self):
        proj = build.assemble(self.m, None, "2026-10-13T11:00:00")
        meta = json.dumps(proj["projectMeta"], ensure_ascii=False)
        self.assertNotIn("FOREST", meta)
        self.assertNotIn("OCLP", self.nodes["n-mac"]["description"])


class AssembleTest(unittest.TestCase):
    def test_carries_decisions_positions_and_seq(self):
        inv, f = inventory(), facts()
        first = build.assemble(build.build(inv, f), None, f["measuredAt"], inv.get("project"))
        self.assertEqual(first["projectMeta"]["name"], "Mac の実測点検")
        prev = copy.deepcopy(first)
        node = prev["layers"]["L1"]["nodes"][0]
        node["x"], node["y"] = 999, 888
        prev["suppressions"] = {"T-some-threat": {"reason": "リスク受容"}}
        prev["projectMeta"] = dict(prev["projectMeta"], name="自分で付けた名前")

        f2 = facts()
        f2["listeners"].append({"process": "NewServer", "pid": "200", "addr": "*:7000", "port": 7000, "scope": "all"})
        second = build.assemble(build.build(inv, f2), prev, f2["measuredAt"], inv.get("project"))

        self.assertEqual(second["suppressions"], prev["suppressions"])
        self.assertEqual(second["projectMeta"]["name"], "自分で付けた名前")
        moved = {n["id"]: n for n in second["layers"]["L1"]["nodes"]}[node["id"]]
        self.assertEqual((moved["x"], moved["y"]), (999, 888))
        old_seq = {n["id"]: n["seq"] for n in first["layers"]["L1"]["nodes"]}
        for n in second["layers"]["L1"]["nodes"]:
            if n["id"] in old_seq:
                self.assertEqual(n["seq"], old_seq[n["id"]], n["id"])
        new = {n["id"]: n for n in second["layers"]["L1"]["nodes"]}["n-all-7000"]
        self.assertGreater(new["seq"], max(old_seq.values()))
        self.assertGreaterEqual(second["idCounters"]["L1"]["node"], new["seq"])


class ReportTest(unittest.TestCase):
    def test_report_from_outputs(self):
        out = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(FIX, "facts.json"), out)
            with open(os.path.join(out, "threats.json"), "w") as fp:
                json.dump([{"threats": [
                    {"asset": "C1 認証なしサーバー", "name": "認証欠如", "effectiveSeverity": "High", "status": ""},
                    {"asset": "C2 済み", "name": "受容済み", "severity": "High", "status": "リスク受容"},
                ]}], fp, ensure_ascii=False)
            with open(os.path.join(out, "ipa-checklist.csv"), "w", encoding="utf-8-sig", newline="") as fp:
                w = csv.writer(fp)
                w.writerow(["集計", "要対応 1; 問題なし 0"])
                w.writerow(["グループ", "項目 No", "項目", "状態", "要対応（脅威検出数）", "未入力（脅威検出数）"])
                w.writerow(["A", "ipa-01", "外部公開範囲の見直し", "要対応", "1", "0"])
            sys_argv = sys.argv
            sys.argv = ["report.py", out]
            try:
                report.main()
            finally:
                sys.argv = sys_argv
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn("ファイアウォール: **有効**", text)
            self.assertIn("`MyServer`", text)
            self.assertIn("⚠ 管理画面が認証なしで開く", text)
            self.assertIn("⚠ 解約済みのはずが応答", text)
            self.assertIn("**22**", text)
            self.assertIn("| ipa-01 外部公開範囲の見直し | 要対応 | 1 | 0 |", text)
            self.assertIn("C1 認証なしサーバー", text)
            self.assertNotIn("受容済み", text)
            self.assertIn("初回のため差分はありません", text)
            # 実測と差分が、一般論の脅威一覧より前に来る
            self.assertLess(text.index("## 1. 実測"), text.index("## 2. 前回との差分"))
            self.assertLess(text.index("## 2. 前回との差分"), text.index("## 3. 参考"))
            # the English copy has the same sections; CyberRiskScape's own names stay as they are
            with open(os.path.join(out, "report.en.md"), encoding="utf-8") as fp:
                en = fp.read()
            self.assertIn("Firewall: **on**", en)
            self.assertIn("⚠ admin page opens without login", en)
            self.assertIn("| ipa-01 外部公開範囲の見直し | 要対応 | 1 | 0 |", en)
            self.assertLess(en.index("## 1. What only"), en.index("## 2. Changes"))
            self.assertLess(en.index("## 2. Changes"), en.index("## 3. Reference"))
            self.assertNotIn("初回のため", en)
        finally:
            shutil.rmtree(out)


class NoEngineTest(unittest.TestCase):
    """評価エンジンを入れていない Mac でも、レポートと前回との差分が出る。"""

    def test_report_without_engine(self):
        root = tempfile.mkdtemp()
        try:
            first, second = os.path.join(root, "2026-10-01_090000"), os.path.join(root, "2026-10-02_090000")
            for d in (first, second):
                os.makedirs(d)
            prev, cur = facts(), facts()
            cur["lanProbe"] = [dict(x, open=False) for x in cur["lanProbe"]]
            for d, f in ((first, prev), (second, cur)):
                with open(os.path.join(d, "facts.json"), "w", encoding="utf-8") as fp:
                    json.dump(f, fp, ensure_ascii=False)
            sys_argv = sys.argv
            try:
                for d in (first, second):
                    sys.argv = ["report.py", d]
                    report.main()
            finally:
                sys.argv = sys_argv
            with open(os.path.join(first, "report.md"), encoding="utf-8") as fp:
                self.assertIn("初回のため差分はありません", fp.read())
            with open(os.path.join(second, "report.md"), encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn("リモートログイン（SSH）が閉じました", text)
            self.assertNotIn("## 3. 参考", text)
            self.assertIn("./setup.sh --with-engine", text)
            with open(os.path.join(second, "report.en.md"), encoding="utf-8") as fp:
                en = fp.read()
            self.assertIn("### Better", en)
            self.assertNotIn("kept in the original Japanese", en)
        finally:
            shutil.rmtree(root)


class ReportDiffTest(unittest.TestCase):
    def test_report_embeds_diff(self):
        out = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(FIX, "facts.json"), out)
            with open(os.path.join(out, "threats.json"), "w") as fp:
                json.dump([{"threats": []}], fp)
            with open(os.path.join(out, "ipa-checklist.csv"), "w", encoding="utf-8-sig", newline="") as fp:
                w = csv.writer(fp)
                w.writerow(["集計", ""])
                w.writerow(["グループ", "項目 No", "項目", "状態", "要対応（脅威検出数）", "未入力（脅威検出数）"])
            with open(os.path.join(out, "diff.md"), "w", encoding="utf-8") as fp:
                fp.write("# 差分\n\n## 追加\n\n- 新しい入口 :7000\n")
            sys_argv = sys.argv
            sys.argv = ["report.py", out]
            try:
                report.main()
            finally:
                sys.argv = sys_argv
            with open(os.path.join(out, "report.md"), encoding="utf-8") as fp:
                text = fp.read()
            self.assertIn("### 差分", text)
            self.assertIn("#### 追加", text)
            self.assertIn("- 新しい入口 :7000", text)
        finally:
            shutil.rmtree(out)


class EasyReportTest(unittest.TestCase):
    def test_plain_language_findings(self):
        import easy_report
        f = facts()
        d = easy_report.build_data(f)
        self.assertEqual(d["verdict"], "red")
        titles = " ".join(t["title"]["ja"] for t in d["todo"])
        self.assertIn("リモートログイン", titles)          # lanProbe 22 open
        self.assertIn("管理画面が、ログインなしで開きます", titles)
        self.assertIn("やめたはずのサイト", titles)
        self.assertIn("大事な鍵", titles)
        self.assertIn("AI が自動で動く", titles)
        # red comes before yellow, every task says how to fix it
        levels = [t["level"] for t in d["todo"]]
        self.assertEqual(levels, sorted(levels, key=lambda x: x != "red"))
        self.assertTrue(all(t["how"]["ja"] and t["how"]["en"] for t in d["todo"]))
        self.assertEqual(len(d["checks"]), 6)
        ok_ja = [o["text"]["ja"] for o in d["ok"]]
        self.assertIn("ファイアウォール（外から勝手につながれるのを防ぐ壁）は有効です。", ok_ja)
        self.assertIn("https://shop.example.com/ は誰でも見られます（公開用のサイトなら正常です）。", ok_ja)
        self.assertTrue(all(o["cat"] in {c["cat"] for c in d["checks"]} for o in d["ok"]))

    def test_apple_daemons_are_not_warnings(self):
        import easy_report
        f = facts()
        f["listeners"] = [{"process": "rapportd", "pid": "1", "addr": "*:49152", "port": 49152, "scope": "all"}]
        f["lanProbe"], f["urls"], f["secrets"] = [], [], []
        f["agents"]["claude_launchd_jobs"] = []
        d = easy_report.build_data(f)
        self.assertEqual(d["verdict"], "green")
        self.assertTrue(any("rapportd" in x["text"]["ja"] for x in d["ok"]))

    def test_tidy_env_file_is_caution_not_nogo(self):
        import easy_report
        f = facts()
        f["lanProbe"], f["urls"], f["listeners"] = [], [], []
        f["agents"]["claude_launchd_jobs"] = []
        f["secrets"] = [{"file": "/Users/someone/app/.env.local", "kinds": ["anthropic"], "private": True, "gitIgnored": True}]
        d = easy_report.build_data(f)
        self.assertEqual(d["verdict"], "yellow")
        f["secrets"][0]["gitIgnored"] = False   # in a repo and not ignored: could be pushed
        self.assertEqual(easy_report.build_data(f)["verdict"], "red")
        f["secrets"][0].update(gitIgnored=True, private=False)  # readable by others
        self.assertEqual(easy_report.build_data(f)["verdict"], "red")

    def test_storage_reads_permissions_and_gitignore(self):
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["git", "init", "-q", d], check=True)
            with open(os.path.join(d, ".gitignore"), "w") as fp:
                fp.write(".env\n")
            for name in (".env", "config.py"):
                with open(os.path.join(d, name), "w") as fp:
                    fp.write("x")
            os.chmod(os.path.join(d, ".env"), 0o600)
            os.chmod(os.path.join(d, "config.py"), 0o644)
            self.assertEqual(collect.storage(os.path.join(d, ".env")), {"private": True, "gitIgnored": True})
            self.assertEqual(collect.storage(os.path.join(d, "config.py")), {"private": False, "gitIgnored": False})
        finally:
            shutil.rmtree(d)

    def test_diff_with_previous_run(self):
        import easy_report
        prev = facts()
        cur = facts()
        cur["lanProbe"] = [dict(x, open=False) for x in cur["lanProbe"]]
        cur["secrets"] = []
        ch = easy_report.changes(prev, cur)
        self.assertIn("リモートログイン（SSH）が閉じました", [x["ja"] for x in ch["better"]])
        self.assertTrue(any("片付きました" in x["ja"] for x in ch["better"]))
        self.assertEqual(ch["worse"], [])

    def test_every_text_is_bilingual(self):
        import easy_report
        jp = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]")
        prev = facts()
        cur = facts()
        cur["firewall"] = {"enabled": False}
        cur["lanProbe"] = [dict(x, open=not x["open"]) for x in cur["lanProbe"]]
        cur["listeners"].append({"process": "rapportd", "pid": "9", "addr": "*:1", "port": 1, "scope": "all"})
        cur["secrets"].append({"file": "/Users/someone/b.py", "kinds": ["github"], "private": False})
        cur["npm"] = {"used": True, "ignoreScripts": False, "guard": None}
        risky_mac(cur)
        d = easy_report.build_data(cur, prev)
        texts = [x["label"] for x in d["checks"]] + [o["text"] for o in d["ok"]]
        for x in d["todo"]:
            texts += [x["title"], x["what"], x["why"], x["how"]] + x.get("steps", [])
            texts += [x[k] for k in ("time", "undo", "keep", "askAi") if k in x]
            self.assertIn(x["effort"], ("self", "help"))
        texts += d["diff"]["better"] + d["diff"]["worse"]
        texts += [o["text"] for o in easy_report.build_data(facts())["ok"]]
        self.assertTrue(d["diff"]["better"] and d["diff"]["worse"])
        # file paths and app names come from the data and are not translated
        data_bits = [h["file"] for h in cur["secrets"] + prev["secrets"]]
        data_bits += [l["process"] for l in cur["listeners"]] + cur["agents"]["claude_launchd_jobs"]
        self.assertEqual({x["cat"] for x in d["todo"]} >= {"aiperm", "disk", "ssh", "remote", "backup", "guard", "update"}, True)
        good = copy.deepcopy(cur)
        good.update(aiPermissions={"files": 1, "bypass": [], "broad": [], "mcpWide": []},
                    fileVault={"on": True, "oclp": False, "laptop": True}, remoteApps=[],
                    sshKeys=[{"file": "~/.ssh/id_ed25519", "encrypted": True}],
                    timeMachine={"configured": True, "lastBackupAt": cur["measuredAt"][:16]},
                    macGuard={"sip": "custom", "gatekeeper": True, "autoLogin": False, "oclp": True},
                    updates={"check": True, "securityData": False, "oclp": True})
        texts += [o["text"] for o in easy_report.build_data(good)["ok"]]
        for x in texts:
            self.assertEqual(set(x), {"ja", "en"})
            self.assertIsInstance(x["ja"], str)
            self.assertIsInstance(x["en"], str)
            self.assertTrue(x["ja"].strip() and x["en"].strip(), x)
            en = x["en"]
            for bit in data_bits:
                en = en.replace(bit, "")
            self.assertNotRegex(en, jp, x["en"])

    def test_npm_protection(self):
        import easy_report

        def run(npm):
            f = facts()
            f["npm"] = npm
            d = easy_report.build_data(f)
            todo = [x for x in d["todo"] if x["cat"] == "npm"]
            ok = [x for x in d["ok"] if x["cat"] == "npm"]
            return d, todo, ok
        d, todo, ok = run({"used": False, "ignoreScripts": False, "guard": None})
        self.assertFalse(todo or ok)
        self.assertNotIn("npm", [c["cat"] for c in d["checks"]])   # no npm, no checklist item
        _, todo, _ = run({"used": True, "ignoreScripts": False, "guard": None})
        self.assertEqual([x["level"] for x in todo], ["yellow"])
        self.assertIn("npm config set ignore-scripts true", todo[0]["how"]["en"])
        _, todo, ok = run({"used": True, "ignoreScripts": True, "guard": None})
        self.assertFalse(todo); self.assertTrue(ok)
        guard = {"lastScanAt": "2026-10-13T08:00", "high": 0, "medium": 0, "stale": False}
        _, todo, ok = run({"used": True, "ignoreScripts": False, "guard": guard})
        self.assertFalse(todo); self.assertTrue(ok)               # the guard counts as protection
        _, todo, _ = run({"used": True, "ignoreScripts": True, "guard": dict(guard, stale=True)})
        self.assertEqual([x["level"] for x in todo], ["yellow"])
        d, todo, _ = run({"used": True, "ignoreScripts": True, "guard": dict(guard, high=2)})
        self.assertEqual([x["level"] for x in todo], ["red"])
        self.assertEqual(d["verdict"], "red")
        _, todo, _ = run({"used": True, "ignoreScripts": True, "guard": dict(guard, medium=1)})
        self.assertEqual([x["level"] for x in todo], ["yellow"])

    def test_npm_state_is_read_not_written(self):
        tmp = tempfile.mkdtemp()
        try:
            state = os.path.join(tmp, "state.json")
            with open(state, "w", encoding="utf-8") as fp:
                import hashlib
                acked = hashlib.sha256(b"medium|drift|seen").hexdigest()[:16]
                json.dump({"last_quick": {"at": 1e10, "findings": [
                    {"sev": "high", "id": "ioc", "msg": "x"}, {"sev": "info", "id": "self", "msg": "y"},
                    {"sev": "medium", "id": "drift", "msg": "seen"}]},
                    "last_full": {"at": 1e10, "findings": [{"sev": "high", "id": "ioc", "msg": "x"}]},
                    "acknowledged": {acked: {"sev": "medium"}}}, fp)
            with open(state, encoding="utf-8") as fp:
                before = fp.read()
            rc = os.path.join(tmp, "npmrc")
            with open(rc, "w") as fp:
                fp.write("fund=false\nignore-scripts = true\n")
            old = collect.GUARD_STATE
            collect.GUARD_STATE = state
            try:
                g = collect.npm_protection()["guard"]
            finally:
                collect.GUARD_STATE = old
            self.assertEqual((g["high"], g["medium"]), (1, 0))    # counted once; acknowledged ones are skipped
            self.assertFalse(g["stale"])
            with open(state, encoding="utf-8") as fp:
                self.assertEqual(fp.read(), before)
            self.assertTrue(collect.npm_rc_ignore_scripts(rc))
            self.assertIsNone(collect.npm_rc_ignore_scripts(os.path.join(tmp, "missing")))
        finally:
            shutil.rmtree(tmp)

    def test_entry_map_places_each_way_in(self):
        import easy_report
        m = easy_report.build_data(facts())["map"]
        self.assertTrue(m["firewall"])
        lan = {x["label"]["en"]: x["level"] for x in m["lan"]}
        net = {x["label"]["en"]: x["level"] for x in m["net"]}
        self.assertEqual(lan["Remote Login (SSH)"], "red")         # sharing port open on the LAN
        self.assertEqual(lan["MyServer"], "yellow")                # unknown app reachable from the LAN
        self.assertEqual(net["shop.example.com/admin"], "red")     # admin page opens without login
        self.assertEqual(net["old-campaign.example.com"], "yellow")
        self.assertIn("1 automatic AI task", net)
        cats = {c for c, _ in easy_report.CHECKS}
        for x in m["mac"] + m["lan"] + m["net"]:
            self.assertIn(x["cat"], cats)                          # every item can jump to a card
            self.assertIn(x["level"], ("red", "yellow", "green"))

    def test_diagram_from_model(self):
        import easy_report
        g = easy_report.diagram(build.assemble(build.build(inventory(), facts()), None, facts()["measuredAt"]))
        nodes = {n["id"]: n for n in g["nodes"]}
        self.assertEqual((nodes["n-internet"]["col"], nodes["n-site-shop"]["col"], nodes["n-data-orders"]["col"]), (0, 1, 2))
        self.assertTrue(nodes["n-site-shop"]["outside"] and nodes["n-data-orders"]["outside"])   # reachable from the internet
        self.assertFalse(nodes["n-loopback-5678"]["outside"])                                    # 127.0.0.1 only
        self.assertFalse(nodes["n-owner"]["outside"])
        self.assertTrue(all(e[0] in nodes and e[1] in nodes for e in g["edges"]))
        self.assertIsNone(easy_report.diagram({"layers": {"L1": {"nodes": []}}}))

    def test_diagram_has_english_names(self):
        import easy_report
        jp = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]")
        inv = inventory()
        g = easy_report.diagram(build.assemble(build.build(inv, facts()), None, facts()["measuredAt"]),
                                easy_report.inventory_names_en(inv))
        for n in g["nodes"]:
            self.assertEqual(set(n["label"]), {"ja", "en"})
            self.assertNotRegex(n["label"]["en"], jp, n["label"]["en"])     # tool-made and labelEn names
        self.assertEqual(easy_report.label_en("Bartender 6 :7823（全インターフェース）"), "Bartender 6 :7823 (all interfaces)")
        self.assertEqual(easy_report.label_en("自分のサイト（Cloudflare）"), "自分のサイト (Cloudflare)")  # no labelEn: kept
        # a system listener whose name collect.py cannot read gets an English name too
        self.assertEqual(easy_report.label_en("（root 所有・名前不明） :445（全インターフェース）"),
                         "(root-owned, name unknown) :445 (all interfaces)")

    def test_html_is_self_contained_and_escaped(self):
        import easy_report
        out = tempfile.mkdtemp()
        try:
            base = os.path.join(out, "out")
            for stamp in ("2026-10-12_100000", "2026-10-13_100000"):
                os.makedirs(os.path.join(base, stamp))
                shutil.copy(os.path.join(FIX, "facts.json"), os.path.join(base, stamp))
            cur = os.path.join(base, "2026-10-13_100000")
            with open(os.path.join(cur, "report.md"), "w", encoding="utf-8") as fp:
                fp.write("# 詳細 </script><b>x</b>\n")
            with open(os.path.join(cur, "report.en.md"), "w", encoding="utf-8") as fp:
                fp.write("# Detail in English\n")
            sys_argv = sys.argv
            sys.argv = ["easy_report.py", cur]
            try:
                easy_report.main()
            finally:
                sys.argv = sys_argv
            with open(os.path.join(cur, "report.html"), encoding="utf-8") as fp:
                text = fp.read()
            self.assertTrue(text.startswith("<!doctype html>"))
            self.assertLess(text.index("<title>"), text.index("</head>"))
            self.assertNotIn("__PREFLIGHT_DATA__", text)
            self.assertNotIn("</script><b>", text)       # embedded data cannot break out of the script tag
            self.assertNotRegex(text, r'(src|href)="https?://')  # nothing loads from the network
            self.assertIn('"diff": {"better": [], "worse": []}', text)  # previous run was found
            self.assertIn('"prevMeasuredAt": "', text)
            self.assertIn("# Detail in English", text)  # the detail is carried in both languages
            self.assertIn("report.en.md", text)
            self.assertIn("評価エンジン: CyberRiskScape", text)  # upstream credit stays in the expert section
            self.assertEqual(os.stat(os.path.join(cur, "report.html")).st_mode & 0o777, 0o600)
        finally:
            shutil.rmtree(out)


class VersionTest(unittest.TestCase):
    def test_one_version_everywhere(self):
        import easy_report
        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as fp:
            v = fp.read().strip()
        self.assertRegex(v, r"^\d+\.\d+\.\d+$")
        self.assertEqual(report.version(), v)
        self.assertEqual(easy_report.build_data(facts())["version"], v)
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fp:
            self.assertIn("## [%s]" % v, fp.read())  # every version has a changelog entry
        with open(os.path.join(ROOT, "setup.sh"), encoding="utf-8") as fp:
            self.assertIn("<string>$VERSION</string>", fp.read())  # the app's Info.plist takes it from VERSION


class RepoHygieneTest(unittest.TestCase):
    def test_personal_data_is_ignored(self):
        with open(os.path.join(ROOT, ".gitignore")) as f:
            lines = {l.strip() for l in f}
        for p in ("inventory.json", "model.json", "out/", "vendor/"):
            self.assertIn(p, lines)


def find_cli():
    p = os.environ.get("CRS_CLI") or os.path.join(ROOT, "vendor", "CyberRiskScape", "dist-cli", "main.js")
    return p if os.path.isfile(p) and shutil.which("node") else None


class MacChecksTest(unittest.TestCase):
    def levels(self, f, cat):
        import easy_report
        return [x["level"] for x in easy_report.build_data(f)["todo"] if x["cat"] == cat]

    def test_levels(self):
        import easy_report
        f = risky_mac(facts())
        d = easy_report.build_data(f)
        self.assertEqual(sorted(self.levels(f, "aiperm")), ["red", "yellow"])
        self.assertEqual(self.levels(f, "disk"), ["red"])
        self.assertEqual(self.levels(f, "ssh"), ["yellow"])
        self.assertIn("~/.ssh/id_ed25519", d["todo"][[x["cat"] for x in d["todo"]].index("ssh")]["how"]["en"])
        self.assertEqual(self.levels(f, "remote"), ["yellow"])
        self.assertEqual(self.levels(f, "backup"), ["red"])               # over 30 days
        self.assertEqual(sorted(self.levels(f, "guard")), ["red", "red", "yellow"])
        self.assertEqual(self.levels(f, "update"), ["yellow"])
        self.assertEqual(len(d["checks"]), 13)                            # every check except npm (not used here)
        import datetime
        at = datetime.datetime.fromisoformat(f["measuredAt"][:16])
        f["timeMachine"]["lastBackupAt"] = (at - datetime.timedelta(days=10)).isoformat()[:16]
        self.assertEqual(self.levels(f, "backup"), ["yellow"])
        f["timeMachine"]["lastBackupAt"] = (at - datetime.timedelta(days=1)).isoformat()[:16]
        self.assertEqual(self.levels(f, "backup"), [])
        f["timeMachine"] = {"configured": False, "lastBackupAt": None}
        self.assertEqual(self.levels(f, "backup"), ["yellow"])

    def test_oclp_mac_is_judged_fairly(self):
        f = risky_mac(facts())
        f["fileVault"] = {"on": False, "oclp": True, "laptop": True}
        f["macGuard"] = {"sip": "custom", "gatekeeper": True, "autoLogin": False, "oclp": True}
        self.assertEqual(self.levels(f, "disk"), ["yellow"])              # check OCLP compatibility first
        self.assertEqual(self.levels(f, "guard"), [])                     # SIP relaxed for OCLP is normal
        import easy_report
        d = easy_report.build_data(f)
        disk = [x for x in d["todo"] if x["cat"] == "disk"][0]
        self.assertNotIn("keep", disk)                                    # a laptop gets no "desk Mac" excuse
        self.assertIn("Don't suggest a macOS update", disk["askAi"]["en"])
        f["macGuard"]["sip"] = "off"
        self.assertEqual(self.levels(f, "guard"), ["yellow"])
        f["updates"]["oclp"] = True
        self.assertEqual(self.levels(f, "update"), [])                    # OCLP: told, never pushed to update
        texts = json.dumps(easy_report.build_data(f), ensure_ascii=False)
        self.assertNotIn("アップデートしましょう", texts)

    def test_unmeasured_checks_are_hidden(self):
        import easy_report
        f = facts()
        f.update(aiPermissions={"files": 0, "bypass": [], "broad": [], "mcpWide": []},
                 fileVault={"on": None, "oclp": False, "laptop": False}, sshKeys=[], timeMachine=None,
                 macGuard={"sip": None, "gatekeeper": None, "autoLogin": False, "oclp": False})
        cats = [c["cat"] for c in easy_report.build_data(f)["checks"]]
        for c in ("aiperm", "disk", "ssh", "backup", "guard", "remote", "update"):
            self.assertNotIn(c, cats)

    def test_ai_permissions_reads_rules_only(self):
        tmp = tempfile.mkdtemp()
        old = collect.HOME
        try:
            collect.HOME = tmp
            os.makedirs(os.path.join(tmp, ".claude"))
            proj = os.path.join(tmp, "work", "app", ".claude")
            os.makedirs(proj)
            with open(os.path.join(tmp, ".claude", "settings.json"), "w") as fp:
                json.dump({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(git status)", "Bash(*)"]}}, fp)
            with open(os.path.join(proj, "settings.local.json"), "w") as fp:
                json.dump({"permissions": {"allow": ["Bash(python3:*)", "Bash(node -e *)", "Bash(npm test)", "Read(*)"]}}, fp)
            with open(os.path.join(tmp, ".claude.json"), "w") as fp:
                json.dump({"mcpServers": {"fs": {"args": ["-y", "server-filesystem", tmp + "/"]},
                                          "ok": {"args": [os.path.join(tmp, "work")]}}}, fp)
            ap = collect.ai_permissions([os.path.join(tmp, "work")])
            self.assertEqual(ap["files"], 2)
            self.assertEqual(ap["bypass"], ["~/.claude/settings.json"])
            self.assertEqual({(b["rule"], b["kind"]) for b in ap["broad"]},
                             {("Bash(*)", "any"), ("Bash(python3:*)", "code"), ("Bash(node -e *)", "code")})
            self.assertEqual(ap["mcpWide"], ["fs"])
        finally:
            collect.HOME = old
            shutil.rmtree(tmp)

    def test_ssh_passphrase_from_header_only(self):
        import base64
        tmp = tempfile.mkdtemp()
        try:
            def key(cipher):
                raw = b"openssh-key-v1\0" + len(cipher).to_bytes(4, "big") + cipher + b"\0" * 40
                body = base64.b64encode(raw).decode()
                return ("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n%s\n-----END OPENSSH " + "PRIVATE KEY-----\n") % body
            cases = {"plain": (key(b"none"), False), "locked": (key(b"aes256-ctr"), True),
                     "pem": ("-----BEGIN RSA " + "PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nxx\n-----END RSA " + "PRIVATE KEY-----\n", True),
                     "pem_plain": ("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIxx\n-----END RSA " + "PRIVATE KEY-----\n", False),
                     "notakey": ("hello\n", None)}
            for name, (text, want) in cases.items():
                fp = os.path.join(tmp, name)
                with open(fp, "w") as f:
                    f.write(text)
                self.assertEqual(collect.ssh_key_encrypted(fp), want, name)
        finally:
            shutil.rmtree(tmp)


class DiagramServerTest(unittest.TestCase):
    """Diagram.command: 読み込みページと構成図を、このMacの中だけで配る。"""

    def test_serves_loader_and_model(self):
        import functools
        import socketserver
        import threading
        import urllib.error
        import urllib.request
        import diagram
        dist = tempfile.mkdtemp()
        try:
            with open(os.path.join(dist, "index.html"), "w") as fp:
                fp.write("<html>app</html>")
            handler = functools.partial(diagram.Handler, directory=dist, model=b'{"layers": {}}', token="s3cret")
            srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            port = srv.server_address[1]
            base = "http://127.0.0.1:%d" % port
            try:
                def get(p, host=None):
                    req = urllib.request.Request(base + p)
                    if host:
                        req.add_header("Host", host)
                    return urllib.request.urlopen(req, timeout=5).read().decode()

                def refused(p, host=None):
                    with self.assertRaises(urllib.error.HTTPError) as e:
                        get(p, host)
                    self.assertEqual(e.exception.code, 403)

                self.assertIn('indexedDB.open("cyberriskscape"', get("/__preflight/load.html?t=s3cret"))
                self.assertIn("backup-", get("/__preflight/load.html?t=s3cret"))      # work in the app is kept
                self.assertEqual(json.loads(get("/__preflight/model.json?t=s3cret")), {"layers": {}})
                self.assertEqual(json.loads(get("/__preflight/model.json?t=s3cret", "localhost:%d" % port)), {"layers": {}})
                self.assertIn("app", get("/"))
                # the map of weak spots needs the per-run token
                refused("/__preflight/model.json")
                refused("/__preflight/model.json?t=wrong")
                refused("/__preflight/load.html")
                # DNS rebinding: another site's name pointing at 127.0.0.1 is refused
                refused("/__preflight/model.json?t=s3cret", "evil.example:%d" % port)
                refused("/", "evil.example:%d" % port)
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            shutil.rmtree(dist)


@unittest.skipUnless(find_cli(), "CyberRiskScape の CLI がないので結合テストは省略")
class CliIntegrationTest(unittest.TestCase):
    """build.py の出力を本物の CyberRiskScape で評価できるか（スキーマが合っているか）を確かめる。"""

    def test_analyze_checklist_diff(self):
        cli = find_cli()
        out = tempfile.mkdtemp()
        try:
            inv, f = inventory(), facts()
            m1 = os.path.join(out, "prev.json")
            m2 = os.path.join(out, "model.json")
            with open(m1, "w") as fp:
                json.dump(build.assemble(build.build(inv, f), None, f["measuredAt"]), fp, ensure_ascii=False)
            f["listeners"].append({"process": "NewServer", "pid": "200", "addr": "*:7000", "port": 7000, "scope": "all"})
            with open(m2, "w") as fp:
                json.dump(build.assemble(build.build(inv, f), load(m1), f["measuredAt"]), fp, ensure_ascii=False)

            def run(*args):
                r = subprocess.run(["node", cli] + list(args), capture_output=True, text=True, timeout=180)
                self.assertEqual(r.returncode, 0, r.stderr)

            run("analyze", m2, "--format", "json", "--out", os.path.join(out, "threats.json"))
            run("checklist", m2, "--id", "ipa-alert-2026-10", "--format", "csv", "--out", os.path.join(out, "ipa-checklist.csv"))
            subprocess.run(["node", cli, "diff", m1, m2, "--format", "md", "--out", os.path.join(out, "diff.md")],
                           capture_output=True, timeout=180)
            threats = load(os.path.join(out, "threats.json"))[0]["threats"]
            self.assertTrue(any("7000" in t["asset"] or "NewServer" in t["asset"] for t in threats))
            with open(os.path.join(out, "diff.md"), encoding="utf-8") as fp:
                self.assertIn("NewServer", fp.read())
            shutil.copy(os.path.join(FIX, "facts.json"), out)
            sys_argv = sys.argv
            sys.argv = ["report.py", out]
            try:
                report.main()
            finally:
                sys.argv = sys_argv
            self.assertTrue(os.path.exists(os.path.join(out, "report.md")))
        finally:
            shutil.rmtree(out)


if __name__ == "__main__":
    unittest.main()
