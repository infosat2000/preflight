"""Blackbox Blast Preflight の単体テスト。標準ライブラリだけで動く（macOS 標準の python3 3.9 を想定）。

実行: python3 -m unittest discover -s tests
CyberRiskScape の CLI があれば（vendor/ か CRS_CLI）、評価まで通す結合テストも走る。
"""
import copy
import csv
import json
import os
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
        self.assertEqual(hits, [{"file": p, "kinds": ["anthropic"]}])
        self.assertNotIn(key, json.dumps(hits))

    def test_ignores_placeholders_and_skipped_dirs(self):
        self.write("app/.env.example", "KEY=sk-" + "ant-xxxxxxxxxxxxxxxxxxxxxxxxxx\n")
        self.write("app/README.md", "KEY=sk-" + "ant-your-key-goes-here-0000000000\n")
        self.write("node_modules/pkg/.env", "KEY=sk-" + "ant-a1B2c3D4e5F6g7H8i9J0kLmNoPq\n")
        self.write("vendor/x/.env", "KEY=gsk_" + "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuV\n")
        self.assertEqual(collect.secret_scan([self.root]), [])

    def test_private_key(self):
        self.write("keys/id.txt", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n")
        self.assertEqual(collect.secret_scan([self.root])[0]["kinds"], ["private_key"])


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
        finally:
            shutil.rmtree(out)


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


class RepoHygieneTest(unittest.TestCase):
    def test_personal_data_is_ignored(self):
        with open(os.path.join(ROOT, ".gitignore")) as f:
            lines = {l.strip() for l in f}
        for p in ("inventory.json", "model.json", "out/", "vendor/"):
            self.assertIn(p, lines)


def find_cli():
    p = os.environ.get("CRS_CLI") or os.path.join(ROOT, "vendor", "CyberRiskScape", "dist-cli", "main.js")
    return p if os.path.isfile(p) and shutil.which("node") else None


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
