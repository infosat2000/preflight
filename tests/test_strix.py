"""1.3.0: AI のペンテスト道具 Strix の結果を読むだけの点検と、OpenAI・OpenRouter の鍵の検出。

Strix 自体は動かさない。結果の形は Strix の strix/report/{state,coverage}.py に合わせた偽物で確かめる。
実行: python3 -m unittest discover -s tests
"""
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import collect  # noqa: E402
import collect_extra as cx  # noqa: E402
import easy_report  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
JP = re.compile(r"[぀-ヿ一-鿿]")
TARGET = "https://booking.example.test/secret-path"


def base_facts():
    with open(os.path.join(FIX, "facts.json"), encoding="utf-8") as f:
        return json.load(f)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text, mode=0o600):
        fp = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(fp, mode)
        return fp

    def run_dir(self, project, name, status, vulns, cov=None, age=0):
        base = os.path.join(project, "strix_runs", name)
        self.write(os.path.join(base, "run.json"), json.dumps({
            "run_name": name, "status": status, "scan_mode": "quick", "end_time": "2026-11-05T10:00:00+00:00",
            "targets_info": [{"type": "web_application", "details": {"target_url": TARGET}}]}))
        self.write(os.path.join(base, "vulnerabilities.json"), json.dumps(vulns))
        if cov is not None:
            self.write(os.path.join(base, "coverage.json"), json.dumps(cov))
        if age:
            t = time.time() - age
            os.utime(os.path.join(self.root, base, "run.json"), (t, t))


class SecretPatternTest(Tmp):
    def test_openai_and_openrouter(self):
        proj = "sk-proj-" + "Ab1_" * 12
        legacy = "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
        router = "sk-or-v1-" + "0f" * 32
        self.write("work/.env", "OPENAI_API_KEY=%s\nOLD=%s\nOR=%s\n" % (proj, legacy, router))
        self.write("work/doc.md", "OPENAI_API_KEY=sk-proj-your-key-here\nsk-ant-xxxxxxxxxxxxxxxxxxxxxxxx\n")
        hits = {os.path.basename(h["file"]): h["kinds"] for h in collect.secret_scan([os.path.join(self.root, "work")])}
        self.assertEqual(hits, {".env": ["openai", "openrouter"]})
        for k in ("openai", "openrouter"):
            self.assertIn(k, easy_report.SECRET_KINDS)

    def test_strix_config_key(self):
        self.write(".strix/cli-config.json", json.dumps({"env": {"STRIX_LLM": "openai/gpt-6", "LLM_API_KEY": "sk-live-value-123456"}}))
        res = {c["kind"]: c for c in cx.cred_files(self.root)}
        self.assertTrue(res["strix"]["plain"])
        self.assertNotIn("sk-live-value", json.dumps(res))
        self.write(".strix/cli-config.json", json.dumps({"env": {"STRIX_LLM": "openai/gpt-6", "LLM_API_KEY": "$LLM_API_KEY"}}))
        self.assertFalse({c["kind"]: c for c in cx.cred_files(self.root)}["strix"]["plain"])
        self.assertIn("strix", easy_report.PLAIN_FIX)


class StrixStatusTest(Tmp):
    def test_nothing_installed(self):
        os.makedirs(os.path.join(self.root, "work", "app"))
        old = cx.which
        cx.which = lambda c: None
        try:
            self.assertIsNone(cx.strix_status([os.path.join(self.root, "work")], {"node_modules"}, 8, home=self.root))
        finally:
            cx.which = old

    def test_reads_latest_run_and_skills(self):
        a = os.path.join("work", "booking")
        self.run_dir(a, "old", "completed", [{"severity": "critical", "title": "old one"}], age=3600)
        self.run_dir(a, "new", "completed", [{"severity": "high", "title": "IDOR on /orders/{id}"}, {"severity": "low", "title": "x"},
                     {"severity": "critical", "title": "SQL injection via " + TARGET + "?q=1"},
                     {"severity": "high", "title": "Auth bypass at booking.example.test/admin (staging)"}],
                     cov={"completeness": {"complete": True, "exit_reason": "finished_by_tool"},
                          "summary": {"surfaces_reviewed": 7, "gaps": 1}})
        b = os.path.join("work", "shop")
        self.run_dir(b, "r1", "stopped", [], cov={"completeness": {"complete": False, "exit_reason": "budget_exceeded"}})
        self.write("work/shop/node_modules/x/strix_runs/r/run.json", json.dumps({"status": "completed"}))  # skipped
        self.write(".claude/skills/penetration-testing-with-strix/SKILL.md", "---\nname: x\n---\n")
        self.write(".claude/skills/my-own-skill/SKILL.md", "---\nname: y\n---\n")
        self.write("work/shop/.claude/skills/owasp-top-10-testing/SKILL.md", "---\nname: z\n---\n")
        s = cx.strix_status([os.path.join(self.root, "work")], {"node_modules"}, 8, home=self.root)
        self.assertEqual(s["globalSkills"], [cx.short(os.path.join(self.root, ".claude/skills/penetration-testing-with-strix"))])
        self.assertEqual(len(s["projectSkills"]), 1)
        p = {os.path.basename(x["dir"]): x for x in s["projects"]}
        self.assertEqual(set(p), {"booking", "shop"})
        bk = p["booking"]["latest"]
        self.assertEqual((p["booking"]["runs"], bk["findings"]["high"], bk["findings"]["critical"]), (2, 2, 1))
        self.assertEqual((bk["complete"], bk["surfaces"], bk["gaps"], bk["targets"]), (True, 7, 1, 1))
        self.assertEqual(bk["worst"], ["SQL injection", "IDOR", "Auth bypass at"])
        sh = p["shop"]["latest"]
        self.assertEqual((sh["complete"], sh["budgetStop"], sh["status"]), (False, True, "stopped"))
        self.assertNotIn(TARGET, json.dumps(s))                    # the target URL is not recorded
        self.assertNotIn("example.test", json.dumps(s))

    def test_broken_files_are_ignored(self):
        self.write("work/a/strix_runs/r/run.json", "{not json")
        self.write("work/b/strix_runs/r/run.json", json.dumps({"status": "running"}))
        self.write("work/b/strix_runs/r/vulnerabilities.json", "[1, \"x\", {\"severity\": \"HIGH\"}]")
        s = cx.strix_status([os.path.join(self.root, "work")], set(), 8, home=self.root)
        self.assertEqual(len(s["projects"]), 1)
        r = s["projects"][0]["latest"]
        self.assertEqual((r["findings"]["high"], r["complete"]), (1, False))


def strix_facts(kind):
    f = base_facts()
    run = {"dir": "~/work/booking/strix_runs/new", "status": "completed", "complete": True, "budgetStop": False,
           "exitReason": "finished_by_tool", "scanMode": "quick", "endedAt": "2026-11-05T10:00", "targets": 1,
           "findings": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}, "worst": [], "coverage": True,
           "surfaces": 7, "gaps": 0}
    s = {"installed": True, "config": True, "globalSkills": [], "projectSkills": ["~/work/booking/.claude/skills/owasp-top-10-testing"],
         "projects": [{"dir": "~/work/booking", "runs": 1, "latest": run}]}
    if kind == "bad":
        run["findings"].update(high=2, medium=1)
        run["worst"] = ["IDOR on /orders/{id}", "SQL injection"]
        partial = dict(run, dir="~/work/shop/strix_runs/r1", status="stopped", complete=False, budgetStop=True,
                       findings={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, worst=[])
        s["projects"].append({"dir": "~/work/shop", "runs": 3, "latest": partial})
        s["globalSkills"] = ["~/.claude/skills/penetration-testing-with-strix"]
    f["strix"] = s
    return f


class StrixReportTest(unittest.TestCase):
    def strix(self, d):
        return [x for x in d["todo"] if x["cat"] == "strix"]

    def test_levels(self):
        d = easy_report.build_data(strix_facts("bad"))
        self.assertEqual(sorted(x["level"] for x in self.strix(d)), ["red", "yellow", "yellow"])
        red = [x for x in self.strix(d) if x["level"] == "red"][0]
        self.assertIn("IDOR", red["what"]["en"])
        partial = [x for x in self.strix(d) if "full scan" in x["title"]["en"]][0]
        self.assertIn("budget", partial["what"]["en"])
        self.assertIn("strix", {c["cat"] for c in d["checks"]})
        self.assertIn("strix", {x["cat"] for x in d["map"]["mac"]})

    def test_bypass_makes_global_skills_red(self):
        f = strix_facts("bad")
        f["aiPermissions"] = {"files": 1, "bypass": ["~/.claude/settings.json"], "broad": [], "mcpWide": []}
        d = easy_report.build_data(f)
        sk = [x for x in self.strix(d) if "any folder" in x["title"]["en"]][0]
        self.assertEqual(sk["level"], "red")

    def test_clean_is_green_and_says_zero_is_not_proof(self):
        d = easy_report.build_data(strix_facts("good"))
        self.assertEqual(self.strix(d), [])
        ok = [o["text"]["ja"] for o in d["ok"] if o["cat"] == "strix"]
        self.assertTrue(ok and "調べた範囲では" in ok[0])

    def test_old_facts_hide_strix(self):
        self.assertNotIn("strix", {c["cat"] for c in easy_report.build_data(base_facts())["checks"]})

    def test_bilingual(self):
        for kind in ("bad", "good"):
            d = easy_report.build_data(strix_facts(kind))
            texts = [o["text"] for o in d["ok"] if o["cat"] == "strix"]
            for x in self.strix(d):
                texts += [x["title"], x["what"], x["why"], x["how"]] + x.get("steps", [])
                texts += [x[k] for k in ("time", "undo", "keep", "askAi") if k in x]
            for x in texts:
                self.assertEqual(set(x), {"ja", "en"})
                self.assertTrue(x["ja"].strip() and x["en"].strip(), x)
                self.assertNotRegex(x["en"], JP, x["en"])



class NextStepTest(unittest.TestCase):
    def test_guide_is_offered_only_to_site_owners_without_results(self):
        f = base_facts()
        self.assertTrue(f.get("urls"))
        d = easy_report.build_data(f)
        self.assertEqual([x["level"] for x in d["next"]], ["next"])
        self.assertEqual(d["counts"]["yellow"] + d["counts"]["red"], len(d["todo"]))   # not counted as a problem
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "docs", "strix-guide.md")))
        self.assertTrue(d["next"][0]["link"].endswith("/docs/strix-guide.md"))
        self.assertEqual(easy_report.build_data(strix_facts("good"))["next"], [])     # already has results
        f["urls"] = []
        self.assertEqual(easy_report.build_data(f)["next"], [])                        # no public site: nothing to test

    def test_next_step_is_bilingual(self):
        x = easy_report.build_data(base_facts())["next"][0]
        for v in [x["title"], x["what"], x["why"], x["how"], x["time"], x["keep"], x["askAi"]] + x["steps"]:
            self.assertEqual(set(v), {"ja", "en"})
            self.assertTrue(v["ja"].strip() and v["en"].strip())
            self.assertNotRegex(v["en"], JP, v["en"])


if __name__ == "__main__":
    unittest.main()
