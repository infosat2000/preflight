"""1.2.0: macOS の更新の知らせ（OCLP の Mac では勧めず警告だけ）と、known.txt（自分で作ったものを外す）のテスト。

実行: python3 -m unittest discover -s tests
"""
import copy
import datetime
import json
import os
import plistlib
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import collect  # noqa: E402
import easy_report  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")

# OCLP の Mac に出してはいけない、更新を勧める言い方
PUSH_WORDS = ("アップデートしましょう", "macOS をアップデート", "macOS を更新", "入れましょう", "入れます",
              "Update macOS", "upgrade macOS", "Install the updates", "install them")


def base():
    with open(os.path.join(FIX, "facts.json"), encoding="utf-8") as f:
        return json.load(f)


def with_updates(**u):
    f = base()
    f["updates"] = dict({"check": True, "securityData": True, "macosAuto": None, "pending": [],
                         "lastCheck": "2026-10-12T09:00", "oclp": False}, **u)
    return f


def update_cards(f):
    return [x for x in easy_report.build_data(f)["todo"] if x["cat"] == "update"]


def update_texts(f):
    d = easy_report.build_data(f)
    out = [o["text"] for o in d["ok"] if o["cat"] == "update"]
    for x in d["todo"]:
        if x["cat"] == "update":
            out += [x["title"], x["what"], x["why"], x["how"]] + x.get("steps", [])
            out += [x[k] for k in ("time", "undo", "keep", "askAi") if k in x]
    return out


class UpdateSettingsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="bb-preflight-test-")
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "com.apple.SoftwareUpdate.plist")

    def write(self, d):
        with open(self.path, "wb") as f:
            plistlib.dump(d, f)

    def test_reads_settings_and_pending(self):
        self.write({"AutomaticCheckEnabled": True, "CriticalUpdateInstall": True, "ConfigDataInstall": True,
                    "AutomaticallyInstallMacOSUpdates": False,
                    "LastSuccessfulDate": datetime.datetime(2026, 10, 1, 8, 30),
                    "RecommendedUpdates": [{"Display Name": "macOS Sequoia 15.7.8", "Display Version": "15.7.8",
                                            "Identifier": "MSU_UPDATE"}, "junk"]})
        u = collect.update_settings(self.path, oclp=False)
        self.assertEqual(u["check"], True)
        self.assertEqual(u["securityData"], True)
        self.assertIs(u["macosAuto"], False)
        self.assertEqual(u["pending"], ["macOS Sequoia 15.7.8 15.7.8"])
        self.assertEqual(u["lastCheck"], "2026-10-01T08:30")
        self.assertIs(u["oclp"], False)

    def test_missing_keys_mean_defaults(self):
        self.write({"ConfigDataInstall": False})
        u = collect.update_settings(self.path, oclp=True)
        self.assertEqual((u["check"], u["securityData"], u["macosAuto"], u["pending"], u["lastCheck"]),
                         (True, False, None, [], ""))
        self.assertIsNone(collect.update_settings(os.path.join(self.dir, "none.plist"), oclp=False))

    def test_broken_plist_does_not_crash(self):
        with open(self.path, "wb") as f:
            f.write(b"not a plist")
        self.assertEqual(collect.update_settings(self.path, oclp=False)["pending"], [])


class UpdateFindingsTest(unittest.TestCase):
    def test_non_oclp_pending_updates_are_reported(self):
        cards = update_cards(with_updates(pending=["macOS Sequoia 15.7.8"]))
        self.assertEqual([c["level"] for c in cards], ["yellow"])
        self.assertIn("macOS Sequoia 15.7.8", cards[0]["what"]["en"])
        self.assertIn("backup", cards[0]["how"]["en"])

    def test_non_oclp_stale_check_is_reported(self):
        self.assertEqual(len(update_cards(with_updates(lastCheck="2026-09-01T09:00"))), 1)   # 42 days
        self.assertEqual(len(update_cards(with_updates(check=False))), 1)
        f = with_updates()
        self.assertEqual(update_cards(f), [])                                              # 1 day: fine
        self.assertTrue(any("last checked 1 days ago" in x["en"] for x in update_texts(f)))
        self.assertEqual(update_cards(with_updates(lastCheck="")), [])                     # unknown: not guessed

    def test_oclp_mac_is_never_told_to_update(self):
        # the owner's Mac: OCLP, updates waiting, last check long ago, protection data off
        f = with_updates(oclp=True, pending=["macOS Sequoia 15.7.8", "macOS Tahoe 26.1"], lastCheck="2026-01-01T09:00",
                         securityData=False, check=False)
        self.assertEqual(update_cards(f), [])
        texts = update_texts(f)
        blob = json.dumps(texts, ensure_ascii=False)
        for w in PUSH_WORDS:
            self.assertNotIn(w, blob)
        self.assertIn("再起動できなくなる", blob)                                          # the warning is there
        self.assertIn("unable to restart", blob)
        self.assertIn("macOS Tahoe 26.1", blob)                                            # told what is waiting, not pushed
        whole = json.dumps(easy_report.build_data(f), ensure_ascii=False)
        self.assertNotIn("アップデートしましょう", whole)

    def test_oclp_auto_install_is_a_warning_to_turn_it_off(self):
        cards = update_cards(with_updates(oclp=True, macosAuto=True))
        self.assertEqual([c["level"] for c in cards], ["yellow"])
        c = cards[0]
        self.assertIn("unable to restart", c["why"]["en"])
        self.assertIn("turn off", " ".join(s["en"] for s in c["steps"]))
        blob = json.dumps(update_texts(with_updates(oclp=True, macosAuto=True)), ensure_ascii=False)
        for w in PUSH_WORDS:
            self.assertNotIn(w, blob)

    def test_update_texts_are_bilingual(self):
        for f in (with_updates(pending=["X 1"], check=False, securityData=False),
                  with_updates(oclp=True, macosAuto=True, pending=["X 1"]), with_updates(oclp=True)):
            for x in update_texts(f):
                self.assertEqual(set(x), {"ja", "en"})
                self.assertTrue(x["ja"].strip() and x["en"].strip(), x)
                self.assertNotRegex(x["en"].replace("X 1", ""), r"[぀-ヿ一-鿿]", x["en"])


class KnownTest(unittest.TestCase):
    def test_known_txt_is_read_without_comments(self):
        d = tempfile.mkdtemp(prefix="bb-preflight-test-")
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "known.txt"), "w", encoding="utf-8") as f:
            f.write("# 自分で作ったもの\ncom.koichi.dell-dimmer\n\n  Bartender 6  # menu bar\ncom.koichi.dell-dimmer\n")
        old = os.environ.get("BB_PREFLIGHT_HOME")
        os.environ["BB_PREFLIGHT_HOME"] = d
        try:
            self.assertEqual(collect.known_names(), ["com.koichi.dell-dimmer", "Bartender 6"])
        finally:
            if old is None:
                del os.environ["BB_PREFLIGHT_HOME"]
            else:
                os.environ["BB_PREFLIGHT_HOME"] = old

    def facts(self):
        f = base()
        f["autostart"] = {"total": 2, "bundled": 0, "items": [
            {"label": "com.koichi.dell-dimmer", "file": "~/Library/LaunchAgents/com.koichi.dell-dimmer.plist", "where": "user",
             "program": "~/bin/dimmer", "flags": ["unsigned"], "sign": {"kind": "unsigned"}},
            {"label": "com.apple.finder.agent", "file": "~/Library/LaunchAgents/com.apple.finder.agent.plist", "where": "user",
             "program": "~/Library/Caches/x", "flags": ["fakeApple", "temp", "ioc"], "sign": {"kind": "adhoc"}}]}
        return f

    def levels(self, f, cat):
        return sorted(x["level"] for x in easy_report.build_data(f)["todo"] if x["cat"] == cat)

    def test_known_names_move_yellow_items_to_ok(self):
        f = self.facts()
        self.assertEqual(self.levels(f, "autostart"), ["red", "yellow"])
        self.assertEqual(self.levels(f, "ai"), ["yellow"])
        self.assertEqual(self.levels(f, "apps"), ["yellow"])
        f["known"] = ["com.koichi.dell-dimmer", "com.example.nightly", "MyServer", "Helper App"]
        self.assertEqual(self.levels(f, "autostart"), ["red"])
        self.assertEqual(self.levels(f, "ai"), [])
        self.assertEqual(self.levels(f, "apps"), [])
        ok = json.dumps([o for o in easy_report.build_data(f)["ok"]], ensure_ascii=False)
        self.assertIn("com.koichi.dell-dimmer", ok)                                       # still shown, as yours
        self.assertIn("known.txt", ok)

    def test_known_never_hides_red_flags(self):
        f = self.facts()
        f["known"] = ["com.apple.finder.agent"]
        self.assertEqual(self.levels(f, "autostart"), ["red", "yellow"])

    def test_cards_explain_how_to_mark_your_own(self):
        d = easy_report.build_data(self.facts())
        for cat in ("ai", "apps"):
            card = [x for x in d["todo"] if x["cat"] == cat][0]
            self.assertIn("known.txt", card["keep"]["en"])
        card = [x for x in d["todo"] if x["cat"] == "autostart" and x["level"] == "yellow"][0]
        self.assertIn("known.txt", card["keep"]["ja"])

    def test_same_permission_in_two_files_is_listed_once(self):
        f = base()
        rule = "Bash(python3 -c ' *)"
        f["aiPermissions"] = {"files": 2, "bypass": [], "mcpWide": [],
                              "broad": [{"kind": "code", "rule": rule, "file": "~/.claude/settings.json"},
                                        {"kind": "code", "rule": rule, "file": "~/work/.claude/settings.local.json"}]}
        card = [x for x in easy_report.build_data(copy.deepcopy(f))["todo"] if x["cat"] == "aiperm"][0]
        self.assertEqual(card["what"]["en"].count(rule), 1)


if __name__ == "__main__":
    unittest.main()
