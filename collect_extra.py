"""実測（読み取り専用）の追加分: 居座り・偽装・開くだけで動く仕掛け・AI ツールの鍵と版・ブラウザの拡張機能。

collect.py から呼ぶ。何も変更せず、sudo も使わない。鍵やファイルの中身は記録せず、場所と種類だけを残す。
/usr/bin/python3 (3.9) で動く書き方にする。

判定（赤・黄）は easy_report.py が行う。ここでは「どこに・何が・誰の署名で」あるかと、その印（flags）だけを記録する。
"""
import collections
import glob
import json
import os
import plistlib
import re
import shutil
import subprocess

HOME = os.path.expanduser("~")
HERE = os.path.dirname(os.path.realpath(__file__))

# Google の開発者 ID（Chrome や Google の更新ツールの署名）
GOOGLE_TEAM = "EQHXZ8M8AV"

# Apple・Google を名乗るときによく使われる名前（拡張子を除き、大文字小文字は区別しない）
APPLE_NAMES = {"finder", "crashreporter", "softwareupdate", "softwareupdated", "system settings", "system preferences",
               "systemupdater", "icloud", "icloudsync", "icloudz", "safari", "spotlight", "keychain", "launchd",
               "trustd", "xprotect", "mrt", "appleupdate"}
GOOGLE_NAMES = {"googleupdate", "googleupdater", "googlesoftwareupdate", "keystone", "ksfetch", "google chrome"}

# 一時置き場（再起動で消える・誰でも書ける・キャッシュ）。ここから自動で動くものはまず無い
TEMP_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", HOME + "/Library/Caches/")
# パッケージ管理（Homebrew・MacPorts・Nix）の置き場。署名がなくても、そういうもの
PKG_DIRS = ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/usr/local/Homebrew/", "/opt/local/", "/nix/store/")
# Apple 自身の置き場
APPLE_DIRS = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/Library/Apple/")
# ホームの隠しフォルダのうち、開発の道具などがふつうに使うもの
KNOWN_DOT_DIRS = {".claude", ".config", ".local", ".npm", ".nvm", ".cargo", ".rustup", ".pyenv", ".rbenv", ".volta",
                  ".bun", ".deno", ".docker", ".orbstack", ".colima", ".rd", ".lima", ".bb-preflight", ".codex",
                  ".gemini", ".cursor", ".vscode", ".ollama", ".n8n", ".hermes", ".sdkman", ".jenv", ".asdf",
                  ".nodenv", ".goenv", ".gem", ".conda", ".pixi", ".fly", ".supabase", ".wrangler", ".lmstudio",
                  ".oh-my-zsh", ".rvm", ".pnpm", ".yarn", ".gradle", ".m2", ".android", ".dotnet", ".tailscale"}
INTERPRETERS = {"sh", "bash", "zsh", "dash", "osascript", "python", "python3", "node", "perl", "ruby", "env", "bun", "deno"}
MACHO = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def short(p):
    return "~" + p[len(HOME):] if p.startswith(HOME + "/") or p == HOME else p


def load_ioc(path=None):
    """既知の痕跡の一覧（ioc.json）。無ければ空。"""
    try:
        with open(path or os.path.join(HERE, "ioc.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


# --- 署名 -------------------------------------------------------------------

_SIG_CACHE = {}


def signature(path):
    """codesign で署名を読む（読むだけ）。kind: apple / appstore / devid / dev / adhoc / unsigned / other / None（読めない）。"""
    path = os.path.realpath(path)
    if path in _SIG_CACHE:
        return _SIG_CACHE[path]
    res = {"kind": None, "team": "", "signer": "", "valid": None}
    if not shutil.which("codesign"):
        _SIG_CACHE[path] = res
        return res
    try:
        r = subprocess.run(["codesign", "-dv", "--verbose=2", path], capture_output=True, text=True, timeout=20)
        out = r.stderr + r.stdout
    except Exception:  # noqa: BLE001
        _SIG_CACHE[path] = res
        return res
    if "not signed at all" in out:
        res["kind"] = "unsigned"
    elif "Signature=adhoc" in out:
        res["kind"] = "adhoc"
    elif re.search(r"^Authority=Software Signing$", out, re.M):
        res["kind"] = "apple"
    elif "Authority=Apple Mac OS Application Signing" in out:
        res["kind"] = "appstore"
    elif "Authority=Developer ID Application" in out:
        res["kind"] = "devid"
    elif "Authority=Apple Development" in out:
        res["kind"] = "dev"
    elif r.returncode == 0:
        res["kind"] = "other"
    m = re.search(r"^TeamIdentifier=(\S+)", out, re.M)
    if m and m.group(1) != "not":
        res["team"] = m.group(1)
    m = re.search(r"^Authority=Developer ID Application: (.+?) \(", out, re.M)
    if m:
        res["signer"] = m.group(1)
    if res["kind"] not in (None, "unsigned"):
        try:
            res["valid"] = subprocess.run(["codesign", "--verify", path], capture_output=True, timeout=60).returncode == 0
        except Exception:  # noqa: BLE001
            res["valid"] = None
    _SIG_CACHE[path] = res
    return res


def brand_claim(*names):
    """名前が Apple か Google を名乗っているか。"apple" / "google" / None。"""
    for n in names:
        if not n:
            continue
        base = os.path.basename(str(n).rstrip("/"))
        low = re.sub(r"\.(app|plist|sh|py|js|bin)$", "", base.lower())
        if low.startswith("com.apple.") or low in APPLE_NAMES:
            return "apple"
        if low.startswith("com.google.") or low in GOOGLE_NAMES:
            return "google"
    return None


def genuine(claim, sig):
    """名乗っている会社の本物の署名か。"""
    if claim == "apple":
        return sig.get("kind") == "apple"
    if claim == "google":
        return sig.get("kind") == "devid" and sig.get("team") == GOOGLE_TEAM
    return True


def place_flags(path):
    """置き場所の印。temp: 一時置き場 / hiddenHomeFile: ホーム直下の隠しファイル / hiddenDir: 見慣れない隠しフォルダ /
    shared: /Users/Shared / pkg: パッケージ管理 / apple: Apple の置き場。"""
    flags = []
    p = path if path.startswith("/") else os.path.join(HOME, path)
    if p.startswith(TEMP_DIRS) or p in ("/tmp", "/private/tmp"):
        flags.append("temp")
    if p.startswith("/Users/Shared/"):
        flags.append("shared")
    if p.startswith(PKG_DIRS):
        flags.append("pkg")
    if p.startswith(APPLE_DIRS):
        flags.append("apple")
    if p.startswith(HOME + "/."):
        rest = p[len(HOME) + 1:]
        top = rest.split("/", 1)[0]
        if "/" not in rest:
            flags.append("hiddenHomeFile")
        elif top not in KNOWN_DOT_DIRS:
            flags.append("hiddenDir")
    return flags


def is_macho(fp):
    try:
        with open(fp, "rb") as f:
            return f.read(4) in MACHO
    except OSError:
        return False


# --- 自動で起動するもの -------------------------------------------------------

OCLP_DIR = "/Library/Application Support/Dortania/"
LAUNCH_DIRS = ((HOME + "/Library/LaunchAgents", "user"), ("/Library/LaunchAgents", "agent"), ("/Library/LaunchDaemons", "daemon"))


def launch_target(p):
    """plist から、実際に動くもの（プログラムか、インタープリタに渡すスクリプト）を取り出す。"""
    args = [str(a) for a in (p.get("ProgramArguments") or [])]
    prog = str(p.get("Program") or (args[0] if args else ""))
    script, inline = False, ""
    if os.path.basename(prog) in INTERPRETERS or re.match(r"^python[0-9.]*$", os.path.basename(prog)):
        rest = args[1:]  # ProgramArguments の先頭は、Program があってもなくても argv[0]
        for i, a in enumerate(rest):
            if a in ("-c", "-lc", "-e") and i + 1 < len(rest):
                inline = rest[i + 1]
                break
            if a.startswith("-") or (os.path.basename(prog) == "env" and "=" in a):
                continue
            if os.path.basename(prog) == "env" and not a.startswith("/"):
                continue
            prog, script = a, True
            break
    return prog, script, inline, " ".join(args)


DOWNLOAD_RUN = re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\$\(\s*(curl|wget)\b|<\(\s*(curl|wget)\b")
DECODE_RUN = re.compile(r"base64\s+(-d|-D|--decode)\b[^\n]*(\|\s*(ba|z)?sh\b|\|\s*python|\|\s*osascript|\|\s*perl)|\beval\b[^\n]*base64\s+(-d|-D|--decode)")


def judge_program(prog, script, names, ioc_hit=False):
    """1つの実行ファイル（またはスクリプト）に印を付ける。"""
    flags = list(place_flags(prog))
    exists = os.path.exists(prog)
    claim = brand_claim(*names)
    sig = {"kind": None, "team": "", "signer": "", "valid": None}
    if exists and not script:
        sig = signature(prog)
    if claim and not ("apple" in flags and claim == "apple"):
        if script or not genuine(claim, sig):
            flags.append("fake" + claim.capitalize())
    if not exists:
        flags.append("missing")
    if not script and sig.get("kind") in ("unsigned", "adhoc"):
        flags.append(sig["kind"])
    if sig.get("valid") is False:
        flags.append("invalidSig")
    if ioc_hit:
        flags.append("ioc")
    return flags, sig


def autostart(claude_jobs=(), ioc=None, dirs=LAUNCH_DIRS, app_dirs=("/Applications", HOME + "/Applications")):
    """LaunchAgents・LaunchDaemons と、アプリの中に入っているログイン項目の部品。

    ログイン項目の一覧そのもの（システム設定の「ログイン項目」）は、sudo なしでは読めない。
    そのため、アプリの中にある自動起動の部品（Contents/Library/LoginItems・LaunchAgents）を名前と署名で確かめる。
    """
    ioc = ioc if ioc is not None else load_ioc()
    bad_labels = {x["label"]: x.get("where") for x in ioc.get("launchLabels", [])}
    items, total = [], 0
    for d, where in dirs:
        for f in sorted(glob.glob(os.path.join(d, "*.plist"))):
            total += 1
            try:
                with open(f, "rb") as fp:
                    p = plistlib.load(fp)
            except Exception:  # noqa: BLE001
                items.append({"label": os.path.basename(f), "file": short(f), "where": where, "program": "",
                              "flags": ["unreadable"], "sign": {}})
                continue
            if not isinstance(p, dict):
                continue
            label = str(p.get("Label") or os.path.basename(f)[:-6])
            prog, script, inline, cmd = launch_target(p)
            hit = label in bad_labels and bad_labels[label] in (None, where)
            flags, sig = judge_program(prog, script, (label, os.path.basename(f), prog), hit)
            if DOWNLOAD_RUN.search(cmd) or DECODE_RUN.search(cmd):
                flags.append("downloadRun")
            if label in claude_jobs:
                flags.append("claudeJob")
            if label.startswith("com.dortania.") and prog.startswith(OCLP_DIR):
                flags.append("oclp")  # OpenCore Legacy Patcher 自身の自動起動（OCLP の Mac では必要なもの）
            if p.get("Disabled") is True:
                flags.append("disabled")
            items.append({"label": label, "file": short(f), "where": where, "program": short(prog), "script": script,
                          "inline": bool(inline), "flags": sorted(set(flags)), "sign": sig})
    bundled = 0
    for d in app_dirs:
        for app in sorted(glob.glob(os.path.join(d, "*.app"))):
            for sub in ("Contents/Library/LoginItems/*.app", "Contents/Library/LaunchAgents/*.plist"):
                for helper in glob.glob(os.path.join(app, sub)):
                    bundled += 1
                    claim = brand_claim(helper)
                    if not claim:
                        continue  # 名乗っていない部品は、親のアプリと同じ署名で守られている
                    sig = signature(helper if helper.endswith(".app") else app)
                    if not genuine(claim, sig):
                        items.append({"label": os.path.basename(helper), "file": short(helper), "where": "bundled",
                                      "program": short(helper), "script": False, "inline": False,
                                      "flags": ["fake" + claim.capitalize()], "sign": sig})
    return {"items": items, "total": total, "bundled": bundled}


# --- 偽装・改ざん ---------------------------------------------------------------

SCAN_CAP = 60000  # 1か所あたりに見る数の上限（大きなキャッシュで時間を使い切らないように）
SKIP_SCAN = {"node_modules", ".git", "Homebrew", "pip", "pypoetry", "go-build", "ms-playwright", "Cypress", "electron",
             "node-gyp", "yarn", "pnpm", "JetBrains", "Google/Chrome", "Code", "Cursor", "Slack", "discord", "Docker",
             "MobileSync", "CloudDocs", "Knowledge", "com.apple.TCC", "AddressBook", "CallHistoryDB", "Steam"}
WALLET_APPS = ("Ledger Live", "Exodus", "Trezor Suite", "Electrum", "Atomic Wallet", "Wasabi Wallet", "Sparrow",
               "Coinomi", "Guarda", "Bitcoin Core", "Bitcoin-Qt", "Trust Wallet", "Phantom")


def disguise_roots():
    roots = [(HOME + "/Library/Caches", 3), (HOME + "/Library/Application Support", 3), (HOME + "/.cache", 3),
             (HOME + "/.config", 3), ("/private/tmp", 2), ("/Users/Shared", 2)]
    try:
        for n in os.listdir(HOME):
            p = os.path.join(HOME, n)
            if n.startswith(".") and os.path.isdir(p) and not os.path.islink(p) and n not in KNOWN_DOT_DIRS | {".cache", ".Trash"}:
                roots.append((p, 2))
    except OSError:
        pass
    return roots


def walk_candidates(root, depth):
    """.app と Mach-O の実行ファイルを探す（中身は先頭 4 バイトだけ読む）。
    浅い所から順に見る（数の上限に達しても、com.apple.* のような1段目の怪しい名前は見落とさないように）。"""
    seen, queue = 0, collections.deque([(root, 0)])
    while queue:
        dp, level = queue.popleft()
        try:
            entries = sorted(os.listdir(dp))
        except OSError:
            continue
        seen += len(entries)
        if seen > SCAN_CAP:
            return
        rel = dp[len(root):].lstrip("/")
        for n in entries:
            full = os.path.join(dp, n)
            if os.path.islink(full):
                continue
            if os.path.isdir(full):
                if n.endswith(".app"):
                    yield full
                elif level + 1 < depth and n not in SKIP_SCAN and os.path.join(rel, n) not in SKIP_SCAN:
                    queue.append((full, level + 1))
                continue
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_mode & 0o111 and is_macho(full):
                yield full


def disguise(ioc=None, roots=None, procs=None, app_dirs=("/Applications", HOME + "/Applications")):
    """Apple・Google を名乗る偽のアプリ、既知の痕跡、一時置き場から動いているもの、ウォレットアプリの改ざん。"""
    ioc = ioc if ioc is not None else load_ioc()
    fakes, seen = [], set()
    for root, depth in (roots if roots is not None else disguise_roots()):
        if not os.path.isdir(root):
            continue
        for c in walk_candidates(root, depth):
            names = [c] + [part for part in c[len(root):].split("/") if part]
            claim = brand_claim(*names)
            flags = place_flags(c)
            if not claim and "hiddenHomeFile" not in flags:
                continue
            sig = signature(c)
            if claim and not genuine(claim, sig):
                fakes.append({"file": short(c), "claim": claim, "sign": sig, "flags": flags})
                seen.add(os.path.realpath(c))
            elif "hiddenHomeFile" in flags and sig.get("kind") in ("unsigned", "adhoc", None):
                fakes.append({"file": short(c), "claim": None, "sign": sig, "flags": flags})
                seen.add(os.path.realpath(c))
    hits = []
    for x in ioc.get("files", []):
        pat = os.path.expanduser(x["path"])
        for m in sorted(glob.glob(pat)):
            hits.append({"file": short(m), "pattern": x["path"], "source": x.get("source", "")})
    running = []
    for path in (procs if procs is not None else process_paths()):
        rp = os.path.realpath(path)
        if rp in seen or not os.path.exists(path):
            continue
        flags = place_flags(path)
        claim = brand_claim(path, os.path.dirname(path))
        if not (claim or "temp" in flags or "hiddenHomeFile" in flags) or "apple" in flags:
            continue
        sig = signature(path)
        if claim and not genuine(claim, sig):
            running.append({"file": short(path), "claim": claim, "sign": sig, "flags": flags})
        elif not claim and sig.get("kind") in ("unsigned", "adhoc"):
            running.append({"file": short(path), "claim": None, "sign": sig, "flags": flags})
        seen.add(rp)
    wallets = []
    for d in app_dirs:
        for n in WALLET_APPS:
            app = os.path.join(d, n + ".app")
            if os.path.isdir(app):
                sig = signature(app)
                wallets.append({"app": n, "file": short(app), "sign": sig,
                                "tampered": sig.get("kind") in ("unsigned", "adhoc") or sig.get("valid") is False})
    return {"fakes": fakes, "ioc": hits, "running": running, "wallets": wallets, "iocUpdated": ioc.get("updated", "")}


def process_paths():
    """今動いているプロセスの実行ファイルの場所（ps で読むだけ）。"""
    try:
        out = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, timeout=20).stdout
    except Exception:  # noqa: BLE001
        return []
    return sorted({l.strip() for l in out.splitlines() if l.strip().startswith("/")})


# --- シェルの起動ファイルと git の全体フック -----------------------------------

SHELL_FILES = (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile")
TEMP_RUN = re.compile(r"(^|[;&|(]\s*|\b(nohup|exec|sh|bash|zsh|python3?|open|source|\.)\s+)[\"']?"
                      r"((/private)?/tmp/|/var/tmp/|(~|\$HOME|/Users/[^/\s]+)/Library/Caches/)")
BACKGROUND = re.compile(r"(^|[;\s])nohup\s|[^&]&\s*(disown\s*)?$")
OSASCRIPT = re.compile(r"\bosascript\b")
HIDDEN_RUN = re.compile(r"(^|[;&|(]\s*|\b(nohup|exec)\s+)[\"']?(~|\$HOME)/\.(?!(%s)\b)[A-Za-z0-9_.-]+(\s|$|[\"'&;])"
                        % "|".join(re.escape(d[1:]) for d in sorted(KNOWN_DOT_DIRS)))


def shell_lines(text):
    """起動ファイルの、気になる行の番号と種類。行の中身は返さない。"""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        kinds = []
        if DOWNLOAD_RUN.search(s):
            kinds.append("downloadRun")
        if DECODE_RUN.search(s):
            kinds.append("decodeRun")
        if TEMP_RUN.search(s):
            kinds.append("tempRun")
        if HIDDEN_RUN.search(s):
            kinds.append("hiddenRun")
        if OSASCRIPT.search(s):
            kinds.append("osascript")
        if BACKGROUND.search(s):
            kinds.append("background")
        if kinds:
            hits.append({"line": i, "kinds": kinds})
    return hits


def git_config_values(paths):
    """~/.gitconfig などから core.hooksPath と init.templateDir を読む（git コマンドは呼ばない。
    コマンドライン・デベロッパ・ツールが無い Mac では、git を呼ぶとインストールの案内が出てしまうため）。"""
    vals = {}
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        sec = ""
        for line in text.splitlines():
            s = line.strip()
            m = re.match(r"^\[\s*([A-Za-z0-9.-]+)(\s+\"[^\"]*\")?\s*\]", s)
            if m:
                sec = m.group(1).lower() + ("" if not m.group(2) else ".sub")
                continue
            k, eq, v = s.partition("=")
            if not eq:
                continue
            key = "%s.%s" % (sec, k.strip().lower())
            if key in ("core.hookspath", "init.templatedir"):
                vals[key] = v.split("#", 1)[0].strip().strip('"')
    return vals


GIT_HOOKS = ("pre-commit", "post-checkout", "post-merge", "pre-push", "commit-msg", "prepare-commit-msg", "post-commit",
             "pre-rebase", "post-rewrite", "pre-auto-gc", "fsmonitor-watchman", "reference-transaction")


def shell_persistence(home=None):
    """シェルの起動ファイルの気になる行と、git の全体フック。"""
    home = home or HOME
    files = []
    for n in SHELL_FILES:
        fp = os.path.join(home, n)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="ignore") as f:
                text = f.read(1_000_000)
            mode = os.stat(fp).st_mode
        except OSError:
            continue
        files.append({"file": "~/" + n, "hits": shell_lines(text), "othersCanWrite": bool(mode & 0o022)})
    vals = git_config_values([os.path.join(home, ".gitconfig"), os.path.join(home, ".config", "git", "config")])
    git = []
    for key, sub in (("core.hookspath", ""), ("init.templatedir", "hooks")):
        v = vals.get(key)
        if not v:
            continue
        v = home + v[1:] if v.startswith("~") else v.replace("$HOME", home)
        d = os.path.join(v, sub)
        hooks = []
        try:
            if not os.path.isabs(d):
                raise OSError("relative")  # リポジトリごとに変わる場所。ここでは中を見ない
            for n in sorted(os.listdir(d)):
                fp = os.path.join(d, n)
                if n in GIT_HOOKS and os.path.isfile(fp) and os.stat(fp).st_mode & 0o111:
                    hooks.append(n)
        except OSError:
            pass
        flags = [f for f in place_flags(d.rstrip("/")) if f in ("temp", "hiddenDir", "shared")]
        if brand_claim(*[p for p in d.split("/") if p]):
            flags.append("fakeName")
        git.append({"setting": "core.hooksPath" if key == "core.hookspath" else "init.templateDir",
                    "dir": short(d.rstrip("/")), "hooks": hooks, "flags": flags})
    return {"files": files, "git": git}


# --- リポジトリを開くだけで動く仕掛け ---------------------------------------------

RULE_FILES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md", "SKILL.md"}
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH = re.compile("[\u200b\u200c\u2060-\u2064\u180e]|(?<!^)\ufeff")
RUNNER = re.compile(r"\b(node|bun|bunx|deno|npx|python3?|curl|wget|sh|bash|zsh)\b")


def hidden_text(text):
    kinds = []
    if TAG_CHARS.search(text):
        kinds.append("tags")
    if BIDI.search(text):
        kinds.append("bidi")
    if len(ZERO_WIDTH.findall(text)) >= 3:
        kinds.append("zeroWidth")
    return kinds


def read_text(fp, limit=2_000_000):
    try:
        if os.path.getsize(fp) > limit:
            return None
        with open(fp, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def hook_commands(hooks):
    cmds = []
    for groups in (hooks or {}).values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g or {}).get("hooks", []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    cmds.append(h["command"])
    return cmds


def open_to_run(roots, skip_dirs, depth, ioc=None):
    """走査範囲のプロジェクトにある、フォルダを開くだけで動く仕掛けと、指示ファイルの見えない文字。"""
    ioc = ioc if ioc is not None else load_ioc()
    bad = [x["path"] for x in ioc.get("repoFiles", [])]
    hooks, tasks, iocs, hidden = [], [], [], []
    rule_paths = [os.path.join(HOME, ".claude", "CLAUDE.md")]
    rule_paths += glob.glob(os.path.join(HOME, ".claude", "skills", "*", "SKILL.md"))
    rule_paths += glob.glob(os.path.join(HOME, ".claude", "agents", "*.md"))
    rule_paths += glob.glob(os.path.join(HOME, ".claude", "commands", "*.md"))
    for root in roots:
        root = os.path.expanduser(root)
        for dp, dns, fns in os.walk(root):
            if dp[len(root):].count(os.sep) >= depth:
                dns[:] = []
            dns[:] = [d for d in dns if d not in skip_dirs]
            name = os.path.basename(dp)
            proj = os.path.dirname(dp)
            if name == ".claude" and os.path.realpath(dp) != os.path.realpath(os.path.join(HOME, ".claude")):
                for n in ("settings.json", "settings.local.json"):
                    if n in fns:
                        try:
                            with open(os.path.join(dp, n), encoding="utf-8") as f:
                                h = (json.load(f) or {}).get("hooks") or {}
                        except (OSError, ValueError, AttributeError):
                            h = {}
                        if isinstance(h, dict) and h:
                            cmds = hook_commands(h)
                            hooks.append({"file": short(os.path.join(dp, n)), "events": sorted(h),
                                          "runsCode": any(RUNNER.search(c) for c in cmds)})
                rule_paths += [os.path.join(dp, "agents", x) for x in os.listdir(os.path.join(dp, "agents"))
                               if x.endswith(".md")] if os.path.isdir(os.path.join(dp, "agents")) else []
            if name == ".vscode" and "tasks.json" in fns:
                text = read_text(os.path.join(dp, "tasks.json")) or ""
                if re.search(r"\"runOn\"\s*:\s*\"folderOpen\"", text):
                    tasks.append({"file": short(os.path.join(dp, "tasks.json")),
                                  "runsCode": bool(re.search(r"setup\.mjs|\bbun\b|curl|wget", text))})
            if name in (".claude", ".vscode"):
                for b in bad:
                    if b.startswith(name + "/") and b.split("/", 1)[1] in fns:
                        iocs.append({"file": short(os.path.join(proj, b))})
            if name == "rules" and os.path.basename(proj) == ".cursor":
                rule_paths += [os.path.join(dp, x) for x in fns if x.endswith(".mdc")]
            rule_paths += [os.path.join(dp, x) for x in fns if x in RULE_FILES]
    for fp in dict.fromkeys(rule_paths):
        text = read_text(fp)
        if text:
            kinds = hidden_text(text)
            if kinds:
                hidden.append({"file": short(fp), "kinds": kinds})
    global_hooks = 0
    try:
        with open(os.path.join(HOME, ".claude", "settings.json"), encoding="utf-8") as f:
            global_hooks = len(hook_commands((json.load(f) or {}).get("hooks") or {}))
    except (OSError, ValueError, AttributeError):
        pass
    return {"hooks": hooks, "tasks": tasks, "ioc": iocs, "hidden": hidden, "globalHooks": global_hooks}


# --- AI ツールや開発ツールの鍵、MCP、AI CLI の版 ------------------------------------

CRED_FILES = [
    (".git-credentials", "git", re.compile(r"://[^\s:/]+:[^\s@]+@")),
    (".npmrc", "npm", re.compile(r"_authToken\s*=\s*(?!\$\{)\S+")),
    (".config/gh/hosts.yml", "gh", re.compile(r"oauth_token:\s*\S+")),
    (".docker/config.json", "docker", re.compile(r"\"auth\"\s*:\s*\"[^\"]{8,}\"")),
    (".netrc", "netrc", re.compile(r"\bpassword\s+\S+")),
    (".pypirc", "pypi", re.compile(r"^\s*password\s*[=:]\s*\S+", re.M)),
    (".aws/credentials", "aws", re.compile(r"aws_secret_access_key\s*=\s*\S+")),
    (".codex/auth.json", "codex", None),
    (".gemini/.env", "gemini", None),
    (".gemini/oauth_creds.json", "gemini", None),
    (".config/github-copilot/apps.json", "copilot", None),
    (".config/github-copilot/hosts.json", "copilot", None),
    (".claude/.credentials.json", "claude", None),
]


def cred_files(home=None):
    """鍵の置き場所になりやすいファイルが、本人以外にも読めないか、平文の鍵を持っていないか。値は返さない。"""
    home = home or HOME
    res = []
    for rel, kind, plain in CRED_FILES:
        fp = os.path.join(home, rel)
        if not os.path.isfile(fp):
            continue
        try:
            private = os.stat(fp).st_mode & 0o077 == 0
        except OSError:
            continue
        text = read_text(fp, 1_000_000) if plain else None
        res.append({"file": "~/" + rel, "kind": kind, "private": private,
                    "plain": bool(text and plain.search(text)) if plain else None})
    return res


SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.I)


def secret_values(d):
    """env や headers のうち、鍵らしい名前に、変数でない値が入っている数。"""
    n = 0
    for k, v in (d or {}).items() if isinstance(d, dict) else []:
        if SECRET_NAME.search(str(k)) and isinstance(v, str) and len(v) >= 8 and not v.startswith("$") and "${" not in v:
            n += 1
    return n


def unpinned(command, args):
    """npx / bunx / uvx で、版を固定せずに毎回最新を取ってくるか。"""
    exe = os.path.basename(str(command or ""))
    rest = [str(a) for a in args or []]
    if exe in ("npx", "bunx", "pnpx"):
        for a in rest:
            if a.startswith("-"):
                continue
            body = a[1:] if a.startswith("@") else a
            return "@" not in body
    if exe == "uvx":
        for a in rest:
            if a.startswith("-"):
                continue
            return "==" not in a and "@" not in a
    return False


def url_flags(url):
    m = re.match(r"^(https?)://([^/:]+)", str(url or ""))
    if not m:
        return False
    return m.group(1) == "http" and m.group(2) not in ("localhost", "127.0.0.1", "::1", "[::1]")


def strip_jsonc(text):
    """VS Code の設定（コメントと末尾のカンマあり）を JSON として読めるようにする。文字列の中は触らない。"""
    out, i, n, s = [], 0, len(text), False
    while i < n:
        c = text[i]
        if s:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                s = False
        elif c == '"':
            s = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def codex_servers(text):
    """~/.codex/config.toml の [mcp_servers.名前] を読む（3.9 には tomllib が無いので、必要な形だけ）。"""
    servers, cur, sub = {}, None, None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^\[mcp_servers\.([^\].]+)(\.(env|http_headers))?\]$", s)
        if m:
            cur, sub = m.group(1).strip('"'), m.group(3)
            servers.setdefault(cur, {"env": {}})
            continue
        if s.startswith("["):
            cur = None
            continue
        if cur is None or "=" not in s:
            continue
        k, _, v = s.partition("=")
        k, v = k.strip(), v.strip()
        if sub:
            servers[cur].setdefault("env", {})[k] = v.strip('"')
        elif k in ("command", "url"):
            servers[cur][k] = v.strip('"')
        elif k == "args":
            servers[cur]["args"] = re.findall(r"\"([^\"]*)\"", v)
        elif k == "env":
            servers[cur]["env"].update(dict(re.findall(r"([A-Za-z0-9_]+)\s*=\s*\"([^\"]*)\"", v)))
    return servers


def mcp_sources(home=None):
    home = home or HOME
    sup = os.path.join(home, "Library", "Application Support")
    return [(os.path.join(home, ".claude.json"), "Claude Code"),
            (os.path.join(sup, "Claude", "claude_desktop_config.json"), "Claude Desktop"),
            (os.path.join(home, ".cursor", "mcp.json"), "Cursor"),
            (os.path.join(home, ".gemini", "settings.json"), "Gemini CLI"),
            (os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "Windsurf"),
            (os.path.join(sup, "Code", "User", "mcp.json"), "VS Code"),
            (os.path.join(sup, "Code", "User", "settings.json"), "VS Code"),
            (os.path.join(home, ".codex", "config.toml"), "Codex")]


def mcp_inventory(home=None):
    """Claude 以外も含めた MCP サーバーの一覧。名前と形と印だけを残し、鍵の値や URL の中身は残さない。"""
    res, seen = [], set()
    for fp, app in mcp_sources(home):
        text = read_text(fp, 50_000_000)  # ~/.claude.json は履歴を含むので大きいことがある
        if not text:
            continue
        if fp.endswith(".toml"):
            groups = [codex_servers(text)]
        else:
            try:
                d = json.loads(strip_jsonc(text) if "/Code/User/" in fp else text)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            groups = [d.get("mcpServers"), d.get("servers"), (d.get("mcp") or {}).get("servers") if isinstance(d.get("mcp"), dict) else None]
            groups += [(v or {}).get("mcpServers") for v in (d.get("projects") or {}).values() if isinstance(v, dict)]
        for g in groups:
            for name, conf in (g or {}).items() if isinstance(g, dict) else []:
                if not isinstance(conf, dict) or (fp, name) in seen:
                    continue
                seen.add((fp, name))
                url = conf.get("url") or conf.get("serverUrl") or conf.get("httpUrl")
                res.append({"app": app, "source": short(fp), "name": str(name),
                            "transport": "remote" if url else "local",
                            "unpinned": unpinned(conf.get("command"), conf.get("args")),
                            "insecureUrl": url_flags(url),
                            "secretValues": secret_values(conf.get("env")) + secret_values(conf.get("headers"))})
    return res


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])


def package_version(start, name):
    """start から上にたどって、name のパッケージの package.json の版を読む。"""
    d = os.path.dirname(start) if os.path.isfile(start) else start
    for _ in range(8):
        pj = os.path.join(d, "package.json")
        if os.path.isfile(pj):
            try:
                with open(pj, encoding="utf-8") as f:
                    j = json.load(f)
                if j.get("name") == name:
                    return str(j.get("version") or "")
            except (OSError, ValueError):
                pass
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return ""


def which(cmd):
    extra = [os.path.join(HOME, ".local", "bin"), os.path.join(HOME, ".claude", "local"), "/opt/homebrew/bin", "/usr/local/bin"]
    path = os.pathsep.join([os.environ.get("PATH", "")] + extra)
    return shutil.which(cmd, path=path)


def claude_version():
    exe = which("claude")
    if not exe:
        return ""
    real = os.path.realpath(exe)
    m = re.search(r"/versions/(\d+\.\d+\.\d+)", real)
    if m:
        return m.group(1)
    v = package_version(real, "@anthropic-ai/claude-code")
    if v:
        return v
    # ~/.claude/local の古い入れ方は、中の node_modules を見る
    v = package_version(os.path.join(HOME, ".claude", "local", "node_modules", "@anthropic-ai", "claude-code"), "@anthropic-ai/claude-code")
    if v:
        return v
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15).stdout
    except Exception:  # noqa: BLE001
        return ""
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def gemini_version():
    exe = which("gemini")
    return package_version(os.path.realpath(exe), "@google/gemini-cli") if exe else ""


def app_version(name):
    for d in ("/Applications", os.path.join(HOME, "Applications")):
        p = os.path.join(d, name + ".app", "Contents", "Info.plist")
        try:
            with open(p, "rb") as f:
                return str(plistlib.load(f).get("CFBundleShortVersionString") or "")
        except Exception:  # noqa: BLE001
            continue
    return ""


def ai_cli_versions(ioc=None, found=None):
    """AI の道具の版を読み、既知の脆弱性が直った版より古いかを記録する。macOS の版は見ない。"""
    ioc = ioc if ioc is not None else load_ioc()
    if found is None:
        found = {"claude": claude_version(), "cursor": app_version("Cursor"), "gemini": gemini_version()}
    res = []
    for x in ioc.get("aiCli", []):
        v = found.get(x["tool"]) or ""
        if not v:
            continue
        res.append({"tool": x["tool"], "name": x.get("name", x["tool"]), "version": v, "fixed": x["fixed"],
                    "cve": x.get("cve", ""), "old": vtuple(v) < vtuple(x["fixed"])})
    return res


def ai_keys():
    return {"credFiles": cred_files(), "mcp": mcp_inventory(), "cli": ai_cli_versions()}


# --- ブラウザの拡張機能 ---------------------------------------------------------

BROWSERS = (("Chrome", "Google/Chrome"), ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "Microsoft Edge"),
            ("Chromium", "Chromium"), ("Vivaldi", "Vivaldi"), ("Arc", "Arc/User Data"))
STORE_HOSTS = ("clients2.google.com", "edge.microsoft.com")


def browser_extensions(ioc=None, base=None):
    """Chrome 系ブラウザの拡張機能を、既知の悪い ID と、ストアの外から入ったものとで確かめる（manifest.json を読むだけ）。"""
    ioc = ioc if ioc is not None else load_ioc()
    bad = {x["id"] for x in ioc.get("browserExtensions", [])}
    base = base or os.path.join(HOME, "Library", "Application Support")
    found, total, browsers = [], 0, []
    for name, rel in BROWSERS:
        root = os.path.join(base, rel)
        if not os.path.isdir(root):
            continue
        browsers.append(name)
        for ext_dir in sorted(glob.glob(os.path.join(root, "*", "Extensions", "*"))):
            ext_id = os.path.basename(ext_dir)
            if not re.match(r"^[a-p]{32}$", ext_id):
                continue
            mans = sorted(glob.glob(os.path.join(ext_dir, "*", "manifest.json")))
            if not mans:
                continue
            total += 1
            try:
                with open(mans[-1], encoding="utf-8-sig") as f:
                    man = json.load(f)
            except (OSError, ValueError):
                man = {}
            label = str(man.get("name") or ext_id)
            if label.startswith("__MSG_"):
                label = ext_id
            upd = str(man.get("update_url") or "")
            store = any(h in upd for h in STORE_HOSTS)
            if ext_id in bad or not store:
                found.append({"browser": name, "id": ext_id, "name": label[:60], "bad": ext_id in bad, "store": store})
    return {"browsers": browsers, "total": total, "items": found} if browsers else None

