#!/usr/bin/env python3
"""実測（読み取り専用）: このMacの待ち受け・ファイアウォール・公開URL・AIエージェント周りを調べて facts.json に書く。

- 何も変更しない（kill・設定変更なし）。秘密情報の値は出力しない（ファイル名と件数のみ）。
- /usr/bin/python3 (3.9) で動く書き方にする（3.10 以降の記法は使わない）。

使い方: python3 collect.py <inventory.json> <out/facts.json>
"""
import datetime
import glob
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import shutil
import socket
import time
import subprocess
import sys

HOME = os.path.expanduser("~")


def run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        return "ERROR: %s" % e


def classify_addr(addr):
    """待ち受けアドレスを loopback / tailscale / lan / all に分類する。"""
    host = addr.rsplit(":", 1)[0].strip("[]")
    if host in ("*", "0.0.0.0", "::"):
        return "all"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "tailscale"
    return "lan"


def listeners():
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"])
    rows, pid, cmd = [], None, None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("c"):
            cmd = line[1:]
        elif line.startswith("n"):
            addr = line[1:]
            port = int(addr.rsplit(":", 1)[1]) if addr.rsplit(":", 1)[1].isdigit() else 0
            rows.append({"process": cmd, "pid": pid, "addr": addr, "port": port, "scope": classify_addr(addr)})
    # lsof（root 権限なし）は root 所有の待ち受け（SMB 445・Kerberos 88・CUPS 631・SSH 等）を返さない。
    # netstat は所有者に関係なく全部見えるので、netstat を正にして lsof でプロセス名を補う。
    known = {(r["port"], r["scope"]) for r in rows}
    for line in run(["netstat", "-an", "-p", "tcp"]).splitlines():
        f = line.split()
        if len(f) < 6 or f[5] != "LISTEN":
            continue
        host, _, p = f[3].rpartition(".")
        if not p.isdigit():
            continue
        addr = "%s:%s" % ("*" if host == "*" else host, p)
        scope = classify_addr(addr)
        if (int(p), scope) not in known:
            known.add((int(p), scope))
            rows.append({"process": "（root 所有・名前不明）", "pid": "", "addr": addr, "port": int(p), "scope": scope})
    # 同じ (process, port, scope) は1つにまとめる（IPv4/IPv6 の重複など）
    seen, uniq = set(), []
    for r in rows:
        k = (r["process"], r["port"], r["scope"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def lan_ips():
    """自分の LAN 側 IP。ifconfig（macOS）を優先し、無ければ既定経路の送信元 IP を使う（パケットは送らない）。"""
    ips = [l.split()[1] for l in run(["ifconfig"]).splitlines()
           if l.strip().startswith("inet ") and len(l.split()) > 1 and classify_addr(l.split()[1] + ":0") == "lan"]
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # UDP の connect は経路を決めるだけで送信しない
            ip = s.getsockname()[0]
            s.close()
            if classify_addr(ip + ":0") == "lan":
                ips = [ip]
        except OSError:
            pass
    return ips


def port_open(ip, port, timeout=2.0):
    """TCP で接続できるかだけを確かめる（何も送らずに閉じる）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_lan(ports):
    """LAN 側の自分の IP に対して、遠隔管理系ポートが実際に開いているかを確かめる。"""
    res = []
    for ip in lan_ips()[:1]:
        for p in ports:
            res.append({"ip": ip, "port": p, "open": port_open(ip, p)})
    return res


def firewall():
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    g = run([fw, "--getglobalstate"])
    s = run([fw, "--getstealthmode"])
    return {"enabled": "enabled" in g.lower(), "stealth": "stealth mode is on" in s.lower(), "raw": g.strip()}


def probe_urls(endpoints):
    """公開URLへ未認証でアクセスし、ステータスと転送先だけ記録する（転送は追わない）。"""
    res = []
    for ep in endpoints:
        out = run(["curl", "-s", "-o", "/dev/null", "-m", "10", "-w", "%{http_code} %{redirect_url}", ep["url"]], timeout=15)
        parts = out.strip().split(" ", 1)
        code = parts[0] if parts and parts[0].isdigit() else "ERR"
        loc = parts[1] if len(parts) > 1 else ""
        if code == "ERR" or code == "000":
            verdict = "unreachable"
        elif code in ("401", "403") or "cloudflareaccess.com" in loc or "/cdn-cgi/access" in loc:
            verdict = "auth_required"
        elif code.startswith("2"):
            verdict = "open"
        else:
            verdict = "other"
        res.append({"id": ep["id"], "url": ep["url"], "code": code, "redirect": loc, "verdict": verdict})
    return res


def agents():
    """AIエージェント周り: ローカル MCP サーバー名、claude を呼ぶ launchd ジョブ、有効プラグイン数。"""
    mcp = set()
    plugins = 0
    for f in [HOME + "/.claude.json", HOME + "/.claude/settings.json"]:
        try:
            d = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        mcp.update((d.get("mcpServers") or {}).keys())
        for v in (d.get("projects") or {}).values():
            mcp.update((v.get("mcpServers") or {}).keys())
        plugins = max(plugins, len([k for k, v in (d.get("enabledPlugins") or {}).items() if v]))
    jobs = []
    for f in sorted(glob.glob(HOME + "/Library/LaunchAgents/*.plist")):
        try:
            p = plistlib.load(open(f, "rb"))
        except Exception:  # noqa: BLE001
            continue
        args = " ".join(p.get("ProgramArguments") or [p.get("Program", "")])
        body = args
        # 引数のスクリプトが claude を呼ぶかも見る（先頭 64KB のみ）
        for a in p.get("ProgramArguments") or []:
            if os.path.isfile(a) and a.endswith((".sh", ".py", ".js")):
                try:
                    body += open(a, errors="ignore").read(65536)
                except Exception:  # noqa: BLE001
                    pass
        # パス（~/.claude/ 等）ではなく、実際の呼び出しだけを数える
        if re.search(r"(^|[\s/\"'`;(])claude\s+(-p|--print)\b|api\.anthropic\.com|anthropic\.Anthropic\(|from anthropic import", body):
            jobs.append(p.get("Label") or os.path.basename(f))
    return {"local_mcp_servers": sorted(mcp), "claude_launchd_jobs": jobs, "enabled_plugins": plugins}


SECRET_PATTERNS = [
    ("anthropic", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("github", r"gh[pousr]_[A-Za-z0-9]{30,}"),
    ("stripe_live", r"[sr]k_live_[A-Za-z0-9]{16,}"),
    ("aws", r"AKIA[0-9A-Z]{16}"),
    ("groq", r"gsk_[A-Za-z0-9]{30,}"),
    ("npm", r"npm_[A-Za-z0-9]{36}"),
    ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


PLACEHOLDER = re.compile(r"x{3,}|X{3,}|your|example|dummy|\.\.\.|\*{3,}", re.I)


def storage(fp):
    """鍵が見つかったファイルの置き方。本人しか読めないか、Git の追跡から外れているか。"""
    try:
        private = os.stat(fp).st_mode & 0o077 == 0
    except OSError:
        private = None
    try:
        r = subprocess.run(["git", "-C", os.path.dirname(fp), "check-ignore", "-q", fp],
                           capture_output=True, timeout=10)
        # 0: 無視されている / 1: 無視されていない（追跡されうる）/ それ以外: Git の管理外
        git_ignored = True if r.returncode == 0 else False if r.returncode == 1 else None
    except Exception:  # noqa: BLE001
        git_ignored = None
    return {"private": private, "gitIgnored": git_ignored}


GUARD_STATE = os.path.join(HOME, ".claude", "supply-chain", "state.json")
GUARD_STALE_DAYS = 3  # supply-chain-guard 自身が「日次が止まっている」とみなす日数に合わせる


def npm_rc_ignore_scripts(path):
    """~/.npmrc に ignore-scripts=true があるか（npm が無いときの代わり）。"""
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                k, _, v = line.partition("=")
                if k.strip() == "ignore-scripts":
                    return v.strip().lower() == "true"
    except OSError:
        return None
    return False


def npm_protection():
    """npm の感染対策の状態（読むだけ。npm の設定も supply-chain-guard の結果も変えない）。

    - used: npm を使っている形跡（npm コマンドか ~/.npm キャッシュ）
    - ignoreScripts: install のときにパッケージのスクリプトを動かさない設定か
    - guard: supply-chain-guard の最後の走査結果（入っていなければ None）
    """
    npm = shutil.which("npm")
    used = bool(npm) or os.path.isdir(os.path.join(HOME, ".npm"))
    ignore = None
    if npm:
        out = run([npm, "config", "get", "ignore-scripts"]).strip().lower()
        if out in ("true", "false"):
            ignore = out == "true"
    if ignore is None:
        ignore = npm_rc_ignore_scripts(os.path.join(HOME, ".npmrc"))
    guard = None
    try:
        with open(GUARD_STATE, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = None
    if isinstance(state, dict):
        # 本人が「確認済み」にしたものは数えない（supply-chain-guard の finding_key と同じ作り方）
        acked = state.get("acknowledged") or {}
        seen, count = set(), {"high": 0, "medium": 0}
        for key in ("last_quick", "last_full"):
            for x in (state.get(key) or {}).get("findings", []):
                sev, k = x.get("sev"), (x.get("sev"), x.get("msg"))
                if k in seen or sev not in count or x.get("id") == "self":
                    continue
                seen.add(k)
                fk = hashlib.sha256(("%s|%s|%s" % (sev, x.get("id"), x.get("msg"))).encode("utf-8", "replace")).hexdigest()[:16]
                if fk not in acked:
                    count[sev] += 1
        at = [(state.get(k) or {}).get("at") for k in ("last_quick", "last_full")]
        at = [a for a in at if isinstance(a, (int, float))]
        last = max(at) if at else None
        quick = (state.get("last_quick") or {}).get("at")
        guard = {
            "lastScanAt": datetime.datetime.fromtimestamp(last).isoformat(timespec="minutes") if last else "",
            "high": count["high"],
            "medium": count["medium"],
            "stale": not isinstance(quick, (int, float)) or time.time() - quick > GUARD_STALE_DAYS * 86400,
        }
    return {"used": used, "ignoreScripts": ignore, "guard": guard}


def secret_scan(roots):
    """平文の鍵らしき文字列を探す。値は出さず、ファイル名と種類だけ返す。"""
    hits = []
    rx = [(n, re.compile(p)) for n, p in SECRET_PATTERNS]
    exts = (".md", ".txt", ".json", ".yaml", ".yml", ".html", ".js", ".py", ".sh", ".toml")
    for root in roots:
        root = os.path.expanduser(root)
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in ("node_modules", ".git", "dist", "dist-cli", "vendor", "vendor-CyberRiskScape", "__pycache__",
                                          "venv", ".venv", "site-packages", "out")]
            for fn in fns:
                if not (fn.endswith(exts) or fn.startswith(".env") or fn in (".npmrc", ".netrc", ".pypirc")
                        or fn.endswith((".token", ".plist", ".env", ".cfg", ".ini", ".conf"))):
                    continue
                fp = os.path.join(dp, fn)
                try:
                    if os.path.getsize(fp) > 2_000_000:
                        continue
                    with open(fp, errors="ignore") as f:
                        s = f.read()
                except Exception:  # noqa: BLE001
                    continue
                kinds = sorted({n for n, r in rx for v in r.findall(s) if not PLACEHOLDER.search(v if isinstance(v, str) else "")})
                if kinds:
                    hits.append(dict({"file": fp, "kinds": kinds}, **storage(fp)))
    return hits


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        inv = json.load(f)
    facts = {
        "measuredAt": datetime.datetime.now().isoformat(timespec="seconds"),
        "listeners": listeners(),
        "firewall": firewall(),
        "lanProbe": probe_lan(inv.get("remoteAdminPorts", [])),
        "urls": probe_urls(inv.get("endpoints", [])),
        "agents": agents(),
        "secrets": secret_scan(inv.get("secretScanRoots", [])),
        "npm": npm_protection(),
    }
    os.makedirs(os.path.dirname(sys.argv[2]), exist_ok=True)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(facts, f, ensure_ascii=False, indent=1)
    print("listeners=%d urls=%d secrets=%d firewall=%s" % (
        len(facts["listeners"]), len(facts["urls"]), len(facts["secrets"]), facts["firewall"]["enabled"]))


if __name__ == "__main__":
    main()
