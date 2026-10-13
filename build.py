#!/usr/bin/env python3
"""facts.json（実測）+ inventory.json（台帳）+ 前回の model.json → CyberRiskScape のプロジェクト JSON。

設計の約束:
- ノード ID は実測内容から決める（連番にしない）。脅威 ID はノード ID を含むので、
  ID が変わらなければアプリで付けた「リスク受容」等の判断が再実測後も残る。
- 前回ファイルから suppressions / riskScores / controlStatuses / manualThreats / projectMeta、
  ノードと境界の座標・seq を引き継ぐ。書き換えるのは構成と属性だけ。
- 実測していない属性は書かない（アプリ上は「未入力」になる）。もっともらしい値で埋めない。

使い方: python3 build.py <inventory.json> <facts.json> <model.json(前回・上書き先)>
"""
import json
import os
import sys

COLS = {"users": 40, "exposed": 380, "local": 720, "public": 1060, "saas": 1400, "agent": 1740}
ROW = 130
CARRY_KEYS = ("suppressions", "riskScores", "controlStatuses", "manualThreats", "projectMeta", "disabledLibraryIds")


def slug(s):
    out = "".join(c if c.isalnum() else "-" for c in s.lower())
    return "-".join(p for p in out.split("-") if p)[:40] or "x"


class Model:
    def __init__(self):
        self.nodes, self.edges, self.bounds = [], [], []
        self.rows = {k: 0 for k in COLS}

    def node(self, nid, ntype, label, col=None, parent=None, **attrs):
        n = {"id": nid, "type": ntype, "label": label, "x": 0, "y": 0}
        if parent:
            n["parentId"] = parent
        else:
            n["x"] = COLS[col]
            n["y"] = 60 + self.rows[col] * ROW
            self.rows[col] += 1
        n.update({k: v for k, v in attrs.items() if v is not None})
        self.nodes.append(n)
        return nid

    def edge(self, src, dst, auth, network, encryption, name=None, semantic=None):
        e = {"id": "e-%s--%s" % (src[2:], dst[2:]), "source": src, "target": dst,
             "auth": auth, "network": network, "encryption": encryption}
        if name:
            e["dataFlowName"] = name[:80]
        if semantic:
            e["semantic"] = semantic
        self.edges.append(e)

    def boundary(self, bid, btype, cols, trust, **attrs):
        """指定した列のノードを囲む境界を作る。"""
        xs = [n for n in self.nodes if "parentId" not in n and n["x"] in [COLS[c] for c in cols]]
        if not xs:
            return
        x0 = min(n["x"] for n in xs) - 30
        y0 = min(n["y"] for n in xs) - 40
        x1 = max(n["x"] for n in xs) + 230
        y1 = max(n["y"] for n in xs) + 110
        b = {"id": bid, "type": btype, "x": x0, "y": y0, "width": x1 - x0, "height": y1 - y0, "trustLevel": trust}
        b.update(attrs)
        self.bounds.append(b)


def build(inv, facts):
    m = Model()
    names = inv.get("portNames", {})
    admin_ports = set(inv.get("remoteAdminPorts", []))
    eph = inv.get("ephemeralPortFrom", 49152)
    fw = facts["firewall"]
    today = facts["measuredAt"][:10]

    owner = m.node("n-owner", "USER", "本人", "users", userTrustAttribute="Employee")
    m.node("n-mac", "PC", "メインMac（ファイアウォール: %s）" % ("有効" if fw["enabled"] else "無効"), "local",
           managedState="Managed",
           description="実測 %s。待ち受け %d 件。パッチ状況は実測していない（OCLP 環境のため要確認）。" % (
               facts["measuredAt"], len(facts["listeners"])))

    # --- このMacで待ち受けているサーバー ---
    lan_needed = any(l["scope"] in ("all", "lan") for l in facts["listeners"])
    tail_needed = any(l["scope"] == "tailscale" for l in facts["listeners"])
    if lan_needed:
        m.node("n-lan-other", "USER", "同じLAN上の他の機器・来訪者", "users", userTrustAttribute="Guest")
    if tail_needed:
        m.node("n-tail-device", "SMARTPHONE", "本人の端末（Tailscale 経由）", "users", managedState="Managed")

    seen = set()
    for l in sorted(facts["listeners"], key=lambda r: (r["scope"], r["port"])):
        port = l["port"]
        key = slug(l["process"]) if port >= eph else str(port)
        nid = "n-%s-%s" % (l["scope"], key)
        if nid in seen:
            continue
        seen.add(nid)
        pname = names.get(str(port), l["process"])
        portlabel = "随時変わるポート" if port >= eph else ":%d" % port
        label = "%s %s" % (pname, portlabel)
        if l["scope"] == "loopback":
            # Mac の中だけで完結する処理。外から線を引かない（雑音を出さない）
            m.node(nid, "PROCESS", label + "（127.0.0.1のみ）", "local", description="プロセス: %s" % l["process"])
        elif l["scope"] == "tailscale":
            m.node(nid, "FRONT_END_SERVER", label + "（Tailscale のみ）", "exposed",
                   description="プロセス: %s / 待ち受け: %s" % (l["process"], l["addr"]),
                   attackSurface={"hasGlobalIp": False, "hasSourceIpRestriction": True})
            m.edge("n-tail-device", nid, "None", "VPN", "E2EE", "Tailscale 経由で開く")
        else:
            surf = {"hasGlobalIp": False, "hasSourceIpRestriction": False}
            if port in admin_ports:
                surf["hasRemoteAccessRestriction"] = False
            m.node(nid, "FRONT_END_SERVER", label + "（全インターフェース）", "exposed",
                   description="プロセス: %s / 待ち受け: %s / ファイアウォール: %s。LAN 内の他の機器から届く可能性がある。" % (
                       l["process"], l["addr"], "有効（アプリ単位の許可次第）" if fw["enabled"] else "無効"),
                   attackSurface=surf)
            m.edge("n-lan-other", nid, "None", "VPC", "Plain", "LAN から直接届く")

    # --- 公開サイト（実測: 未認証アクセスの応答） ---
    urls = {u["id"]: u for u in facts["urls"]}
    if any(s for s in inv.get("publicSites", [])):
        m.node("n-internet", "USER", "インターネット上の利用者・第三者", "users", userTrustAttribute="Guest")
    for s in inv.get("publicSites", []):
        u = urls.get(s.get("endpoint"), {})
        verdict = u.get("verdict", "未実測")
        nid = "n-site-" + s["id"]
        surf = dict(s.get("attackSurface", {}))
        if s.get("admin"):
            protected = verdict == "auth_required"
            surf["hasUserAuthentication"] = protected
            auth = s.get("authWhenProtected", "Password") if protected else "None"
        else:
            auth = s.get("visitorAuth", "None")
        m.node(nid, "FRONT_END_SERVER", s["label"], "public", attackSurface=surf,
               description="実測 %s: HTTP %s %s → %s" % (today, u.get("code", "-"), u.get("redirect", ""), verdict))
        m.edge("n-internet", nid, auth, "Internet", "TLS", s.get("visitorFlow"))
    # 手放したはずの入口が応答していたら赤で出す
    for u in facts["urls"]:
        if u["id"].startswith("old-") and u["verdict"] != "unreachable":
            nid = "n-site-" + u["id"]
            m.node(nid, "FRONT_END_SERVER", "解約済みのはずの入口が応答: %s" % u["url"], "public",
                   attackSurface={"hasGlobalIp": True, "hasUserAuthentication": False},
                   description="実測 %s: HTTP %s → %s" % (today, u["code"], u["verdict"]))
            m.edge("n-internet", nid, "None", "Internet", "TLS", "解約後も届く")

    for d in inv.get("dataStores", []):
        nid = "n-data-" + d["id"]
        m.node(nid, d.get("type", "DATA_STORE"), d["label"], "public")
        if d.get("pii"):
            m.node(nid + "-pii", "PERSONAL_INFO", d["pii"]["label"], parent=nid)
        if d.get("from"):
            m.edge("n-site-" + d["from"], nid, d.get("edgeAuth", "Token"), "VPC", "TLS", "保存・参照")

    # --- 外部サービス（台帳） ---
    for s in inv.get("saas", []):
        nid = "n-saas-" + s["id"]
        m.node(nid, s.get("type", "SAAS"), s["label"], "saas", cloudSanction="Sanctioned", cloudOwnership="Company")
        m.edge(owner, nid, s.get("ownerAuth", "Password"), "Internet", "TLS", "管理画面へのログイン")
        for link in s.get("appLinks", []):
            m.edge("n-site-" + link["from"], nid, link.get("auth", "ApiKey"), "Internet", "TLS", link.get("flow"))

    # --- AI エージェント ---
    ag = facts["agents"]
    m.node("n-agent-claude", "AGENT", "Claude Code（このMac・プラグイン %d 個）" % ag["enabled_plugins"], "agent",
           description="本人の指示で動く。シェル実行・ファイル編集が可能。")
    if any(s["id"] == "anthropic" for s in inv.get("saas", [])):
        m.edge("n-agent-claude", "n-saas-anthropic", "Token", "Internet", "TLS", "モデル呼び出し")
    for name in ag["local_mcp_servers"]:
        nid = "n-mcp-" + slug(name)
        m.node(nid, "MCP_SERVER", "ローカル MCP: %s" % name, "agent")
        m.edge("n-agent-claude", nid, "None", "VPC", "Plain", "ツール呼び出し（stdio）", semantic="tool_invocation")
    for c in inv.get("aiConnectors", {}).get("items", []):
        nid = "n-conn-" + c["id"]
        m.node(nid, "TOOL", c["label"] + ("（送信・書き込み可）" if c.get("canSend") else ""), "agent")
        m.edge("n-agent-claude", nid, "Token", "Internet", "TLS", "ツール呼び出し", semantic="tool_invocation")
    for job in ag["claude_launchd_jobs"]:
        nid = "n-job-" + slug(job)
        m.node(nid, "AGENT", "定期ジョブ: %s" % job, "agent", description="launchd から無人で起動")
        if any(s["id"] == "anthropic" for s in inv.get("saas", [])):
            m.edge(nid, "n-saas-anthropic", "Token", "Internet", "TLS", "モデル呼び出し")

    # --- 平文の鍵らしき文字列（値は持たない） ---
    for h in facts["secrets"]:
        nid = "n-secret-" + slug(os.path.relpath(h["file"], os.path.expanduser("~")))
        m.node(nid, "CREDENTIAL", "平文の鍵の疑い: %s（%s）" % (os.path.basename(h["file"]), ",".join(h["kinds"])),
               parent="n-mac", description=h["file"])

    # --- 信頼境界 ---
    m.boundary("b-home", "ROUNDED", ["exposed", "local"], "Internal", macroTrust="Office Area")
    m.boundary("b-cloud", "RECT_DASHED", ["public", "saas"], "Internet")
    m.boundary("b-agent", "ROUNDED_DASHED", ["agent"], "Internal")
    return m


def assemble(m, prev, measured_at):
    pl = (prev or {}).get("layers", {}).get("L1", {})
    prev_nodes = {n["id"]: n for n in pl.get("nodes", [])}
    prev_edges = {e["id"]: e for e in pl.get("edges", [])}
    prev_bounds = {b["id"]: b for b in pl.get("boundaries", [])}

    def seqs(items, prevmap):
        nxt = max([p.get("seq", 0) for p in prevmap.values()] + [0]) + 1
        for it in items:
            p = prevmap.get(it["id"])
            if p and p.get("seq"):
                it["seq"] = p["seq"]
            else:
                it["seq"] = nxt
                nxt += 1
        return max([it["seq"] for it in items] + [nxt - 1])

    for n in m.nodes:  # 人がアプリで動かした座標を残す
        p = prev_nodes.get(n["id"])
        if p:
            n["x"], n["y"] = p["x"], p["y"]
    for b in m.bounds:
        p = prev_bounds.get(b["id"])
        if p:
            for k in ("x", "y", "width", "height"):
                b[k] = p[k]
    cn = seqs(m.nodes, prev_nodes)
    ce = seqs(m.edges, prev_edges)
    cb = seqs(m.bounds, prev_bounds)

    emp = lambda: {"nodes": [], "edges": [], "boundaries": [], "annotations": []}  # noqa: E731
    layers = (prev or {}).get("layers") or {"L0": emp(), "L1": emp(), "L2": emp(), "L3": emp()}
    layers["L1"] = {"nodes": m.nodes, "edges": m.edges, "boundaries": m.bounds,
                    "annotations": pl.get("annotations", [])}
    counters = (prev or {}).get("idCounters") or {k: {"node": 0, "edge": 0, "boundary": 0} for k in ("L0", "L2", "L3")}
    counters["L1"] = {"node": cn, "edge": ce, "boundary": cb}
    proj = {"schemaVersion": 1, "layers": layers, "activeLayer": "L1", "idCounters": counters,
            "activeFramework": (prev or {}).get("activeFramework", "ALL"),
            "projectMeta": {"name": "FOREST LIFE* 事業の実測点検", "systemName": "メインMac・公開サイト・外部サービス・AIエージェント",
                            "purpose": "IPA 注意喚起（2026-10-09）に沿った点検。実測から自動生成（%s）" % measured_at,
                            "businessImpact": "購入者情報・APIキー・販売導線", "securityObjectives": ""},
            "updatedAt": 0}
    for k in CARRY_KEYS:
        if prev and k in prev:
            proj[k] = prev[k]
    proj.setdefault("suppressions", {})
    return proj


def main():
    inv = json.load(open(sys.argv[1]))
    facts = json.load(open(sys.argv[2]))
    out = sys.argv[3]
    prev = json.load(open(out)) if os.path.exists(out) else None
    m = build(inv, facts)
    proj = assemble(m, prev, facts["measuredAt"])
    tmp = out + ".tmp"
    json.dump(proj, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, out)
    print("nodes=%d edges=%d boundaries=%d (carried decisions: %d)" % (
        len(m.nodes), len(m.edges), len(m.bounds), len(proj.get("suppressions", {}))))


if __name__ == "__main__":
    main()
