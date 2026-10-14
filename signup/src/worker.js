// Preflight のメール登録（Cloudflare Worker + D1 + Resend）。名簿は FOREST LIFE* の Cloudflare に置く。
//
//   POST /subscribe     申し込み（紹介ページの欄から。確認メールを送る）
//   GET  /confirm?t=    確認リンク（登録を終え、ダウンロードの案内を送る）
//   GET  /unsubscribe   配信停止の確認画面（ボタンを押すと止まる。リンクの先読みで止まらないように）
//   POST /unsubscribe   配信停止（メールソフトのワンクリック停止 RFC 8058 もここに来る）
//   cron（毎時）         3日後・7日後のメール、期限切れの確認待ちと、保存期間を過ぎた記録の削除
//
// SEND_MODE が "live" でない間は、Resend を呼ばずにログに出すだけ（設定の途中で誤って送らないため）。
import { renderEmail } from "./emails.js";

export const CONSENT = {
  ja: "メールアドレスを登録すると、ダウンロードの案内のほか、更新のお知らせと点検サービスのご案内をお送りします。いつでも配信を止められます。",
  en: "When you sign up, we'll send you the download, plus news about updates and our check-up service. You can unsubscribe at any time.",
};

const DAY = 86400_000;
export const CONFIRM_TTL = 7 * DAY;     // 確認リンクの有効期限
export const RESEND_GAP = 10 * 60_000;  // 確認メールを送り直すまでの間隔
export const STEPS = [3 * DAY, 7 * DAY]; // 確認から何日後に案内を送るか（step 1, 2）
export const KEEP_AFTER = 31 * DAY;     // 停止のあと、同意の記録を残す期間（最後の送信または停止から）
const IP_LIMIT = 5;                     // 同じ IP からの申し込みは1時間に5回まで
const EMAIL_RE = /^[^\s@"<>()[\]\\,;:]+@[^\s@"<>()[\]\\,;:]+\.[^\s@"<>()[\]\\,;:]+$/;

const iso = (t) => new Date(t).toISOString();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
export const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const randomToken = () => hex(crypto.getRandomValues(new Uint8Array(24)));

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg)));
}
export const unsubToken = (env, id, email) => hmac(env.TOKEN_SECRET, `unsub:${id}:${email}`);

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function settings(env) {
  return {
    publicBase: (env.PUBLIC_BASE || "").replace(/\/$/, ""),
    siteBase: (env.SITE_BASE || "https://blackboxblast.com").replace(/\/$/, ""),
    origins: (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean),
    from: env.MAIL_FROM,
    replyTo: env.MAIL_REPLY_TO,
    senderName: env.SENDER_NAME || "FOREST LIFE*",
    senderAddress: env.SENDER_ADDRESS || "",
    contact: env.CONTACT || "",
    downloadUrl: env.DOWNLOAD_URL || "",
    live: env.SEND_MODE === "live",
  };
}

// ------------------------------------------------------------ 返し方

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

const json = (body, status, extra = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });

const PAGE = {
  ja: {
    confirmed: ["登録が終わりました", "ダウンロードの案内をメールでお送りしました。届かないときは、迷惑メールのフォルダも見てください。"],
    expired: ["リンクの期限が切れています", "お手数ですが、紹介ページからもう一度申し込んでください。"],
    unsubAsk: ["配信を止めますか", "下のボタンを押すと、このアドレスへのメールを止めます。Preflight はそのまま使えます。"],
    unsubBtn: "配信を止める",
    unsubDone: ["配信を止めました", "これ以降、このアドレスにはお送りしません。Preflight はそのまま使えます。"],
    bad: ["リンクが正しくありません", "メールにあったリンクを、そのまま開いてください。"],
    back: "Preflight の紹介ページへ",
  },
  en: {
    confirmed: ["You're signed up", "We've emailed you the download. If it doesn't arrive, check your spam folder."],
    expired: ["This link has expired", "Please sign up again from the Preflight page."],
    unsubAsk: ["Unsubscribe?", "Click the button below to stop emails to this address. Preflight keeps working."],
    unsubBtn: "Unsubscribe",
    unsubDone: ["You're unsubscribed", "We won't email this address again. Preflight keeps working."],
    bad: ["This link isn't valid", "Please open the link exactly as it appears in the email."],
    back: "Back to the Preflight page",
  },
};

const escHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page(lang, s, [title, text], status = 200, form = "") {
  const l = lang === "en" ? "en" : "ja";
  const back = `${s.siteBase}/${l}/preflight/`;
  const html = `<!doctype html><html lang="${l}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escHtml(title)}</title>
<style>:root{color-scheme:light dark}body{margin:0;padding:48px 16px;font-family:-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;line-height:1.7;background:#f4f5f7;color:#1b1d21}@media (prefers-color-scheme:dark){body{background:#0c0d0f;color:#e6e8eb}}main{max-width:520px;margin:0 auto}h1{font-size:1.5rem;margin:0 0 12px}button{font:inherit;font-weight:700;padding:10px 18px;border:0;border-radius:4px;background:#ff7a1a;color:#0c0d0f;cursor:pointer}a{color:inherit}</style>
<main><h1>${escHtml(title)}</h1><p>${escHtml(text)}</p>${form}<p><a href="${escHtml(back)}">${escHtml(PAGE[l].back)}</a></p></main></html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" },
  });
}

// ------------------------------------------------------------ 送信

export async function sendEmail(env, s, sub, kind, extra = {}, fetchImpl = fetch) {
  const unsubUrl = `${s.publicBase}/unsubscribe?id=${sub.id}&t=${await unsubToken(env, sub.id, sub.email)}`;
  const v = { ...s, unsubUrl, ...extra };
  const mail = renderEmail(kind, sub.lang, v);
  const body = {
    from: s.from,
    to: [sub.email],
    subject: mail.subject,
    text: mail.text,
    html: mail.html,
    ...(s.replyTo ? { reply_to: s.replyTo } : {}),
    // 確認メールは宣伝ではないので停止の見出しを付けない。ほかはメールソフトの「配信停止」ボタンに対応する
    ...(kind === "confirm" ? {} : { headers: { "List-Unsubscribe": `<${unsubUrl}>`, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" } }),
  };
  if (s.live) {
    // 特定電子メール法の表示（送信者・所在地・連絡先）が欠けたまま送らない
    const missing = ["from", "publicBase", "senderName", "senderAddress", "contact", ...(kind === "welcome" ? ["downloadUrl"] : [])].filter((k) => !s[k]);
    if (missing.length) throw new Error(`not configured: ${missing.join(", ")}`);
  } else {
    console.log("dry-run email", JSON.stringify({ kind, to: sub.email, subject: mail.subject }));
    return { dry: true };
  }
  const res = await fetchImpl("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
      // 同じメールを二重に送らない（cron の再実行などで）
      "Idempotency-Key": extra.idempotencyKey || `${kind}-${sub.id}-${sub.step}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`resend ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

async function verifyTurnstile(env, token, ip, fetchImpl) {
  if (!env.TURNSTILE_SECRET) return false; // 試し運転でも必須（無いまま外に出しても、誰も登録できないようにする）
  if (typeof token !== "string" || !token || token.length > 2048) return false;
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  const res = await fetchImpl("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  if (!res.ok) return false;
  const out = await res.json();
  return out.success === true;
}

async function logEvent(db, email, kind, detail, ipHash, now) {
  await db.prepare("INSERT INTO events (email, kind, detail, ip_hash, at) VALUES (?, ?, ?, ?, ?)").bind(email, kind, detail ?? null, ipHash ?? null, iso(now)).run();
}

// ------------------------------------------------------------ 申し込み

export async function subscribe(request, env, { now = Date.now(), fetchImpl = fetch } = {}) {
  const s = settings(env);
  const origin = request.headers.get("Origin") || "";
  if (!s.origins.includes(origin)) return json({ error: "origin" }, 403);
  const h = cors(origin);
  if (!(request.headers.get("Content-Type") || "").startsWith("application/json")) return json({ error: "type" }, 415, h);
  let body;
  try {
    const raw = await request.text();
    if (raw.length > 4096) return json({ error: "size" }, 413, h);
    body = JSON.parse(raw);
  } catch {
    return json({ error: "format" }, 400, h);
  }
  const ok = json({ ok: true }, 200, h); // 登録済みかどうかは返さない（アドレスの調べ出しを防ぐ）
  if (!body || typeof body !== "object") return json({ error: "format" }, 400, h);
  if (body.website) return ok; // ボット向けの見えない欄に何か入っていたら、何もせず受け付けたふりをする
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (email.length > 254 || !EMAIL_RE.test(email)) return json({ error: "email" }, 400, h);
  const lang = body.lang === "en" ? "en" : "ja";
  if (body.consent !== true) return json({ error: "consent" }, 400, h);

  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ipHash = ip ? (await sha256(`${env.IP_HASH_SALT || ""}:${ip}`)).slice(0, 32) : null;
  const db = env.DB;
  if (ipHash) {
    const r = await db.prepare("SELECT COUNT(*) AS n FROM events WHERE ip_hash = ? AND kind = 'signup' AND at > ?").bind(ipHash, iso(now - 3600_000)).first();
    if (r && r.n >= IP_LIMIT) return json({ error: "rate" }, 429, h);
  }
  if (!(await verifyTurnstile(env, body.turnstileToken, ip, fetchImpl))) return json({ error: "challenge" }, 400, h);

  const existing = await db.prepare("SELECT * FROM subscribers WHERE email = ?").bind(email).first();
  await logEvent(db, email, "signup", lang, ipHash, now);
  if (existing && existing.status === "active") return ok;
  if (existing && existing.status === "pending" && existing.confirm_sent_at && now - Date.parse(existing.confirm_sent_at) < RESEND_GAP) return ok;

  const token = randomToken();
  const confirmHash = await sha256(token);
  let id;
  if (existing) {
    await db.prepare("UPDATE subscribers SET lang = ?, status = 'pending', confirm_hash = ?, confirm_sent_at = ?, consent_text = ?, step = 0, confirmed_at = NULL, unsubscribed_at = NULL WHERE id = ?")
      .bind(lang, confirmHash, iso(now), CONSENT[lang], existing.id).run();
    id = existing.id;
  } else {
    const r = await db.prepare("INSERT INTO subscribers (email, lang, status, confirm_hash, confirm_sent_at, consent_text, created_at) VALUES (?, ?, 'pending', ?, ?, ?, ?) RETURNING id")
      .bind(email, lang, confirmHash, iso(now), CONSENT[lang], iso(now)).first();
    id = r.id;
  }
  const sub = { id, email, lang, step: 0 };
  try {
    await sendEmail(env, s, sub, "confirm", { confirmUrl: `${s.publicBase}/confirm?t=${token}`, idempotencyKey: `confirm-${confirmHash.slice(0, 32)}` }, fetchImpl);
  } catch (err) {
    console.error("confirm mail failed", err && err.message);
    // すぐにもう一度押せるように、送り直しの間隔を空ける
    await db.prepare("UPDATE subscribers SET confirm_sent_at = ? WHERE id = ?").bind(iso(now - RESEND_GAP), id).run();
    return json({ error: "send" }, 502, h);
  }
  return ok;
}

// ------------------------------------------------------------ 確認

export async function confirm(request, env, { now = Date.now(), fetchImpl = fetch } = {}) {
  const s = settings(env);
  const url = new URL(request.url);
  const token = url.searchParams.get("t") || "";
  const langHint = url.searchParams.get("lang") === "en" ? "en" : "ja";
  if (!/^[0-9a-f]{48}$/.test(token)) return page(langHint, s, PAGE[langHint].bad, 400);
  const db = env.DB;
  const sub = await db.prepare("SELECT * FROM subscribers WHERE confirm_hash = ?").bind(await sha256(token)).first();
  if (!sub) return page(langHint, s, PAGE[langHint].expired, 410);
  const L = PAGE[sub.lang] ? sub.lang : "ja";
  if (sub.status === "active") return page(L, s, PAGE[L].confirmed);
  if (sub.status !== "pending" || now - Date.parse(sub.confirm_sent_at) > CONFIRM_TTL) return page(L, s, PAGE[L].expired, 410);
  // 確認のあとも confirm_hash は残す（メールソフトがリンクを先に開いても、本人が押したときに「登録済み」と出せるように）
  await db.prepare("UPDATE subscribers SET status = 'active', confirmed_at = ?, step = 0, last_sent_at = ? WHERE id = ?").bind(iso(now), iso(now), sub.id).run();
  await logEvent(db, sub.email, "confirm", sub.consent_text, null, now);
  await sendEmail(env, s, { ...sub, step: 0 }, "welcome", { idempotencyKey: `welcome-${sub.id}-${Date.parse(sub.confirm_sent_at)}` }, fetchImpl);
  return page(L, s, PAGE[L].confirmed);
}

// ------------------------------------------------------------ 配信停止

export async function unsubscribe(request, env, { now = Date.now() } = {}) {
  const s = settings(env);
  const url = new URL(request.url);
  const id = Number(url.searchParams.get("id"));
  const t = url.searchParams.get("t") || "";
  const db = env.DB;
  const sub = Number.isInteger(id) && id > 0 ? await db.prepare("SELECT * FROM subscribers WHERE id = ?").bind(id).first() : null;
  const L = sub && PAGE[sub.lang] ? sub.lang : "ja";
  if (!sub || !timingSafeEqual(t, await unsubToken(env, sub.id, sub.email))) return page(L, s, PAGE[L].bad, 400);
  if (request.method === "GET") {
    if (sub.status === "unsubscribed") return page(L, s, PAGE[L].unsubDone);
    const form = `<form method="post"><p><button type="submit">${escHtml(PAGE[L].unsubBtn)}</button></p></form>`;
    return page(L, s, PAGE[L].unsubAsk, 200, form);
  }
  const oneClick = (await request.text()).includes("List-Unsubscribe=One-Click");
  if (sub.status !== "unsubscribed") {
    await db.prepare("UPDATE subscribers SET status = 'unsubscribed', unsubscribed_at = ? WHERE id = ?").bind(iso(now), sub.id).run();
    await logEvent(db, sub.email, "unsubscribe", oneClick ? "one-click" : "page", null, now);
  }
  // メールソフトのワンクリック停止には、空の 200 を返す（RFC 8058）
  if (oneClick) return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
  return page(L, s, PAGE[L].unsubDone);
}

// ------------------------------------------------------------ 定期の処理

// Resend の無料枠は1日100通まで。1回（毎時）に送る数を抑えて、確認メールの分を残す
export async function runScheduled(env, { now = Date.now(), fetchImpl = fetch, limit = 10 } = {}) {
  const s = settings(env);
  const db = env.DB;
  const sent = [];
  for (let i = 0; i < STEPS.length; i++) {
    const step = i + 1;
    const { results } = await db.prepare("SELECT * FROM subscribers WHERE status = 'active' AND step = ? AND confirmed_at <= ? ORDER BY id LIMIT ?")
      .bind(step - 1, iso(now - STEPS[i]), limit).all();
    for (const sub of results) {
      try {
        await sendEmail(env, s, { ...sub, step }, `step${step}`, { idempotencyKey: `step${step}-${sub.id}-${Date.parse(sub.confirmed_at)}` }, fetchImpl);
        await db.prepare("UPDATE subscribers SET step = ?, last_sent_at = ? WHERE id = ? AND step = ?").bind(step, iso(now), sub.id, step - 1).run();
        await logEvent(db, sub.email, "send", `step${step}`, null, now);
        sent.push(`${sub.id}:step${step}`);
      } catch (err) {
        console.error("send failed", sub.id, err && err.message); // 次の回にもう一度試す
      }
    }
  }
  // 確認されないまま期限を過ぎた申し込みは消す
  const stale = await db.prepare("SELECT id, email FROM subscribers WHERE status = 'pending' AND confirm_sent_at < ?").bind(iso(now - CONFIRM_TTL)).all();
  // 配信を止めて、最後の送信と停止の両方から保存期間を過ぎたものは、記録ごと消す
  const done = await db.prepare("SELECT id, email FROM subscribers WHERE status = 'unsubscribed' AND unsubscribed_at < ? AND (last_sent_at IS NULL OR last_sent_at < ?)")
    .bind(iso(now - KEEP_AFTER), iso(now - KEEP_AFTER)).all();
  const removed = [];
  for (const sub of [...stale.results, ...done.results]) {
    await db.prepare("DELETE FROM subscribers WHERE id = ?").bind(sub.id).run();
    await db.prepare("DELETE FROM events WHERE email = ?").bind(sub.email).run();
    removed.push(sub.id);
  }
  // 申し込みの記録（いたずら調査用）は、名簿に残っていない人の分を 31 日で消す
  await db.prepare("DELETE FROM events WHERE at < ? AND email NOT IN (SELECT email FROM subscribers)").bind(iso(now - KEEP_AFTER)).run();
  return { sent, removed };
}

// ------------------------------------------------------------ 入口

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      // 秘密の値がそろうまでは、何も受け付けない
      if (!env.TOKEN_SECRET || !env.TURNSTILE_SECRET || !env.IP_HASH_SALT) return json({ error: "not_ready" }, 503);
      if (url.pathname === "/subscribe") {
        const origin = request.headers.get("Origin") || "";
        if (request.method === "OPTIONS") {
          return settings(env).origins.includes(origin) ? new Response(null, { status: 204, headers: cors(origin) }) : new Response(null, { status: 403 });
        }
        if (request.method === "POST") return await subscribe(request, env);
      }
      if (url.pathname === "/confirm" && request.method === "GET") return await confirm(request, env);
      if (url.pathname === "/unsubscribe" && (request.method === "GET" || request.method === "POST")) return await unsubscribe(request, env);
      return new Response("Not found", { status: 404, headers: { "X-Robots-Tag": "noindex" } });
    } catch (err) {
      console.error("signup:", err && err.message);
      return json({ error: "server" }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env).then((r) => console.log("scheduled", JSON.stringify(r))));
  },
};
