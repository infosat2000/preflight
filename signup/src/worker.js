// Preflight のメール登録（Cloudflare Worker + D1 + Resend）。名簿は FOREST LIFE* の Cloudflare に置く。
//
//   POST /subscribe     申し込み（紹介ページの欄から。確認メールを送る）
//   GET  /confirm?t=    確認リンク（登録を終え、ダウンロードの案内を送る）
//   GET  /unsubscribe   配信停止の確認画面（ボタンを押すと止まる。リンクの先読みで止まらないように）
//   POST /unsubscribe   配信停止（メールソフトのワンクリック停止 RFC 8058 もここに来る）
//   GET  /download      確認済みの人専用のダウンロード画面（ボタンを押すと zip を渡す。期限切れなら新しいリンクを送れる）
//   POST /download      zip を渡す（R2 の非公開の置き場から）／ action=resend で新しいリンクをメールで送る
//   cron（毎時）         3日後のメール、新しい版のお知らせ（NEWS を入れたとき）、期限切れの確認待ちと、保存期間を過ぎた記録の削除
//
// SEND_MODE が "live" でない間は、Resend を呼ばずにログに出すだけ（設定の途中で誤って送らないため）。
import { renderEmail, NEWS } from "./emails.js";

export const CONSENT = {
  ja: "メールアドレスを登録すると、ダウンロードの案内のほか、使い方のご案内と、更新や注意が必要なセキュリティ情報のお知らせをお送りします。いつでも配信を止められます。",
  en: "When you sign up, we'll send you the download, plus a short guide to using it and news about updates and security issues worth knowing about. You can unsubscribe at any time.",
};

const DAY = 86400_000;
export const CONFIRM_TTL = 7 * DAY;     // 確認リンクの有効期限
export const RESEND_GAP = 10 * 60_000;  // 確認メールを送り直すまでの間隔
export const STEPS = [3 * DAY]; // 確認から何日後に案内を送るか（step 1）
export const KEEP_AFTER = 31 * DAY;     // 停止のあと、同意の記録を残す期間（最後の送信または停止から）
export const DOWNLOAD_TTL = 7 * DAY;    // ダウンロードのリンクの有効期限
export const DOWNLOAD_LIMIT = 5;        // 1つのリンクで受け取れる回数
const RELINK_GAP = 10 * 60_000;         // 新しいダウンロードのリンクを送り直すまでの間隔
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
export const downloadToken = (env, id, email, exp) => hmac(env.TOKEN_SECRET, `dl:${id}:${email}:${exp}`);

export async function downloadLink(env, s, sub, now) {
  const exp = now + DOWNLOAD_TTL;
  return `${s.publicBase}/download?id=${sub.id}&e=${exp}&t=${await downloadToken(env, sub.id, sub.email, exp)}`;
}

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
    downloadKey: env.DOWNLOAD_KEY || "",          // R2 の中の zip の名前（例: Preflight.zip）
    downloadName: env.DOWNLOAD_NAME || "BB-Preflight.zip",
    sourceUrl: env.SOURCE_URL || "",              // リポジトリを公開したら入れる。空ならメールに載せない
    news: env.NEWS || "",                         // お知らせを送る版（emails.js の NEWS）。空なら送らない
    newsPerRun: Math.max(1, Math.min(50, Number(env.NEWS_PER_RUN) || 3)), // 1回（毎時）に送るお知らせの数
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
    unsubAsk: ["配信を止めますか", "下のボタンを押すと、このアドレスへのメールを止めます。BB Preflight はそのまま使えます。"],
    unsubBtn: "配信を止める",
    unsubDone: ["配信を止めました", "これ以降、このアドレスにはお送りしません。BB Preflight はそのまま使えます。"],
    bad: ["リンクが正しくありません", "メールにあったリンクを、そのまま開いてください。"],
    dlAsk: ["BB Preflight のダウンロード", "下のボタンを押すと、zip のダウンロードが始まります。このリンクはあなた専用です。人には渡さないでください。"],
    dlBtn: "ダウンロードする",
    dlExpired: ["リンクの期限が切れています", "下のボタンを押すと、登録のアドレスに新しいリンクをお送りします。"],
    dlUsed: ["このリンクで受け取れる回数を超えました", "下のボタンを押すと、登録のアドレスに新しいリンクをお送りします。"],
    relinkBtn: "新しいリンクを送る",
    relinked: ["新しいリンクをお送りしました", "メールを見てください。届かないときは、迷惑メールのフォルダも見てください。"],
    relinkWait: ["新しいリンクは送ったばかりです", "メールを見てください。10分たっても届かないときは、もう一度お試しください。"],
    dlMissing: ["いまはダウンロードできません", "準備中です。少し時間をおいて、もう一度開いてください。"],
    back: "BB Preflight の紹介ページへ",
  },
  en: {
    confirmed: ["You're signed up", "We've emailed you the download. If it doesn't arrive, check your spam folder."],
    expired: ["This link has expired", "Please sign up again from the BB Preflight page."],
    unsubAsk: ["Unsubscribe?", "Click the button below to stop emails to this address. BB Preflight keeps working."],
    unsubBtn: "Unsubscribe",
    unsubDone: ["You're unsubscribed", "We won't email this address again. BB Preflight keeps working."],
    bad: ["This link isn't valid", "Please open the link exactly as it appears in the email."],
    dlAsk: ["Download BB Preflight", "Click the button below to download the zip. This link is just for you, so please don't share it."],
    dlBtn: "Download",
    dlExpired: ["This link has expired", "Click the button below and we'll email a new link to the address you signed up with."],
    dlUsed: ["This link has been used too many times", "Click the button below and we'll email a new link to the address you signed up with."],
    relinkBtn: "Send me a new link",
    relinked: ["We've sent you a new link", "Check your email. If it doesn't arrive, look in your spam folder."],
    relinkWait: ["We just sent you a new link", "Check your email. If nothing arrives in 10 minutes, try again."],
    dlMissing: ["The download isn't available right now", "We're getting it ready. Please try again a little later."],
    back: "Back to the BB Preflight page",
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

export function maskEmail(email) {
  const [user, domain] = String(email).split("@");
  return `${user.slice(0, 1)}***@${domain || ""}`;
}

export function redactTokens(text) {
  return String(text).replace(/([?&]t=)[^&\s>"]+/g, "$1<redacted>");
}

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
    const missing = ["from", "publicBase", "senderName", "senderAddress", "contact", ...(kind === "welcome" || kind === "news" ? ["downloadKey"] : [])].filter((k) => !s[k]);
    if ((kind === "welcome" || kind === "news") && !env.DOWNLOADS) missing.push("DOWNLOADS (R2)");
    if (missing.length) throw new Error(`not configured: ${missing.join(", ")}`);
  } else {
    // 試し運転では、本文と URL の形だけを見られるようにする（宛先は伏せ、リンクの合言葉は消す）
    // 試験用のアドレス（TEST_ADDRESS）宛てだけは、リンクを伏せずに出す。確認・ダウンロード・停止を本番の前に通しで試すため
    const showLinks = env.TEST_ADDRESS && sub.email === env.TEST_ADDRESS.trim().toLowerCase();
    console.log("dry-run email", JSON.stringify({ kind, to: maskEmail(sub.email), subject: mail.subject, text: showLinks ? mail.text : redactTokens(mail.text) }));
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
  if (existing && existing.status === "active") {
    // 案内メールをなくした人が申し込み直したら、新しいリンクを送り直す（10分に1回まで）。
    // 返事は誰にでも同じ ok なので、登録済みかどうかは外から分からない
    const last = await db.prepare("SELECT MAX(at) AS at FROM events WHERE email = ? AND kind = 'relink'").bind(email).first();
    if (last && last.at && now - Date.parse(last.at) < RELINK_GAP) return ok;
    try {
      await sendEmail(env, s, { ...existing }, "welcome", { downloadUrl: await downloadLink(env, s, existing, now), idempotencyKey: `relink-${existing.id}-${now}` }, fetchImpl);
      await logEvent(db, email, "relink", null, null, now);
    } catch (err) {
      console.error("relink mail failed", err && err.message);
    }
    return ok;
  }
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
  await sendEmail(env, s, { ...sub, step: 0 }, "welcome", { downloadUrl: await downloadLink(env, s, sub, now), idempotencyKey: `welcome-${sub.id}-${Date.parse(sub.confirm_sent_at)}` }, fetchImpl);
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

// ------------------------------------------------------------ ダウンロード

// 確認済みの人だけが、メールの専用リンクから zip を受け取れる。zip は R2 の非公開の置き場にあり、外から直接は開けない。
// GET は画面を出すだけ（メールソフトがリンクを先に開いても、回数を使わないように）。ボタンの POST で zip を渡す。
export async function download(request, env, { now = Date.now(), fetchImpl = fetch } = {}) {
  const s = settings(env);
  const url = new URL(request.url);
  const id = Number(url.searchParams.get("id"));
  const exp = Number(url.searchParams.get("e"));
  const t = url.searchParams.get("t") || "";
  const db = env.DB;
  const sub = Number.isInteger(id) && id > 0 && Number.isInteger(exp) ? await db.prepare("SELECT * FROM subscribers WHERE id = ?").bind(id).first() : null;
  const L = sub && PAGE[sub.lang] ? sub.lang : "ja";
  // 署名が合わない、または確認を済ませていないなら、何も渡さない。
  // 配信を止めた人も、受け取ったリンクの期限内なら受け取れる（オーナーの判断 2026-10-14）
  const stopped = sub && sub.status === "unsubscribed";
  if (!sub || !(sub.status === "active" || stopped) || !timingSafeEqual(t, await downloadToken(env, sub.id, sub.email, exp))) return page(L, s, PAGE[L].bad, 400);
  // 配信を止めた人には、新しいリンクのメールも送らない
  const relinkForm = stopped ? "" : `<form method="post"><input type="hidden" name="action" value="resend"><p><button type="submit">${escHtml(PAGE[L].relinkBtn)}</button></p></form>`;
  const used = async () => (await db.prepare("SELECT COUNT(*) AS n FROM events WHERE email = ? AND kind = 'download' AND detail = ?").bind(sub.email, String(exp)).first()).n;

  const form = request.method === "POST" ? new URLSearchParams(await request.text()) : null;
  if (form && form.get("action") === "resend" && !stopped) {
    // 新しいリンクは、署名の正しいリンク（期限切れでもよい）からだけ、登録のアドレスに送る
    const last = await db.prepare("SELECT MAX(at) AS at FROM events WHERE email = ? AND kind = 'relink'").bind(sub.email).first();
    if (last && last.at && now - Date.parse(last.at) < RELINK_GAP) return page(L, s, PAGE[L].relinkWait);
    await sendEmail(env, s, { ...sub }, "welcome", { downloadUrl: await downloadLink(env, s, sub, now), idempotencyKey: `relink-${sub.id}-${now}` }, fetchImpl);
    await logEvent(db, sub.email, "relink", null, null, now);
    return page(L, s, PAGE[L].relinked);
  }
  if (now > exp) return page(L, s, PAGE[L].dlExpired, 410, relinkForm);
  if ((await used()) >= DOWNLOAD_LIMIT) return page(L, s, PAGE[L].dlUsed, 429, relinkForm);
  if (!form) {
    const btn = `<form method="post"><p><button type="submit">${escHtml(PAGE[L].dlBtn)}</button></p></form>`;
    return page(L, s, PAGE[L].dlAsk, 200, btn);
  }
  const obj = env.DOWNLOADS && s.downloadKey ? await env.DOWNLOADS.get(s.downloadKey) : null;
  if (!obj) return page(L, s, PAGE[L].dlMissing, 503);
  await logEvent(db, sub.email, "download", String(exp), null, now);
  return new Response(obj.body, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${s.downloadName.replace(/[^A-Za-z0-9._-]/g, "_")}"`,
      ...(obj.size ? { "Content-Length": String(obj.size) } : {}),
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex",
      "Referrer-Policy": "no-referrer",
    },
  });
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
  const news = await sendNews(env, s, { now, fetchImpl });
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
  return { sent: [...sent, ...news.sent], removed, ...(news.waiting ? { newsWaiting: news.waiting } : {}) };
}

// 新しい版のお知らせを、確認済みで配信を止めていない人に、1回に newsPerRun 通ずつ送る。
// - R2 の zip が NEWS の notBefore より後に置き換わるまでは、1通も送らない（古い zip を配らないように）
// - zip を置き換えた後に登録した人や、新しいリンクを受け取った人は、もう新しい版を持っているので送らない
// - 送ったことは events に 'send' / 'news:<版>' で残し、同じ人に二度送らない
export async function sendNews(env, s, { now = Date.now(), fetchImpl = fetch } = {}) {
  if (!s.news) return { sent: [] };
  const item = NEWS[s.news];
  if (!item) return { sent: [], waiting: `unknown NEWS ${s.news}` };
  const head = env.DOWNLOADS && s.downloadKey ? await env.DOWNLOADS.head(s.downloadKey) : null;
  const uploaded = head && head.uploaded ? new Date(head.uploaded).getTime() : NaN;
  if (!(uploaded > Date.parse(item.notBefore))) return { sent: [], waiting: "zip not replaced yet" };
  const tag = `news:${s.news}`;
  const { results } = await env.DB.prepare(
    `SELECT * FROM subscribers s WHERE status = 'active' AND confirmed_at < ?
       AND NOT EXISTS (SELECT 1 FROM events e WHERE e.email = s.email AND ((e.kind = 'send' AND e.detail = ?) OR (e.kind = 'relink' AND e.at >= ?)))
     ORDER BY id LIMIT ?`,
  ).bind(iso(uploaded), tag, iso(uploaded), s.newsPerRun).all();
  const sent = [];
  for (const sub of results) {
    try {
      const r = await sendEmail(env, s, { ...sub }, "news", { newsId: s.news, downloadUrl: await downloadLink(env, s, sub, now), idempotencyKey: `news-${s.news}-${sub.id}` }, fetchImpl);
      if (r && r.dry) continue; // 試し運転では「送った」と記録しない（本番にしたときに、ちゃんと届くように）
      await env.DB.prepare("UPDATE subscribers SET last_sent_at = ? WHERE id = ?").bind(iso(now), sub.id).run();
      await logEvent(env.DB, sub.email, "send", tag, null, now);
      sent.push(`${sub.id}:${tag}`);
    } catch (err) {
      console.error("news failed", sub.id, err && err.message); // 次の回にもう一度試す
    }
  }
  return { sent };
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
      if (url.pathname === "/download" && (request.method === "GET" || request.method === "POST")) return await download(request, env);
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
