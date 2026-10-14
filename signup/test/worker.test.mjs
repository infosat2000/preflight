// Run (from signup/): node --test test/worker.test.mjs
// D1 の代わりに Node の組み込み SQLite で schema.sql をそのまま使い、Resend と Turnstile は fetch の差し替えで受ける。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import worker, { subscribe, confirm, unsubscribe, download, downloadLink, runScheduled, unsubToken, maskEmail, DOWNLOAD_TTL, DOWNLOAD_LIMIT, redactTokens, CONSENT, STEPS, CONFIRM_TTL, KEEP_AFTER } from "../src/worker.js";
import { renderEmail } from "../src/emails.js";

const SCHEMA = readFileSync(new URL("../schema.sql", import.meta.url), "utf8");
const DAY = 86400_000;
const T0 = Date.parse("2026-10-13T00:00:00Z");

// D1 と同じ形（prepare → bind → first / run / all）の薄い包み
function d1() {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  const wrap = (sql, args = []) => ({
    bind: (...a) => wrap(sql, a),
    first: async () => db.prepare(sql).get(...args) ?? null,
    run: async () => { db.prepare(sql).run(...args); return { success: true }; },
    all: async () => ({ results: db.prepare(sql).all(...args) }),
  });
  return { prepare: (sql) => wrap(sql), raw: db };
}

// R2 の get だけの薄い代わり
function r2(files) {
  return { get: async (key) => (key in files ? { body: files[key], size: files[key].length } : null) };
}

function setup(over = {}) {
  const sent = [];
  const fetchImpl = async (url, init) => {
    if (url.startsWith("https://challenges.cloudflare.com/")) {
      const token = init.body.get("response");
      return new Response(JSON.stringify({ success: token === "good" }));
    }
    if (url === "https://api.resend.com/emails") {
      sent.push({ ...JSON.parse(init.body), key: init.headers["Idempotency-Key"] });
      return new Response(JSON.stringify({ id: `m${sent.length}` }));
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const env = {
    DB: d1(),
    SEND_MODE: "live",
    RESEND_API_KEY: "re_test",
    TURNSTILE_SECRET: "ts",
    TOKEN_SECRET: "secret-for-tests",
    IP_HASH_SALT: "salt",
    PUBLIC_BASE: "https://signup.example.dev",
    SITE_BASE: "https://blackboxblast.com",
    ALLOWED_ORIGINS: "https://blackboxblast.com",
    MAIL_FROM: "Blackbox Blast（FOREST LIFE*） <preflight@mail.example.com>",
    SENDER_NAME: "FOREST LIFE*",
    SENDER_ADDRESS: "東京都テスト区1-2-3",
    CONTACT: "hello@example.com",
    DOWNLOAD_KEY: "latest/Preflight.zip",
    DOWNLOADS: r2({ "latest/Preflight.zip": "PK-zip-bytes" }),
    ...over,
  };
  return { env, sent, fetchImpl };
}

const post = (body, { origin = "https://blackboxblast.com", ip = "203.0.113.5", type = "application/json" } = {}) =>
  new Request("https://signup.example.dev/subscribe", {
    method: "POST",
    headers: { Origin: origin, "Content-Type": type, "CF-Connecting-IP": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

const good = (extra = {}) => ({ email: "Taro@Example.com", lang: "ja", consent: true, turnstileToken: "good", ...extra });
const tokenFrom = (mail) => mail.text.match(/confirm\?t=([0-9a-f]{48})/)[1];
const unsubFrom = (mail) => mail.text.match(/unsubscribe\?id=(\d+)&t=([0-9a-f]{64})/);

test("signup sends one confirm email and stores the address in lower case", async () => {
  const { env, sent, fetchImpl } = setup();
  const res = await subscribe(post(good()), env, { now: T0, fetchImpl });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Access-Control-Allow-Origin"), "https://blackboxblast.com");
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].to, ["taro@example.com"]);
  assert.match(sent[0].subject, /確認/);
  assert.equal(sent[0].headers, undefined, "confirm mail is not an ad, so no List-Unsubscribe");
  const row = env.DB.raw.prepare("SELECT * FROM subscribers").get();
  assert.equal(row.status, "pending");
  assert.equal(row.consent_text, CONSENT.ja);
  assert.notEqual(row.confirm_hash, tokenFrom(sent[0]), "only the hash of the token is stored");
});

test("signup is refused from another site, without consent, or with a bad challenge", async () => {
  const { env, sent, fetchImpl } = setup();
  assert.equal((await subscribe(post(good(), { origin: "https://evil.example" }), env, { now: T0, fetchImpl })).status, 403);
  assert.equal((await subscribe(post(good({ consent: false })), env, { now: T0, fetchImpl })).status, 400);
  assert.equal((await subscribe(post(good({ turnstileToken: "bad" })), env, { now: T0, fetchImpl })).status, 400);
  assert.equal((await subscribe(post(good({ email: "not-an-email" })), env, { now: T0, fetchImpl })).status, 400);
  assert.equal((await subscribe(post("email=x", { type: "application/x-www-form-urlencoded" }), env, { now: T0, fetchImpl })).status, 415);
  assert.equal(sent.length, 0);
});

test("the hidden bot field makes it a silent no-op", async () => {
  const { env, sent, fetchImpl } = setup();
  const res = await subscribe(post(good({ website: "http://spam" })), env, { now: T0, fetchImpl });
  assert.equal(res.status, 200);
  assert.equal(sent.length, 0);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM subscribers").get().n, 0);
});

test("one IP gets at most 5 sign-ups an hour", async () => {
  const { env, fetchImpl } = setup();
  for (let i = 0; i < 5; i++) {
    assert.equal((await subscribe(post(good({ email: `u${i}@example.com` })), env, { now: T0 + i, fetchImpl })).status, 200);
  }
  assert.equal((await subscribe(post(good({ email: "u9@example.com" })), env, { now: T0 + 10, fetchImpl })).status, 429);
  assert.equal((await subscribe(post(good({ email: "u9@example.com" }), { ip: "198.51.100.7" }), env, { now: T0 + 10, fetchImpl })).status, 200);
});

test("signing up again soon does not resend, and an active address gets no new confirm mail", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  await subscribe(post(good()), env, { now: T0 + 60_000, fetchImpl });
  assert.equal(sent.length, 1);
  await subscribe(post(good()), env, { now: T0 + 11 * 60_000, fetchImpl });
  assert.equal(sent.length, 2, "resent after the gap");
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[1])}`), env, { now: T0 + 12 * 60_000, fetchImpl });
  const before = sent.length;
  const res = await subscribe(post(good()), env, { now: T0 + DAY, fetchImpl });
  assert.equal(res.status, 200, "same answer, so nobody can tell the address is registered");
  assert.equal(sent.length, before + 1);
  assert.ok(!/confirm\?t=/.test(sent.at(-1).text) && dlFrom(sent.at(-1)), "a download mail, not another confirm mail");
});

test("confirm activates, sends the welcome mail with the download and a working one-click unsubscribe", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  const res = await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0 + 1000, fetchImpl });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /登録が終わりました/);
  const welcome = sent[1];
  assert.match(welcome.text, /https:\/\/signup\.example\.dev\/download\?id=\d+&e=\d+&t=[0-9a-f]{64}/);
  assert.match(welcome.text, /送信者: FOREST LIFE\*/);
  assert.match(welcome.text, /所在地: 東京都テスト区1-2-3/);
  assert.equal(welcome.headers["List-Unsubscribe-Post"], "List-Unsubscribe=One-Click");
  const [, id, t] = unsubFrom(welcome);
  assert.equal(welcome.headers["List-Unsubscribe"], `<https://signup.example.dev/unsubscribe?id=${id}&t=${t}>`);
  const row = env.DB.raw.prepare("SELECT * FROM subscribers").get();
  assert.equal(row.status, "active");
  // clicking the confirm link twice (or a mail scanner opening it first) is harmless
  const again = await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0 + 2000, fetchImpl });
  assert.equal(again.status, 200);
  assert.equal(sent.length, 2);
  // one-click unsubscribe from the mail app
  const oc = await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${t}`, { method: "POST", body: "List-Unsubscribe=One-Click", headers: { "Content-Type": "application/x-www-form-urlencoded" } }), env, { now: T0 + 3000 });
  assert.equal(oc.status, 200);
  assert.equal(await oc.text(), "");
  assert.equal(env.DB.raw.prepare("SELECT status FROM subscribers").get().status, "unsubscribed");
});

test("an expired or unknown confirm link does nothing", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  const late = await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0 + CONFIRM_TTL + 1, fetchImpl });
  assert.equal(late.status, 410);
  const unknown = await confirm(new Request(`https://signup.example.dev/confirm?t=${"0".repeat(48)}`), env, { now: T0, fetchImpl });
  assert.equal(unknown.status, 410);
  const junk = await confirm(new Request("https://signup.example.dev/confirm?t=<script>"), env, { now: T0, fetchImpl });
  assert.equal(junk.status, 400);
  assert.equal(sent.length, 1);
  assert.equal(env.DB.raw.prepare("SELECT status FROM subscribers").get().status, "pending");
});

test("unsubscribe GET only asks; a wrong token is refused", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0, fetchImpl });
  const [, id, t] = unsubFrom(sent[1]);
  const ask = await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${t}`), env, { now: T0 });
  assert.match(await ask.text(), /<form method="post">/);
  assert.equal(env.DB.raw.prepare("SELECT status FROM subscribers").get().status, "active", "link prefetch must not unsubscribe");
  const wrong = await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${"a".repeat(64)}`, { method: "POST" }), env, { now: T0 });
  assert.equal(wrong.status, 400);
  const done = await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${t}`, { method: "POST" }), env, { now: T0 });
  assert.match(await done.text(), /配信を止めました/);
  assert.equal(await unsubToken(env, Number(id), "taro@example.com"), t);
});

test("cron sends day 3 and day 7 mails once each, and never after unsubscribing", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  await subscribe(post(good({ email: "hanako@example.com", lang: "en" })), env, { now: T0, fetchImpl });
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0, fetchImpl });
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[1])}`), env, { now: T0, fetchImpl });
  const n = sent.length;
  assert.deepEqual((await runScheduled(env, { now: T0 + STEPS[0] - 1, fetchImpl })).sent, []);
  const r1 = await runScheduled(env, { now: T0 + STEPS[0], fetchImpl });
  assert.equal(r1.sent.length, 2);
  assert.match(sent[n + 1].subject, /Reading your BB Preflight results/);
  assert.deepEqual((await runScheduled(env, { now: T0 + STEPS[0] + 3600_000, fetchImpl })).sent, [], "not twice");
  // Hanako unsubscribes before day 7
  const [, id, t] = unsubFrom(sent[n + 1]);
  await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${t}`, { method: "POST" }), env, { now: T0 + 4 * DAY });
  const r2 = await runScheduled(env, { now: T0 + STEPS[1], fetchImpl });
  assert.equal(r2.sent.length, 1);
  assert.deepEqual(sent.at(-1).to, ["taro@example.com"]);
  assert.match(sent.at(-1).subject, /お手伝い/);
  assert.match(sent.at(-1).text, /hello@example\.com/);
});

test("cron deletes stale pending sign-ups and, after the keeping period, unsubscribed records", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good({ email: "never@example.com" })), env, { now: T0, fetchImpl });
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[1])}`), env, { now: T0, fetchImpl });
  const [, id, t] = unsubFrom(sent[2]);
  await unsubscribe(new Request(`https://signup.example.dev/unsubscribe?id=${id}&t=${t}`, { method: "POST" }), env, { now: T0 + DAY });
  const r = await runScheduled(env, { now: T0 + CONFIRM_TTL + 1, fetchImpl });
  assert.equal(r.removed.length, 1, "the never-confirmed one");
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM subscribers").get().n, 1);
  await runScheduled(env, { now: T0 + DAY + KEEP_AFTER + 1, fetchImpl });
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM subscribers").get().n, 0);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM events").get().n, 0);
});

test("nothing is sent unless SEND_MODE is live", async () => {
  const { env, sent, fetchImpl } = setup({ SEND_MODE: undefined });
  const res = await subscribe(post(good()), env, { now: T0, fetchImpl });
  assert.equal(res.status, 200);
  assert.equal(sent.length, 0);
});

test("a failed confirm mail answers 502 with CORS and can be retried at once", async () => {
  const { env, fetchImpl } = setup();
  let fail = true;
  const flaky = async (url, init) => (url === "https://api.resend.com/emails" && fail ? new Response("quota", { status: 429 }) : fetchImpl(url, init));
  const res = await subscribe(post(good()), env, { now: T0, fetchImpl: flaky });
  assert.equal(res.status, 502);
  assert.equal(res.headers.get("Access-Control-Allow-Origin"), "https://blackboxblast.com");
  fail = false;
  assert.equal((await subscribe(post(good()), env, { now: T0 + 1000, fetchImpl: flaky })).status, 200);
});

test("router answers CORS preflight only for the allowed site", async () => {
  const { env } = setup();
  const ok = await worker.fetch(new Request("https://signup.example.dev/subscribe", { method: "OPTIONS", headers: { Origin: "https://blackboxblast.com" } }), env);
  assert.equal(ok.status, 204);
  assert.equal(ok.headers.get("Access-Control-Allow-Methods"), "POST, OPTIONS");
  const bad = await worker.fetch(new Request("https://signup.example.dev/subscribe", { method: "OPTIONS", headers: { Origin: "https://evil.example" } }), env);
  assert.equal(bad.status, 403);
  assert.equal((await worker.fetch(new Request("https://signup.example.dev/other"), env)).status, 404);
});

test("emails escape HTML and English mails carry the English footer", () => {
  const v = { confirmUrl: "https://x/confirm?t=1", downloadUrl: "https://x/dl", unsubUrl: "https://x/u", senderName: "FOREST LIFE*", senderAddress: "<b>addr</b>", contact: "c@x" };
  const ja = renderEmail("welcome", "ja", v);
  assert.match(ja.html, /&lt;b&gt;addr&lt;\/b&gt;/);
  assert.doesNotMatch(ja.html, /<b>addr/);
  const en = renderEmail("step2", "en", v);
  assert.match(en.text, /Unsubscribe: https:\/\/x\/u/);
  assert.match(en.text, /Sender: FOREST LIFE\*/);
  const c = renderEmail("confirm", "en", v);
  assert.doesNotMatch(c.text, /Unsubscribe:/);
});

test("live mode refuses to send while the sender address or contact is missing", async () => {
  const { env, sent, fetchImpl } = setup({ SENDER_ADDRESS: "", CONTACT: "" });
  const res = await subscribe(post(good()), env, { now: T0, fetchImpl });
  assert.equal(res.status, 502);
  assert.equal(sent.length, 0);
});

test("without its secrets the worker refuses everything, even in dry-run", async () => {
  const { env } = setup({ SEND_MODE: "dry-run", TURNSTILE_SECRET: "" });
  const res = await worker.fetch(post(good()), env);
  assert.equal(res.status, 503);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM subscribers").get().n, 0);
  const { env: env2, fetchImpl } = setup({ SEND_MODE: "dry-run", TURNSTILE_SECRET: "" });
  const direct = await subscribe(post(good()), env2, { now: T0, fetchImpl });
  assert.equal(direct.status, 400, "no Turnstile secret means no sign-up");
});

test("dry-run logs hide the address and the link secrets", () => {
  assert.equal(maskEmail("taro@example.com"), "t***@example.com");
  const out = redactTokens("確認: https://signup.example/confirm?t=abc123\n停止: https://signup.example/unsubscribe?id=5&t=def.456 です");
  assert.ok(!out.includes("abc123") && !out.includes("def.456"));
  assert.ok(out.includes("confirm?t=<redacted>") && out.includes("id=5&t=<redacted>"));
});

const dlFrom = (mail) => mail.text.match(/(https:\/\/signup\.example\.dev\/download\?id=\d+&e=(\d+)&t=[0-9a-f]{64})/);
const dlPost = (url, body = "") => new Request(url, { method: "POST", body, headers: { "Content-Type": "application/x-www-form-urlencoded" } });

async function confirmed(over = {}) {
  const ctx = setup(over);
  await subscribe(post(good()), ctx.env, { now: T0, fetchImpl: ctx.fetchImpl });
  await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(ctx.sent[0])}`), ctx.env, { now: T0 + 1000, fetchImpl: ctx.fetchImpl });
  const [, url, exp] = dlFrom(ctx.sent[1]);
  return { ...ctx, url, exp: Number(exp) };
}

test("the personal download link shows a button on GET and hands over the zip on POST", async () => {
  const { env, url, exp, fetchImpl } = await confirmed();
  assert.equal(exp, T0 + 1000 + DOWNLOAD_TTL);
  const ask = await download(new Request(url), env, { now: T0 + 2000, fetchImpl });
  assert.equal(ask.status, 200);
  assert.match(await ask.text(), /<form method="post">/);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM events WHERE kind = 'download'").get().n, 0); // GET uses nothing up
  const res = await download(dlPost(url), env, { now: T0 + 3000, fetchImpl });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Type"), "application/zip");
  assert.match(res.headers.get("Content-Disposition"), /attachment; filename="BB-Preflight.zip"/);
  assert.equal(await res.text(), "PK-zip-bytes");
});

test("a tampered, unknown or unconfirmed download link gets nothing", async () => {
  const { env, url, fetchImpl } = await confirmed();
  const bad = url.replace(/t=[0-9a-f]{4}/, "t=0000");
  assert.equal((await download(dlPost(bad), env, { now: T0 + 2000, fetchImpl })).status, 400);
  const later = url.replace(/e=\d+/, `e=${T0 + 99 * DAY}`); // stretching the expiry breaks the signature
  assert.equal((await download(dlPost(later), env, { now: T0 + 2000, fetchImpl })).status, 400);
  env.DB.raw.prepare("UPDATE subscribers SET status = 'pending'").run();
  assert.equal((await download(dlPost(url), env, { now: T0 + 2000, fetchImpl })).status, 400);
});

test("after unsubscribing, the link still works until it expires, but sends no new link", async () => {
  const { env, url, exp, sent, fetchImpl } = await confirmed();
  env.DB.raw.prepare("UPDATE subscribers SET status = 'unsubscribed'").run();
  const res = await download(dlPost(url), env, { now: T0 + 2000, fetchImpl });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "PK-zip-bytes");
  const late = await download(new Request(url), env, { now: exp + 1, fetchImpl });
  assert.equal(late.status, 410);
  assert.doesNotMatch(await late.text(), /value="resend"/);
  const before = sent.length;
  const re = await download(dlPost(url, "action=resend"), env, { now: exp + 2, fetchImpl });
  assert.notEqual(re.status, 200);
  assert.equal(sent.length, before, "no mail to someone who unsubscribed");
});

test("a link works 5 times, expires after 7 days, and can send a fresh link to the same address", async () => {
  const { env, url, exp, sent, fetchImpl } = await confirmed();
  for (let i = 0; i < DOWNLOAD_LIMIT; i++) assert.equal((await download(dlPost(url), env, { now: T0 + 2000 + i, fetchImpl })).status, 200);
  const used = await download(dlPost(url), env, { now: T0 + 3000, fetchImpl });
  assert.equal(used.status, 429);
  assert.match(await used.text(), /name="action" value="resend"/);
  assert.equal((await download(new Request(url), env, { now: exp + 1, fetchImpl })).status, 410);
  const re = await download(dlPost(url, "action=resend"), env, { now: exp + 2, fetchImpl });
  assert.equal(re.status, 200);
  assert.equal(sent.length, 3);
  assert.deepEqual(sent[2].to, ["taro@example.com"]); // only ever to the signed-up address
  const [, fresh] = dlFrom(sent[2]);
  assert.equal((await download(dlPost(fresh), env, { now: exp + 3, fetchImpl })).status, 200);
  // asking again right away does not send another mail
  await download(dlPost(url, "action=resend"), env, { now: exp + 4, fetchImpl });
  assert.equal(sent.length, 3);
});

test("live mode will not send the welcome mail without the zip store", async () => {
  const { env, sent, fetchImpl } = setup({ DOWNLOADS: undefined });
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  await assert.rejects(confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0 + 1000, fetchImpl }), /DOWNLOADS/);
});

test("router serves the download page and a missing zip answers 503", async () => {
  const { env } = await confirmed({ DOWNLOADS: r2({}) });
  const sub = env.DB.raw.prepare("SELECT * FROM subscribers").get();
  const url = await downloadLink(env, { publicBase: "https://signup.example.dev" }, sub, Date.now()); // the router uses the real clock
  const res = await worker.fetch(dlPost(url), env);
  assert.equal(res.status, 503);
});

test("the welcome mail links the source only once SOURCE_URL is set", () => {
  const v = { downloadUrl: "https://x/download?id=1&e=2&t=3", unsubUrl: "https://x/u", senderName: "FL", senderAddress: "a", contact: "c@x" };
  assert.doesNotMatch(renderEmail("welcome", "ja", v).text, /github\.com/);
  assert.match(renderEmail("welcome", "ja", { ...v, sourceUrl: "https://github.com/infosat2000/preflight" }).text, /GitHub で確かめられます: https:\/\/github\.com\/infosat2000\/preflight/);
  assert.match(renderEmail("welcome", "en", { ...v, sourceUrl: "https://github.com/infosat2000/preflight" }).text, /on GitHub: https:\/\/github\.com/);
});

test("in dry-run, only mails to TEST_ADDRESS show their links in the log", async () => {
  const { env, fetchImpl } = setup({ SEND_MODE: "dry-run", TEST_ADDRESS: "Taro@Example.com" });
  const logs = [];
  const orig = console.log;
  console.log = (...a) => logs.push(a.join(" "));
  try {
    await subscribe(post(good()), env, { now: T0, fetchImpl });
    await subscribe(post(good({ email: "hanako@example.com" })), env, { now: T0, fetchImpl });
  } finally {
    console.log = orig;
  }
  assert.match(logs[0], /confirm\?t=[0-9a-f]{48}/);
  assert.match(logs[1], /confirm\?t=<redacted>/);
});

test("signing up again while confirmed resends the download mail, at most every 10 minutes", async () => {
  const { env, sent, fetchImpl } = await confirmed();
  const before = sent.length;
  const again = await subscribe(post(good()), env, { now: T0 + 5000, fetchImpl });
  assert.equal(again.status, 200);
  assert.deepEqual(await again.json(), { ok: true }); // same answer as for a new address
  assert.equal(sent.length, before + 1);
  assert.ok(dlFrom(sent.at(-1)), "the resent mail carries a fresh download link");
  await subscribe(post(good()), env, { now: T0 + 6000, fetchImpl });
  assert.equal(sent.length, before + 1, "no second mail within 10 minutes");
  await subscribe(post(good()), env, { now: T0 + 5000 + 10 * 60_000 + 1, fetchImpl });
  assert.equal(sent.length, before + 2);
});
