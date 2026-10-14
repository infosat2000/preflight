// Run (from signup/): node --test test/worker.test.mjs
// D1 の代わりに Node の組み込み SQLite で schema.sql をそのまま使い、Resend と Turnstile は fetch の差し替えで受ける。
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import worker, { subscribe, confirm, unsubscribe, runScheduled, unsubToken, CONSENT, STEPS, CONFIRM_TTL, KEEP_AFTER } from "../src/worker.js";
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
    DOWNLOAD_URL: "https://github.com/infosat2000/preflight/releases/latest",
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

test("signing up again soon does not resend, and an active address gets nothing new", async () => {
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
  assert.equal(sent.length, before);
});

test("confirm activates, sends the welcome mail with the download and a working one-click unsubscribe", async () => {
  const { env, sent, fetchImpl } = setup();
  await subscribe(post(good()), env, { now: T0, fetchImpl });
  const res = await confirm(new Request(`https://signup.example.dev/confirm?t=${tokenFrom(sent[0])}`), env, { now: T0 + 1000, fetchImpl });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /登録が終わりました/);
  const welcome = sent[1];
  assert.match(welcome.text, /releases\/latest/);
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
  assert.match(sent[n + 1].subject, /Reading your Preflight results/);
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
