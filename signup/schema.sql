-- Preflight のメール登録の名簿（Cloudflare D1）。
-- 作り方: wrangler d1 execute preflight-signup --remote --file=schema.sql
-- 配信停止のリンクは、id と TOKEN_SECRET から作る HMAC で確かめる（合言葉を保存しない）。

CREATE TABLE IF NOT EXISTS subscribers (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  email           TEXT NOT NULL UNIQUE,      -- 小文字にそろえて保存する
  lang            TEXT NOT NULL DEFAULT 'ja', -- 'ja' | 'en'
  status          TEXT NOT NULL,             -- 'pending'（確認待ち） | 'active' | 'unsubscribed'
  confirm_hash    TEXT,                      -- 確認リンクの合言葉の SHA-256（合言葉そのものは持たない）
  confirm_sent_at TEXT,
  consent_text    TEXT,                      -- 申し込み欄に出ていた同意の文面（特定電子メール法の同意の記録）
  created_at      TEXT NOT NULL,
  confirmed_at    TEXT,
  unsubscribed_at TEXT,
  step            INTEGER NOT NULL DEFAULT 0, -- 送った案内メールの段階（1 = 3日後）
  last_sent_at    TEXT                       -- 最後にメールを送った日時（同意の記録を残す期間の起点）
);

CREATE INDEX IF NOT EXISTS subscribers_confirm ON subscribers (confirm_hash);
CREATE INDEX IF NOT EXISTS subscribers_due ON subscribers (status, step, confirmed_at);

-- 申し込み・確認・停止の記録（いたずらの調査と、同意の記録のため）。IP は塩つきのハッシュだけを残す。
CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL,
  kind       TEXT NOT NULL,                  -- 'signup' | 'confirm' | 'unsubscribe' | 'send' | 'download'（detail = リンクの期限） | 'relink'
  detail     TEXT,
  ip_hash    TEXT,
  at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS events_ip ON events (ip_hash, at);
CREATE INDEX IF NOT EXISTS events_email ON events (email, at);

-- 紹介ページと BB の案内の閲覧・押された回数（1.3.0 の後に追加）。日付・種類・場所・言語ごとの件数だけで、
-- 誰が見たか（IP・Cookie・ブラウザの情報）は残さない。日付は日本時間。
CREATE TABLE IF NOT EXISTS hits (
  day   TEXT NOT NULL,                       -- 'YYYY-MM-DD'（日本時間）
  kind  TEXT NOT NULL,                       -- 'view'（見えた） | 'click'（押された）
  place TEXT NOT NULL,                       -- 'page'（紹介ページ） | 'hero'（BB のトップ） | 'article'（記事の末尾）
  lang  TEXT NOT NULL,                       -- 'ja' | 'en'
  n     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, kind, place, lang)
);
