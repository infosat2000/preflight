# Preflight のメール登録（signup）

紹介ページ（blackboxblast.com/ja/preflight/）の申し込み欄から届くメールアドレスを受け取り、確認メール・ダウンロードの案内・3日後と7日後の案内を送る仕組みです。

- **置き場所は FOREST LIFE* の Cloudflare アカウントです。** Blackbox Blast のサイト（Pages）とは別のアカウントに置くので、サイトを人に譲っても名簿は手元に残ります。
- 名簿は Cloudflare D1、送信は Resend、ロボットよけは Cloudflare Turnstile、配る zip は Cloudflare R2（非公開）。どれも無料の枠で動く見込みです。
- ソースは GitHub で見られるようにしますが、すぐ使える zip は、メールを確認した人だけに専用のリンクで渡します。
- `SEND_MODE` を `live` にするまでは、メールは一通も送りません（送る内容をログに出すだけ）。

## しくみ

| 入口 | していること |
|---|---|
| `POST /subscribe` | 申し込み。Turnstile を確かめ、確認メールを送る。登録済みかどうかは答えない |
| `GET /confirm?t=…` | 確認リンク。登録を終え、ダウンロードの案内を送る |
| `GET /unsubscribe` | 配信停止の確認画面（押すまで止めない） |
| `POST /unsubscribe` | 配信停止。メールソフトの「配信停止」ボタン（ワンクリック）にも対応 |
| `GET /download?id=…&e=…&t=…` | 確認済みの人専用のダウンロード画面（ボタンを押すまで渡さない） |
| `POST /download` | zip を渡す。期限切れや回数切れなら、登録のアドレスに新しいリンクを送る（10分に1回まで） |
| 1時間ごと（cron） | 3日後・7日後の案内を送る（1回に各10通まで）。古い記録を消す |

守っていること:

- 確認リンクの合言葉は保存しない（SHA-256 だけ）。配信停止とダウンロードのリンクは署名（HMAC）で確かめる。
- ダウンロードのリンクは、その人専用で7日間・5回まで。zip の置き場（R2）には外から開ける URL を付けない。停止した人のリンクは使えなくなる。
- IP アドレスは塩つきのハッシュだけを残す。1つの IP から1時間に5件まで。
- 確認されないままの申し込みは7日で消す。
- 配信を止めた人の記録は、最後に送った日と停止した日の両方から31日たったら消す。特定電子メール法の「同意の記録は最後に送った日から1か月残す」に合わせている（総務省のパンフレットで確認。措置命令を受けたときは1年）。
- 開封やクリックは記録しない。Resend はドメインごとに初めから記録しない設定で、その設定は変えない。
- 送信者・所在地・連絡先が空のままでは、本番でも送らない（エラーにする）。
- 秘密の値（TOKEN_SECRET・TURNSTILE_SECRET・IP_HASH_SALT）が1つでも欠けていると、試し運転でも何も受け付けない（503）。

## マジカルさんの作業（初回だけ）

ここは本人がする作業です。アカウントの作成や DNS の変更は、こちらでは行いません。

### 1. 受け口のドメインを決める

FOREST LIFE* 側のドメインのサブドメインを2つ使います（例）。

- `signup.<ドメイン>`: 申し込みの受け口（この Worker）
- `send.<ドメイン>`: メールの送り元（Resend）

ドメインは Cloudflare の FOREST LIFE* のアカウントで DNS を管理している必要があります。`wrangler.toml` は `signup.forestlife.dev` と `send.forestlife.dev` で書いてあります（2026-10-13 にドメインを forestlife.dev に決定）。shop など、ほかの用途のサブドメインとは分けます。

### 2. Resend

1. resend.com で FOREST LIFE* としてアカウントを作り、二段階認証を有効にする。
2. Domains で `send.<ドメイン>` を追加する。リージョンは Tokyo を選ぶ。
3. 表示される DNS レコード（MX、SPF の TXT、`resend._domainkey` の TXT）を Cloudflare の DNS にそのまま入れ、Verify する。
4. DMARC も入れる: `_dmarc.<ドメイン>` に TXT `v=DMARC1; p=none;`（すでにあれば足さない）。
5. API Keys で「Sending access」だけ、ドメインを `send.<ドメイン>` に絞ったキーを作る。キーはこの画面でしか見られないので、すぐ次の手順4で入れる。
6. 開封とクリックの記録（Open / Click tracking）がオフのままであることを確かめる。

無料の枠は1日100通・月3,000通です。cron は1回に各10通までにしてあります。

### 3. Cloudflare（D1 と Turnstile）

Mac のターミナルで、このフォルダ（`signup/`）に移ってから:

```sh
npx wrangler login                      # FOREST LIFE* のアカウントでログイン
npx wrangler d1 create preflight-signup # 出てきた database_id を wrangler.toml に入れる
npx wrangler d1 execute preflight-signup --remote --file=schema.sql
```

Turnstile: Cloudflare のダッシュボードの Turnstile で、ホスト名 `blackboxblast.com` のウィジェットを作る（Managed）。サイトキーは紹介ページに、シークレットキーは次の手順で Worker に入れます。

### 4. 秘密の値を入れる

```sh
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put TURNSTILE_SECRET
openssl rand -hex 32 | npx wrangler secret put TOKEN_SECRET
openssl rand -hex 32 | npx wrangler secret put IP_HASH_SALT
```

`TOKEN_SECRET` を後で変えると、それまでに送ったメールの配信停止リンクが使えなくなります。変えないでください。

### 5. 配る zip を置く（R2）

Cloudflare のダッシュボードで R2 を使えるようにし、非公開の置き場を作ります（公開 URL・独自ドメインはつながない）。

```sh
npx wrangler r2 bucket create preflight-downloads
./upload-zip.sh v1.0.0        # 指定の版の zip を作って置く。省略すると v$(cat ../VERSION)
DRY_RUN=1 ./upload-zip.sh HEAD # 置かずに、作った zip を手元で確かめる
```

`latest/Preflight.zip` が配られる zip です（`wrangler.toml` の `DOWNLOAD_KEY`）。版ごとの zip も `versions/` に残ります。zip には `signup/` や `tests/` は入りません（`.gitattributes`）。

### 6. 表示の値を入れて、まず試しに動かす

`wrangler.toml` の `[vars]` に、送信者の住所（`SENDER_ADDRESS`）と問い合わせ先（`CONTACT`）を入れます。`SEND_MODE` は `dry-run` のままにします。

```sh
npx wrangler deploy
npx wrangler tail   # 申し込みを試すと、送るはずのメールがログに出る
```

本番の前に、確認 → ダウンロード → 配信停止を通しで試すときは、`TEST_ADDRESS` に自分のアドレスを入れて入れ直します。そのアドレス宛てのメールだけ、リンクが伏せられずにログに出るので、そのリンクを開いて試せます。終わったら空に戻します。

### 7. 本番にする（最後）

紹介ページから自分のアドレスで申し込み、ログに確認メールが出ることを確かめてから、`SEND_MODE = "live"` にして `npx wrangler deploy` します。自分宛てに確認メール・ダウンロードの案内が届き、専用リンクから zip を受け取れ、配信停止のリンクで止まることを確かめてください。

## テスト

Node.js 22.5 以降で（D1 の代わりに組み込みの SQLite を使います）:

```sh
cd signup
node --test test/worker.test.mjs
```

Resend と Turnstile には実際には接続しません。

## まだ決まっていないこと

- FOREST LIFE* 側のドメイン名。
- 所在地（GMO オフィスサポートで FOREST LIFE* 宛てを受け取れるか）と、問い合わせ用のアドレス。
- リポジトリを公開する日（ソースは公開、zip は登録した人だけ、と決定済み）。
- 7日後の案内（点検サービスのご案内）が特定商取引法の「通信販売の電子メール広告」に当たる場合、承諾の記録を3年残す必要がある（総務省のパンフレットの注記）。当たるかどうかは確かめていない。当たるなら、配信停止した人の記録を消す期間（`KEEP_AFTER`）を延ばす。
