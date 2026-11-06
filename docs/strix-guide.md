# 自分のアプリの穴を、AI に探してもらう（Strix の安全な始め方）

BB Preflight は **Mac の戸締まり**を見ます。待ち受けているポート、鍵の置き方、AI に与えた権限などです。
一方、**自分で作ったアプリの中の穴**は見ません。たとえば「予約フォームの番号を1つ変えると、他人の名前と電話番号が見える」といった穴です。

この穴を探すのが、オープンソースの AI ペンテスト道具 [Strix](https://github.com/usestrix/strix)（Apache-2.0）です。
ここでは、BB Preflight の使用者が Strix を**安全に**取り入れる手順をまとめます。
BB Preflight は Strix を動かしません。Strix の結果を読み、0件でも途中で止まった回がないか、鍵の置き方は安全かを、次の点検から確かめます。

> この説明は 2026-11-06 に [Strix の公式ドキュメント](https://docs.strix.ai/) と README で確かめた内容です。料金や対応モデルは変わることがあります。

## 先に決めておく 3 つのこと

1. **調べてよいのは、自分のアプリか、書面で許可をもらったものだけ。**
   Strix は、向けた相手に本当に攻撃を試します。他人のサイトに無断で使うと、不正アクセス禁止法などに触れるおそれがあります。公式 README も、所有しているか書面で明確に許可されたシステムだけに使うよう求めています。
2. **本番ではなく、複製で試す。**
   - 手元のフォルダは、Strix の作業部屋（Docker）に**書き換えられる形で**つながります（`.git` は除く）。渡すのは複製にします。
   - 公開中のサイトに向けると、本物のメールが送られたり、データベースに試験の行が書き込まれたりします。試すのはプレビュー環境か、手元で動かした複製にします。
   - 本番の鍵（Stripe の本番キー、本番のデータベースのパスワードなど）を、その複製に置かないでください。
3. **最初は「quick」と「予算の上限」をセットにする。**

| 調べる深さ | 時間の目安（公式） | 向いている使い方 |
|---|---|---|
| `quick` | 数分 | 直すたびの確認 |
| `standard` | 約30分 | 週に1回など |
| `deep`（**指定しないとこれ**） | 1〜4時間 | 公開の前 |

- 上限は `--max-budget 3` のようにドルで指定します。桁を間違えないでください（3ドルと30ドルは大違い）。
- 上限は AI の利用料の見積もりで管理されます。公式には「少し超えることがある」と書かれています。
- Strix 本体は無料です。かかるのは、中で動く AI の利用料だけです。

## 中で動く AI について

- Strix の README がおすすめしているのは、OpenRouter か Vercel AI Gateway 経由の Z.ai GLM-5.3 です（`openrouter/z-ai/glm-5.3` など）。
- 一部の会社の上位モデルは、各社の審査制プログラムへの参加が前提だと README に書かれています。Claude Opus 5.5 は Anthropic の CVP、OpenAI GPT-6.1 Sol は Daybreak、Gemini 4 Argon は Fairwind が必要です。参加していないと、攻撃を試す作業の多くが止められます。
- 個人で試すなら、審査のいらない推奨モデルから始めるのが無難です。CVP に個人が申し込める段階は、報道ベースの情報しか確認できていません。
- **鍵はファイルに書かず、キーチェーンに入れます。** `~/.strix/cli-config.json` に鍵を書くと、BB Preflight が「平文の鍵」として知らせます。

## 手順

### 1. 準備（1回だけ）

- Docker（Docker Desktop・OrbStack など）を入れて起動しておきます。
- Strix は、版を固定して入れます。公式 README の `curl … | bash` は、取ってきたものをその場で実行する形です。BB Preflight はシェルの設定にこの形があると警告するので、ここでは版を指定できる方法をおすすめします。

```bash
uv tool install strix-agent==1.7.0
```

（`uv` がない場合は `pipx install strix-agent==1.7.0`。Python 3.12 以上が必要です。新しい版にするときは、版の番号を書き換えてもう一度実行します。）

- AI の鍵をキーチェーンに入れます。入力した鍵は画面に表示されません。

```bash
security add-generic-password -a "$USER" -s strix-llm -w
```

### 2. 試す複製を作る

```bash
cp -R ~/projects/my-app ~/strix-sandbox/my-app
```

### 3. 走らせる（最初は quick・上限3ドル）

```bash
cd ~/strix-sandbox
STRIX_LLM="openrouter/z-ai/glm-5.3" \
LLM_API_KEY="$(security find-generic-password -s strix-llm -w)" \
strix -n --target ./my-app --scan-mode quick --max-budget 3
```

この例は OpenRouter の鍵を使う場合です。ほかの AI にするときは、[対応している AI の一覧](https://docs.strix.ai/llm-providers/overview) から `STRIX_LLM` のモデル名を選びます。

結果は `~/strix-sandbox/strix_runs/<回の名前>/` にできます。

- `vulnerabilities.csv`: 指摘の一覧
- 指摘ごとの Markdown: 原因・再現の手順・直し方
- `coverage.json`: どこまで調べたか（`completeness` と `gaps`）

### 4. Claude Code に頼む場合

Strix には、Claude Code などに渡す作業手順（スキル）が 9 種類あります。入れるのは**試す複製の中だけ**にします。
`~/.claude/skills` など全体の置き場所に入れると、Claude Code がどのフォルダからでも攻撃の試験を始められる状態になります。BB Preflight はそれを黄（確認なしで実行するモードと重なると赤）で知らせます。

Claude Code への頼み方の例です。

```text
~/strix-sandbox/my-app は、私が作ったアプリの複製です。Strix で、このフォルダだけを quick モード、予算の上限3ドルで調べてください。
本番のサイトや、ほかのフォルダには向けないでください。鍵は security find-generic-password -s strix-llm -w で読み、画面やファイルには出さないでください。
終わったら、見つかった穴・直し方・調べきれなかった範囲（coverage.json）を、ふつうの言葉でまとめてください。直すのは、私が確かめてからにしてください。
```

### 5. 結果を読む（「0件＝安全」ではない）

0件だったときは、次の 3 つを確かめます。

1. 最後まで終わったか（`run.json` の `status` が `completed` か）
2. 予算の上限で止まっていないか
3. どこまで調べたか（`coverage.json` の `gaps`。利用者の目線だけで、管理者の目線は見ていない、など）

BB Preflight をもう一度開くと、ここまでを自動で確かめます。

- 走査範囲（台帳の `secretScanRoots`）に `~/strix-sandbox` を入れておくと、結果を読めます。
- 重大・高の指摘は赤、途中で止まった回は黄で出ます。最後まで終わって0件なら緑です。

### 6. 直したら、同じ手順でもう一度

直したら複製を作り直し、同じ範囲を quick で確かめ直します。同じ再現の手順で穴が消えていれば「直った」と言えます。
それでも、Strix の答えはいつも「調べた範囲では」という条件付きです。

## English summary

BB Preflight checks how the Mac itself is locked down. It does not test your own app for holes such as one user seeing another user's booking; that is what Strix, an open-source AI pentesting tool, does.

1. Only test apps you own or have written permission to test.
2. Work on a copy, never on production. Local folders are mounted writable, and live sites get real emails and real database rows.
3. Start with `--scan-mode quick` and a small `--max-budget`. The default mode is `deep`, which takes 1–4 hours.

Install Strix pinned (`uv tool install strix-agent==1.7.0`) and keep the LLM key in Keychain. Put the Strix skills only inside the copy you are testing. Re-run BB Preflight afterwards: it reads `strix_runs/` and warns when a zero-finding run stopped early.
