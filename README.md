# Blackbox Blast Preflight

**Mac の実測結果から脅威モデルを自動で作り、IPA の注意喚起と 221 本の脅威ルールで点検するツール**

このMacで実際に待ち受けているポート、ファイアウォールの状態、公開サイトの未認証応答、AI エージェントの定期ジョブ、平文の鍵などを読み取り専用で調べ、
その結果から [CyberRiskScape](https://github.com/takashi-ohmoto-git/CyberRiskScape)（OSS の脅威モデリングツール）の構成図を自動生成して評価します。
前回との差分を取るので、「知らないうちに増えた入口」に気付けます。

[Blackbox Blast](https://blackboxblast.com/) の点検ツールです。対象は**1人〜数人の事業者が使う Mac 1台**と、それにつながる公開サイト・外部サービスです。

## 効くところ・効かないところ

**効くところ**
- **実測で、思い込みの穴が見つかる。** 作者の Mac では、手作業の点検で漏れていたファイル共有（445）・Kerberos（88）・プリンタ共有（631）の LAN 側待ち受けを見つけた。権限なしの `lsof` には出ず、`netstat` を正にした実測で分かったもの。
- **差分で、直したことを数字で示せる。** 上の対処の後、「関連する脅威 24 件が解消・追加 0 件」と確認できた。
- **AI エージェントの入口が見える。** claude を呼ぶ定期ジョブ、ローカル MCP、外部へ送信できるコネクタを図に入れる。
- **npm の感染対策を確かめる。** npm を使っている Mac では、install スクリプトを止める設定（`ignore-scripts`）と、感染を見張る supply-chain-guard の最新の結果（`~/.claude/supply-chain/state.json`）を読む。走査そのものはしない。
- **Mac の基本の守りを見る。** Claude Code に与えた許可の広さ（`Bash(*)` や確認を飛ばすモード、ホーム全体を渡した MCP）、FileVault、SSH 鍵のパスフレーズの有無、サポート詐欺でよく使われる遠隔操作アプリ、Time Machine の最後のバックアップ、SIP・Gatekeeper・自動ログイン、ウイルス対策のデータ（XProtect など）を自動で受け取る設定。macOS 本体のアップデートは勧めない。どれも sudo なしで読むだけ。SSH 鍵はファイルを読むが、見るのは先頭の暗号方式の名前だけで、鍵の値は記録も表示もしない。OpenCore Legacy Patcher（OCLP）で動く Mac は SIP を一部ゆるめるのが前提なので、その分は問題にしない。

**効かないところ**
- レポート 3・4 節の脅威一覧は、CyberRiskScape のルールが構成要素の**種類**から一般論として出すもの。たとえば AI エージェント 1 つに High の脅威が十数件並ぶが、その Mac で確かめた問題ではない。件数は危険度を表さない。
- 「問題なし」は安全の保証ではない。台帳に書いていない要素は評価されない。
- 複数台の Mac、Windows、Linux、クラウド基盤は対象外（下の「分かっている限界」）。

- 何も変更しません（プロセスの停止や設定変更はしない）。sudo も使いません。
- 秘密情報の値はどのファイルにも書かず、画面にも出しません。鍵を探すときと SSH 鍵のパスフレーズの有無を見るときはファイルを読みますが、記録するのはファイルの場所（`~/…` の形）と種類だけです。SSH 鍵は先頭の暗号方式の名前だけを見ます。
- 評価エンジンは既定では入れません。`./setup.sh --with-engine` で入れるときは部品を npm で入れますが、`npm ci --ignore-scripts` でパッケージの install スクリプトは動かしません。版とロックファイルも固定しています。
- 外部への通信は、台帳に書いた自分の公開URLへの確認アクセスだけです。

## 必要なもの

- macOS（`lsof`・`netstat`・`socketfilterfw`・`curl` を使います）
- python3（macOS 標準の 3.9 で動きます。追加のライブラリは不要）。初めて使う Mac では「コマンドライン・デベロッパ・ツール」を入れる案内が出ることがあります。その場合はインストールしてから、もう一度開いてください
- 専門家向けの評価エンジン（IPA 17 項目の判定と脅威の一覧）を使うときだけ: Node.js と npm、git

## はじめかた

```bash
git clone <このリポジトリ> blackbox-blast-preflight && cd blackbox-blast-preflight
./setup.sh      # ~/.bb-preflight/inventory.json にひな形を置き、起動ボタンを置く（python3 だけで動く）
# ~/.bb-preflight/inventory.json を自分の環境に合わせて書き換える（下の「台帳の書き方」）
./run.sh        # 実測 → レポート

# 専門家向け: 評価エンジン CyberRiskScape v0.6.0 も入れて、IPA 17 項目の判定と脅威の一覧を出す
./setup.sh --with-engine
```

結果は `~/.bb-preflight/out/<日時>/` に出ます。

ターミナルを使わない場合は、Finder で **`Preflight.command` をダブルクリック**します。`setup.sh` はアイコン付きの起動ボタン `~/Applications/Blackbox Blast Preflight.app` も置くので、Finder の「アプリケーション」・Launchpad・Spotlight からも開けます（置きたくない場合は `BB_PREFLIGHT_NO_SHORTCUT=1 ./setup.sh`）。Dock に入れておくと便利です。リポジトリのフォルダを移したら `setup.sh` をもう一度実行してください。初回はセットアップして台帳を開き、2 回目以降は実測してレポートを開きます。
（ZIP でダウンロードした場合は macOS に止められることがあります。そのときは一度開こうとしたあと、システム設定 →「プライバシーとセキュリティ」の「このまま開く」で一度だけ許可してください（macOS 15 からは、右クリック →「開く」では許可できません）。`git clone` で取得した場合は止められません。）

| ファイル | 中身 |
|---|---|
| `report.html` | ふつうの言葉で書いた点検結果。総合判定（NO-GO / CAUTION / CLEAR）・やること・直し方・前回との違い。起動ボタンからはこれがブラウザで開く。外部の読み込みはなく、どこにも送らない |
| `report.md` | 1 枚まとめ（実測結果 → 前回との差分。評価エンジンを入れたときは、参考: IPA 17 項目の判定 → 参考: 未対応の High 以上の脅威 も） |
| `ipa-checklist.csv` / `.md`（評価エンジンあり） | IPA 注意喚起（2026-10-09）17 項目のチェックリスト |
| `threats.json`（評価エンジンあり） | 検出された全脅威 |
| `diff.md`（評価エンジンあり） | 構成図どうしの差分（2 回目以降） |
| `facts.json` | 実測の生データ |

### 個人データの置き場所

台帳・構成図・レポートは**自分の弱点の地図**なので、コードとは別の `~/.bb-preflight/`（権限 700）に置きます。
場所は環境変数 `BB_PREFLIGHT_HOME` で変えられます。リポジトリの `.gitignore` でも `inventory.json`・`model.json`・`out/` を除外しています。

すでに CyberRiskScape の CLI をビルド済みなら、`CRS_CLI=/path/to/dist-cli/main.js ./setup.sh` で取得を省略できます（`run.sh` にも同じ変数を渡してください）。

英語表示のときの名前は、台帳の各項目に `labelEn` を書くと使われます（`portNamesEn` でポートの名前も）。書かなければ、自分で付けた名前はそのまま出ます。

## 判断の記録（リスク受容など）

`~/.bb-preflight/model.json` を CyberRiskScape のアプリで開き、「リスク受容」などの判断を記録して同じファイルに保存します。
次に `run.sh` を回しても判断は残ります（ノード ID を実測内容から決めているため）。

アプリは github.io のデモではなく、手元で起動してください。構成図を他サイトの保存領域に残さないためです。

```bash
cd vendor/CyberRiskScape && npm run build && npx vite preview --host 127.0.0.1
```

## 台帳の書き方（inventory.json）

実測できないこと（外部サービスの認証方式、データの置き場所、claude.ai のコネクタなど）を人が書きます。
ひな形は [examples/inventory.example.json](examples/inventory.example.json) です。

| キー | 中身 |
|---|---|
| `project` | 構成図の名前・対象システム・事業への影響（任意） |
| `mac` | このMacの表示名と補足（任意） |
| `portNames` | ポート番号 → 表示名。root 所有でプロセス名が分からない待ち受けに名前を付ける |
| `remoteAdminPorts` | 遠隔管理・共有系のポート。LAN 側の IP で開いているか実際に試す |
| `endpoints` | 未認証でアクセスして応答を確かめる公開URL。**ID が `old-` で始まるものは「解約済みのはず」の入口**として扱い、応答したら赤で出す |
| `secretScanRoots` | 平文の鍵を探すフォルダ |
| `publicSites` | 公開サイト。`admin: true` は管理画面で、`endpoint` の応答が 401/403/Cloudflare Access なら認証あり、200 なら認証なしとして描く |
| `dataStores` | データの置き場所。`pii` を書くと個人情報として描く |
| `saas` | 外部サービス。`ownerAuth` は管理画面へのログイン方式。`id: "anthropic"` があると Claude の呼び出し線を引く |
| `aiConnectors.items` | ローカル設定に出ない AI のコネクタ。`canSend: true` は外部へ送信・書き込みできるもの |

約束ごと:

1. **実測していない値は書かない。** 分からない属性は空のまま（アプリでは「未入力」）。もっともらしい値で埋めると、穴が「問題なし」に化ける。
2. **認証方式が分からない線は Password にする**（弱い側に倒す）。隠れるより赤く出る方を選ぶ。
3. 秘密情報の値はどのファイルにも書かない。

## 実測 → 構成図の対応

| 実測 | ノード | 属性・線 |
|---|---|---|
| 127.0.0.1 / ::1 だけで待ち受け | PROCESS（Mac 内の処理） | 外から線を引かない（雑音を出さない） |
| Tailscale IP（100.64/10）で待ち受け | FRONT_END_SERVER | hasGlobalIp=false, hasSourceIpRestriction=true / 本人の端末から VPN・E2EE・認証 None |
| `*` / 0.0.0.0 / LAN IP で待ち受け | FRONT_END_SERVER | hasGlobalIp=false, hasSourceIpRestriction=false（遠隔管理ポートは hasRemoteAccessRestriction=false も）/ 「LAN 上の他の機器」から VPC・Plain・認証 None |
| 公開管理画面が 401/403/Access へ転送 | FRONT_END_SERVER | hasUserAuthentication=true、線の認証は台帳の値 |
| 公開管理画面が 200 で開く | 同上 | hasUserAuthentication=false、線の認証 None（赤） |
| 解約済みドメインが応答 | FRONT_END_SERVER | 「解約済みのはずの入口が応答」として赤で追加 |
| claude を呼ぶ launchd ジョブ | AGENT | Anthropic へ Token の線 |
| 平文の鍵らしき文字列 | CREDENTIAL（Mac の中） | ダミー値（xxx・your・example 等）は除外 |
| ファイアウォール | report.md の 1 節で判定 | Mac ノードのラベルにも状態を書く |

ノード ID は実測内容から決めます（例 `n-all-22`、`n-tailscale-4880`、随時変わるポートはプロセス名から）。連番にしないので、再実測しても判断と座標が引き継がれます。

## 分かっている限界

- 平文の鍵の検出は API キー形式（Anthropic・GitHub・Stripe live・AWS・Groq）と秘密鍵だけ。**平文パスワードは検出できない。**
- root 所有の待ち受けはプロセス名が分からない（sudo を使わない方針）。`portNames` で名前を付ける。
- 図に出せるのは「入口があるか」まで。ファイアウォールのアプリ単位の許可で、実際に LAN から届くかは確かめていない（別の機器からの試験はしない）。
- claude を呼ぶ定期ジョブの判定は、plist の引数と、そこから直接呼ばれるスクリプトの本文まで。別スクリプトを挟む呼び出しは数えていない。
- 外部サービスのログ保持・MFA の有無は台帳頼み。
- 「問題なし」「対象なし」は、該当する要素を台帳に書いていないだけの場合がある。

## 動作確認した環境

- Intel Mac（作者の実機）。
- GitHub Actions の `macos-latest`（Apple Silicon）。ひな形の台帳のまま、毎回の push で2通りを通している（[.github/workflows/macos.yml](.github/workflows/macos.yml)）: Node.js を使えなくした python3 だけの入れ方（`setup.sh` → テスト → 起動ファイル 2 回）と、評価エンジンありの入れ方（`setup.sh --with-engine` → テスト → `run.sh` 2 回）。

## 開発

```bash
python3 -m unittest discover -s tests
```

評価エンジン（`vendor/CyberRiskScape` か `CRS_CLI`）があれば、生成した構成図を本物の CLI で評価する結合テストも走ります。
評価エンジンの版を上げるときは、`setup.sh` の `CRS_TAG` と `CRS_COMMIT` を両方書き換え、テストを通してください。

## バージョン

版は `VERSION` ファイルだけで管理しています（[セマンティック バージョニング](https://semver.org/lang/ja/)）。
レポートの上端と末尾、`./run.sh --version`、アプリの「情報を見る」に同じ番号が出ます。
変更の記録は [CHANGELOG.md](CHANGELOG.md) にあります。版を上げるときは、`VERSION` と `CHANGELOG.md` を同じコミットで書き換えます。

## ライセンス

Apache License 2.0。評価エンジンの CyberRiskScape（Copyright 2026 TAKASHI OMOTO、Apache 2.0）はこのリポジトリには含まず、`./setup.sh --with-engine` のときだけ公式リポジトリから取得します。詳しくは [NOTICE](NOTICE)。
本ツールは CyberRiskScape プロジェクトとは関係のない独立したプロジェクトです。

無保証です。Issue への対応は不定期です。
