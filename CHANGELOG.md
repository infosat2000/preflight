# 変更の記録

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に、版の付け方は [セマンティック バージョニング](https://semver.org/lang/ja/) に従います。
1.0.0 を一般公開の版とし、それまでは 0.x で進めます。

## [Unreleased]

## [1.0.1] - 未定

### 変更
- 呼び名を「BB Preflight」にそろえる。レポートの見出しと末尾、起動時の表示、README・NOTICE から「Blackbox Blast Edition」を外す。作り手と著作権は FOREST LIFE* のまま。ファイル名・フォルダ名・環境変数は変えない。

## [1.0.0] - 2026-10-15

一般公開の版。製品名は BB Preflight（FOREST LIFE*）。

### 追加
- メール登録の仕組み（signup/）。FOREST LIFE* の Cloudflare に置く Worker と D1 で、紹介ページの申し込みを受け、Resend で確認メール・ダウンロードの案内・3日後と7日後の案内を送る。SEND_MODE を live にするまでは送らない。手順は signup/README.md。
- 配る zip は、メールを確認した人だけに専用のリンク（7日間・5回まで）で渡す。zip は R2 の非公開の置き場に置き、signup/upload-zip.sh で作って置く。

### 変更
- 製品名を「Preflight（FOREST LIFE*）」とし、Blackbox Blast で紹介する版として「Blackbox Blast Edition」と添える。著作権の表示（NOTICE・LICENSE・レポートの末尾）は FOREST LIFE* にそろえる。
- 起動ボタンの名前を「BB Preflight.app」「BB Preflight Diagram.app」に変える（BB は Blackbox Blast Edition の印）。setup.sh を実行すると、前の名前（Blackbox Blast Preflight*.app、Preflight*.app）のうち、この setup.sh が作ったものは片付ける。データの置き場所（~/.bb-preflight）と環境変数（BB_PREFLIGHT_*）は変えない。
- 起動ボタンのバンドルIDを dev.forestlife.preflight（.diagram）に変える。前の名前・前のバンドルIDの起動ボタンは、リポジトリのフォルダを移したあとでも setup.sh が片付ける（この setup.sh が作ったものだけ）。
- リポジトリの置き場所を infosat2000/preflight に移した。

## [0.9.0] - 2026-10-13

最初の版（非公開）。一般公開（1.0.0）の直前の版として 0.9.0 とする。

### 追加
- このMacの実測（ファイアウォール、待ち受け、LAN 側の遠隔操作の入口、公開URL、平文の鍵、AI の自動実行）。
- 実測から構成図を作り、CyberRiskScape v0.6.0 の脅威ルールと IPA 注意喚起 17 項目で評価する。
- ふつうの言葉で読める日英の HTML レポート（NO-GO / CAUTION / CLEAR、ライト・ダーク切り替え）。
- 直し方の手順、目安の時間、元に戻す方法、AI に頼むための依頼文。
- 前回の点検との差分（前回の日付つき）。リスク受容などの判断は次回に引き継ぐ。
- ダブルクリックで動く Preflight.command と、アイコン付きの「Blackbox Blast Preflight.app」。管理者のユーザーなら /Applications に、そうでなければ ~/Applications に置き、初めて置いたときは Finder でその場所を開く。
- 専門家向けの詳しい情報（report.md / report.en.md）。
- レポートの中に構成図を描く（つないでくる人 → 入口 → その先。ほかの人が届く道は色を変える）。評価エンジンがなくても見られる。英語表示では、台帳に英語名（labelEn / portNamesEn）がない名前だけ日本語のまま出し、図の説明でそのことを案内する。名前の分からないシステムの待ち受けも英語で出す。
- 専門家向けの `Diagram.command` と、その起動ボタン「Blackbox Blast Preflight Diagram.app」（評価エンジンを入れたときだけ置く）: 開くと、最新の構成図を読み込んだ評価エンジンのブラウザ版を、このMacの中だけで開く。
- 入口の地図（レーダーと3つの場所の一覧）。レーダーは「止める」ボタンで止められ、次に開いたときも覚えている（動きを減らす設定の Mac では最初から止まっている）。
- npm の感染対策の点検（ignore-scripts の設定と supply-chain-guard の結果を読む）。npm の公開用トークンも鍵として探す。
- 点検項目の追加: AI に与えた権限、Mac の守り（SIP・Gatekeeper・自動ログイン）、ディスクの暗号化（FileVault）、SSH 鍵のパスフレーズ、遠隔操作アプリ、バックアップ（Time Machine）、更新の設定（ウイルス対策のデータを自動で受け取るか。macOS 本体のアップデートは勧めない）。OCLP の Mac は判断を合わせる。

- 点検中に「3/14 …を調べています」と進み具合を出す。鍵の検索は 8 階層までにし、キャッシュ類を飛ばす。
- 見つかった鍵のファイルは `~/…` の形で記録する（「AI に頼む」の依頼文にユーザー名が入らない）。
- 評価エンジンなしでも動くようにした。点検とレポートは macOS に入っている python3 だけで出る。IPA 17 項目の判定と脅威の一覧が要るときは `./setup.sh --with-engine`。

### セキュリティ
- `Diagram.command` の手元のサーバーは、Host が `127.0.0.1` / `localhost` でない要求を断る（DNS リバインディング対策）。構成図は、起動ごとに作る合言葉つきの URL からしか読めない。
- 平文の鍵の検索で、このツール自身のフォルダと点検結果の置き場所（~/.bb-preflight）を見ない。秘密鍵は、見出しの行の後に鍵の本文が続くときだけ数える（ツールを ~/Claude などの検索範囲に置くと、自分のコードとテストを秘密鍵と誤検知して NO-GO になっていた）。
- setup.sh は評価エンジンの部品を `npm ci --ignore-scripts` で入れる（install スクリプトを動かさない）。
