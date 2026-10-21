# 変更の記録

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に、版の付け方は [セマンティック バージョニング](https://semver.org/lang/ja/) に従います。
1.0.0 を一般公開の版とし、それまでは 0.x で進めます。

## [Unreleased]

## [1.2.0] - 2026-10-21

1.1.0 は出さずに、検出の候補をまとめて入れた版。点検は 14 項目から 20 項目になる。どれも読み取り専用で、sudo は使わない。照らし合わせる既知の痕跡の一覧は `ioc.json`（2026-10-21 時点、出典つき）に分けた。

### 追加
- 自動で起動するものの点検。~/Library/LaunchAgents・/Library/LaunchAgents・/Library/LaunchDaemons の plist を全部読み、動かす実行ファイル（インタープリタに渡すスクリプトも）の場所と署名を確かめる。Apple や Google を名乗るのに本物の署名がないもの、一時置き場やキャッシュから動くもの、ネットから取ってきてその場で実行するものは赤、作り手の分からないものは黄。本物の Apple・Google の署名（Google は開発者 ID EQHXZ8M8AV）は許す。Homebrew などパッケージ管理の置き場と、claude を呼ぶジョブ（「AI の自動実行」で扱う）は黄にしない。ログイン項目の一覧そのものは sudo なしでは読めないので、アプリの中にある自動起動の部品を名前と署名で確かめる。
- 名前を偽ったアプリの点検。~/Library/Caches・~/Library/Application Support・~/.cache・~/.config・見慣れない隠しフォルダ・/private/tmp・/Users/Shared にある .app と Mach-O のうち、Apple や Google を名乗るものの署名を確かめる。既知の痕跡（CrashStealer・PamStealer・MacSync・Mini Shai-Hulud など）、ホーム直下の隠しファイルの実行ファイル、一時置き場から動いている署名のないプログラム、署名が壊れた暗号資産ウォレットのアプリも知らせる。
- シェルと git への居座りの点検。~/.zshrc など 7 つの起動ファイルの、ネットから取ってきて実行する行・隠した文字列を戻して実行する行・一時置き場や見慣れない隠しファイルを動かす行（行番号と種類だけを記録し、中身は記録しない）。git の全体設定の core.hooksPath と init.templateDir のフック（git コマンドは呼ばず、設定ファイルを読む）。
- 開くだけで動く仕掛けの点検。走査範囲のプロジェクトにある .claude/settings.json のフック、.vscode/tasks.json の folderOpen、ワームが置くファイル名（.claude/setup.mjs など）、CLAUDE.md・AGENTS.md・.cursorrules・SKILL.md などに埋め込まれた見えない文字（タグ文字・向きを変える文字・ゼロ幅の文字）。
- AI ツールの鍵と版の点検。~/.git-credentials・~/.npmrc・GitHub CLI・Docker・Codex・Gemini CLI・Copilot などの鍵のファイルが本人以外に読めないか、平文の鍵がないか。Claude Code・Claude Desktop・Cursor・Gemini CLI・Windsurf・VS Code・Codex の MCP 設定に鍵が直接書かれていないか、http でつないでいないか、版を固定していないか。Claude Code（2.1.84 未満・CVE-2026-40068）、Cursor（2.5 未満・CVE-2026-26268）、Gemini CLI（0.39.1 未満・CVE-2026-12537）の版。鍵の値は記録しない。
- ブラウザの拡張機能の点検。Chrome 系ブラウザの拡張機能を、AI の会話を盗むと報告された ID と照らし、公式ストアの外から入ったものを知らせる。
- npm の版を読み、12 以上なら install スクリプトが標準で止まるので、感染対策ありとみなす。
- 前回との差分に、自動で起動するものと怪しいファイルの増減を出す（前回も 1.2.0 以降で測っていたときだけ）。
- レポートの「この点検で分からないこと」に、ウイルス対策ソフトの代わりではないこと、ログイン項目の一覧は読めないことを書く。
- macOS の更新の知らせ。OCLP 以外の Mac では、届いたまま入っていない Apple の更新があるとき、自動の確認がオフのとき、最後の確認から 30 日を超えたときに黄で知らせる（バックアップを取ってから入れる手順つき）。読むのは /Library/Preferences/com.apple.SoftwareUpdate.plist だけで、Apple には問い合わせない。
- OCLP の Mac では更新を勧めず、「macOS を新しい版にすると、再起動できなくなることがある。OCLP の対応を確かめ、バックアップを取ってから」と警告する。macOS 本体の自動インストールがオンのときだけ、それをオフにする手順を黄で出す。
- `~/.bb-preflight/known.txt`。自分で作った自動起動・AI の自動実行・外から届くアプリの名前を1行ずつ書くと、次から黄にせず「確認済み」として緑の欄に名前を出す。偽の Apple 名や一時置き場など、赤の印は書いても外れない。

### 変更
- 同じ広い許可が複数の設定ファイルにあるとき、AI の許可のカードには1回だけ出す。

### 変わらないこと
- OCLP の Mac に、macOS の更新を勧めることはない（テストで確かめている）。AI ツールの版の知らせは、その道具だけの更新で、macOS の版は変わらない。

## [1.0.1] - 2026-10-18

### 変更
- 7日後の案内（点検サービスのご案内）をやめる。登録で送るのは、確認・ダウンロード・3日後の結果の読み方だけ。同意文も「使い方のご案内と、更新や注意が必要なセキュリティ情報のお知らせ」に変える。
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
