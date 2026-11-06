---
name: bb-preflight
description: Check this Mac's security with BB Preflight (free, read-only, nothing is sent anywhere) and explain the results in plain words, then help fix them one at a time with the user's OK. Use when the user asks to check, audit or lock down their Mac, asks "is my Mac safe", wants to see what AI agents (Claude Code, MCP, scheduled jobs) can reach, or wants to read Strix pentest results. 「この Mac を点検して」「Mac のセキュリティを確認して」「戸締まりを見て」「Preflight を回して」「Strix の結果を読んで」などで使う。
---

# BB Preflight（Mac の戸締まり点検）

BB Preflight は、Mac の実際の状態を**読むだけ**で点検する無料のツールです（Apache-2.0、https://github.com/infosat2000/preflight）。
見るのは、待ち受けているポート、ファイアウォール、ファイルに書かれた API キー、AI エージェントに与えた権限、自動で起動するもの、偽装アプリ、ブラウザの拡張機能、Strix の結果などです。
点検そのものは何も変えず、sudo も使わず、結果をどこにも送りません（外への通信は、台帳に書いた自分の公開 URL への確認だけ）。

## 守ること

- **点検は読むだけ。直すのは、1件ずつ、コマンドか手順を見せて、ユーザーの OK をもらってから。** 設定の変更、ファイルの削除、権限の変更を、黙ってまとめて行わない。
- **鍵の値を画面に出さない・読まない。** レポートは鍵の場所と種類しか書かない。その鍵のファイルを開いて中身を表示しない。
- **結果を外に送らない。** レポート・`facts.json`・`model.json` は、そのMacの弱点の地図。Web に貼る、Issue に書く、ほかのサービスへ送ることはしない。
- **macOS 本体のアップデートを勧めない**（OpenCore Legacy Patcher で動く Mac では、再起動できなくなることがある）。レポートが勧める範囲に従う。
- **Strix を動かさない。** このスキルは Strix の結果を読むだけ。Strix を試したい場合は `docs/strix-guide.md` を一緒に読み、そこにある3つのルールを守る。

## 手順

### 1. 入っているか確かめる

- `~/.bb-preflight/` があれば、以前に使っている。ツール本体の場所は、ユーザーに聞くか、`~/BB-Preflight`・`~/preflight` を探す。
- 無ければ、入れてよいかを聞いてから取得する（中身はソースで確かめられる）:

```bash
git clone https://github.com/infosat2000/preflight ~/BB-Preflight
cd ~/BB-Preflight && ./setup.sh
```

`setup.sh` は python3 だけで動き、`~/.bb-preflight/inventory.json`（台帳）のひな形を置く。追加のライブラリは入れない。

### 2. 台帳を一緒に書く（初回だけ）

`~/.bb-preflight/inventory.json` を開き、ユーザーに聞きながら埋める。
- `endpoints` と `publicSites`: 自分の公開サイト（自分のものだけ）
- `secretScanRoots`: 鍵の置き忘れを探すフォルダ（例 `~/projects`）
- そのほかの項目は README の「台帳の書き方」に従う

### 3. 点検する

```bash
cd <ツールの場所> && ./run.sh
```

1〜3分ほどかかる。結果は `~/.bb-preflight/out/<日時>/` に出る。

### 4. 結果を説明する

- いちばん新しい `~/.bb-preflight/out/<日時>/report.md` を読む。
- 総合判定（NO-GO / CAUTION / CLEAR）と、赤（今すぐ直す）・黄（確認しておく）を、**ふつうの言葉で**、赤から順に短く説明する。
- 「前回の点検から変わったこと」があれば伝える。
- `report.html` はブラウザで開ける（`open` で開いてよいか聞く）。各カードの「直し方」と「AI に頼む」の依頼文が、そのまま使える。
- 「問題なし」は安全の保証ではないことを、最後に一言添える。

### 5. 一緒に直す

- ユーザーが選んだ項目だけを、1件ずつ直す。カードの手順をもとに、実行するコマンドや設定画面の場所を見せ、OK をもらってから進める。
- 元に戻す方法があれば、先に伝える（カードの「元に戻すには」）。
- 自分で作った自動起動など、問題ないものは `~/.bb-preflight/known.txt` に名前を1行ずつ書くと、次から「確認済み」になる（赤は消えない）。
- 直したら `./run.sh` をもう一度回し、「前回の点検から変わったこと」に出たかを確かめる。

## Strix の結果について

- 走査範囲（`secretScanRoots`）に `strix_runs/` があれば、BB Preflight が最新の回を読む。
- 指摘が0件でも、途中で止まった回は「最後まで調べた結果ではない」として黄で出る。0件は「調べた範囲では見つからなかった」という意味で、安全の保証ではない。
