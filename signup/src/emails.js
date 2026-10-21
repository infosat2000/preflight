// メールの文面（日本語・英語）。どれもテキストと HTML の両方を作る。
// 宣伝に当たるメール（ようこそ・3日後・7日後）には、特定電子メール法の表示（送信者・所在地・連絡先・配信停止）を末尾に付ける。
// 確認メールは本人確認だけなので宣伝は入れないが、送り主は同じように書く。
// 新しい版のお知らせ（news）は NEWS に版ごとに書き、wrangler の NEWS にその版を入れると、毎時の cron が少しずつ送る。

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const T = {
  ja: {
    confirm: {
      subject: "【確認】BB Preflight の受け取りの登録",
      body: (v) => [
        "BB Preflight の受け取りの登録をありがとうございます。",
        "下のリンクを押すと登録が終わり、ダウンロードの案内をお送りします。",
        v.confirmUrl,
        "このリンクの有効期限は7日です。",
        "心当たりがない場合は、このメールを捨ててください。リンクを押さなければ、何も登録されません。",
      ],
    },
    welcome: {
      subject: "BB Preflight のダウンロードと導入の手順",
      body: (v) => [
        "登録が終わりました。BB Preflight は、ここから受け取れます。",
        v.downloadUrl,
        "このリンクはあなた専用です。7日間、5回まで使えます。期限が切れたら、リンクを開くと新しいリンクを受け取れます。",
        "導入の手順:",
        "1. Safari なら自動で「BB-Preflight」フォルダになります。zip のままのときは、ダブルクリックして開きます。",
        "2. BB-Preflight フォルダの中の Preflight.command をダブルクリックします。初めてのときは準備をして、台帳（点検する範囲のメモ）が開きます。",
        "3. 台帳に自分のサイトや使っているサービスを書いて保存し、もう一度開きます。点検はふつう1〜3分で、終わるとブラウザで結果が開きます。",
        "macOS に止められたときは、「システム設定」→「プライバシーとセキュリティ」の下の方にある「このまま開く」を押してください。",
        "BB Preflight は読み取るだけで、何も変えません。点検の結果をどこかに送ることもありません。",
        ...(v.sourceUrl ? [`中身（ソースコード）と変更の記録は、GitHub で確かめられます: ${v.sourceUrl}`] : []),
      ],
    },
    step1: {
      subject: "BB Preflight の結果の読み方（NO-GO が出たら）",
      body: () => [
        "BB Preflight は使ってみましたか。今日は、結果の読み方をお伝えします。",
        "NO-GO（赤）: 離陸の前に直してほしいところです。外から届く入口や、人に見られやすい鍵などです。カードの「直し方」の手順どおりに進めると、たいてい数分で直せます。",
        "CAUTION（黄）: 確認しておきたいところです。自分で使っている機能なら、そのままで構いません。「このままでよい場合」の欄を見て判断してください。",
        "CLEAR（緑）: 見た範囲で、気になるところはありませんでした。安全の保証ではありません。",
        "直したら、BB Preflight をもう一度開いて点検してください。直っていれば「前回の点検から変わったこと」に出ます。",
        "このメールで、登録のときにお伝えした案内はひと区切りです。このあとは、新しい版や、注意が必要なセキュリティ情報があるときだけお送りします。",
      ],
    },
    footer: (v, ad) => [
      ad ? "このメールは、BB Preflight のダウンロードを申し込まれた方にお送りしています。" : "このメールは、BB Preflight の受け取りの登録をされた方にお送りしています。",
      ...(ad ? [`配信の停止: ${v.unsubUrl}`] : []),
      `送信者: ${v.senderName}`,
      `所在地: ${v.senderAddress}`,
      `お問い合わせ: ${v.contact}`,
    ],
    unsubLabel: "配信を止める",
    confirmLabel: "登録を終える",
    downloadLabel: "ダウンロードする",
  },
  en: {
    confirm: {
      subject: "Confirm your sign-up for BB Preflight",
      body: (v) => [
        "Thanks for signing up to get BB Preflight.",
        "Click the link below to finish, and we'll send you the download.",
        v.confirmUrl,
        "This link works for 7 days.",
        "If this wasn't you, just ignore this email. Nothing is signed up unless the link is clicked.",
      ],
    },
    welcome: {
      subject: "Your BB Preflight download and how to install it",
      body: (v) => [
        "You're signed up. Get BB Preflight here:",
        v.downloadUrl,
        "This link is just for you. It works 5 times within 7 days. After that, open it and you can ask for a new one.",
        "To install:",
        "1. Double-click the zip to open it.",
        "2. Double-click Preflight.command inside the folder. The first time, it sets itself up and opens your list (a short note of what to check).",
        "3. Add your own sites and the services you use to the list, save it, and open BB Preflight again. A check usually takes 1 to 3 minutes, then the report opens in your browser.",
        "If macOS blocks it, open System Settings, then Privacy & Security, and click Open Anyway near the bottom.",
        "BB Preflight only reads. It changes nothing and sends your results nowhere.",
        ...(v.sourceUrl ? [`The source code and change history are on GitHub: ${v.sourceUrl}`] : []),
      ],
    },
    step1: {
      subject: "Reading your BB Preflight results (when you get a NO-GO)",
      body: () => [
        "Have you tried BB Preflight yet? Here's how to read the results.",
        "NO-GO (red): fix these before takeoff. These are doors reachable from outside, keys stored where others could see them, and so on. Follow the fix steps on the card; most take a few minutes.",
        "CAUTION (yellow): worth a look. If it's a feature you use on purpose, you can leave it. The \"when it's fine to leave\" line helps you decide.",
        "CLEAR (green): nothing stood out in what BB Preflight looked at. It is not a guarantee of safety.",
        "After fixing something, open BB Preflight again and run the check. If it worked, the change shows up under \"Changes since the last check\".",
        "This is the last of the emails we mentioned when you signed up. From now on, we'll only write when there's a new version or a security issue worth knowing about.",
      ],
    },
    footer: (v, ad) => [
      ad ? "You're getting this because you signed up to download BB Preflight." : "You're getting this because someone signed up for BB Preflight with this address.",
      ...(ad ? [`Unsubscribe: ${v.unsubUrl}`] : []),
      `Sender: ${v.senderName}`,
      `Address: ${v.senderAddress}`,
      `Contact: ${v.contact}`,
    ],
    unsubLabel: "Unsubscribe",
    confirmLabel: "Finish signing up",
    downloadLabel: "Download",
  },
};

// 新しい版のお知らせ。notBefore より後に R2 の zip が置き換わるまでは送らない（古い zip を配らないように）
export const NEWS = {
  "1.2.0": {
    notBefore: "2026-10-21T02:41:25Z", // 1.2.0 を main に入れた時刻
    ja: {
      subject: "BB Preflight 1.2.0 を出しました（点検は20項目に）",
      body: (v) => [
        "BB Preflight を 1.2.0 にしました。点検は14項目から20項目になりました。",
        "今年報告された Mac の情報を盗むマルウェアは、多くが Apple や Google を名乗るアプリを置いていきます。1.2.0 では、この偽装と、自動で起動するような居座りも見るようにしました。",
        "新しく見る6つ:\n・自動で起動するもの（LaunchAgents などが動かすプログラムの場所と署名）\n・名前を偽ったアプリ（Apple や Google を名乗るのに、本物の署名がないもの）\n・シェルと git への居座り（~/.zshrc などと、git の全体のフック）\n・フォルダを開くだけで動く仕掛け（.claude/settings.json のフック、.vscode/tasks.json など）\n・AI ツールの鍵と版（鍵のファイルの置き方、MCP の設定、既知の脆弱性を直した版か）\n・ブラウザの拡張機能",
        "ほかに、届いた macOS の更新が入っていないときにも知らせます。OCLP で動く Mac には更新を勧めず、「新しい版にすると再起動できなくなることがある」と注意だけ出します。",
        "これまでどおり読むだけで、何も変えず、結果をどこかに送ることもありません。ウイルス対策ソフトの代わりではありません。",
        "1.2.0 は、ここから受け取れます。あなた専用のリンクで、7日間、5回まで使えます。",
        v.downloadUrl,
        "入れ替え方:\n1. 受け取った zip を開くと、BB-Preflight フォルダができます。\n2. 前の版の BB-Preflight フォルダをゴミ箱に入れ、新しいフォルダを同じ場所に置きます。名前が「BB-Preflight 2」になっていたら、「BB-Preflight」に直してください。\n3. いつもどおり BB Preflight を開きます。台帳と前回の結果はそのまま残るので、書き直す必要はありません。",
        "新しい点検で、自分で入れた自動起動などが黄色に出ることがあります。心当たりのあるものは、~/.bb-preflight/known.txt に名前を1行ずつ書くと、次から「確認済み」になります。赤の印は、書いても消えません。",
        `リンクの期限が切れたら、リンクを開くと新しいリンクを受け取れます。紹介ページで同じメールアドレスを入れ直しても届きます: ${v.siteBase}/ja/preflight/`,
        ...(v.sourceUrl ? [`変更の記録（CHANGELOG）: ${v.sourceUrl}/blob/main/CHANGELOG.md`] : []),
      ],
    },
    en: {
      subject: "BB Preflight 1.2.0 is out (now 20 checks)",
      body: (v) => [
        "BB Preflight 1.2.0 is out. It now runs 20 checks, up from 14.",
        "Many of the Mac infostealers reported this year drop an app that pretends to be Apple or Google. 1.2.0 now looks for that disguise and the places malware hides to stay.",
        "The 6 new checks:\n- What starts on its own (where the programs run by LaunchAgents and the like live, and who signed them)\n- Apps with fake names (claiming to be Apple or Google without a genuine signature)\n- Hooks in your shell and git (~/.zshrc and friends, and global git hooks)\n- Folders that run code when opened (.claude/settings.json hooks, .vscode/tasks.json, and so on)\n- AI tool keys and versions (how key files are stored, MCP settings, and whether known vulnerabilities are fixed)\n- Browser extensions",
        "It also tells you when an Apple update is waiting to be installed. On Macs running OCLP it never suggests updating; it only warns that an update may leave the Mac unable to start.",
        "As before, it only reads. It changes nothing and sends your results nowhere. It is not a replacement for antivirus software.",
        "Get 1.2.0 here. The link is just for you and works 5 times within 7 days.",
        v.downloadUrl,
        "To swap in the new version:\n1. Open the zip. You'll get a BB-Preflight folder.\n2. Move your old BB-Preflight folder to the Trash and put the new one in the same place. If it's called \"BB-Preflight 2\", rename it to \"BB-Preflight\".\n3. Open BB Preflight as usual. Your list and your last results stay where they are, so there's nothing to redo.",
        "The new checks may show things you set up yourself in yellow. For the ones you recognize, add their names to ~/.bb-preflight/known.txt, one per line, and they'll show as confirmed next time. Red flags stay red even if listed.",
        `If the link expires, open it and you can ask for a new one. You can also enter the same email on the BB Preflight page again: ${v.siteBase}/en/preflight/`,
        ...(v.sourceUrl ? [`What changed (CHANGELOG): ${v.sourceUrl}/blob/main/CHANGELOG.md`] : []),
      ],
    },
  },
};

// kind: 'confirm' | 'welcome' | 'step1' | 'news'（v.newsId の版のお知らせ）
export function renderEmail(kind, lang, v) {
  const t = T[lang] || T.ja;
  const m = kind === "news" ? NEWS[v.newsId] && (NEWS[v.newsId][lang] || NEWS[v.newsId].ja) : t[kind];
  if (!m) throw new Error(`unknown email kind: ${kind}`);
  const ad = kind !== "confirm";
  const lines = m.body(v);
  const foot = t.footer(v, ad);
  const text = `${lines.join("\n\n")}\n\n--\n${foot.join("\n")}\n`;
  const linkLabel = { [v.confirmUrl]: t.confirmLabel, [v.downloadUrl]: t.downloadLabel };
  const para = (s) => {
    if (s && /^https?:\/\//.test(s)) {
      return `<p><a href="${esc(s)}" style="display:inline-block;padding:10px 18px;background:#ff7a1a;color:#0c0d0f;font-weight:700;text-decoration:none;border-radius:4px">${esc(linkLabel[s] || s)}</a></p><p style="font-size:12px;color:#666;word-break:break-all">${esc(s)}</p>`;
    }
    return `<p>${esc(s).replace(/\n/g, "<br>")}</p>`;
  };
  const footHtml = foot.map((s) => {
    if (ad && s.endsWith(v.unsubUrl)) {
      return `<p style="margin:2px 0"><a href="${esc(v.unsubUrl)}" style="color:#666">${esc(t.unsubLabel)}</a></p>`;
    }
    return `<p style="margin:2px 0">${esc(s)}</p>`;
  }).join("");
  const html = `<!doctype html><html lang="${lang === "en" ? "en" : "ja"}"><meta charset="utf-8"><body style="margin:0;padding:24px;font-family:-apple-system,'Hiragino Sans','Noto Sans JP',sans-serif;font-size:15px;line-height:1.7;color:#1b1d21;background:#ffffff"><div style="max-width:560px">${lines.map(para).join("")}<hr style="border:0;border-top:1px solid #ddd;margin:24px 0 12px"><div style="font-size:12px;color:#666">${footHtml}</div></div></body></html>`;
  return { subject: m.subject, text, html };
}
