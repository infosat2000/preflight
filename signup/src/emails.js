// メールの文面（日本語・英語）。どれもテキストと HTML の両方を作る。
// 宣伝に当たるメール（ようこそ・3日後・7日後）には、特定電子メール法の表示（送信者・所在地・連絡先・配信停止）を末尾に付ける。
// 確認メールは本人確認だけなので宣伝は入れないが、送り主は同じように書く。

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const T = {
  ja: {
    confirm: {
      subject: "【確認】Preflight の受け取りの登録",
      body: (v) => [
        "Preflight（Blackbox Blast Edition）の受け取りの登録をありがとうございます。",
        "下のリンクを押すと登録が終わり、ダウンロードの案内をお送りします。",
        v.confirmUrl,
        "このリンクの有効期限は7日です。",
        "心当たりがない場合は、このメールを捨ててください。リンクを押さなければ、何も登録されません。",
      ],
    },
    welcome: {
      subject: "Preflight のダウンロードと導入の手順",
      body: (v) => [
        "登録が終わりました。Preflight は、ここから受け取れます。",
        v.downloadUrl,
        "導入の手順:",
        "1. 受け取った zip をダブルクリックして開きます。",
        "2. フォルダの中の Preflight.command をダブルクリックします。初めてのときは準備をして、台帳（点検する範囲のメモ）が開きます。",
        "3. 台帳に自分のサイトや使っているサービスを書いて保存し、もう一度開きます。点検はふつう1〜3分で、終わるとブラウザで結果が開きます。",
        "macOS に止められたときは、「システム設定」→「プライバシーとセキュリティ」の下の方にある「このまま開く」を押してください。",
        "Preflight は読み取るだけで、何も変えません。点検の結果をどこかに送ることもありません。",
      ],
    },
    step1: {
      subject: "Preflight の結果の読み方（NO-GO が出たら）",
      body: () => [
        "Preflight は使ってみましたか。今日は、結果の読み方をお伝えします。",
        "NO-GO（赤）: 離陸の前に直してほしいところです。外から届く入口や、人に見られやすい鍵などです。カードの「直し方」の手順どおりに進めると、たいてい数分で直せます。",
        "CAUTION（黄）: 確認しておきたいところです。自分で使っている機能なら、そのままで構いません。「このままでよい場合」の欄を見て判断してください。",
        "CLEAR（緑）: 見た範囲で、気になるところはありませんでした。安全の保証ではありません。",
        "直したら、Preflight をもう一度開いて点検してください。直っていれば「前回の点検から変わったこと」に出ます。",
      ],
    },
    step2: {
      subject: "点検して、直すところまでお手伝いします",
      body: (v) => [
        "Preflight の結果で、自分で直すのが不安なところはありませんでしたか。",
        "FOREST LIFE* では、Mac の点検と、見つかったところを直すお手伝いをしています。AI エージェントの設定や、公開しているサイトの入口も一緒に見ます。",
        `ご相談は、このメールへの返信か、${v.contact} からどうぞ。`,
        "このメールで、登録のときにお伝えした案内はひと区切りです。このあとは、新しい版や、注意が必要なセキュリティ情報があるときだけお送りします。",
      ],
    },
    footer: (v, ad) => [
      ad ? "このメールは、Preflight のダウンロードを申し込まれた方にお送りしています。" : "このメールは、Preflight の受け取りの登録をされた方にお送りしています。",
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
      subject: "Confirm your sign-up for Preflight",
      body: (v) => [
        "Thanks for signing up to get Preflight (Blackbox Blast Edition).",
        "Click the link below to finish, and we'll send you the download.",
        v.confirmUrl,
        "This link works for 7 days.",
        "If this wasn't you, just ignore this email. Nothing is signed up unless the link is clicked.",
      ],
    },
    welcome: {
      subject: "Your Preflight download and how to install it",
      body: (v) => [
        "You're signed up. Get Preflight here:",
        v.downloadUrl,
        "To install:",
        "1. Double-click the zip to open it.",
        "2. Double-click Preflight.command inside the folder. The first time, it sets itself up and opens your list (a short note of what to check).",
        "3. Add your own sites and the services you use to the list, save it, and open Preflight again. A check usually takes 1 to 3 minutes, then the report opens in your browser.",
        "If macOS blocks it, open System Settings, then Privacy & Security, and click Open Anyway near the bottom.",
        "Preflight only reads. It changes nothing and sends your results nowhere.",
      ],
    },
    step1: {
      subject: "Reading your Preflight results (when you get a NO-GO)",
      body: () => [
        "Have you tried Preflight yet? Here's how to read the results.",
        "NO-GO (red): fix these before takeoff. These are doors reachable from outside, keys stored where others could see them, and so on. Follow the fix steps on the card; most take a few minutes.",
        "CAUTION (yellow): worth a look. If it's a feature you use on purpose, you can leave it. The \"when it's fine to leave\" line helps you decide.",
        "CLEAR (green): nothing stood out in what Preflight looked at. It is not a guarantee of safety.",
        "After fixing something, open Preflight again and run the check. If it worked, the change shows up under \"Changes since the last check\".",
      ],
    },
    step2: {
      subject: "We can check your Mac with you and help fix it",
      body: (v) => [
        "Did your Preflight results show anything you'd rather not fix on your own?",
        "FOREST LIFE* offers Mac check-ups and help fixing what they find, including AI agent settings and the doors your public sites leave open.",
        `To ask, reply to this email or contact ${v.contact}.`,
        "This is the last of the emails we mentioned when you signed up. From now on, we'll only write when there's a new version or a security issue worth knowing about.",
      ],
    },
    footer: (v, ad) => [
      ad ? "You're getting this because you signed up to download Preflight." : "You're getting this because someone signed up for Preflight with this address.",
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

// kind: 'confirm' | 'welcome' | 'step1' | 'step2'
export function renderEmail(kind, lang, v) {
  const t = T[lang] || T.ja;
  const m = t[kind];
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
    return `<p>${esc(s)}</p>`;
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
