"""e-Kakushin (SECOM e-innovation) ログイン / 情報取得.

requests だけを使って以下を行う:
  1. ログインページ (servicetop.do) にアクセスしてセッション Cookie と
     CSRF トークン (Struts TOKEN) を取得する
  2. 取得したトークンと .env の認証情報でログイン POST を送信する
  3. 「すでにログイン済み / 強制ログアウト」画面が出た場合は、その画面の
     フォームを解析して強制ログアウトを実行し、自動で再ログインする
  4. ログイン後のトップページ HTML を取得して情報を抽出する

標準ライブラリ以外の依存は requests のみ。
"""

from __future__ import annotations

import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import requests

# ---- エンドポイント ---------------------------------------------------------
BASE = "https://www0.e-kakushin.com"
LOGIN_FORM_URL = f"{BASE}/emember/servicetop.do"
LOGIN_POST_URL = f"{BASE}/emember/docroot/realm/login"

# サイトは Shift_JIS (Windows-31J)
SITE_ENCODING = "cp932"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

# 「すでにログイン済み / 強制ログアウト」画面を示すキーワード
FORCE_LOGOUT_KEYWORDS = (
    "強制ログアウト",
    "二重ログイン",
    "すでにログイン",
    "既にログイン",
    "ログイン中です",
    "多重ログイン",
    "他の端末",
    "別の端末",
)

# 再ログイン / 強制ログアウトを実行するボタンらしさを示すキーワード
FORCE_LOGOUT_BUTTON_KEYWORDS = (
    "強制ログアウト",
    "再ログイン",
    "ログアウトして",
    "続行",
    "はい",
    "ok",
)

MAX_FORCE_LOGOUT_RETRY = 2


# ---------------------------------------------------------------------------
# HTML フォーム解析 (stdlib のみ)
# ---------------------------------------------------------------------------
class _Form:
    def __init__(self, action: str, method: str) -> None:
        self.action = action
        self.method = (method or "get").lower()
        # name -> value
        self.fields: dict[str, str] = {}
        # 送信ボタン候補: (name, value, label_text)
        self.submit_buttons: list[tuple[str, str, str]] = []


class _FormParser(HTMLParser):
    """ページ中の <form> を抽出する簡易パーサ."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self._cur: _Form | None = None
        self._pending_button: tuple[str, str] | None = None  # (name, value)
        self._button_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = _Form(a.get("action", ""), a.get("method", "get"))
            self.forms.append(self._cur)
            return
        if self._cur is None:
            return
        if tag == "input":
            itype = a.get("type", "text").lower()
            name = a.get("name", "")
            value = a.get("value", "")
            if not name:
                return
            if itype in ("submit", "image", "button"):
                self._cur.submit_buttons.append((name, value, value))
            elif itype in ("checkbox", "radio"):
                if "checked" in a:
                    self._cur.fields[name] = value
            else:
                self._cur.fields[name] = value
        elif tag == "button":
            self._pending_button = (a.get("name", ""), a.get("value", ""))
            self._button_text = []
        elif tag == "select":
            # 既定の選択肢が無い場合は空で登録
            name = a.get("name", "")
            if name:
                self._cur.fields.setdefault(name, "")

    def handle_data(self, data: str) -> None:
        if self._pending_button is not None:
            self._button_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "button" and self._cur is not None and self._pending_button is not None:
            name, value = self._pending_button
            label = "".join(self._button_text).strip()
            self._cur.submit_buttons.append((name, value, label or value))
            self._pending_button = None
            self._button_text = []
        elif tag == "form":
            self._cur = None


def parse_forms(html: str) -> list[_Form]:
    p = _FormParser()
    p.feed(html)
    return p.forms


# ---------------------------------------------------------------------------
# 抽出ユーティリティ
# ---------------------------------------------------------------------------
def load_env(path: str | os.PathLike[str] = ".env") -> dict[str, str]:
    """単純な .env パーサ (python-dotenv を使わない)."""
    env: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return env
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def extract_token(html: str) -> str | None:
    """ログインフォームの Struts CSRF トークンを取り出す."""
    m = re.search(
        r'name="org\.apache\.struts\.taglib\.html\.TOKEN"\s+value="([^"]+)"',
        html,
    )
    return m.group(1) if m else None


def extract_title(html: str) -> str | None:
    m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else None


def extract_error(html: str) -> str | None:
    m = re.search(
        r'class="[^"]*(?:error|err|alert|msg-error)[^"]*"[^>]*>(.*?)<',
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        text = re.sub(r"\s+", " ", m.group(1)).strip()
        return text or None
    return None


def is_login_form_page(html: str) -> bool:
    """ログインフォームが表示されているページか."""
    return 'name="customerCodeAlias"' in html and 'name="password"' in html


def is_force_logout_page(html: str) -> bool:
    """「すでにログイン済み / 強制ログアウト」画面か."""
    if is_login_form_page(html):
        return False
    return any(kw in html for kw in FORCE_LOGOUT_KEYWORDS)


# ---------------------------------------------------------------------------
# ログイン処理
# ---------------------------------------------------------------------------
def _get_login_form(session: requests.Session) -> requests.Response:
    resp = session.get(LOGIN_FORM_URL, allow_redirects=True, timeout=30)
    resp.encoding = SITE_ENCODING
    resp.raise_for_status()
    return resp


def _post_login(
    session: requests.Session,
    form_resp: requests.Response,
    env: dict[str, str],
) -> requests.Response:
    token = extract_token(form_resp.text)
    if not token:
        raise SystemExit("CSRF トークンを取得できませんでした。")

    payload = {
        "actionEvent": "loginEvent",
        "org.apache.struts.taglib.html.TOKEN": token,
        "customerCodeAlias": env["E_COMPANY_ID"],
        "userCodeAlias": env["E_LOGIN"],
        "password": env["E_PASS"],
    }
    headers = {
        "Referer": form_resp.url,
        "Origin": BASE,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = session.post(
        LOGIN_POST_URL,
        data=payload,
        headers=headers,
        allow_redirects=True,
        timeout=30,
    )
    resp.encoding = SITE_ENCODING
    resp.raise_for_status()
    return resp


def _submit_force_logout(
    session: requests.Session, resp: requests.Response
) -> requests.Response | None:
    """強制ログアウト画面のフォームを解析して送信する.

    画面構造を決め打ちせず、ページ内のフォームと送信ボタンを汎用的に解析し、
    「強制ログアウト / 再ログイン」に該当するボタンを選んで送信する。
    """
    forms = parse_forms(resp.text)
    if not forms:
        print("     強制ログアウト画面にフォームが見つかりませんでした。")
        return None

    # ログインフォーム以外を優先的に対象とする
    candidates = [f for f in forms if "customerCodeAlias" not in f.fields] or forms
    form = candidates[0]

    # 送信ボタンの選択: 強制ログアウト/再ログインらしいラベルを優先
    chosen: tuple[str, str, str] | None = None
    for btn in form.submit_buttons:
        label = (btn[2] or "").lower()
        if any(kw in label for kw in FORCE_LOGOUT_BUTTON_KEYWORDS):
            chosen = btn
            break
    if chosen is None and form.submit_buttons:
        chosen = form.submit_buttons[0]

    data = dict(form.fields)
    # Struts の TOKEN がフォームに無ければ本文から補完
    if "org.apache.struts.taglib.html.TOKEN" not in data:
        tok = extract_token(resp.text)
        if tok:
            data["org.apache.struts.taglib.html.TOKEN"] = tok
    if chosen and chosen[0]:
        data[chosen[0]] = chosen[1]

    action_url = urljoin(resp.url, form.action) if form.action else resp.url
    label = chosen[2] if chosen else "(default)"
    print(f"     強制ログアウトを実行します: action={action_url} button='{label}'")

    headers = {
        "Referer": resp.url,
        "Origin": BASE,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if form.method == "post":
        out = session.post(
            action_url, data=data, headers=headers, allow_redirects=True, timeout=30
        )
    else:
        out = session.get(
            action_url, params=data, headers=headers, allow_redirects=True, timeout=30
        )
    out.encoding = SITE_ENCODING
    out.raise_for_status()
    return out


def login(session: requests.Session, env: dict[str, str]) -> requests.Response:
    """ログインを実行し、ログイン後ページのレスポンスを返す.

    「すでにログイン済み / 強制ログアウト」画面が出た場合は自動で強制ログアウト
    してから再ログインする。
    """
    missing = [
        name
        for name in ("E_COMPANY_ID", "E_LOGIN", "E_PASS")
        if not env.get(name)
    ]
    if missing:
        raise SystemExit(f".env に必要な値がありません: {', '.join(missing)}")

    # 1. ログインフォーム取得
    form_resp = _get_login_form(session)
    token = extract_token(form_resp.text)
    print(f"[1] ログインフォーム取得 OK  token={(token or '')[:12]}...")

    # 2. ログイン POST
    resp = _post_login(session, form_resp, env)
    print(f"[2] ログイン POST 完了  status={resp.status_code} url={resp.url}")

    # 3. 強制ログアウト画面が出たら処理して再ログイン
    for attempt in range(1, MAX_FORCE_LOGOUT_RETRY + 1):
        if not is_force_logout_page(resp.text):
            break
        print(
            f"[!] 「すでにログイン済み / 強制ログアウト」画面を検出 "
            f"(タイトル: {extract_title(resp.text)}) -> 再ログイン試行 {attempt}"
        )
        logged_out = _submit_force_logout(session, resp)
        if logged_out is None:
            break
        # 強制ログアウト後、改めてログインフォームを取得して再ログイン
        form_resp = _get_login_form(session)
        resp = _post_login(session, form_resp, env)
        print(f"    再ログイン POST 完了  status={resp.status_code} url={resp.url}")

    return resp


def is_logged_in(resp: requests.Response) -> bool:
    """ログイン成功判定: ログインフォーム / 強制ログアウト画面でなければ成功."""
    html = resp.text
    return not is_login_form_page(html) and not is_force_logout_page(html)


# ---------------------------------------------------------------------------
# サブシステム (各サービス) への遷移
# ---------------------------------------------------------------------------
SUBSYSTEM_LOGIN_PATH = "/emember/login.do"


def extract_services(html: str) -> list[dict[str, str]]:
    """ログイン後ページから「ご利用可能サービス」の一覧を抽出する.

    画面の各サービスは onclick="forwardSubSystem('<srvcCd>','<contractCode>')"
    のリンクとして並ぶ。サービス名はリンクのテキストから取得する。
    """
    services: list[dict[str, str]] = []
    pattern = re.compile(
        r"forwardSubSystem\('([^']*)'\s*,\s*'([^']*)'\)\"[^>]*>(.*?)</a>",
        re.IGNORECASE | re.DOTALL,
    )
    for m in pattern.finditer(html):
        srvc_cd, contract_code, label_html = m.groups()
        name = re.sub(r"<[^>]+>", "", label_html)
        name = re.sub(r"\s+", " ", name).strip()
        services.append(
            {"srvcCd": srvc_cd, "contractCode": contract_code, "name": name}
        )
    # 同一 (srvcCd, contractCode) の重複を除去 (名前は最初のものを採用)
    seen: set[tuple[str, str]] = set()
    uniq: list[dict[str, str]] = []
    for s in services:
        key = (s["srvcCd"], s["contractCode"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


def _extract_forward_form_fields(html: str) -> dict[str, str]:
    """name="forward" フォームの hidden 項目を抽出する."""
    forms = parse_forms(html)
    for f in forms:
        if "ekakCstmrCd" in f.fields or "usrCd" in f.fields:
            return dict(f.fields)
    # 見つからなければ最初のフォーム
    return dict(forms[0].fields) if forms else {}


def _normalize_encoding(enc: str | None) -> str:
    """サーバが返すエンコーディング名を Python が扱える名前に正規化する."""
    if not enc:
        return SITE_ENCODING
    e = enc.strip().lower().replace("-", "").replace("_", "")
    if e in ("windows31j", "shiftjis", "sjis", "ms932", "cp932", "windows932"):
        return "cp932"
    if e in ("eucjp",):
        return "euc_jp"
    try:
        "".encode(enc)  # 妥当な名前かチェック
        return enc
    except LookupError:
        return SITE_ENCODING


def open_service(
    session: requests.Session,
    landing_resp: requests.Response,
    srvc_cd: str,
    contract_code: str,
) -> requests.Response:
    """ブラウザの forwardSubSystem() 相当の遷移でサブシステムを開く.

    forwardSubSystem は name="forward" フォームの contractCode を書き換え、
    action を /emember/login.do?srvcCd=...&contractCode=... にして POST する。
    SSO ハンドオフでリダイレクトが続くため allow_redirects=True で追従する。
    """
    fields = _extract_forward_form_fields(landing_resp.text)
    fields["contractCode"] = contract_code

    action = (
        f"{SUBSYSTEM_LOGIN_PATH}?srvcCd={srvc_cd}&contractCode={contract_code}"
    )
    action_url = urljoin(landing_resp.url, action)
    headers = {
        "Referer": landing_resp.url,
        "Origin": BASE,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = session.post(
        action_url, data=fields, headers=headers, allow_redirects=True, timeout=30
    )
    # 遷移先はサービス側。サーバの文字コード名 (例: Windows-31J) を正規化
    resp.encoding = _normalize_encoding(resp.encoding)
    resp.raise_for_status()
    return resp


# ---------------------------------------------------------------------------
# 安否確認サービス (eanpi) 内のナビゲーション
# ---------------------------------------------------------------------------
EANPI_ORIGIN = "https://www3.e-kakushin.com"


def _anpi_post(
    session: requests.Session, path: str, data: dict, referer: str, **kw
) -> requests.Response:
    """eanpi サブシステムへの POST (Shift_JIS 正規化込み)."""
    url = urljoin(referer, path)
    r = session.post(
        url,
        data=data,
        headers={"Referer": referer, "Origin": EANPI_ORIGIN},
        allow_redirects=True,
        timeout=120,
        **kw,
    )
    r.encoding = _normalize_encoding(r.encoding)
    return r


def _form_with(forms_html: str, *required_fields: str) -> dict[str, str]:
    """必須フィールドを含むフォームの hidden 項目を取得する."""
    for f in parse_forms(forms_html):
        if all(k in f.fields for k in required_fields):
            return dict(f.fields)
    return dict(parse_forms(forms_html)[0].fields)


def enter_mgr_disaster_list(
    session: requests.Session, service_resp: requests.Response, my_user_id: str
) -> requests.Response:
    """安否確認サービスのトップ → 災害・訓練一覧 (管理者) まで遷移する.

    途中で「管理者アクセス一覧 (同時アクセス制限)」が出た場合は、自分の
    ユーザーの接続を切断してから一覧へ進む。
    """
    # サービスTOP(自動 submit フォーム) → MgrMenu
    mform = parse_forms(service_resp.text)[0]
    menu = _anpi_post(session, mform.action, mform.fields, service_resp.url)

    # 災害一覧 (MgrVnSearchCalamity.do, actionEvent=init)
    base = _form_with(menu.text, "menuKbn", "sessionId")
    lst = _anpi_post(
        session,
        "/eanpi/disaster/MgrVnSearchCalamity.do",
        {**base, "actionEvent": "init"},
        menu.url,
    )

    # 同時アクセス制限が出たら自分のユーザーを切断して再取得
    if "管理者アクセス一覧" in lst.text or "同時アクセス" in lst.text:
        md = re.search(
            r"goSubmit\('del','(" + re.escape(my_user_id) + r")','([^']+)'\)",
            lst.text,
        ) or re.search(r"goSubmit\('del','([^']+)','([^']+)'\)", lst.text)
        if md:
            f = dict(parse_forms(lst.text)[0].fields)
            f.update(
                actionEvent="del",
                userNo=md.group(1),
                sessionId=md.group(2),
                subMenuKbn="01",
            )
            after = _anpi_post(session, "/eanpi/disaster/AcsMgrList.do", f, lst.url)
            lst = _anpi_post(
                session,
                "/eanpi/disaster/MgrVnSearchCalamity.do",
                {**_form_with(after.text, "menuKbn"), "actionEvent": "init"},
                after.url,
            )
    return lst


def find_disaster_index(list_html: str, name: str) -> tuple[str, str] | None:
    """災害一覧 HTML から名称にマッチする行の (selectIndex, saigaiCd) を返す."""
    # saigaiList[N].saigaiNm と saigaiCd の対応を作る
    nm = {
        int(m.group(1)): m.group(2)
        for m in re.finditer(
            r'name="saigaiList\[(\d+)\]\.saigaiNm" value="([^"]*)"', list_html
        )
    }
    cd = {
        int(m.group(1)): m.group(2)
        for m in re.finditer(
            r'name="saigaiList\[(\d+)\]\.saigaiCd" value="([^"]*)"', list_html
        )
    }
    for idx, title in nm.items():
        if name in title:
            return str(idx), cd.get(idx, "")
    return None


def open_safety_summary(
    session: requests.Session, list_resp: requests.Response, select_index: str
) -> requests.Response:
    """安否状況集計 (MgrVnConfirmSafetyList.do) を開く.

    一覧の『安否状況集計』リンク = goSubmit('confirm', index) 相当。
    """
    form = parse_forms(list_resp.text)[0]
    return _anpi_post(
        session,
        "/eanpi/disaster/MgrVnConfirmSafetyList.do",
        {**form.fields, "actionEvent": "init", "selectIndex": select_index},
        list_resp.url,
    )


def open_target_user_list(
    session: requests.Session, summary_resp: requests.Response
) -> requests.Response:
    """安否状況集計の『対象者数』リンクを開き、対象者一覧を取得する.

    対象者数リンク = usrSearch('usrList', 1, 'YYYYYY', '06', '', '02') 相当。
    """
    f = dict(parse_forms(summary_resp.text)[0].fields)
    f.update(
        actionEvent="usrList",
        backPage="usrList",
        answrKbn="06",
        outoJykyCd="",
        layer="1",
        orgAreaCdUsrList="YYYYYY",
        skeiKisoKbn="02",
    )
    return _anpi_post(
        session, "/eanpi/disaster/MgrConfirmSafetyDetail.do", f, summary_resp.url
    )


class _TableParser(HTMLParser):
    """HTML テーブルを行×セルの二次元リストへ変換する."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        tl = tag.lower()
        if tl == "table":
            self._table = []
            self.tables.append(self._table)
        elif tl == "tr" and self._table is not None:
            self._row = []
            self._table.append(self._row)
        elif tl in ("td", "th") and self._row is not None:
            self._cell = []
        elif tl == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag):
        tl = tag.lower()
        if tl in ("td", "th") and self._cell is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def _decode_cell_bytes(b: bytes) -> str:
    """セルの生バイトを、UTF-8 優先・cp932 フォールバックでデコードする."""
    b = re.sub(rb"<[^>]*>", b" ", b)
    b = re.sub(rb"&nbsp;", b" ", b, flags=re.I)
    b = b.strip()
    for enc in ("utf-8", "cp932"):
        try:
            return re.sub(r"\s+", " ", b.decode(enc)).strip()
        except UnicodeDecodeError:
            continue
    return re.sub(r"\s+", " ", b.decode("cp932", "replace")).strip()


# 対象者一覧の正規のヘッダ (サーバが一部カラム名のバイトを壊して送るため、
# 文字化けが検出された場合はこの正規名で補正する)
TARGET_LIST_CANONICAL_HEADER = [
    "No",
    "利用者名",
    "ユーザーID",
    "役職",
    "本人の安否",
    "出社可否",
    "家族の安否",
    "家屋の状況",
    "安否代行",
    "返答日時",
    "応答区分",
    "コメント",
    "登録者",
    "音声",
]


def _looks_mojibake(text: str) -> bool:
    """cp932 で誤デコードされた UTF-8 (文字化け) らしさを判定する.

    cp932 に落ちた UTF-8 は、半角カナや特定の珍しい漢字 (螳/縺/繧/蜿/譌/蜃 等)、
    および欠落を示す '?' が CJK 文字に混在する特徴を持つ。
    """
    if "\ufffd" in text:
        return True
    # cp932-misdecoded-UTF8 で頻出する字
    if re.search(r"[\uff61-\uff9f]", text) and re.search(r"[\u3040-\u9fff]", text):
        return True
    if re.search(r"[螳縺繧蜿譌蜃螻迥諷牙凄遉]", text):
        return True
    # CJK の直後/直前に素の '?' がある (バイト欠落)
    if re.search(r"[\u3040-\u9fff]\?|\?[\u3040-\u9fff]", text):
        return True
    return False


def extract_target_user_rows(detail_bytes: bytes) -> list[list[str]]:
    """対象者一覧 (生バイト) から、ヘッダ+データ行の表を抽出する.

    ページは Shift_JIS(cp932) だが一部セルが UTF-8 で出力されており、さらに
    一部カラム名はサーバ側でバイトが壊れている。各セルを UTF-8 優先でデコード
    し、ヘッダに文字化けが残る場合は正規のカラム名で補正する。
    """
    # テーブル領域を生バイトのまま行×セルに分解
    table_matches = re.findall(rb"<table[^>]*>(.*?)</table>", detail_bytes, re.S | re.I)
    for tbody in table_matches:
        rows_bytes = re.findall(rb"<tr[^>]*>(.*?)</tr>", tbody, re.S | re.I)
        parsed: list[list[str]] = []
        for rb in rows_bytes:
            cells = re.findall(rb"<t[hd][^>]*>(.*?)</t[hd]>", rb, re.S | re.I)
            parsed.append([_decode_cell_bytes(c) for c in cells])
        header_text = " ".join(" ".join(r) for r in parsed[:2])
        if "利用者名" in header_text and "ユーザー" in header_text:
            rows = [r for r in parsed if any(c for c in r)]
            if not rows:
                return []
            # ヘッダ補正: 文字化けが残っていて列数が一致するなら正規名に置換
            header = rows[0]
            if (
                len(header) == len(TARGET_LIST_CANONICAL_HEADER)
                and any(_looks_mojibake(c) for c in header)
            ):
                rows[0] = list(TARGET_LIST_CANONICAL_HEADER)
            return rows
    return []


def write_csv(rows: list[list[str]], path: str | os.PathLike[str]) -> None:
    """二次元リストを UTF-8 (BOM 付き) の CSV として書き出す.

    BOM 付きにすることで Excel でも文字化けせず開ける。
    """
    import csv

    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerows(rows)


def main() -> None:
    env_path = os.environ.get("ENV_FILE", ".env")
    env = load_env(env_path)

    # 取得対象 (必要に応じて環境変数で上書き可能)
    drill_name = os.environ.get("DRILL_NAME", "【訓練】東日本エリア上期2回目")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    resp = login(session, env)
    print(f"[3] ページタイトル: {extract_title(resp.text)}")
    if not is_logged_in(resp):
        print("[NG] ログインに失敗しました。")
        err = extract_error(resp.text)
        if err:
            print(f"     サーバメッセージ: {err}")
        Path("login_failed_page.html").write_text(resp.text, encoding="utf-8")
        sys.exit(1)
    print("[OK] ログインに成功しました。")

    # 安否確認サービスを開く
    services = extract_services(resp.text)
    target = next(
        (s for s in services if "安否確認" in s["name"] or "安心確認" in s["name"]),
        None,
    ) or next((s for s in services if s["srvcCd"] == "S20"), None)
    if target is None:
        print("[NG] 安否確認サービスが見つかりませんでした。")
        sys.exit(1)
    svc = open_service(session, resp, target["srvcCd"], target["contractCode"])
    print(f"[4] サービスを開きました: {extract_title(svc.text)} ({svc.url})")

    # 災害・訓練一覧 (管理者)
    lst = enter_mgr_disaster_list(session, svc, env["E_LOGIN"])
    print(f"[5] 災害・訓練一覧を取得 ({len(lst.text)} 文字)")

    # 目的の訓練を検索
    found = find_disaster_index(lst.text, drill_name)
    if found is None:
        print(f"[NG] 訓練『{drill_name}』が一覧に見つかりませんでした。")
        sys.exit(1)
    select_index, saigai_cd = found
    print(f"[6] 対象の訓練を発見: {drill_name} "
          f"(selectIndex={select_index}, saigaiCd={saigai_cd})")

    # 安否状況集計を開く
    summary = open_safety_summary(session, lst, select_index)
    print(f"[7] 安否状況集計を開きました ({extract_title(summary.text)})")

    # 対象者数リンク → 対象者一覧
    detail = open_target_user_list(session, summary)
    rows = extract_target_user_rows(detail.content)
    if not rows:
        print("[NG] 対象者一覧の表を抽出できませんでした。")
        Path("detail_list.html").write_text(detail.text, encoding="utf-8")
        sys.exit(1)
    header, *data = rows
    print(f"[8] 対象者一覧を取得: {len(data)} 名")

    # CSV 出力
    csv_path = Path(f"安否状況_対象者リスト_{saigai_cd or 'list'}.csv")
    write_csv(rows, csv_path)
    print(f"[9] CSV を保存しました: {csv_path} (ヘッダ + {len(data)} 行)")
    # 画面確認用に数件表示
    for r in data[:5]:
        print("      ", " | ".join(r[:4]))


if __name__ == "__main__":
    main()

