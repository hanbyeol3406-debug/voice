# -*- coding: utf-8 -*-
"""
사기문자 1초 판독 & 응급수습 앱 — 〈누르지마유〉
- 단순 스미싱 확률 표시가 아니라:
  1) 문자 속 가짜 전화번호·악성 링크를 자동 마스킹(클릭 원천 차단)
  2) 사칭된 기관(금산군청·농협·건보공단·택배사·엠세이퍼 등)의 '검증된 진짜 공식 대표번호'로 원터치 전화 연결
  3) 지인·부고장·자녀 사칭 링크의 실제 도메인 정체 해부 + 한국어 음성(TTS) 큰 소리 경고
  4) 실수로 이미 링크를 눌렀을 때 당황하지 않고 따라 하는 '1분 응급 수습 모드'
- 외부 유료 API 키 불필요 · 단일 화면 · 모바일 엄지 터치 최적화
"""

import html
import json
import re
from urllib.parse import urlparse

import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="누르지마유 · 사기문자 판독 & 진짜번호 연결",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)


def _supports_width_stretch() -> bool:
    try:
        parts = [int(p) for p in st.__version__.split(".")[:2] if p.isdigit()]
        return tuple(parts) >= (1, 45)
    except Exception:
        return False


STRETCH_KW = {"width": "stretch"} if _supports_width_stretch() else {"use_container_width": True}


# =============================================================================
# 공식 검증된 실제 대표번호 데이터베이스 (웹 공식 안내 기준 검증 완료)
# =============================================================================

OFFICIAL_AGENCIES = {
    "geumsan": {
        "name": "금산군청 대표민원실",
        "tel": "041-750-2114",
        "sub_tel": "041-750-2324 (민원지적과)",
        "domain_Display": "geumsan.go.kr",
        "official_domains": ("geumsan.go.kr", "korea.kr", "gov.kr", "wetax.go.kr"),
        "keywords": ("금산군", "금산군청", "금산읍", "과태료", "쓰레기", "투기", "민원", "지방세", "지원금", "보건소", "진산면", "복수면"),
        "guide": "군청·면사무소는 절대 개인 휴대폰 번호나 단축 인터넷 주소로 과태료 납부·환급 링크를 보내지 않습니다.",
    },
    "nonghyup": {
        "name": "NH농협 (농축협 · 농협은행 · 농협카드)",
        "tel": "1661-2100",
        "sub_tel": "농협은행 1661-3000 / NH농협카드 분실·사기 24시간 1644-4000",
        "domain_Display": "nonghyup.com",
        "official_domains": ("nonghyup.com", "nhbank.com"),
        "keywords": ("농협", "NH", "축협", "해외결제", "승인", "카드", "자동이체", "계좌", "저금리", "대환대출", "한도"),
        "guide": "결제 문자의 전화번호로 절대 전화하지 마세요! 위 공식 고객센터(1661-2100 또는 1644-4000)로 직접 걸어 확인하세요.",
    },
    "nhis": {
        "name": "국민건강보험공단 공식 고객센터",
        "tel": "1577-1000",
        "sub_tel": "국민연금 1355",
        "domain_Display": "nhis.or.kr",
        "official_domains": ("nhis.or.kr", "nps.or.kr", "hira.or.kr"),
        "keywords": ("건강보험", "건강검진", "건보", "보험료", "환급금", "장기요양", "진료비", "국민연금"),
        "guide": "건강검진 결과통보서나 미수령 환급금 문자의 인터넷 주소로 앱 설치나 신분증 입력을 요구하면 100% 사기입니다.",
    },
    "delivery": {
        "name": "우체국 · CJ대한통운 공식 고객센터",
        "tel": "1588-1300",
        "sub_tel": "우체국 1588-1300 / CJ대한통운 1588-1255",
        "domain_Display": "epost.go.kr / cjlogistics.com",
        "official_domains": ("epost.go.kr", "koreapost.go.kr", "cjlogistics.com", "hanjin.com", "logen.co.kr"),
        "keywords": ("택배", "우체국", "대한통운", "CJ", "주소지", "미배달", "반송", "통관", "운송장", "배송", "소포"),
        "guide": "주소 불명·보관 장소 확인이라며 인터넷 주소를 누르게 하는 택배 문자는 대표적인 악성앱 설치 수법입니다.",
    },
    "msafer": {
        "name": "엠세이퍼(명의도용방지) 공식 센터",
        "tel": "1670-1382",
        "sub_tel": "경찰청·금융감독원 통합신고 112",
        "domain_Display": "msafer.or.kr",
        "official_domains": ("msafer.or.kr",),
        "keywords": ("엠세이퍼", "개통완료", "알뜰폰", "유심", "명의도용", "휴대폰 개통"),
        "guide": "최근 '휴대폰 개통완료 [엠세이퍼] msafer-kr.com' 식의 가짜 도메인 사칭 문자가 급증하고 있습니다. 공식 주소는 msafer.or.kr 뿐입니다.",
    },
    "family_obit": {
        "name": "지인 · 가족 본인에게 직접 확인 (경찰청 112)",
        "tel": "112",
        "sub_tel": "피싱 피해 상담 112 / 금융감독원 1332",
        "domain_Display": "저장된 연락처로 직접 통화 필수",
        "official_domains": (),
        "keywords": ("부고", "별세", "장례식장", "발인", "빈소", "청첩장", "결혼식", "엄마", "아빠", "액정", "수리", "보험", "폰이 고장"),
        "guide": "모바일 부고장·청첩장 링크나 '폰 액정이 깨졌다'는 문자면 절대 링크를 누르지 마시고, 휴대폰에 원래 저장된 번호로 직접 전화해 확인하세요!",
    },
    "police": {
        "name": "경찰청 · 검찰 · 금감원 사칭 주의 (공식 신고 112)",
        "tel": "112",
        "sub_tel": "금융감독원 콜센터 1332",
        "domain_Display": "police.go.kr / fss.or.kr",
        "official_domains": ("police.go.kr", "spo.go.kr", "fss.or.kr", "scourt.go.kr", "efine.go.kr"),
        "keywords": ("검찰", "경찰", "금융감독원", "금감원", "대포통장", "사건번호", "출석요구서", "등기", "법원"),
        "guide": "경찰·검찰·금융감독원은 절대 문자로 사건 서류 링크를 보내거나 안전계좌 이체·현금 전달을 요구하지 않습니다.",
    },
}

# 한 번의 터치로 바로 테스트·비교할 수 있는 실제 빈발 사례 5종
SAMPLE_MESSAGES = [
    {
        "label": "🖤 부고장 사기",
        "text": "[Web발신]\n삼가 고인의 명복을 빕니다.\n부친께서 금일 별세하셨기에 부고 알림 드립니다.\n빈소 확인: https://bugo-info.top/8821",
    },
    {
        "label": "🏛️ 군청 과태료 사기",
        "text": "[국외발신]\n[금산군청] 쓰레기 무단투기 단속 적발 과태료 고지서가 발부되었습니다.\n내역 확인: https://url.kr/gs991\n문의: 02-6955-0000",
    },
    {
        "label": "💳 농협 결제 사기",
        "text": "[Web발신]\n[NH농협] 본인인증 해외직구 895,000원 정상승인 완료.\n본인이 아닐 시 즉시 신고바랍니다.\n고객센터: 070-7890-1234",
    },
    {
        "label": "📱 자녀 폰고장 사기",
        "text": "엄마 나 폰 액정 깨져서 수리 맡겼어ㅠㅠ 임시폰이라 통화는 안되고 급하게 휴대폰 보험 처리해야 하는데 신분증 사진이랑 농협 카드번호만 먼저 찍어줄 수 있어? https://bit.ly/fix-phone1",
    },
    {
        "label": "✅ 정상 안내 예시",
        "text": "[금산군청] 오늘 오후 강풍 및 기온 하강이 예보되어 있으니 시설물 관리와 건강관리에 유의하시기 바랍니다. 문의 금산군청 041-750-2114 https://www.geumsan.go.kr",
    },
]

SHORTENER_DOMAINS = {
    "bit.ly", "url.kr", "me2.do", "han.gl", "tinyurl.com", "t.co", "vo.la",
    "gg.gg", "is.gd", "rebrand.ly", "cutt.ly", "shorturl.at", "buly.kr",
}

SUSPICIOUS_TLDS = (
    ".top", ".xyz", ".shop", ".club", ".online", ".site", ".icu", ".vip",
    ".work", ".click", ".link", ".live", ".cn", ".ru", ".buzz", ".rest",
)

TRUSTED_ROOT_DOMAINS = (
    ".go.kr", ".or.kr", "gov.kr", "korea.kr",
    "nonghyup.com", "nhbank.com", "kbstar.com", "shinhan.com", "wooribank.com", "hanabank.com",
    "epost.go.kr", "cjlogistics.com", "naver.com", "kakao.com",
)

URL_REGEX = re.compile(
    r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

PHONE_REGEX = re.compile(
    r"(?<!\d)(?:01[016789]-\d{3,4}-\d{4}|0[2-6][1-5]?-\d{3,4}-\d{4}|070-\d{3,4}-\d{4}|1[568]\d{2}-\d{4})(?!\d)"
)


def extract_host(raw_url: str) -> str:
    target = raw_url if raw_url.lower().startswith(("http://", "https://")) else f"http://{raw_url}"
    try:
        host = (urlparse(target).hostname or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return raw_url.lower()


def is_trusted_domain(host: str) -> bool:
    if not host:
        return False
    for td in TRUSTED_ROOT_DOMAINS:
        if td.startswith("."):
            if host.endswith(td):
                return True
        else:
            if host == td or host.endswith("." + td):
                return True
    return False


def detect_agency_key(text: str) -> str:
    """문자 내용에서 사칭·언급된 기관을 찾아 실제 공식 번호 레코드 매칭"""
    best_key = None
    best_hits = 0
    for key, info in OFFICIAL_AGENCIES.items():
        hits = sum(1 for kw in info["keywords"] if kw in text)
        if hits > best_hits:
            best_hits = hits
            best_key = key
    return best_key if best_key else "police"


def analyze_message(raw_text: str) -> dict:
    """
    규칙·도메인·번호 대조 기반 정직한 분석 엔진
    - 아는 척 확률(예: 87.3%)을 지어내지 않고, 발견된 구체적 위험 근거만 명확히 제시
    """
    text = raw_text.strip()
    reasons_danger = []
    reasons_caution = []
    reasons_safe = []

    urls = URL_REGEX.findall(text)
    phones = PHONE_REGEX.findall(text)
    agency_key = detect_agency_key(text)
    agency = OFFICIAL_AGENCIES[agency_key]

    # 1) 발신 표기 점검
    if any(tag in text for tag in ("[국제발신]", "[국외발신]", "국제발신", "국외발신")):
        reasons_danger.append("해외에서 보낸 문자(`[국외/국제발신]`)입니다. 한국 관공서·은행·택배사는 해외 번호로 문자를 보내지 않습니다.")

    # 2) URL 도메인 정밀 해부
    inspected_urls = []
    for u in urls:
        host = extract_host(u)
        if not host:
            continue
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
        is_short = host in SHORTENER_DOMAINS
        is_bad_tld = host.endswith(SUSPICIOUS_TLDS)
        is_apk = ".apk" in u.lower()
        trusted = is_trusted_domain(host)

        # 기관 사칭 도메인 여부 (예: msafer-kr.com, nh-bank.top)
        impersonated_domain = (
            agency["official_domains"]
            and not any(host == d or host.endswith("." + d) for d in agency["official_domains"])
            and not trusted
        )

        status = "safe" if trusted else "caution"
        note = "정부·공공·공식 도메인 형식" if trusted else "공식 홈페이지 주소와 다름 (절대 클릭 금지)"

        if is_apk:
            status = "danger"
            note = "악성 앱(.apk) 직접 설치 주소"
            reasons_danger.append(f"휴대폰을 원격 조종하는 **악성 앱 설치 주소(`{u}`)**가 들어 있습니다.")
        elif is_ip:
            status = "danger"
            note = "정체를 숨긴 숫자(IP) 주소"
            reasons_danger.append(f"정상 홈페이지가 아닌 **숫자 IP 주소(`{host}`)**로 연결됩니다.")
        elif is_short:
            status = "danger"
            note = "실제 주소를 숨긴 단축 URL"
            reasons_danger.append(f"진짜 목적지를 숨긴 **단축 인터넷 주소(`{host}`)**가 쓰였습니다.")
        elif is_bad_tld:
            status = "danger"
            note = f"사기 문자에 자주 쓰이는 해외 도메인({host})"
            reasons_danger.append(f"스미싱에 집중 악용되는 **위험 도메인(`{host}`)** 주소입니다.")
        elif impersonated_domain:
            status = "danger"
            note = f"공식 주소({agency['domain_Display']})가 아닌 외부 주소"
            reasons_danger.append(
                f"**{agency['name']}** 공식 주소(`{agency['domain_Display']}`)가 아닌 낯선 주소(`{host}`)가 적혀 있습니다."
            )
        elif trusted:
            reasons_safe.append(f"인터넷 주소(`{host}`)가 공식 기관·포털 도메인 형식과 일치합니다.")
        else:
            reasons_caution.append(f"인터넷 주소(`{host}`)가 포함되어 있으니 출처가 확실하지 않으면 누르지 마세요.")

        inspected_urls.append({"raw": u, "host": host, "status": status, "note": note})

    # 3) 전형적인 피싱 요구 수법 점검
    if any(k in text for k in ("신분증", "주민등록", "계좌번호", "카드번호", "비밀번호", "보안카드", "인증번호", "원격", "팀뷰어", "애니데스크", "상품권", "핀번호")):
        reasons_danger.append("문자로 **신분증 사진·카드번호·비밀번호·원격제어·상품권**을 요구하는 것은 100% 금융사기입니다.")

    if any(k in text for k in ("액정", "수리 맡겼", "임시폰", "폰이 고장")) and any(k in text for k in ("엄마", "아빠", "보험", "결제", "카드", "신분증")):
        reasons_danger.append("전형적인 **자녀 사칭('폰 액정 파손·수리')** 메신저 피싱 수법입니다.")

    if any(k in text for k in ("부고", "별세", "빈소", "발인", "장례식", "청첩장", "결혼식")) and urls:
        if not all(item["status"] == "safe" for item in inspected_urls):
            reasons_danger.append("**부고장·청첩장 인터넷 주소**를 눌러 악성 앱을 깔게 하는 대표적 지인 사칭 수법입니다.")

    if any(k in text for k in ("해외결제", "승인완료", "정상승인", "본인이 아닐", "소비자보호원", "통관보류", "과태료", "무단투기")) and (phones or urls):
        # 문자 속 전화번호가 공식 대표번호와 일치하는지 대조
        official_digits = re.sub(r"\D", "", agency["tel"])
        sub_digits_all = re.sub(r"\D", " ", agency["sub_tel"])
        has_unverified_phone = False
        for ph in phones:
            ph_digits = re.sub(r"\D", "", ph)
            if ph_digits != official_digits and ph_digits not in sub_digits_all:
                has_unverified_phone = True
                if ph.startswith("070-") or ph.startswith("010-") or ph.startswith("02-"):
                    reasons_danger.append(
                        f"결제·과태료 문자 안에 공식 대표번호(`{agency['tel']}`)가 아닌 **의심스러운 전화번호(`{ph}`)**가 적혀 있습니다. 이 번호로 전화하면 사기범에게 연결됩니다!"
                    )
                else:
                    reasons_caution.append(
                        f"문자 속 전화번호(`{ph}`)가 공식 대표번호(`{agency['tel']}`)와 다릅니다. 문자 속 번호 대신 아래 공식 번호로 확인하세요."
                    )
        if not phones and not inspected_urls:
            reasons_caution.append("결제·과태료 관련 내용이 있으니 반드시 공식 고객센터로 직접 사실 여부를 확인하세요.")
        elif not has_unverified_phone and phones and not reasons_danger:
            reasons_safe.append(f"문자에 적힌 전화번호가 공식 대표번호(`{agency['tel']}`)와 일치합니다.")

    # 4) 최종 등급 판정 (거짓 퍼센트 없이 3단계 신호등)
    if reasons_danger:
        level = "danger"
        badge = "🚨 매우 위험 · 사기 문자 의심!"
        headline = "절대 파란 글씨(링크)나 문자 속 번호를 누르지 마세요!"
        tts = (
            f"경고합니다! 사기 문자로 강력히 의심됩니다. "
            f"문자 안의 인터넷 주소나 전화번호를 절대 누르지 마세요. "
            f"{reasons_danger[0]} "
            f"확인이 필요하시면 화면 아래의 진짜 공식 대표번호 버튼을 눌러 확인하세요."
        )
    elif reasons_caution or (urls and not reasons_safe):
        level = "caution"
        badge = "⚠️ 주의 · 직접 확인 필요"
        headline = "링크를 누르기 전에 진짜 기관·지인에게 먼저 전화해 확인하세요."
        tts = (
            f"주의가 필요한 문자입니다. 문자 안의 인터넷 주소를 바로 누르지 마시고, "
            f"화면 아래의 공식 대표번호나 원래 저장된 지인 연락처로 먼저 전화해 확인하세요."
        )
    else:
        level = "safe"
        badge = "🟢 위험 요소 발견 안 됨 (공식 번호 대조 권장)"
        headline = "뚜렷한 스미싱 함정은 없으나, 금전 요구 시엔 반드시 통화로 확인하세요."
        tts = (
            f"문자에서 뚜렷한 악성 주소나 사기 패턴은 발견되지 않았습니다. "
            f"다만 돈을 보내라거나 개인정보를 묻는다면 반드시 공식 번호로 직접 전화해 확인하세요."
        )

    # 5) 안전한 마스킹 본문 생성 (어르신이 실수로 누르지 못하도록 링크·가짜번호 무력화)
    safe_body = html.escape(text)
    for item in inspected_urls:
        escaped_u = html.escape(item["raw"])
        if item["status"] == "safe":
            rep = f"<span class='mask-safe'>✅ {escaped_u}</span>"
        else:
            rep = f"<span class='mask-danger'>🚫 [위험 링크 차단됨: {html.escape(item['host'])}]</span>"
        safe_body = safe_body.replace(escaped_u, rep)

    official_digits = re.sub(r"\D", "", agency["tel"])
    for ph in set(phones):
        ph_digits = re.sub(r"\D", "", ph)
        escaped_ph = html.escape(ph)
        if ph_digits == official_digits or ph_digits in re.sub(r"\D", " ", agency["sub_tel"]):
            safe_body = safe_body.replace(escaped_ph, f"<span class='mask-safe'>📞 {escaped_ph}(공식번호 일치)</span>")
        else:
            safe_body = safe_body.replace(
                escaped_ph,
                f"<span class='mask-danger'>🚫 [미검증 번호 통화금지: {escaped_ph}]</span>",
            )

    return {
        "level": level,
        "badge": badge,
        "headline": headline,
        "reasons_danger": reasons_danger,
        "reasons_caution": reasons_caution,
        "reasons_safe": reasons_safe,
        "inspected_urls": inspected_urls,
        "phones": phones,
        "agency": agency,
        "safe_body_html": safe_body.replace("\n", "<br>"),
        "tts": tts,
    }


def _embed_html(html_code: str, height: int) -> None:
    if hasattr(st, "iframe"):
        st.iframe(html_code, height=height)
    else:
        components.html(html_code, height=height, scrolling=False)


def render_tts_bar(tts_text: str, is_danger: bool) -> None:
    """어르신용 큰 소리 음성 경고 버튼"""
    safe_json = json.dumps(tts_text, ensure_ascii=False)
    btn_bg = "#DC2626" if is_danger else "#1D4ED8"
    code = f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; font-family: 'Pretendard', 'Malgun Gothic', sans-serif; }}
  body {{ margin: 0; padding: 0; background: transparent; }}
  .wrap {{ display: flex; gap: 8px; align-items: center; }}
  .play {{
    flex: 1; background: {btn_bg}; color: #fff; border: none; border-radius: 12px;
    padding: 12px 16px; font-size: 1rem; font-weight: 800; cursor: pointer;
  }}
  .stop {{
    background: #F1F5F9; color: #334155; border: 1.5px solid #CBD5E1; border-radius: 12px;
    padding: 12px 14px; font-size: 0.95rem; font-weight: 700; cursor: pointer;
  }}
</style></head>
<body>
  <div class="wrap">
    <button class="play" id="pBtn" onclick="speakNow()">🔊 판독 결과 큰 소리로 듣기</button>
    <button class="stop" onclick="stopNow()">⏹️ 멈춤</button>
  </div>
  <script>
    const txt = {safe_json};
    function speakNow() {{
      if (!('speechSynthesis' in window)) {{
        alert('이 브라우저에서는 음성 안내를 지원하지 않습니다.');
        return;
      }}
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(txt);
      u.lang = 'ko-KR';
      u.rate = 0.90;
      const b = document.getElementById('pBtn');
      u.onstart = () => {{ b.innerText = '🔊 음성으로 읽어드리는 중...'; }};
      u.onend = () => {{ b.innerText = '🔊 판독 결과 큰 소리로 듣기'; }};
      u.onerror = () => {{ b.innerText = '🔊 판독 결과 큰 소리로 듣기'; }};
      window.speechSynthesis.speak(u);
    }}
    function stopNow() {{
      if ('speechSynthesis' in window) window.speechSynthesis.cancel();
      document.getElementById('pBtn').innerText = '🔊 판독 결과 큰 소리로 듣기';
    }}
  </script>
</body></html>"""
    _embed_html(code, height=54)


# =============================================================================
# 세션 상태 관리
# =============================================================================

if "mode" not in st.session_state:
    st.session_state.mode = "check"  # 'check' | 'emergency'
if "msg_input" not in st.session_state:
    st.session_state.msg_input = SAMPLE_MESSAGES[1]["text"]
if "large_font" not in st.session_state:
    st.session_state.large_font = False


def switch_mode(m: str) -> None:
    st.session_state.mode = m


def load_sample(txt: str) -> None:
    st.session_state.mode = "check"
    st.session_state.msg_input = txt


def clear_message() -> None:
    st.session_state.msg_input = ""


# =============================================================================
# 모바일 엄지 터치 & 고대비 깔끔 디자인 (사이드바 없음 · 단일 화면)
# =============================================================================

font_scale = "1.12rem" if st.session_state.large_font else "1.0rem"

st.markdown(
    f"""
<style>
  [data-testid="stSidebar"], [data-testid="collapsedControl"] {{
      display: none !important;
  }}
  html, body, [class*="css"] {{
      font-size: {font_scale};
      font-family: 'Pretendard', 'Noto Sans KR', 'Malgun Gothic', sans-serif;
  }}
  .block-container {{
      padding-top: 1.3rem !important;
      padding-bottom: 3rem !important;
      max-width: 740px !important;
  }}
  div.stButton > button {{
      min-height: 50px !important;
      border-radius: 14px !important;
      font-weight: 800 !important;
      font-size: 0.97rem !important;
      padding: 0.5rem 0.9rem !important;
  }}
  div.stButton > button[kind="secondary"] {{
      background: #FFFFFF !important;
      border: 1.5px solid #CBD5E1 !important;
      color: #1E293B !important;
  }}
  div.stButton > button[kind="secondary"]:hover {{
      border-color: #2563EB !important;
      color: #2563EB !important;
      background: #EFF6FF !important;
  }}
  @media (max-width: 640px) {{
      div[data-testid="stHorizontalBlock"] {{
          display: flex !important;
          flex-direction: row !important;
          flex-wrap: wrap !important;
          gap: 8px !important;
      }}
      div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {{
          flex: 1 1 calc(50% - 8px) !important;
          min-width: 138px !important;
      }}
  }}
  .title-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
  }}
  .app-title {{
      font-size: 1.45rem;
      font-weight: 900;
      color: #0F172A;
      letter-spacing: -0.02em;
  }}
  .result-danger {{
      background: #FEF2F2;
      border: 2.5px solid #DC2626;
      border-radius: 20px;
      padding: 20px 22px;
      margin: 10px 0;
  }}
  .result-caution {{
      background: #FFFBEB;
      border: 2.5px solid #D97706;
      border-radius: 20px;
      padding: 20px 22px;
      margin: 10px 0;
  }}
  .result-safe {{
      background: #F0FDF4;
      border: 2px solid #16A34A;
      border-radius: 20px;
      padding: 20px 22px;
      margin: 10px 0;
  }}
  .mask-box {{
      background: #FFFFFF;
      border: 1.5px solid #E2E8F0;
      border-radius: 14px;
      padding: 14px 16px;
      margin-top: 12px;
      line-height: 1.7;
      font-size: 0.96rem;
      color: #1E293B;
  }}
  .mask-danger {{
      background: #FEE2E2;
      color: #B91C1C;
      font-weight: 900;
      padding: 2px 8px;
      border-radius: 6px;
      text-decoration: line-through;
  }}
  .mask-safe {{
      background: #DCFCE7;
      color: #166534;
      font-weight: 800;
      padding: 2px 8px;
      border-radius: 6px;
  }}
  .call-card {{
      background: #FFFFFF;
      border: 2px solid #2563EB;
      border-radius: 18px;
      padding: 18px 20px;
      margin: 12px 0;
      box-shadow: 0 4px 16px rgba(37, 99, 235, 0.08);
  }}
  .call-btn-link {{
      display: block;
      text-align: center;
      background: #2563EB;
      color: #FFFFFF !important;
      text-decoration: none !important;
      font-weight: 900;
      font-size: 1.12rem;
      padding: 14px 18px;
      border-radius: 14px;
      margin-top: 12px;
  }}
  .call-btn-red {{
      display: block;
      text-align: center;
      background: #DC2626;
      color: #FFFFFF !important;
      text-decoration: none !important;
      font-weight: 900;
      font-size: 1.12rem;
      padding: 14px 18px;
      border-radius: 14px;
      margin-top: 10px;
  }}
  .step-card {{
      background: #FFFFFF;
      border: 1.5px solid #FCA5A5;
      border-left: 6px solid #DC2626;
      border-radius: 16px;
      padding: 16px 18px;
      margin-bottom: 12px;
  }}
</style>
""",
    unsafe_allow_html=True,
)

# =============================================================================
# 상단 헤더 & 2개 핵심 모드 스위치
# =============================================================================

hc1, hc2 = st.columns([3.4, 1.3])
with hc1:
    st.markdown(
        """
<div class="title-bar">
  <div class="app-title">🛡️ 누르지마유 <span style="font-size:0.95rem; font-weight:700; color:#64748B;">· 수상한 문자 1초 판독기</span></div>
</div>
""",
        unsafe_allow_html=True,
    )
with hc2:
    st.session_state.large_font = st.toggle("🔍 큰 글씨", value=st.session_state.large_font)

top1, top2 = st.columns(2)
with top1:
    st.button(
        "🔍 문자 판독 · 진짜번호 확인",
        key="tab_check",
        type="primary" if st.session_state.mode == "check" else "secondary",
        on_click=switch_mode,
        args=("check",),
        **STRETCH_KW,
    )
with top2:
    st.button(
        "😱 이미 링크를 눌렀어요! (응급수습)",
        key="tab_emergency",
        type="primary" if st.session_state.mode == "emergency" else "secondary",
        on_click=switch_mode,
        args=("emergency",),
        **STRETCH_KW,
    )


# =============================================================================
# [화면 A] 🔍 문자 판독 · 가짜번호 차단 · 진짜 공식번호 연결
# =============================================================================
if st.session_state.mode == "check":
    st.caption("받은 문자를 아래 칸에 붙여넣거나, 자주 오는 사기 문자 예시 버튼을 눌러 확인해 보세요.")

    # 예시 원터치 버튼 (발표 시연 및 어르신 교육용)
    sc_cols = st.columns(5)
    for col_s, smp in zip(sc_cols, SAMPLE_MESSAGES):
        with col_s:
            st.button(
                smp["label"],
                key=f"smp_{smp['label']}",
                on_click=load_sample,
                args=(smp["text"],),
                **STRETCH_KW,
            )

    msg_val = st.text_area(
        "📩 확인하고 싶은 문자 내용 붙여넣기",
        key="msg_input",
        height=125,
        placeholder="여기를 길게 눌러 복사한 문자를 [붙여넣기] 해주세요.",
    )

    in_b1, in_b2 = st.columns([3.2, 1.2])
    with in_b1:
        st.caption("※ 입력한 문자 내용은 서버에 저장되지 않고 내 휴대폰 화면에서만 즉시 검사됩니다.")
    with in_b2:
        st.button("🗑️ 지우기", on_click=clear_message, **STRETCH_KW)

    if msg_val.strip():
        res = analyze_message(msg_val)
        card_cls = (
            "result-danger"
            if res["level"] == "danger"
            else ("result-caution" if res["level"] == "caution" else "result-safe")
        )
        title_color = (
            "#B91C1C"
            if res["level"] == "danger"
            else ("#92400E" if res["level"] == "caution" else "#166534")
        )

        reasons_all = (
            [f"🚨 {r}" for r in res["reasons_danger"]]
            + [f"⚠️ {r}" for r in res["reasons_caution"]]
            + [f"✅ {r}" for r in res["reasons_safe"]]
        )
        reasons_html = "".join(
            f"<li style='margin-bottom:6px; font-weight:700; color:#1E293B;'>{r}</li>"
            for r in reasons_all
        )

        st.markdown(
            f"""
<div class="{card_cls}">
  <div style="font-size:1.0rem; font-weight:900; color:{title_color}; margin-bottom:4px;">
    {res['badge']}
  </div>
  <div style="font-size:1.38rem; font-weight:900; color:#0F172A; line-height:1.3; margin-bottom:12px;">
    {html.escape(res['headline'])}
  </div>
  <ul style="margin:0; padding-left:20px; line-height:1.55;">
    {reasons_html}
  </ul>
  <div class="mask-box">
    <div style="font-size:0.82rem; font-weight:800; color:#64748B; margin-bottom:4px;">
      🔒 위험 링크·미검증 번호 안전 차단 보기 (실수로 눌러도 연결되지 않습니다)
    </div>
    {res['safe_body_html']}
  </div>
</div>
""",
            unsafe_allow_html=True,
        )

        # 한국어 음성 경고 버튼
        render_tts_bar(res["tts"], is_danger=(res["level"] == "danger"))

        # 핵심 차별점: 문자 속 번호 대신 '검증된 진짜 공식 대표번호' 원터치 연결 카드
        ag = res["agency"]
        st.markdown(
            f"""
<div class="call-card">
  <div style="font-size:0.86rem; font-weight:800; color:#2563EB; margin-bottom:4px;">
    ✅ 불안하실 땐 문자 속 번호 말고, 검증된 진짜 번호로 직접 확인하세요!
  </div>
  <div style="font-size:1.18rem; font-weight:900; color:#0F172A;">
    🏛️ {html.escape(ag['name'])} : <span style="color:#1D4ED8;">{html.escape(ag['tel'])}</span>
  </div>
  <div style="font-size:0.88rem; color:#475569; margin-top:4px; font-weight:600;">
    보조 안내번호: {html.escape(ag['sub_tel'])} · 공식 홈페이지: <b>{html.escape(ag['domain_Display'])}</b>
  </div>
  <div style="font-size:0.9rem; color:#334155; background:#F8FAFC; padding:10px 12px; border-radius:10px; margin-top:8px;">
    💡 {html.escape(ag['guide'])}
  </div>
  <a class="call-btn-link" href="tel:{ag['tel']}">📞 진짜 {html.escape(ag['name'])} ({html.escape(ag['tel'])}) 전화 걸기</a>
</div>
""",
            unsafe_allow_html=True,
        )

        # 만약 링크 정체가 발견되었으면 도메인 해부 표를 깔끔하게 접기 메뉴로 제공
        if res["inspected_urls"]:
            with st.expander(f"🔎 문자 속 인터넷 주소 정체 자세히 보기 ({len(res['inspected_urls'])}개)"):
                for u_item in res["inspected_urls"]:
                    mark_icon = "🚨 위험" if u_item["status"] == "danger" else ("✅ 공식" if u_item["status"] == "safe" else "⚠️ 주의")
                    st.markdown(
                        f"- **{mark_icon}** | 실제 연결 도메인: `{u_item['host']}` — {u_item['note']}"
                    )

    else:
        st.info("👆 위 칸에 확인하고 싶은 문자를 붙여넣거나, 상단의 예시 버튼(`🖤 부고장 사기`, `🏛️ 군청 과태료 사기` 등)을 눌러보세요.")

    # 우리 동네 어르신 자주 확인하는 진짜 공식 대표번호 모음 (접기 메뉴로 평소엔 깔끔하게)
    with st.expander("📖 금산 · 금융 · 택배 '진짜 공식 전화번호부' 한눈에 보기"):
        for ag_item in OFFICIAL_AGENCIES.values():
            st.markdown(
                f"- **{ag_item['name']}** : `{ag_item['tel']}` ({ag_item['sub_tel']})"
            )


# =============================================================================
# [화면 B] 😱 이미 링크를 눌렀어요! (당황 방지 1분 응급 수습 순서도)
# =============================================================================
else:
    st.markdown(
        """
<div class="result-danger" style="margin-top:6px;">
  <div style="font-size:1.28rem; font-weight:900; color:#B91C1C; margin-bottom:4px;">
    🚨 당황하지 마세요! 지금 아래 1 ➔ 2 ➔ 3 순서대로만 하시면 막을 수 있습니다.
  </div>
  <div style="font-size:0.94rem; color:#334155; font-weight:700;">
    단순히 인터넷 창만 열렸다가 닫은 경우엔 큰 피해가 없는 경우가 많지만, <b>파일(.apk)이 설치되었거나 신분증·비밀번호를 입력했다면</b> 즉시 아래 조치를 진행하세요.
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    render_tts_bar(
        "당황하지 마세요. 첫째, 휴대폰 상단 메뉴를 내려 비행기 탑승 모드를 켜서 해커의 원격 조종을 끊으세요. "
        "둘째, 다른 전화기로 112에 전화해 계좌 일괄 지급정지를 요청하세요. "
        "셋째, 엠세이퍼에서 내 명의로 몰래 개통된 휴대폰이 없는지 차단하세요.",
        is_danger=True,
    )

    st.markdown(
        """
<div class="step-card">
  <div style="font-size:1.12rem; font-weight:900; color:#DC2626;">1단계. 지금 즉시 '비행기 모드' 켜기 (악성 앱 원격조종 차단)</div>
  <div style="font-size:0.95rem; color:#1E293B; margin-top:6px; line-height:1.6;">
    • 휴대폰 화면 맨 위를 손가락으로 쓸어내려 <b>[✈️ 비행기 탑승 모드]</b>를 켜세요. (와이파이도 함께 끄세요)<br>
    • 인터넷이 끊기면 사기범이 내 휴대폰을 원격 조종하거나 인증번호를 가로채지 못합니다.
  </div>
</div>

<div class="step-card">
  <div style="font-size:1.12rem; font-weight:900; color:#DC2626;">2단계. 가족 전화기로 112 신고 & 내 모든 계좌 일괄 지급정지</div>
  <div style="font-size:0.95rem; color:#1E293B; margin-top:6px; line-height:1.6;">
    • 감염이 의심되는 내 폰 대신 <b>가족이나 이웃의 전화기(또는 유선전화)</b>로 <b>112</b>에 전화하세요.<br>
    • <b>"스미싱 링크를 눌렀는데 계좌 일괄 지급정지 부탁드립니다"</b>라고 말하면 경찰·금융권 통합센터에서 한 번에 출금을 막아줍니다.
  </div>
  <a class="call-btn-red" href="tel:112">📞 112 통합신고 바로 전화 걸기</a>
  <a class="call-btn-link" href="tel:1644-4000" style="background:#1E293B;">📞 NH농협카드 24시간 금융사기 신고 (1644-4000)</a>
</div>

<div class="step-card">
  <div style="font-size:1.12rem; font-weight:900; color:#DC2626;">3단계. 내 명의로 몰래 알뜰폰이 개통되는 것 막기 (엠세이퍼)</div>
  <div style="font-size:0.95rem; color:#1E293B; margin-top:6px; line-height:1.6;">
    • 신분증 사진이나 개인정보를 입력했다면 사기범이 내 이름으로 몰래 휴대폰을 개통해 대출을 받을 수 있습니다.<br>
    • 과기정통부 공식 <b>엠세이퍼(명의도용방지서비스)</b>에서 <b>[가입제한 서비스]</b>를 걸어두거나 가까운 대리점·파출소를 방문하세요.
  </div>
  <a class="call-btn-link" href="https://www.msafer.or.kr" target="_blank" rel="noopener noreferrer">🔐 정부 공식 엠세이퍼(msafer.or.kr) 열기</a>
</div>
""",
        unsafe_allow_html=True,
    )
