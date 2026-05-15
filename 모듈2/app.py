import streamlit as st
import openai
import json
import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

from scanners import ssrf, bola, idor, insecure_design

load_dotenv()

# ──────────────────────────────────────────
# 페이지 기본 설정
# ──────────────────────────────────────────
st.set_page_config(
    page_title="보안 취약점 진단 시스템",
    page_icon="🔒",
    layout="wide"
)

# ──────────────────────────────────────────
# 백엔드 API 자동 탐색 함수
# ──────────────────────────────────────────
# 시도할 포트 목록 — 일반적으로 많이 쓰는 백엔드 포트 순서
CANDIDATE_PORTS = [8000, 8080, 8888, 5000, 4000, 3001, 9000, 8001, 8443, 443, 80]

def find_backend_url(input_url: str) -> tuple[str, str]:
    """
    사용자가 입력한 URL에서 실제 백엔드 API URL을 자동으로 찾습니다.
    /auth/login 에 POST 요청을 보내서 JSON 응답이 오면 백엔드로 판단합니다.

    반환값: (찾은 백엔드 URL, 상태 메시지)
    """
    parsed  = urlparse(input_url.rstrip("/"))
    scheme  = parsed.scheme or "http"
    host    = parsed.hostname

    # 입력한 포트를 가장 먼저 시도
    input_port = parsed.port
    ports = ([input_port] if input_port else []) + [p for p in CANDIDATE_PORTS if p != input_port]

    for port in ports:
        candidate = f"{scheme}://{host}:{port}"
        try:
            resp = requests.post(
                f"{candidate}/auth/login",
                json={"username": "probe", "password": "probe"},
                timeout=3
            )
            # JSON 응답이 오면 → 백엔드 API 서버
            resp.json()
            if input_port and port != input_port:
                msg = f"입력한 :{input_port}은 프론트엔드입니다. 백엔드 API :{port}를 자동으로 찾았습니다."
            else:
                msg = f"백엔드 API 확인 완료: {candidate}"
            return candidate, msg
        except (ValueError, Exception):
            # JSON 파싱 실패(HTML 응답) 또는 연결 실패 → 다음 포트 시도
            continue

    # 끝까지 못 찾으면 입력값 그대로 반환
    return input_url.rstrip("/"), "백엔드 자동 탐색 실패 — 입력한 URL로 그대로 진행합니다."


# API 키는 .env 파일에서만 읽음 (사용자에게 노출 안 함)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ──────────────────────────────────────────
# 진단 항목 목록 — 스캐너 추가 시 여기만 수정
# ──────────────────────────────────────────
SCANNERS = [
    {"key": "SSRF",           "module": ssrf,           "label": "SSRF",           "desc": "서버 측 요청 위조",          "owasp": "A10:2021"},
    {"key": "BOLA",           "module": bola,           "label": "BOLA",           "desc": "객체 수준 인가 취약점",       "owasp": "A01:2021"},
    {"key": "IDOR",           "module": idor,           "label": "IDOR",           "desc": "안전하지 않은 직접 객체 참조", "owasp": "A01:2021"},
    {"key": "Insecure Design", "module": insecure_design,"label": "Insecure Design","desc": "불안전한 설계",              "owasp": "A04:2021"},
]

# ──────────────────────────────────────────
# 심각도 표시
# ──────────────────────────────────────────
SEVERITY_MAP = {
    "CRITICAL": ("🔴", "치명적"),
    "HIGH":     ("🟠", "높음"),
    "MEDIUM":   ("🟡", "중간"),
    "LOW":      ("🟢", "낮음"),
    "INFO":     ("🔵", "정보"),
}

def severity_label(s: str) -> str:
    icon, text = SEVERITY_MAP.get(s.upper(), ("⚪", s))
    return f"{icon} {text} ({s})"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ──────────────────────────────────────────
# OpenAI 분석 함수
# ──────────────────────────────────────────
def analyze_vulnerability(client: openai.OpenAI, vuln: dict) -> dict:
    vuln_name   = vuln.get("name",          vuln.get("type",        "알 수 없음"))
    attack_desc = vuln.get("attack_method", vuln.get("description", "알 수 없음"))
    result_val  = vuln.get("result",        vuln.get("status",      "알 수 없음"))
    keywords    = vuln.get("detected_keywords", [])
    owasp       = vuln.get("owasp", "")

    prompt = f"""
당신은 사이버 보안 전문가입니다.
아래는 모의 인터넷뱅킹 사이트에 대한 침투 테스트(Penetration Test) 결과입니다.
이 취약점에 대해 한국어로 다음 세 가지를 작성해 주세요.

[취약점 정보]
- 이름: {vuln_name}
- 심각도(Severity): {vuln.get('severity', '알 수 없음')}
- OWASP 분류: {owasp if owasp else '없음'}
- 공격 엔드포인트(Endpoint): {vuln.get('endpoint', '알 수 없음')}
- 공격 방법/설명: {attack_desc}
- 사용한 페이로드(Payload): {vuln.get('payload', '없음')}
- 공격 결과/상태: {result_val}
- 탐지된 키워드: {', '.join(keywords) if keywords else '없음'}
- 증거: {vuln.get('evidence', '없음')}

아래 형식으로 JSON만 출력하세요 (설명 텍스트 없이):
{{
  "description": "취약점에 대한 기술적 설명 (3~5문장)",
  "scenario": "실제 공격자가 이 취약점을 악용하는 구체적인 시나리오 (단계별로 설명)",
  "countermeasure": "이 취약점을 방어하기 위한 대응방안 (개발자 관점에서 구체적으로)"
}}
"""
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


# ──────────────────────────────────────────
# 취약점 카드 렌더링
# ──────────────────────────────────────────
def render_vuln_card(vuln: dict, client: openai.OpenAI, index: int):
    vuln_name = vuln.get("name", vuln.get("type", f"취약점 #{index+1}"))
    severity  = vuln.get("severity", "UNKNOWN")

    vuln_id = vuln.get("id", "")
    with st.expander(
        f"**{severity_label(severity)}** &nbsp;|&nbsp; `{vuln_id}`",
        expanded=True
    ):
        st.markdown("##### 공격 결과 정보")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"- **엔드포인트(Endpoint):** `{vuln.get('endpoint', 'N/A')}`")
            attack_desc = vuln.get("attack_method", vuln.get("description", "N/A"))
            st.markdown(f"- **공격 방법:** {attack_desc}")
            if vuln.get("owasp"):
                st.markdown(f"- **OWASP 분류:** {vuln.get('owasp')}")
        with c2:
            st.markdown(f"- **페이로드(Payload):** `{vuln.get('payload', 'N/A')}`")
            result_val = vuln.get("result", vuln.get("status", "N/A"))
            st.markdown(f"- **공격 결과:** {result_val}")
            # 증거 — 길면 잘라서 코드 블록으로 표시
            evidence = str(vuln.get("evidence", "N/A"))
            if len(evidence) > 200:
                st.markdown("- **증거(Evidence):**")
                st.code(evidence[:500] + ("..." if len(evidence) > 500 else ""), language=None)
            else:
                st.markdown(f"- **증거(Evidence):** {evidence}")
            keywords = vuln.get("detected_keywords", [])
            if keywords:
                st.markdown(f"- **탐지 키워드:** `{', '.join(keywords)}`")

        st.divider()

        with st.spinner(f"🤖 AI 분석 중..."):
            try:
                analysis = analyze_vulnerability(client, vuln)
                r1, r2, r3 = st.columns(3)
                with r1:
                    st.markdown("##### 🔍 취약점 설명")
                    st.info(analysis.get("description", "분석 결과 없음"))
                with r2:
                    st.markdown("##### ⚔️ 공격 시나리오")
                    st.warning(analysis.get("scenario", "분석 결과 없음"))
                with r3:
                    st.markdown("##### 🛡️ 대응방안")
                    st.success(analysis.get("countermeasure", "분석 결과 없음"))
            except json.JSONDecodeError:
                st.error("⚠️ AI 응답 파싱 실패. 다시 시도해 주세요.")
            except openai.AuthenticationError:
                st.error("❌ OpenAI API 키를 확인해 주세요. (.env 파일)")
                st.stop()
            except openai.RateLimitError:
                st.error("⏳ API 호출 한도 초과. 잠시 후 다시 시도해 주세요.")
                st.stop()
            except Exception as e:
                st.error(f"AI 분석 오류: {e}")


# ──────────────────────────────────────────
# 사이드바 — 진단 항목 안내만 표시
# ──────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 진단 항목")
    st.caption("URL을 입력하면 아래 항목들을 자동으로 모두 진단합니다.")
    st.divider()

    for s in SCANNERS:
        st.markdown(f"**{s['label']}**")
        st.caption(f"{s['desc']} · {s['owasp']}")

    st.divider()
    st.caption("진단 결과는 AI가 자동 분석합니다.")


# ──────────────────────────────────────────
# 메인 화면 — 입력
# ──────────────────────────────────────────
st.title("🔒 보안 취약점 진단 시스템")
st.caption("진단할 사이트의 URL을 입력하고 버튼을 누르면 자동으로 취약점을 진단하고 AI가 분석합니다.")

col_url, col_btn = st.columns([5, 1])
with col_url:
    target_url = st.text_input(
        "URL",
        placeholder="예: http://52.79.242.217:8000",
        label_visibility="collapsed"
    )
with col_btn:
    run_btn = st.button("▶ 진단 시작", use_container_width=True, type="primary")

st.caption("버튼을 누르면 SSRF, BOLA, IDOR, Insecure Design 4가지 항목을 자동으로 진단합니다.")
st.divider()


# ──────────────────────────────────────────
# 진단 실행
# ──────────────────────────────────────────
if run_btn:
    if not target_url.strip():
        st.error("❌ URL을 입력해 주세요.")
        st.stop()

    if not OPENAI_API_KEY:
        st.error("❌ 서버에 OpenAI API 키가 설정되지 않았습니다. .env 파일을 확인해 주세요.")
        st.stop()

    client = openai.OpenAI(api_key=OPENAI_API_KEY)

    # ─ 백엔드 자동 탐색 ─
    st.subheader("🔄 진단 진행 중...")
    with st.spinner("🔍 백엔드 API 탐색 중..."):
        backend_url, discovery_msg = find_backend_url(target_url.strip())

    st.caption(f"✅ 백엔드 API: {backend_url}")

    progress_bar = st.progress(0)
    status_text  = st.empty()

    all_vulns    = []
    raw_results  = {}
    total = len(SCANNERS)

    for i, scanner in enumerate(SCANNERS):
        status_text.markdown(
            f"**{scanner['label']}** ({scanner['desc']}) 스캔 중... &nbsp; `{i+1}/{total}`"
        )
        try:
            result = scanner["module"].run_scan(backend_url)   # ← 탐색된 백엔드 URL 사용
            raw_results[scanner["label"]] = result

            # 스캐너가 error 필드를 반환한 경우 (로그인 실패 등)
            if "error" in result:
                st.warning(f"⚠️ **{scanner['label']}** 스캔 오류: {result['error']}")

            vulns = result.get("vulnerabilities", [])
            for v in vulns:
                v.setdefault("_scanner", scanner["label"])
            all_vulns.extend(vulns)

        except Exception as e:
            err_msg = str(e)
            raw_results[scanner["label"]] = {"error": err_msg}
            st.warning(f"⚠️ **{scanner['label']}** 예외 발생: {err_msg}")

        progress_bar.progress((i + 1) / total)

    status_text.markdown("✅ **스캔 완료!** AI 분석을 시작합니다...")
    progress_bar.progress(1.0)

    # ─ 원본 JSON 파일로 저장 ─
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"scan_result_{timestamp}.json")
    full_raw = {
        "target": target_url.strip(),
        "scan_time": timestamp,
        "scanner_results": raw_results
    }
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(full_raw, f, ensure_ascii=False, indent=2)

    st.divider()

    # ─ 결과 요약 카드 ─
    total_count    = len(all_vulns)
    critical_count = sum(1 for v in all_vulns if v.get("severity","").upper() == "CRITICAL")
    high_count     = sum(1 for v in all_vulns if v.get("severity","").upper() == "HIGH")
    medium_count   = sum(1 for v in all_vulns if v.get("severity","").upper() == "MEDIUM")

    st.subheader(f"📊 진단 결과 — {target_url}")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("진단 항목",    f"{total}개")
    m2.metric("발견된 취약점", f"{total_count}개")
    m3.metric("🔴 치명적",    critical_count)
    m4.metric("🟠 높음",      high_count)
    m5.metric("🟡 중간",      medium_count)

    st.divider()

    # ─ 진단 항목별 결과 배지 ─
    st.markdown("##### 진단 항목별 결과")
    badge_cols = st.columns(len(SCANNERS))
    for i, scanner in enumerate(SCANNERS):
        scanner_vulns = [v for v in all_vulns if v.get("_scanner") == scanner["label"]]
        raw = raw_results.get(scanner["label"], {})
        has_error = "error" in raw
        count = len(scanner_vulns)
        with badge_cols[i]:
            if has_error:
                st.warning(f"**{scanner['label']}** ⚠️ 오류")
            elif count == 0:
                st.success(f"**{scanner['label']}** ✅ 양호")
            else:
                worst = min(
                    scanner_vulns,
                    key=lambda v: SEVERITY_ORDER.get(v.get("severity","").upper(), 9)
                )
                icon = SEVERITY_MAP.get(worst.get("severity","").upper(), ("⚪",""))[0]
                st.error(f"**{scanner['label']}** {icon} {count}건")

    st.divider()

    # ─ 원본 JSON 디버그 뷰 ─
    with st.expander("🔍 스캐너 원본 JSON 보기 (디버그용)", expanded=False):
        st.caption(f"📁 저장 위치: `{save_path}`")
        for label, raw in raw_results.items():
            st.markdown(f"**{label}**")
            st.json(raw)

    st.divider()

    # ─ 취약점 상세 카드 (심각도 순) ─
    if total_count == 0:
        st.info("선택한 항목에서 취약점이 발견되지 않았습니다. 위 디버그 뷰에서 스캐너 원본 결과를 확인해 주세요.")
    else:
        st.markdown(f"##### 취약점 상세 분석 ({total_count}건)")
        sorted_vulns = sorted(
            all_vulns,
            key=lambda v: SEVERITY_ORDER.get(v.get("severity", "").upper(), 9)
        )
        for i, vuln in enumerate(sorted_vulns):
            render_vuln_card(vuln, client, i)

else:
    # ─ 대기 화면 ─
    st.info("👆 위 입력창에 URL을 입력하고 **▶ 진단 시작** 버튼을 눌러주세요.")
