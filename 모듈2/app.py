import streamlit as st
import openai, json, os, sys, glob, importlib.util, requests
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

st.set_page_config(page_title="보안 취약점 진단 시스템", page_icon="🔒", layout="wide")

# ══════════════════════════════════════════════════════════════
# CSS — Streamlit 기본 스타일 전면 덮어쓰기
# ══════════════════════════════════════════════════════════════
st.markdown("""<style>
/* ── 전역 배경 / 레이아웃 ── */
[data-testid="stAppViewContainer"] { background: #f0f2f6 !important; }
.block-container {
    padding: 1.2rem 4rem 4rem !important;
    max-width: 1300px !important;
    margin: 0 auto !important;
}
#MainMenu, footer, .stDeployButton, [data-testid="stHeader"] { display: none !important; }
* { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

/* ── 컬럼 간격 ── */
[data-testid="column"] { padding: 0 6px !important; }
div[data-testid="stHorizontalBlock"] { gap: 0 !important; }
.element-container { margin-bottom: 3px !important; }

/* ── 카드 기본형 ── */
.card {
    background: white; border-radius: 12px;
    padding: 18px 20px; height: 100%;
    box-shadow: 0 2px 8px rgba(0,0,0,.06);
    box-sizing: border-box;
}
.card-sm { background: white; border-radius: 10px; padding: 14px 16px; box-shadow: 0 2px 8px rgba(0,0,0,.06); }
.card-label { font-size: .78rem; font-weight: 700; color: #64748b; letter-spacing: .04em; text-transform: uppercase; margin-bottom: 10px; }

/* ── 점수 카드 ── */
.score-num  { font-size: 3rem; font-weight: 800; line-height: 1; color: #1e293b; }
.score-deno { font-size: 1.1rem; color: #94a3b8; }
.grade-chip { display: inline-flex; align-items: center; gap: 5px; padding: 5px 16px; border-radius: 20px; font-weight: 700; font-size: .92rem; margin-top: 10px; }

/* ── 핵심 지표 / 분포 ── */
.kv  { display: flex; justify-content: space-between; padding: 6px 0; font-size: .87rem; border-bottom: 1px solid #f1f5f9; }
.kv:last-child { border-bottom: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; vertical-align: middle; margin-right: 6px; }
.dist-row { font-size: .86rem; padding: 4px 0; color: #374151; }

/* ── 배지/태그 ── */
.tag { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: .73rem; font-weight: 700; white-space: nowrap; line-height: 1.6; }
.tag-CRITICAL { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.tag-HIGH     { background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }
.tag-MEDIUM   { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
.tag-LOW      { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
.tag-INFO     { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }
.tag-VULN     { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.tag-OK       { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }

/* ── 테이블 ── */
.tbl-head { display: grid; grid-template-columns: 44px 1.6fr 1fr 92px 82px 44px;
            background: #f8fafc; border-radius: 8px 8px 0 0;
            padding: 9px 12px; border-bottom: 2px solid #e8ecf0; }
.tbl-head span { font-size: .75rem; font-weight: 700; color: #6b7280; }

.trow { display: grid; grid-template-columns: 44px 1.6fr 1fr 92px 82px 44px;
        align-items: center; padding: 9px 12px; border-bottom: 1px solid #f1f5f9;
        background: white; transition: background .12s; }
.trow:hover  { background: #f8fafc; }
.trow.sel    { background: #eff6ff; }
.trow .cell  { font-size: .85rem; color: #374151; }
.trow .cell-id { font-weight: 600; color: #1e293b; }
.trow .cell-num { font-size: .84rem; color: #9ca3af; }
.trow.sel .cell-num, .trow.sel .cell-id { color: #2563eb; }

.tbl-wrap { border-radius: 10px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.06); }

/* ── 상세 패널 ── */
.detail-panel { background: white; border-radius: 12px; padding: 18px;
                box-shadow: 0 2px 8px rgba(0,0,0,.06); height: 100%; box-sizing: border-box; }
.detail-id { font-size: 1rem; font-weight: 700; color: #1e293b; }
.detail-meta { font-size: .8rem; color: #64748b; line-height: 1.9; margin: 10px 0; }
.detail-section { margin-top: 12px; }
.detail-section-title { font-size: .73rem; font-weight: 700; color: #6b7280; text-transform: uppercase;
                        letter-spacing: .05em; margin-bottom: 5px; }
.finding-box { background: #eff6ff; border-left: 3px solid #2563eb; border-radius: 6px;
               padding: 10px 14px; font-size: .83rem; color: #1e40af; line-height: 1.6; }
.scenario-box { background: #fff7ed; border-left: 3px solid #ea580c; border-radius: 6px;
                padding: 10px 14px; font-size: .83rem; color: #9a3412; line-height: 1.6; }
.remedy-box { background: #f0fdf4; border-left: 3px solid #16a34a; border-radius: 6px;
              padding: 10px 14px; font-size: .83rem; color: #14532d; line-height: 1.6; }
.detail-scroll { max-height: 340px; overflow-y: auto; padding-right: 4px; }
.detail-scroll::-webkit-scrollbar { width: 4px; }
.detail-scroll::-webkit-scrollbar-track { background: #f1f5f9; border-radius: 4px; }
.detail-scroll::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
.placeholder { display: flex; flex-direction: column; align-items: center; justify-content: center;
               height: 100%; min-height: 200px; color: #cbd5e1; }

/* ── 버튼 (Streamlit) ── */
.stButton > button {
    background: white !important; border: 1px solid #dde1e7 !important;
    border-radius: 6px !important; color: #94a3b8 !important;
    font-size: .78rem !important; padding: 0px 6px !important;
    min-height: 24px !important; line-height: 1 !important; box-shadow: none !important;
}
.stButton > button:hover { background: #eff6ff !important; border-color: #2563eb !important; color: #2563eb !important; }
[data-testid="baseButton-primary"] {
    background: #2563eb !important; color: white !important;
    border: none !important; border-radius: 8px !important; font-size: .9rem !important;
}
[data-testid="baseButton-primary"]:hover { background: #1d4ed8 !important; }

/* ── 인풋/셀렉트박스 ── */
.stTextInput > div > div > input {
    border: 1px solid #dde1e7 !important; border-radius: 8px !important;
    background: white !important; font-size: .88rem !important;
    box-shadow: 0 1px 2px rgba(0,0,0,.04) !important;
}
.stSelectbox > div > div { border: 1px solid #dde1e7 !important; border-radius: 8px !important; background: white !important; }

/* ── Plotly 카드 스타일 ── */
.modebar-container { display: none !important; }
[data-testid="stPlotlyChart"] {
    background: white !important;
    border-radius: 12px !important;
    box-shadow: 0 2px 8px rgba(0,0,0,.06) !important;
    padding: 4px !important;
}
/* plotly 내부 여백 제거 */
[data-testid="stPlotlyChart"] > div { border-radius: 12px !important; }

/* ── 헤더 ── */
.report-hdr { background: white; border-radius: 12px; padding: 18px 24px;
              margin-bottom: 14px; border-left: 5px solid #2563eb;
              box-shadow: 0 2px 8px rgba(0,0,0,.06); }
.report-hdr h3 { margin: 0 0 5px; font-size: 1.2rem; color: #1e293b; }
.report-hdr small { color: #64748b; font-size: .82rem; }

/* ── 구분선 ── */
hr { border: none; border-top: 1px solid #e8ecf0 !important; margin: 10px 0 !important; }
</style>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# 백엔드 자동 탐색
# ══════════════════════════════════════════════════════════════
CANDIDATE_PORTS = [8000, 8080, 8888, 5000, 4000, 3001, 9000, 8001, 8443, 443, 80]

def find_backend_url(input_url: str) -> str:
    parsed     = urlparse(input_url.rstrip("/"))
    scheme     = parsed.scheme or "http"
    host       = parsed.hostname
    input_port = parsed.port
    ports      = ([input_port] if input_port else []) + [p for p in CANDIDATE_PORTS if p != input_port]
    for port in ports:
        candidate = f"{scheme}://{host}:{port}"
        try:
            resp = requests.post(f"{candidate}/auth/login",
                                 json={"username": "probe", "password": "probe"}, timeout=3)
            resp.json()
            return candidate
        except Exception:
            continue
    return input_url.rstrip("/")


# ══════════════════════════════════════════════════════════════
# 스캐너 동적 로드
# ══════════════════════════════════════════════════════════════
def load_scanners() -> list:
    scanner_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Scanner")
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    scanners = []
    for filepath in sorted(glob.glob(os.path.join(scanner_dir, "*_check.py"))):
        module_name = os.path.basename(filepath)[:-3]
        label       = module_name.replace("_check", "").upper()
        try:
            spec   = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            func   = getattr(module, module_name, None)
            if not func or not callable(func):
                for name in dir(module):
                    if name.endswith("_check") and callable(getattr(module, name)):
                        func = getattr(module, name); break
            if not func:
                raise AttributeError("_check 함수 없음")
            scanners.append({"label": label, "run": func})
        except Exception as e:
            scanners.append({"label": label, "run": None, "error": str(e)})
    return scanners

SCANNERS = load_scanners()


# ══════════════════════════════════════════════════════════════
# 헬퍼
# ══════════════════════════════════════════════════════════════
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_KOR   = {"CRITICAL": "치명적", "HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "INFO": "정보"}
SEV_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a", "INFO": "#2563eb"}

def is_vuln(v: dict) -> bool:
    return "취약" in v.get("status", "")

def tag(cls: str, text: str) -> str:
    return f'<span class="tag tag-{cls}">{text}</span>'

def sev_tag(sev: str) -> str:
    k = sev.upper()
    return tag(k, SEV_KOR.get(k, sev))

def calc_score(vulns: list) -> int:
    ded = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
    return max(0, 100 - sum(ded.get(v.get("severity","").upper(), 0) for v in vulns if is_vuln(v)))

def get_grade(s: int):
    if s >= 90: return "우수",  "#16a34a"
    if s >= 75: return "양호",  "#16a34a"
    if s >= 60: return "보통",  "#ca8a04"
    if s >= 40: return "위험",  "#ea580c"
    return       "심각",        "#dc2626"


# ══════════════════════════════════════════════════════════════
# OpenAI AI 분석 (온디맨드 + 캐시)
# ══════════════════════════════════════════════════════════════
def analyze(client: openai.OpenAI, vuln: dict) -> dict:
    desc = vuln.get("attack_method", vuln.get("description", "?"))
    kw   = vuln.get("detected_keywords", [])
    ev   = str(vuln.get("evidence", "없음"))[:300]
    prompt = f"""보안 전문가로서 아래 침투 테스트 결과를 한국어로 분석하고 JSON만 출력하세요.

취약점: {vuln.get('name', vuln.get('type','?'))} | 심각도: {vuln.get('severity')} | OWASP: {vuln.get('owasp','')}
엔드포인트: {vuln.get('endpoint')} | 설명: {desc}
페이로드: {vuln.get('payload','없음')} | 상태: {vuln.get('result', vuln.get('status'))}
탐지 키워드: {', '.join(kw) if kw else '없음'} | 증거: {ev}

{{"description":"기술적 설명 (2~3문장)","scenario":"공격자 악용 시나리오 (단계별로)","countermeasure":"개발자 대응방안 (간결하게)"}}"""
    r   = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    raw = r.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"): raw = raw[4:]
    return json.loads(raw)


# ══════════════════════════════════════════════════════════════
# 세션 초기화
# ══════════════════════════════════════════════════════════════
for k, v in {
    "scan_done": False, "all_vulns": [], "raw_results": {},
    "target_url": "", "backend_url": "", "scan_time": "", "sel": None
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ══════════════════════════════════════════════════════════════
# URL 입력 + 진단 시작
# ══════════════════════════════════════════════════════════════
col_url, col_btn = st.columns([5, 1])
with col_url:
    url_input = st.text_input("URL", placeholder="예: http://52.79.242.217:3000", label_visibility="collapsed")
with col_btn:
    run_btn = st.button("▶ 진단 시작", use_container_width=True, type="primary")

if run_btn:
    if not url_input.strip():
        st.error("❌ URL을 입력해 주세요."); st.stop()
    if not OPENAI_API_KEY:
        st.error("❌ .env 파일에 OPENAI_API_KEY를 설정해 주세요."); st.stop()

    st.session_state.target_url = url_input.strip()
    st.session_state.sel = None
    for k in [k for k in st.session_state if k.startswith("ai_")]:
        del st.session_state[k]

    with st.spinner("🔍 백엔드 API 자동 탐색 중..."):
        backend = find_backend_url(url_input.strip())
    st.session_state.backend_url = backend

    pb, st_txt = st.progress(0), st.empty()
    all_vulns, raw_results = [], {}

    for i, sc in enumerate(SCANNERS):
        st_txt.text(f"[{i+1}/{len(SCANNERS)}] {sc['label']} 스캔 중...")
        if not sc.get("run"):
            raw_results[sc["label"]] = {"error": sc.get("error", "로드 실패")}
        else:
            try:
                result = sc["run"](backend)
                raw_results[sc["label"]] = result
                for v in result.get("vulnerabilities", []):
                    v.setdefault("_scanner", sc["label"])
                    all_vulns.append(v)
            except Exception as e:
                raw_results[sc["label"]] = {"error": str(e)}
        pb.progress((i + 1) / len(SCANNERS))

    st_txt.empty(); pb.empty()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"scan_result_{ts}.json"), "w", encoding="utf-8") as f:
        json.dump({"target": url_input.strip(), "scan_time": ts, "scanner_results": raw_results}, f, ensure_ascii=False, indent=2)

    st.session_state.all_vulns   = all_vulns
    st.session_state.raw_results  = raw_results
    st.session_state.scan_time    = datetime.now().strftime("%Y.%m.%d %H:%M:%S")
    st.session_state.scan_done    = True
    st.rerun()


# ══════════════════════════════════════════════════════════════
# 대기 화면
# ══════════════════════════════════════════════════════════════
if not st.session_state.scan_done:
    st.markdown("---")
    st.info("👆 URL을 입력하고 **▶ 진단 시작** 버튼을 눌러주세요.")
    if SCANNERS:
        st.markdown("**로드된 스캐너:**")
        cols = st.columns(len(SCANNERS))
        for i, sc in enumerate(SCANNERS):
            with cols[i]:
                (st.success if sc.get("run") else st.error)(f"{'✅' if sc.get('run') else '❌'} {sc['label']}")
    st.stop()


# ══════════════════════════════════════════════════════════════
# ── 대시보드 ──
# ══════════════════════════════════════════════════════════════
all_vulns   = st.session_state.all_vulns
raw_results = st.session_state.raw_results

sorted_vulns = sorted(all_vulns,
    key=lambda v: (SEV_ORDER.get(v.get("severity","").upper(), 9), 0 if is_vuln(v) else 1))

total_c = len(sorted_vulns)
vuln_c  = sum(1 for v in sorted_vulns if is_vuln(v))
pass_c  = total_c - vuln_c
crit_c  = sum(1 for v in sorted_vulns if v.get("severity","").upper()=="CRITICAL" and is_vuln(v))
high_c  = sum(1 for v in sorted_vulns if v.get("severity","").upper()=="HIGH"     and is_vuln(v))
med_c   = sum(1 for v in sorted_vulns if v.get("severity","").upper()=="MEDIUM"   and is_vuln(v))
low_c   = sum(1 for v in sorted_vulns if v.get("severity","").upper()=="LOW"      and is_vuln(v))
score   = calc_score(sorted_vulns)
grade, gcolor = get_grade(score)

# ── 보고서 헤더 ─────────────────────────────────────────────
st.markdown(f"""
<div class="report-hdr">
  <h3>🔒 보안 취약점 진단 보고서 <span style="font-size:.85rem;font-weight:400;color:#64748b">(Security Vulnerability Diagnosis Report)</span></h3>
  <small>
    진단 대상: <b>{st.session_state.target_url}</b> &nbsp;|&nbsp;
    백엔드 API: <b>{st.session_state.backend_url}</b> &nbsp;|&nbsp;
    진단 일시: <b>{st.session_state.scan_time}</b>
  </small>
</div>
""", unsafe_allow_html=True)

# ── Row 1: 상단 지표 카드 3개 ───────────────────────────────
r1c1, r1c2, r1c3 = st.columns(3)

with r1c1:
    st.markdown(f"""
    <div class="card">
      <div class="card-label">📊 종합 점수 및 등급</div>
      <span class="score-num" style="color:{gcolor}">{score}</span>
      <span class="score-deno"> / 100</span>
      <br>
      <span class="grade-chip" style="background:{gcolor}1a;color:{gcolor};">✅ {grade}</span>
    </div>
    """, unsafe_allow_html=True)

with r1c2:
    st.markdown(f"""
    <div class="card">
      <div class="card-label">📋 핵심 지표</div>
      <div class="kv"><span>총 진단 항목</span><b>{total_c}</b></div>
      <div class="kv"><span>통과</span><b style="color:#16a34a">{pass_c}</b></div>
      <div class="kv"><span>취약</span><b style="color:#dc2626">{vuln_c}</b></div>
    </div>
    """, unsafe_allow_html=True)

with r1c3:
    st.markdown(f"""
    <div class="card">
      <div class="card-label">⚠️ 위험도 분포</div>
      <div class="dist-row"><span class="dot" style="background:#dc2626"></span>치명적 &nbsp;<b>{crit_c}</b></div>
      <div class="dist-row"><span class="dot" style="background:#ea580c"></span>높음 &nbsp;<b>{high_c}</b></div>
      <div class="dist-row"><span class="dot" style="background:#ca8a04"></span>중간 &nbsp;<b>{med_c}</b></div>
      <div class="dist-row"><span class="dot" style="background:#16a34a"></span>낮음 &nbsp;<b>{low_c}</b></div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Row 2: 차트 2개 + 상세 패널 ─────────────────────────────
r2c1, r2c2, r2c3 = st.columns([2, 2, 2.2])

with r2c1:
    if HAS_PLOTLY and vuln_c > 0:
        lv = [(SEV_KOR[k], v, SEV_COLOR[k]) for k, v in
              [("CRITICAL",crit_c),("HIGH",high_c),("MEDIUM",med_c),("LOW",low_c)] if v > 0]
        ls, vs, cs = zip(*lv)
        fig1 = go.Figure(go.Pie(
            labels=ls, values=vs, hole=0.55, marker_colors=cs,
            textfont_size=11, insidetextorientation="radial",
            hovertemplate="%{label}: %{value}건<extra></extra>"
        ))
        fig1.update_layout(
            title=dict(text="위험도 비율", x=0.5, font=dict(size=13, color="#374151")),
            height=260, margin=dict(t=40, b=10, l=10, r=10),
            legend=dict(orientation="v", x=1.0, y=0.5, font=dict(size=11)),
            paper_bgcolor="white", plot_bgcolor="white",
            font=dict(family="-apple-system,sans-serif")
        )
        st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown("""
        <div class="card" style="height:260px;display:flex;flex-direction:column;justify-content:center;align-items:center">
            <div class="card-label">위험도 비율</div>
            <div style="color:#cbd5e1;font-size:.85rem;margin-top:8px">데이터 없음</div>
        </div>""", unsafe_allow_html=True)

with r2c2:
    if HAS_PLOTLY and vuln_c > 0:
        cats, cat_worst = {}, {}
        for v in sorted_vulns:
            if is_vuln(v):
                c = v.get("_scanner", "기타")
                cats[c] = cats.get(c, 0) + 1
                cat_worst[c] = min(cat_worst.get(c, 9), SEV_ORDER.get(v.get("severity","").upper(), 9))
        r2k = {0:"CRITICAL",1:"HIGH",2:"MEDIUM",3:"LOW",4:"INFO"}
        bar_colors = [SEV_COLOR.get(r2k.get(cat_worst.get(c,4),"INFO"),"#2563eb") for c in cats]
        fig2 = go.Figure(go.Bar(
            x=list(cats.keys()), y=list(cats.values()),
            marker_color=bar_colors, text=list(cats.values()),
            textposition="outside",
            hovertemplate="%{x}: %{y}건<extra></extra>"
        ))
        fig2.update_layout(
            title=dict(text="카테고리별 취약점", x=0.5, font=dict(size=13, color="#374151")),
            height=260, margin=dict(t=40, b=10, l=10, r=10),
            yaxis=dict(showgrid=True, gridcolor="#f1f5f9", zeroline=False, showticklabels=False),
            xaxis=dict(tickfont=dict(size=10)),
            paper_bgcolor="white", plot_bgcolor="white", showlegend=False,
            font=dict(family="-apple-system,sans-serif")
        )
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown("""
        <div class="card" style="height:260px;display:flex;flex-direction:column;justify-content:center;align-items:center">
            <div class="card-label">카테고리별 취약점</div>
            <div style="color:#cbd5e1;font-size:.85rem;margin-top:8px">데이터 없음</div>
        </div>""", unsafe_allow_html=True)

# ── 오른쪽: 상세 패널 (선택 항목 AI 분석) ──────────────────
with r2c3:
    sel = st.session_state.sel
    # sel이 현재 sorted_vulns 범위 안에 있는지 확인 (필터 변경 대비)
    sel_vuln = sorted_vulns[sel] if (sel is not None and 0 <= sel < len(sorted_vulns)) else None

    if sel_vuln is None:
        st.markdown("""
        <div class="detail-panel">
          <div class="placeholder">
            <div style="font-size:2rem">📋</div>
            <div style="margin-top:10px;font-size:.87rem;text-align:center">
              아래 목록에서 항목을 선택하면<br>AI 상세 분석이 표시됩니다.
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        vuln    = sel_vuln
        vuln_id = vuln.get("id", "?")
        sev     = vuln.get("severity", "").upper()

        st.markdown(f"""
        <div class="detail-panel">
          <div style="display:flex;align-items:center;gap:8px;border-bottom:1px solid #f1f5f9;padding-bottom:10px;margin-bottom:10px">
            <span class="detail-id">{vuln_id} 상세 정보</span>
            {sev_tag(sev)}
            {tag("VULN","취약") if is_vuln(vuln) else tag("OK","통과")}
            <span style="margin-left:auto;font-size:.75rem;cursor:pointer;color:#94a3b8">∧</span>
          </div>
          <div class="detail-meta">
            <b>엔드포인트:</b> {vuln.get('endpoint','N/A')}<br>
            <b>OWASP:</b> {vuln.get('owasp','N/A')}<br>
            <b>페이로드:</b> {str(vuln.get('payload','N/A'))[:100]}<br>
            <b>탐지 키워드:</b> {', '.join(vuln.get('detected_keywords',[])) or '없음'}
          </div>
        </div>
        """, unsafe_allow_html=True)

        # AI 분석 (캐시)
        cache_key = f"ai_{vuln_id}_{vuln.get('_scanner','')}"
        if cache_key not in st.session_state:
            if not OPENAI_API_KEY:
                st.error(".env에 OPENAI_API_KEY 필요"); st.stop()
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            with st.spinner("🤖 AI 분석 중..."):
                try:
                    st.session_state[cache_key] = analyze(client, vuln)
                except openai.AuthenticationError:
                    st.error("❌ OpenAI API 키 오류"); st.stop()
                except openai.RateLimitError:
                    st.error("⏳ API 한도 초과"); st.stop()
                except Exception as e:
                    st.error(f"분석 실패: {e}")

        if cache_key in st.session_state:
            a = st.session_state[cache_key]
            st.markdown(f"""
            <div style="margin-top:6px">
              <div class="detail-section">
                <div class="detail-section-title">🔍 발견된 문제점 (Findings)</div>
                <div class="finding-box">{a.get('description','')}</div>
              </div>
              <div class="detail-section">
                <div class="detail-section-title">⚔️ 공격 시나리오</div>
                <div class="scenario-box">{a.get('scenario','')}</div>
              </div>
              <div class="detail-section">
                <div class="detail-section-title">🛡️ 조치 가이드 (Remediation)</div>
                <div class="remedy-box">{a.get('countermeasure','')}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("---")

# ══════════════════════════════════════════════════════════════
# 검색 / 필터
# ══════════════════════════════════════════════════════════════
flt1, flt2, flt3 = st.columns([2.5, 1.2, 1.2])
with flt1:
    search = st.text_input("search", placeholder="🔍  항목 ID 또는 카테고리 검색", label_visibility="collapsed")
with flt2:
    sev_opt = st.selectbox("위험도", ["필터: 위험도 (전체)","치명적","높음","중간","낮음"], label_visibility="collapsed")
with flt3:
    sts_opt = st.selectbox("결과", ["필터: 결과 (전체)","취약","통과"], label_visibility="collapsed")

SEV_MAP_KOR = {"치명적":"CRITICAL","높음":"HIGH","중간":"MEDIUM","낮음":"LOW"}
filtered = sorted_vulns
if search:
    q = search.lower()
    filtered = [v for v in filtered if q in v.get("id","").lower() or q in v.get("_scanner","").lower()]
if sev_opt != "필터: 위험도 (전체)":
    filtered = [v for v in filtered if v.get("severity","").upper() == SEV_MAP_KOR.get(sev_opt, sev_opt)]
if sts_opt != "필터: 결과 (전체)":
    filtered = [v for v in filtered if is_vuln(v)] if sts_opt == "취약" else [v for v in filtered if not is_vuln(v)]


# ══════════════════════════════════════════════════════════════
# 테이블
# ══════════════════════════════════════════════════════════════
st.markdown('<div class="tbl-wrap">', unsafe_allow_html=True)

# 헤더 행
st.markdown("""
<div class="tbl-head">
  <span>순번</span><span>항목 ID</span><span>카테고리</span>
  <span>위험도</span><span>진단 결과</span><span></span>
</div>
""", unsafe_allow_html=True)

if not filtered:
    st.markdown('<div style="background:white;padding:24px;text-align:center;color:#94a3b8;font-size:.88rem">조건에 맞는 항목이 없습니다.</div>', unsafe_allow_html=True)
else:
    for i, vuln in enumerate(filtered):
        sev          = vuln.get("severity","").upper()
        vuln_ok      = not is_vuln(vuln)
        is_selected  = (st.session_state.sel == i)
        sel_cls      = "sel" if is_selected else ""
        num_style    = "color:#2563eb;font-weight:700" if is_selected else "color:#9ca3af"
        id_style     = "color:#2563eb;font-weight:700" if is_selected else "color:#1e293b;font-weight:600"

        # 행 HTML (버튼 칸만 비워둠 — Streamlit 버튼으로 대체)
        row_html = f"""
        <div class="trow {sel_cls}">
          <div class="cell" style="{num_style}">{i+1}</div>
          <div class="cell" style="{id_style}">{vuln.get('id','?')}</div>
          <div class="cell" style="color:#374151">{vuln.get('_scanner','?')}</div>
          <div class="cell">{sev_tag(sev)}</div>
          <div class="cell">{tag("OK","통과") if vuln_ok else tag("VULN","취약")}</div>
          <div class="cell"></div>
        </div>
        """
        # Streamlit 컬럼으로 HTML + 버튼 배치
        rc = st.columns([0.44, 1.58, 1.0, 0.9, 0.82, 0.44])
        with rc[0]:
            st.markdown(f'<div style="height:34px;display:flex;align-items:center;{num_style};font-size:.84rem">{i+1}</div>', unsafe_allow_html=True)
        with rc[1]:
            st.markdown(f'<div style="height:34px;display:flex;align-items:center;{id_style};font-size:.84rem">{vuln.get("id","?")}</div>', unsafe_allow_html=True)
        with rc[2]:
            st.markdown(f'<div style="height:34px;display:flex;align-items:center;font-size:.84rem;color:#374151">{vuln.get("_scanner","?")}</div>', unsafe_allow_html=True)
        with rc[3]:
            st.markdown(f'<div style="height:34px;display:flex;align-items:center">{sev_tag(sev)}</div>', unsafe_allow_html=True)
        with rc[4]:
            status_tag = tag("OK","통과") if vuln_ok else tag("VULN","취약")
            st.markdown(f'<div style="height:34px;display:flex;align-items:center">{status_tag}</div>', unsafe_allow_html=True)
        with rc[5]:
            btn_lbl = "▲" if is_selected else "▽"
            if st.button(btn_lbl, key=f"row_{i}", use_container_width=True):
                st.session_state.sel = None if is_selected else i
                st.rerun()

        # 구분선
        st.markdown('<div style="height:1px;background:#f1f5f9;margin:0"></div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# 디버그 (원본 JSON)
# ══════════════════════════════════════════════════════════════
st.markdown("<br>", unsafe_allow_html=True)
with st.expander("🔍 스캐너 원본 JSON (디버그용)", expanded=False):
    for label, raw in raw_results.items():
        st.markdown(f"**{label}**")
        st.json(raw)
