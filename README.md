# 🔒 보안 취약점 진단 시스템 (Security Vulnerability Diagnosis System)

> OWASP API Top 10 기반의 자동화된 웹 API 보안 취약점 진단 플랫폼

---

## 📌 프로젝트 소개

**보안 취약점 진단 시스템**은 의도적으로 취약하게 설계된 모의 뱅킹 서비스(`NeoBanK`)를 대상으로, OWASP API Security Top 10 기반의 취약점을 자동으로 탐지·분석하는 보안 교육용 플랫폼입니다.

- 🎯 취약한 사이트(`vulnerable_site`)와 보안이 적용된 사이트(`team_site_safe`)를 함께 제공해 **Before/After 비교 학습** 가능
- 🤖 OpenAI GPT-4o-mini를 활용한 **AI 기반 취약점 분석** 및 조치 가이드 제공
- 📊 Streamlit 대시보드를 통한 **실시간 스캔 결과 시각화**

---

## 🗂️ 프로젝트 구조

```
31_project_team3-main/
├── platform/                    # 취약점 진단 플랫폼
│   └── 모듈2/
│       ├── app.py               # Streamlit 메인 앱 (대시보드)
│       ├── requirements.txt     # 플랫폼 의존성
│       ├── Scanner/             # 취약점 스캐너 모듈
│       │   ├── main.py          # 스캐너 실행 진입점
│       │   ├── sqli_check.py    # SQL Injection 스캐너
│       │   ├── bfla_admin_check.py  # BFLA 스캐너
│       │   ├── bola_check.py    # BOLA 스캐너
│       │   ├── idor_check.py    # IDOR 스캐너
│       │   ├── insecure_check.py    # Insecure Design 스캐너
│       │   └── ssrf_check.py    # SSRF 스캐너
│       └── scanners/            # 스캐너 모듈 패키지
│
└── vulnerble_site/              # 실습 대상 사이트
    ├── team_site/               # ❗ 취약한 버전 (학습용)
    │   ├── backend/             # FastAPI 백엔드
    │   ├── frontend/            # React 프론트엔드
    │   └── docker-compose.yml
    └── team_site_safe/          # ✅ 보안 패치 버전
        ├── backend/
        ├── frontend/
        └── docker-compose.yml
```

---

## 🛠️ 기술 스택

### 진단 플랫폼
| 구분 | 기술 |
|------|------|
| UI | Streamlit |
| AI 분석 | OpenAI GPT-4o-mini |
| 시각화 | Plotly |
| 환경 설정 | python-dotenv |

### 모의 뱅킹 서비스 (NeoBanK)
| 구분 | 기술 |
|------|------|
| 백엔드 | FastAPI, Python |
| 프론트엔드 | React 18, React Router v6, Axios |
| 데이터베이스 | SQLite |
| 인증 | JWT (python-jose) |
| 컨테이너 | Docker, Docker Compose |

---

## 🔍 지원 스캐너 (OWASP API Security Top 10 기반)

| 스캐너 | OWASP 분류 | 탐지 내용 |
|--------|-----------|----------|
| `SQLi` | - | SQL Injection 로그인 우회, Time-based Blind SQLi |
| `BOLA` | API1 | Broken Object Level Authorization (다른 사용자 데이터 접근) |
| `IDOR` | API1 | Insecure Direct Object Reference (직접 객체 참조) |
| `BFLA` | API5 | Broken Function Level Authorization (관리자 기능 무단 접근) |
| `SSRF` | - | Server-Side Request Forgery (내부 서버 요청 위조) |
| `INSECURE` | API8 | Insecure Design (비밀번호 평문 저장, 입력값 검증 부재 등) |

---

## ⚙️ 설치 및 실행

### 1단계: 취약한 실습 서버 실행

```bash
cd vulnerble_site/team_site
docker-compose up -d
```

- 백엔드 API: `http://localhost:8000`
- 프론트엔드: `http://localhost:3000`

### 2단계: 진단 플랫폼 설치

```bash
cd platform/모은뱀
pip install -r requirements.txt
```

### 3단계: 환경 변수 설정

프로젝트 루트에 `.env` 파일을 생성합니다.

```env
OPENAI_API_KEY=your_openai_api_key_here
```

### 4단계: 진단 플랫폼 실행

```bash
streamlit run app.py
```

브라우저에서 `http://localhost:8501`에 접속합니다.

---

## 🚀 사용 방법

1. 진단 플랫폼 웹 UI에 접속합니다.
2. **진단할 사이트 URL**을 입력합니다. (예: `http://localhost:3000`)
3. **▶ 진단 시작** 버튼을 클릭합니다.
4. 플랫폼이 백엔드 API 포트를 자동으로 탐색하고 전체 취약점 스캔을 실행합니다.
5. 대시보드에서 스캔 결과를 확인합니다.
   - 위험도별 분포 차트 (치명적 / 높음 / 중간 / 낮음)
   - 카테고리별 취약점 현황 바 차트
   - 항목별 테이블 (검색 및 필터 지원)
6. 목록에서 항목을 선택하면 **AI 상세 분석** (발견된 문제점 / 공격 시나리오 / 조치 가이드)이 표시됩니다.

---

## ⚠️ 주의사항

> **이 프로젝트는 보안 교육 목적으로만 사용해야 합니다.**

- `team_site`는 **의도적으로 취약하게 설계**된 실습용 서비스입니다.
- 허가받지 않은 실제 서비스에 스캐너를 사용하는 것은 **불법**입니다.
- 반드시 격리된 환경(로컬 또는 개인 서버)에서만 실행하세요.

---

## 📚 참고 자료

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [FastAPI 공식 문서](https://fastapi.tiangolo.com/)
- [Streamlit 공식 문서](https://docs.streamlit.io/)

---

## 👥 팀 정보

**31기 프로젝트 Team 3**

| 이름 | 역할 | GitHub |
|------|------|--------|
| 태유빈 | 팀장/플랫폼 구축 | [@u-kong](https://github.com/u-kong) |
| 김건하 | 진단 코드 작성 | [@geonha0507](https://github.com/geonha0507) |
| 김라희 | 진단 코드 작성 | [@La-hee](https://github.com/La-hee) |
| 김정현 | 진단 코드 작성 | [@junghyun1225](https://github.com/junghyun1225) |
| 서범창 | 취약 사이트 제작 | [@west-window](https://github.com/west-window) |
| 유인기 | 플랫폼 구축 | [@navytuna687](https://github.com/navytuna687) |