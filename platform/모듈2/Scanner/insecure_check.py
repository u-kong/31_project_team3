import requests
import time
from datetime import datetime

def get_token(base_url, username, password):
    try:
        resp = requests.post(f"{base_url}/auth/login", json={
            "username": username, "password": password
        }, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except:
        pass
    return None

def insecure_check(base_url, test_account=None, wrong_account=None):
    if test_account is None:
        test_account = {"id": "alice", "pw": "alice1234"}
    if wrong_account is None:
        wrong_account = {"id": "alice", "pw": "wrongpassword"}

    result = {
        "scan_id": "Insecure_Design",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": []
    }

    # --- INSECURE-001: 브루트포스 (기존 유지) ---
    block = False
    for i in range(5):
        try:
            resp = requests.post(f"{base_url}/auth/login", json={
                "username": wrong_account["id"], "password": wrong_account["pw"]
            }, timeout=3)
            if "Too many attempts" in resp.text or resp.status_code == 429:
                block = True
                break
        except: break

    result["vulnerabilities"].append({
        "id": "INSECURE-001",
        "type": "Insecure Design",
        "severity": "High",
        "status": "양호" if block else "취약",
        "owasp": "A04:2021 - Insecure Design",
        "endpoint": "/auth/login",
        "payload": "잘못된 비밀번호로 5회 연속 로그인 시도",
        "detected_keywords": ["Too many attempts"],
        "evidence": "5회 실패 후 차단 확인" if block else "5회 실패 후에도 로그인 시도 차단 없음",
        "description": "로그인 실패 횟수 제한 없음 — 브루트포스 공격으로 계정 탈취 가능"
    })

    # --- INSECURE-002: 2차 인증 (기존 유지) ---
    token = get_token(base_url, test_account["id"], test_account["pw"])
    if token:
        try:
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.post(f"{base_url}/transfer", json={
                "from_account_id": 1, "to_account_id": 2, "amount": 10000, "description": "test"
            }, headers=headers, timeout=3)
            keywords = ["2차 비밀번호", "OTP", "추가 인증", "secondary password"]
            found = any(kw.lower() in resp.text.lower() for kw in keywords)

            result["vulnerabilities"].append({
                "id": "INSECURE-002",
                "type": "Insecure Design",
                "severity": "High",
                "status": "양호" if found else "취약",
                "owasp": "A04:2021 - Insecure Design",
                "endpoint": "/transfer",
                "payload": "이체 요청 후 2차 인증 요구 여부 확인",
                "detected_keywords": keywords,
                "evidence": "2차 인증 요구 확인" if found else "이체 완료까지 추가 인증 없음",
                "description": "계좌 이체 시 2차 비밀번호 인증 없음 — 세션 탈취 시 즉시 이체 가능"
            })
        except: pass

    # --- INSECURE-003: 비밀번호 복잡도 (기존 유지) ---
    try:
        resp = requests.post(f"{base_url}/auth/register", json={
            "username": f"weak_{int(time.time())}", # 중복 방지
            "password": "1234", "email": "test@test.com"
        }, timeout=3)
        weak_accepted = (resp.status_code == 200)
        
        result["vulnerabilities"].append({
            "id": "INSECURE-003",
            "type": "Insecure Design",
            "severity": "Medium",
            "status": "취약" if weak_accepted else "양호",
            "owasp": "A04:2021 - Insecure Design",
            "endpoint": "/auth/register",
            "payload": "password=1234",
            "evidence": "'1234' 비밀번호로 회원가입 성공" if weak_accepted else "약한 비밀번호 차단 확인",
            "description": "비밀번호 복잡도 검증 없음 — 특수문자, 최소 길이 등 정책 미적용"
        })
    except: pass

    # --- INSECURE-004: 세션 타임아웃 정책 미비 (추가됨) ---
    if token: # 앞서 로그인 성공 시 받아온 토큰 재사용
        try:
            # 시연을 위해 5초 대기 (서버의 타임아웃 정책이 이보다 짧은지 테스트)
            time.sleep(5) 
            
            headers = {"Authorization": f"Bearer {token}"}
            # 토큰 유효성을 확인할 수 있는 엔드포인트 호출
            resp = requests.post(f"{base_url}/transfer", headers=headers, timeout=3)
            
            # 401(인증 에러)만 아니면 세션은 살아 있다는 뜻
            is_alive = (resp.status_code != 401)
            stat = "취약" if is_alive else "양호"
            

            result["vulnerabilities"].append({
                "id": "INSECURE-004",
                "type": "Insecure Design",
                "severity": "Low",
                "status": f"{stat}",
                "owasp": "A04:2021 - Insecure Design",
                "endpoint": "/auth/me",
                "payload": "5초 대기 후 세션 유효성 체크",
                "evidence": "5초 후에도 세션이 유지됨" if is_alive else "시간 경과 후 세션 만료 확인",
                "description": "세션 타임아웃 정책 미비 — 비활성 세션에 대한 강제 종료 설계 부재로 계정 탈취 위험"
            })
        except: pass

    return result