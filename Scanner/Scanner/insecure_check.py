import requests
from datetime import datetime

def get_token(base_url, username, password):
    resp = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    if resp.status_code == 200:
        return resp.json()["access_token"]
    raise Exception(f"로그인 실패: {resp.text}")

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

    # INSECURE-001: 로그인 실패 횟수 제한 없음 (브루트포스)
    block = False
    for i in range(5):
        resp = requests.post(f"{base_url}/auth/login", json={
            "username": wrong_account["id"],
            "password": wrong_account["pw"]
        })
        if "Too many attempts" in resp.text:
            block = True
            break

    result["vulnerabilities"].append({
        "id": "INSECURE-001",
        "type": "Insecure Design",
        "severity": "High",
        "status": "양호" if block else "취약",
        "owasp": "A04:2021 - Insecure Design",
        "endpoint": "/auth/login",
        "payload": f"잘못된 비밀번호로 5회 연속 로그인 시도",
        "detected_keywords": ["Too many attempts"],
        "evidence": "5회 실패 후에도 로그인 시도 차단 없음" if not block else "5회 실패 후 차단 확인",
        "description": "로그인 실패 횟수 제한 없음 — 브루트포스 공격으로 계정 탈취 가능"
    })

    # INSECURE-002: 2차 인증 없음
    try:
        token = get_token(base_url, test_account["id"], test_account["pw"])
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.post(f"{base_url}/transfer",
            json={
                "from_account_id": 1,
                "to_account_id": 2,
                "amount": 10000,
                "description": "2차인증 테스트"
            },
            headers=headers
        )

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

    except Exception as e:
        pass

    # INSECURE-003: 비밀번호 복잡도 검증 없음
    resp = requests.post(f"{base_url}/auth/register", json={
        "username": "weakpw_test",
        "password": "1234",
        "email": "test@test.com"
    })

    weak_accepted = resp.status_code == 200

    result["vulnerabilities"].append({
        "id": "INSECURE-003",
        "type": "Insecure Design",
        "severity": "Medium",
        "status": "취약" if weak_accepted else "양호",
        "owasp": "A04:2021 - Insecure Design",
        "endpoint": "/auth/register",
        "payload": "password=1234 (4자리 숫자)",
        "detected_keywords": [],
        "evidence": "'1234' 비밀번호로 회원가입 성공" if weak_accepted else "약한 비밀번호 차단 확인",
        "description": "비밀번호 복잡도 검증 없음 — 특수문자, 최소 길이 등 정책 미적용"
    })

    return result