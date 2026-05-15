import argparse
import json
import sys
from urllib.parse import urljoin
from datetime import datetime
import requests


DEFAULT_ENDPOINTS = [
    "/admin/users",
    "/admin/accounts",
    "/admin/transactions",
]


SENSITIVE_KEYS = {
    "password",
    "access_token",
    "token",
    "secret",
    "authorization",
}


def build_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def mask_sensitive_data(data):
    """
    관리자 API 응답에 password 같은 민감정보가 포함될 수 있으므로
    결과 출력 시 민감 필드는 마스킹합니다.
    """
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                masked[key] = "***MASKED***"
            else:
                masked[key] = mask_sensitive_data(value)
        return masked

    if isinstance(data, list):
        return [mask_sensitive_data(item) for item in data[:3]]

    return data


def safe_json(response: requests.Response):
    try:
        return response.json()
    except Exception:
        return None


def make_response_summary(response: requests.Response) -> dict:
    data = safe_json(response)

    summary = {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
    }

    if data is not None:
        summary["response_preview"] = mask_sensitive_data(data)
    else:
        summary["response_preview"] = response.text[:300]

    return summary


def login(base_url: str, username: str, password: str, timeout: int) -> dict:
    """
    POST /auth/login
    요청: {"username": "...", "password": "..."}
    응답: {"access_token": "...", "user": {...}}
    """
    url = build_url(base_url, "/auth/login")

    response = requests.post(
        url,
        json={
            "username": username,
            "password": password,
        },
        timeout=timeout,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"로그인 실패: username={username}, "
            f"status={response.status_code}, body={response.text[:300]}"
        )

    data = response.json()

    access_token = data.get("access_token")
    user = data.get("user", {})

    if not access_token:
        raise RuntimeError(f"로그인 응답에 access_token이 없습니다: {data}")

    return {
        "access_token": access_token,
        "user": user,
    }


def auth_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}"
    }


def request_admin_endpoint(
    base_url: str,
    endpoint: str,
    access_token: str | None,
    timeout: int
) -> requests.Response:
    url = build_url(base_url, endpoint)

    headers = {}
    if access_token:
        headers = auth_headers(access_token)

    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
    )

    return response


def is_success_response(status_code: int) -> bool:
    return 200 <= status_code < 300


def run_bfla_check(
    base_url: str,
    username: str,
    password: str,
    endpoints: list[str],
    timeout: int
) -> dict:
    result = {
        "check_name": "BFLA Admin Function Authorization Check",
        "base_url": base_url,
        "status": "UNKNOWN",
        "summary": {
            "target_endpoints": endpoints,
            "test_user": username,
        },
        "findings": [],
    }

    # 1. 일반 사용자 로그인
    login_result = login(base_url, username, password, timeout)
    access_token = login_result["access_token"]
    user_info = login_result["user"]

    result["summary"]["login_user"] = {
        "id": user_info.get("id"),
        "username": user_info.get("username"),
        "role": user_info.get("role"),
    }

    vulnerable_count = 0

    for endpoint in endpoints:
        finding = {
            "endpoint": endpoint,
            "method": "GET",
            "checks": {},
            "status": "UNKNOWN",
            "reason": "",
        }

        # 2. 토큰 없이 관리자 API 접근 가능 여부 확인
        no_auth_response = request_admin_endpoint(
            base_url=base_url,
            endpoint=endpoint,
            access_token=None,
            timeout=timeout,
        )

        finding["checks"]["without_token"] = make_response_summary(no_auth_response)

        # 3. 일반 사용자 토큰으로 관리자 API 접근 가능 여부 확인
        user_token_response = request_admin_endpoint(
            base_url=base_url,
            endpoint=endpoint,
            access_token=access_token,
            timeout=timeout,
        )

        finding["checks"]["normal_user_token"] = make_response_summary(user_token_response)

        no_auth_success = is_success_response(no_auth_response.status_code)
        normal_user_success = is_success_response(user_token_response.status_code)

        # 4. 취약 여부 판단
        if no_auth_success and normal_user_success:
            finding["status"] = "VULNERABLE"
            finding["reason"] = (
                "토큰이 없는 요청과 일반 사용자 토큰 요청 모두 관리자 API 접근에 성공했습니다. "
                "Missing Authentication 및 BFLA 취약 가능성이 높습니다."
            )
            vulnerable_count += 1

        elif no_auth_success:
            finding["status"] = "VULNERABLE"
            finding["reason"] = (
                "토큰이 없는 요청으로 관리자 API 접근에 성공했습니다. "
                "인증 검증이 누락된 Broken Access Control 취약 가능성이 높습니다."
            )
            vulnerable_count += 1

        elif normal_user_success:
            finding["status"] = "VULNERABLE"
            finding["reason"] = (
                "일반 사용자 토큰으로 관리자 API 접근에 성공했습니다. "
                "관리자 기능에 대한 권한 검증이 누락된 BFLA 취약 가능성이 높습니다."
            )
            vulnerable_count += 1

        elif no_auth_response.status_code in [401, 403] and user_token_response.status_code in [401, 403]:
            finding["status"] = "NOT_VULNERABLE"
            finding["reason"] = (
                "토큰이 없는 요청과 일반 사용자 요청 모두 차단되었습니다."
            )

        else:
            finding["status"] = "NEEDS_REVIEW"
            finding["reason"] = (
                "예상과 다른 응답 코드가 반환되었습니다. "
                "수동 확인이 필요합니다."
            )

        result["findings"].append(finding)

    if vulnerable_count > 0:
        result["status"] = "VULNERABLE"
        result["summary"]["vulnerable_endpoint_count"] = vulnerable_count
    else:
        result["status"] = "NOT_VULNERABLE"
        result["summary"]["vulnerable_endpoint_count"] = 0

    return result


def main():
    parser = argparse.ArgumentParser(
        description="NeoBanK BFLA 관리자 기능 접근통제 자동진단 스크립트"
    )

    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="진단 대상 백엔드 API 주소"
    )

    parser.add_argument(
        "--username",
        default="alice",
        help="일반 사용자 계정"
    )

    parser.add_argument(
        "--password",
        default="alice1234",
        help="일반 사용자 비밀번호"
    )

    parser.add_argument(
        "--endpoints",
        nargs="*",
        default=DEFAULT_ENDPOINTS,
        help="진단할 관리자 API 엔드포인트 목록"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="요청 타임아웃 초"
    )

    args = parser.parse_args()

    try:
        result = run_bfla_check(
            base_url=args.base_url,
            username=args.username,
            password=args.password,
            endpoints=args.endpoints,
            timeout=args.timeout,
        )

        print(json.dumps(result, ensure_ascii=False, indent=2))

        if result["status"] == "VULNERABLE":
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        error_result = {
            "check_name": "BFLA Admin Function Authorization Check",
            "status": "ERROR",
            "reason": str(e),
        }
        print(json.dumps(error_result, ensure_ascii=False, indent=2))
        sys.exit(2)


def bfla_check(base_url):
    result_raw = run_bfla_check(
        base_url=base_url,
        username="alice",
        password="alice1234",
        endpoints=DEFAULT_ENDPOINTS,
        timeout=5
    )

    result = {
        "scan_id": "BFLA",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": []
    }

    for finding in result_raw["findings"]:
        result["vulnerabilities"].append({
            "id": f"BFLA-{result_raw['findings'].index(finding)+1:03d}",
            "type": "BFLA",
            "severity": "Critical" if finding["status"] == "VULNERABLE" else "Low",
            "status": "취약" if finding["status"] == "VULNERABLE" else "양호",
            "owasp": "A01:2021 - Broken Access Control",
            "endpoint": finding["endpoint"],
            "payload": "일반 사용자 토큰으로 관리자 API 접근 시도",
            "detected_keywords": [],
            "evidence": finding["reason"],
            "description": f"관리자 전용 엔드포인트 {finding['endpoint']} 에 일반 사용자 접근 가능 — 권한 검증 없음"
        })

    return result

if __name__ == "__main__":
    main()