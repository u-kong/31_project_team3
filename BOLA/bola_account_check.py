import argparse
import json
import sys
from urllib.parse import urljoin

import requests


def build_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def login(base_url: str, username: str, password: str) -> dict:
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
            "password": password
        },
        timeout=5
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"로그인 실패: username={username}, "
            f"status={response.status_code}, body={response.text[:300]}"
        )

    data = response.json()

    access_token = data.get("access_token")
    user = data.get("user")

    if not access_token:
        raise RuntimeError(f"access_token이 응답에 없습니다: {data}")

    if not user:
        raise RuntimeError(f"user 정보가 응답에 없습니다: {data}")

    return {
        "username": username,
        "access_token": access_token,
        "user": user
    }


def auth_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}"
    }


def get_my_accounts(base_url: str, access_token: str) -> list:
    """
    GET /accounts/my
    정상 기능을 이용해 현재 로그인 사용자의 계좌 ID를 가져옵니다.
    """
    url = build_url(base_url, "/accounts/my")

    response = requests.get(
        url,
        headers=auth_headers(access_token),
        timeout=5
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"내 계좌 조회 실패: status={response.status_code}, "
            f"body={response.text[:300]}"
        )

    return response.json()


def get_account_by_id(base_url: str, access_token: str, account_id: int) -> requests.Response:
    """
    GET /accounts?id={account_id}
    BOLA 진단 대상 API입니다.
    """
    url = build_url(base_url, "/accounts")

    response = requests.get(
        url,
        headers=auth_headers(access_token),
        params={"id": account_id},
        timeout=5
    )

    return response


def safe_json(response: requests.Response):
    try:
        return response.json()
    except Exception:
        return None


def run_bola_check(
    base_url: str,
    user_a: str,
    pass_a: str,
    user_b: str,
    pass_b: str
) -> dict:
    """
    사용자 A 토큰으로 사용자 B의 account_id에 접근 가능한지 확인합니다.
    """

    result = {
        "check_name": "BOLA Account Object Authorization Check",
        "target_api": "GET /accounts?id={account_id}",
        "base_url": base_url,
        "status": "UNKNOWN",
        "details": {}
    }

    # 1. 사용자 A, B 로그인
    login_a = login(base_url, user_a, pass_a)
    login_b = login(base_url, user_b, pass_b)

    token_a = login_a["access_token"]
    token_b = login_b["access_token"]

    user_a_info = login_a["user"]
    user_b_info = login_b["user"]

    # 2. 정상 기능으로 각자의 계좌 조회
    accounts_a = get_my_accounts(base_url, token_a)
    accounts_b = get_my_accounts(base_url, token_b)

    if not accounts_a:
        raise RuntimeError(f"{user_a} 계정의 계좌가 없습니다.")

    if not accounts_b:
        raise RuntimeError(f"{user_b} 계정의 계좌가 없습니다.")

    account_a = accounts_a[0]
    account_b = accounts_b[0]

    account_a_id = account_a["id"]
    account_b_id = account_b["id"]

    # 3. 정상 접근 확인: A가 자기 계좌 조회
    normal_a_response = get_account_by_id(base_url, token_a, account_a_id)
    normal_a_data = safe_json(normal_a_response)

    # 4. 정상 접근 확인: B가 자기 계좌 조회
    normal_b_response = get_account_by_id(base_url, token_b, account_b_id)
    normal_b_data = safe_json(normal_b_response)

    # 5. BOLA 진단: A 토큰으로 B 계좌 조회
    bola_response = get_account_by_id(base_url, token_a, account_b_id)
    bola_data = safe_json(bola_response)

    result["details"] = {
        "user_a": {
            "username": user_a,
            "user_id": user_a_info.get("id"),
            "own_account_id": account_a_id
        },
        "user_b": {
            "username": user_b,
            "user_id": user_b_info.get("id"),
            "own_account_id": account_b_id
        },
        "normal_check_user_a_own_account": {
            "request": f"GET /accounts?id={account_a_id}",
            "status_code": normal_a_response.status_code,
            "response": normal_a_data
        },
        "normal_check_user_b_own_account": {
            "request": f"GET /accounts?id={account_b_id}",
            "status_code": normal_b_response.status_code,
            "response": normal_b_data
        },
        "bola_check_user_a_access_user_b_account": {
            "request": f"GET /accounts?id={account_b_id}",
            "status_code": bola_response.status_code,
            "response": bola_data
        }
    }

    # 6. 취약 여부 판단
    if bola_response.status_code == 200:
        returned_user_id = None

        if isinstance(bola_data, dict):
            returned_user_id = bola_data.get("user_id")

        result["status"] = "VULNERABLE"
        result["reason"] = (
            f"{user_a}의 인증 토큰으로 {user_b}의 계좌 객체에 접근했는데 "
            f"서버가 200 OK를 반환했습니다. 객체 소유자 검증이 누락된 BOLA 취약점 가능성이 높습니다."
        )

        if returned_user_id is not None:
            result["evidence"] = {
                "expected_user_id": user_a_info.get("id"),
                "returned_account_user_id": returned_user_id,
                "accessed_account_id": account_b_id
            }

    elif bola_response.status_code in [401, 403, 404]:
        result["status"] = "NOT_VULNERABLE"
        result["reason"] = (
            f"{user_a}의 인증 토큰으로 {user_b}의 계좌 객체 접근을 시도했지만 "
            f"서버가 {bola_response.status_code} 응답을 반환하여 접근이 차단되었습니다."
        )

    else:
        result["status"] = "NEEDS_REVIEW"
        result["reason"] = (
            f"예상과 다른 상태 코드가 반환되었습니다. "
            f"status_code={bola_response.status_code}"
        )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="NeoBanK BOLA 자동진단 스크립트"
    )

    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="진단 대상 백엔드 API 주소"
    )

    parser.add_argument(
        "--user-a",
        default="alice",
        help="공격자 역할로 사용할 일반 사용자 계정"
    )

    parser.add_argument(
        "--pass-a",
        default="alice1234",
        help="user-a 비밀번호"
    )

    parser.add_argument(
        "--user-b",
        default="bob",
        help="피해자 역할로 사용할 일반 사용자 계정"
    )

    parser.add_argument(
        "--pass-b",
        default="bob5678",
        help="user-b 비밀번호"
    )

    args = parser.parse_args()

    try:
        result = run_bola_check(
            base_url=args.base_url,
            user_a=args.user_a,
            pass_a=args.pass_a,
            user_b=args.user_b,
            pass_b=args.pass_b
        )

        print(json.dumps(result, ensure_ascii=False, indent=2))

        if result["status"] == "VULNERABLE":
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        error_result = {
            "check_name": "BOLA Account Object Authorization Check",
            "status": "ERROR",
            "reason": str(e)
        }
        print(json.dumps(error_result, ensure_ascii=False, indent=2))
        sys.exit(2)


if __name__ == "__main__":
    main()