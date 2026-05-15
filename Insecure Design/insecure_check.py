import requests
import json


# config.json 불러오기
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)


account = config["test_account"]
wrong_account = config["wrong_account"]


# 세션 생성
session = requests.Session()

# 로그인 토큰
access = ""


# 로그인 함수
def login(base_url, acc):

    global access

    login_url = base_url + "/auth/login"

    payload = {
        "username": acc["id"],
        "password": acc["pw"]
    }

    response = session.post(
        login_url,
        json=payload
    )

    # 로그인 성공 시 토큰 저장
    if response.status_code == 200:

        response_json = response.json()

        access = response_json["access_token"]

    return response


# 송금 요청
def transfer(base_url):

    transfer_url = base_url + "/transfer"

    payload = {
        "from_account_id": 123123123,
        "to_account_id": 111222333,
        "amount": 10000,
        "description": "test"
    }

    headers = {
        "Authorization": f"Bearer {access}"
    }

    response = session.post(
        transfer_url,
        json=payload,
        headers=headers
    )

    return response


# 2차 인증 여부 검사
def check_second_password(response_text, result):

    keywords = [
        "2차 비밀번호",
        "OTP",
        "추가 인증",
        "secondary password"
    ]

    for keyword in keywords:

        if keyword.lower() in response_text.lower():

            result["SecondPassword"] = "[SAFE] 추가 인증 존재"

            return

    result["SecondPassword"] = "[VULNERABLE] 추가 인증 없음"


# 메인 검사 함수
def insecure_check(base_url):

    result = {
        "module": "Insecure Design",
        "BruteForce": "",
        "SecondPassword": ""
    }

    block = False

    # 브루트포스 검사
    for i in range(0, 5):

        response_login = login(base_url, wrong_account)

        if "Too many attempts" in response_login.text:

            block = True
            break


    if not block:

        result["BruteForce"] = "VULNERABLE"

    else:

        result["BruteForce"] = "SAFE"


    # 정상 로그인
    login(base_url, account)

    # 송금 요청
    transfer_response = transfer(base_url)

    # 2차 인증 검사
    check_second_password(
        transfer_response.text,
        result
    )

    return result
