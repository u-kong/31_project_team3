import requests
import json


# config.json 불러오기
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)


# 설정값
BASE_URL = config["target_url"]
account = config["test_account"]
wrong_account = config["wrong_account"]

# 세션 생성
session = requests.Session()

#로그인 토큰
access = ""

#결과 저장
result = {
    "BruteForce": "",
    "SecondPassword": "",
}



# 로그인 함수
def login(acc):
    
    global access

    login_url = BASE_URL + "/auth/login"

    payload = {
        "username": acc["id"],
        "password": acc["pw"]
    }

    response = session.post(
        login_url,
        json=payload
    )
    
    #로그인 성공시 해당 토큰을 저장
    if response.status_code == 200 :
        response_json = response.json()
        access = response_json["access_token"]

    return response


# 송금 요청
def transfer():

    transfer_url = BASE_URL + "/transfer"

    payload = {
        "from_account_id" : 123123123,
        "to_account_id": 111222333,
        "amount": 10000,
        "description" : "test"
        
    }
    
    headers = { "Authorization": f"Bearer {access}" }

    response = session.post(
        transfer_url,
        json=payload,
        headers=headers
    )


    return response


# 2차 인증 여부 검사
def check_second_password(response_text):

    keywords = [
        "2차 비밀번호",
        "OTP",
        "추가 인증",
        "secondary password"
    ]

    for keyword in keywords:

        if keyword.lower() in response_text.lower():

            result["SeSecondPassword"] = "[SAFE] 추가 인증 존재"

            return

    result["SecondPassword"] = "[VULNERABLE] 추가 인증 없음"


# 메인 실행
def main():
    block = False
    for i in range(0, 5) :
        response_login = login(wrong_account)
        
        if "Too many attempts" in response_login.text :
            block = True
            break
    
    if not block :
        result["BruteForce"] = "VULNERABLE"
    
    login(account)
    
    transfer_response = transfer()
    print(transfer_response.text)
    check_second_password(transfer_response.text)
    
    with open("result.json", "w", encoding="utf-8") as f :
        json.dump(
            result, f, ensure_ascii=False, indent=4
        )
        



if __name__ == "__main__":
    main()

