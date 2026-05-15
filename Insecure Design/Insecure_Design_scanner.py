from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from selenium.common.exceptions import TimeoutException

import json
import time


# JSON 설정 파일 불러오기
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)


# 설정값
url = config["target_url"]
selectors = config["selectors"]
account = config["test_account"]
wrong_account = config["wrong_account"]


# 크롬 드라이버 실행
driver = webdriver.Chrome()


# 로그인 함수
def login(acc):

    driver.get(url)

    # 페이지 로딩 대기
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located(
            (By.ID, selectors["id_field"])
        )
    )

    # 아이디 입력
    id_input = driver.find_element(
        By.ID,
        selectors["id_field"]
    )

    id_input.clear()
    id_input.send_keys(acc['id'])

    # 비밀번호 입력
    pw_input = driver.find_element(
        By.ID,
        selectors["pw_field"]
    )

    pw_input.clear()
    pw_input.send_keys(acc['pw'])

    # 로그인
    pw_input.send_keys(Keys.ENTER)


    

# 송금 페이지 이동
def move_transfer_page():

    driver.get(url + "/transfer")

    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located(
            (By.ID, selectors["transfer_button"])
        )
    )

    print("[+] 송금 페이지 이동 완료")


# 송금 시도
def transfer():

    transfer_button = driver.find_element(
        By.ID,
        selectors["transfer_button"]
    )

    transfer_button.click()

    print("[+] 송금 요청 완료")


# OTP 존재 여부 확인
def check_otp():

    try:

        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located(
                (By.ID, selectors["otp_input"])
            )
        )

        print("[SAFE] OTP 인증 존재")

    except TimeoutException:

        print("[VULNERABLE] OTP 인증 없음")


def main() :
    # 전체 실행
    try :
        #로그인 brute force attack 확인
        for i in range(0, 5) :
            login(wrong_account)
        
            if f"로그인 시도 {5 - i}번 남았습니다" in driver.page_source :
                print("정상")
            
            else :
                print("bruteforce 취약")

    finally:

        driver.quit()


if __name__ == "__main__" :
    main()
