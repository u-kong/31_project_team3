from fastapi import APIRouter, HTTPException, Header
from routers.auth import decode_token
from typing import Optional
import requests

router = APIRouter(prefix="/exchange", tags=["exchange"])

ALLOWED_CURRENCIES = {"USD", "EUR", "JPY", "CNY", "GBP"}


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization.split(" ")[1])


# [PATCH] SSRF 방어
#  - url 파라미터 완전 제거
#  - currency 화이트리스트 검증
#  - 서버가 허용된 API(frankfurter.app)만 직접 호출
@router.get("/rate")
def get_exchange_rate(currency: str = "USD", authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)

    if currency not in ALLOWED_CURRENCIES:
        raise HTTPException(status_code=404, detail="Currency not found")

    try:
        resp = requests.get(
            f"https://api.frankfurter.app/latest?from=KRW&to={currency}",
            timeout=5
        )
        data = resp.json()
        rate = round(1 / data["rates"][currency], 2)
        return {"currency": currency, "rate": rate, "change": 0, "change_pct": 0}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"환율 데이터를 가져올 수 없습니다: {str(e)}")


@router.get("/rates")
def get_all_rates(authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)

    try:
        resp = requests.get(
            "https://api.frankfurter.app/latest?from=KRW&to=USD,EUR,JPY,CNY,GBP",
            timeout=5
        )
        data = resp.json()
        result = {}
        for cur, value in data["rates"].items():
            result[cur] = {
                "rate": round(1 / value, 2),
                "change": 0,
                "change_pct": 0
            }
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"환율 데이터를 가져올 수 없습니다: {str(e)}")


@router.get("/rates/live")
def get_live_rates(authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)

    try:
        resp = requests.get(
            "https://api.frankfurter.app/latest?from=KRW&to=USD,EUR,JPY,CNY,GBP",
            timeout=5
        )
        data = resp.json()
        result = {}
        for currency, value in data["rates"].items():
            result[currency] = {
                "rate": round(1 / value, 2),
                "change": 0,
                "change_pct": 0
            }
        return {"date": data["date"], "rates": result}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"환율 데이터를 가져올 수 없습니다: {str(e)}")
