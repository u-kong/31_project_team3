from fastapi import APIRouter, HTTPException, Header
from routers.auth import decode_token
from typing import Optional
import requests

router = APIRouter(prefix="/exchange", tags=["exchange"])


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization.split(" ")[1])


# [VULN] SSRF: url 파라미터를 검증 없이 서버에서 직접 fetch
@router.get("/rate")
def get_exchange_rate(url: Optional[str] = None, currency: str = "USD",
                      authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)

    if url:
        try:
            resp = requests.get(url, timeout=5)
            return {"source": url, "raw": resp.text[:2000]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    rates = {
        "USD": {"rate": 1354.20, "change": +3.50, "change_pct": +0.26},
        "EUR": {"rate": 1487.30, "change": -2.10, "change_pct": -0.14},
        "JPY": {"rate":   9.05, "change": +0.03, "change_pct": +0.33},
        "CNY": {"rate": 186.40, "change": +0.80, "change_pct": +0.43},
        "GBP": {"rate": 1721.60, "change": -5.20, "change_pct": -0.30},
    }
    if currency not in rates:
        raise HTTPException(status_code=404, detail="Currency not found")
    return {"currency": currency, **rates[currency]}


# 목업 환율 (기본 표시용)
@router.get("/rates")
def get_all_rates(authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)
    return {
        "USD": {"rate": 1492.54, "change": +3.50,  "change_pct": +0.26},
        "EUR": {"rate": 1754.39, "change": -2.10,  "change_pct": -0.14},
        "JPY": {"rate":   9.44, "change": +0.03,  "change_pct": +0.33},
        "CNY": {"rate": 219.78, "change": +0.80,  "change_pct": +0.43},
        "GBP": {"rate": 2000.00, "change": -5.20,  "change_pct": -0.30},
    }


# 실제 환율 — frankfurter.app (ECB 기준, 1외화 = N원으로 변환)
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
            result[currency] = {"rate": round(1 / value, 2)}
        return {"date": data["date"], "rates": result}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"환율 데이터를 가져올 수 없습니다: {str(e)}")