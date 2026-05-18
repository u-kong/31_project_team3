from fastapi import APIRouter, HTTPException, Request, Header
from db.database import get_db
from routers.auth import decode_token
from typing import Optional

router = APIRouter(prefix="/accounts", tags=["accounts"])


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization.split(" ")[1])


# [PATCH] SQLi → 파라미터 바인딩
# [PATCH] 본인 계좌만 검색되도록 user_id 필터 추가
@router.get("/search")
def search_account(q: str, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM accounts WHERE account_number LIKE ? AND user_id=?",
        (f"%{q}%", user["sub"])
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# [PATCH] IDOR/BOLA → 계좌 소유자(user_id) 검증 추가
@router.get("")
def get_account(id: int, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id=?", (id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Account not found")
    if str(row["user_id"]) != str(user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")

    return dict(row)


@router.get("/my")
def my_accounts(authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE user_id=?", (user["sub"],))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
