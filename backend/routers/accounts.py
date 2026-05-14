from fastapi import APIRouter, HTTPException, Request, Header
from db.database import get_db
from routers.auth import decode_token
from typing import Optional

router = APIRouter(prefix="/accounts", tags=["accounts"])


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    return decode_token(token)


# ──────────────────────────────────────────
# [VULN] SQLi: account_number 검색 시 직접 삽입
# ──────────────────────────────────────────
@router.get("/search")
def search_account(q: str, authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()

    # ❗ SQL Injection 취약 쿼리
    query = f"SELECT * FROM accounts WHERE account_number LIKE '%{q}%'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

    conn.close()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────
# [VULN] IDOR: id 파라미터로 아무 계좌나 조회 가능 (소유자 확인 없음)
# [VULN] BOLA: 객체 레벨 권한 검증 없음
# ──────────────────────────────────────────
@router.get("")
def get_account(id: int, authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)  # 로그인만 확인, 소유자 확인 ❌
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id=?", (id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Account not found")
    return dict(row)


# ──────────────────────────────────────────
# 내 계좌 목록 (정상 - 비교용)
# ──────────────────────────────────────────
@router.get("/my")
def my_accounts(authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE user_id=?", (user["sub"],))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
