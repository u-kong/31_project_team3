from fastapi import APIRouter, HTTPException, Header
from db.database import get_db
from routers.auth import decode_token
from typing import Optional

router = APIRouter(prefix="/admin", tags=["admin"])


# [PATCH] BFLA → 모든 엔드포인트에 JWT 검증 + DB role 이중 확인
def require_admin(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(authorization.split(" ")[1])

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id=?", (payload["sub"],))
    row = cur.fetchone()
    conn.close()

    if not row or row["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return payload


@router.get("/users")
def get_all_users(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    cur  = conn.cursor()
    # [PATCH] password 컬럼 제외
    cur.execute("SELECT id, username, email, role, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/accounts")
def get_all_accounts(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/transactions")
def get_all_transactions(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.delete("/users/{user_id}")
def delete_user(user_id: int, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted"}
