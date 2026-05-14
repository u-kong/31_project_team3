from fastapi import APIRouter, Header
from db.database import get_db
from typing import Optional

router = APIRouter(prefix="/admin", tags=["admin"])

# ──────────────────────────────────────────
# [VULN] Broken Access Control: 인증/인가 검증 전혀 없음
# → 누구든 /admin/* 엔드포인트 접근 가능
# ──────────────────────────────────────────

@router.get("/users")
def get_all_users():
    # ❗ 토큰 확인 없음
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, username, email, role, password, created_at FROM users")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/accounts")
def get_all_accounts():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/transactions")
def get_all_transactions():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM transactions ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted"}
