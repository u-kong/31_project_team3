from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from db.database import get_db
from routers.auth import decode_token
from typing import Optional

router = APIRouter(prefix="/transfer", tags=["transfer"])


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization.split(" ")[1])


class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float
    description: str = ""


# ──────────────────────────────────────────
# [VULN] BOLA: from_account_id 소유자 검증 없음 → 남의 계좌에서 이체 가능
# ──────────────────────────────────────────
@router.post("")
def transfer(req: TransferRequest, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()

    # ❗ 출금 계좌 소유자 확인 없음
    cur.execute("SELECT * FROM accounts WHERE id=?", (req.from_account_id,))
    from_acc = cur.fetchone()

    cur.execute("SELECT * FROM accounts WHERE id=?", (req.to_account_id,))
    to_acc = cur.fetchone()

    if not from_acc or not to_acc:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    if from_acc["balance"] < req.amount:
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    cur.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (req.amount, req.from_account_id))
    cur.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (req.amount, req.to_account_id))
    cur.execute(
        "INSERT INTO transactions (from_account_id,to_account_id,amount,description) VALUES (?,?,?,?)",
        (req.from_account_id, req.to_account_id, req.amount, req.description)
    )
    conn.commit()
    conn.close()
    return {"message": "Transfer successful"}


# ──────────────────────────────────────────
# [VULN] Broken Access Control: role 검증을 JWT payload에서만 확인
# → JWT 변조로 role=admin 주입 시 접근 가능
# ──────────────────────────────────────────
@router.post("/admin/force")
def admin_force_transfer(req: TransferRequest, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)

    # ❗ DB 조회 없이 토큰 payload의 role만 확인
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id=?", (req.from_account_id,))
    from_acc = cur.fetchone()
    cur.execute("SELECT * FROM accounts WHERE id=?", (req.to_account_id,))
    to_acc = cur.fetchone()

    if not from_acc or not to_acc:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    cur.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (req.amount, req.from_account_id))
    cur.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (req.amount, req.to_account_id))
    conn.commit()
    conn.close()
    return {"message": "[ADMIN] Force transfer complete"}


# 거래 내역 조회 (IDOR 포함)
@router.get("/history")
def transfer_history(account_id: int, authorization: Optional[str] = Header(default=None)):
    get_current_user(authorization)  # 소유자 확인 ❌
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM transactions WHERE from_account_id=? OR to_account_id=? ORDER BY created_at DESC",
        (account_id, account_id)
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
