from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from db.database import get_db, pwd_context
from routers.auth import decode_token
from typing import Optional

router = APIRouter(prefix="/transfer", tags=["transfer"])


def get_current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(authorization.split(" ")[1])


def get_db_role(user_id: str) -> str:
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row["role"]


class TransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float
    description: str = ""
    transfer_pin: str  # [PATCH] 2차 인증 PIN 추가


class AdminTransferRequest(BaseModel):
    from_account_id: int
    to_account_id: int
    amount: float
    description: str = ""


# [PATCH] BOLA → 소유자 검증
# [PATCH] 2차 인증 → transfer_pin 검증
@router.post("")
def transfer(req: TransferRequest, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()

    # [PATCH] 2차 인증 PIN 검증
    cur.execute("SELECT transfer_pin FROM users WHERE id=?", (user["sub"],))
    user_row = cur.fetchone()
    if not user_row or not user_row["transfer_pin"]:
        conn.close()
        raise HTTPException(status_code=403, detail="이체 비밀번호가 설정되지 않았습니다.")
    if not pwd_context.verify(req.transfer_pin, user_row["transfer_pin"]):
        conn.close()
        raise HTTPException(status_code=403, detail="이체 비밀번호가 틀렸습니다.")

    cur.execute("SELECT * FROM accounts WHERE id=?", (req.from_account_id,))
    from_acc = cur.fetchone()
    cur.execute("SELECT * FROM accounts WHERE id=?", (req.to_account_id,))
    to_acc = cur.fetchone()

    if not from_acc or not to_acc:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")

    # [PATCH] 출금 계좌 소유자 확인
    if str(from_acc["user_id"]) != str(user["sub"]):
        conn.close()
        raise HTTPException(status_code=403, detail="본인 계좌에서만 이체할 수 있습니다.")

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


# [PATCH] BFLA → DB에서 role 조회
@router.post("/admin/force")
def admin_force_transfer(req: AdminTransferRequest, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)

    db_role = get_db_role(user["sub"])
    if db_role != "admin":
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


# [PATCH] IDOR → 계좌 소유자 확인
@router.get("/history")
def transfer_history(account_id: int, authorization: Optional[str] = Header(default=None)):
    user = get_current_user(authorization)
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("SELECT user_id FROM accounts WHERE id=?", (account_id,))
    acc = cur.fetchone()
    if not acc:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")
    if str(acc["user_id"]) != str(user["sub"]):
        conn.close()
        raise HTTPException(status_code=403, detail="Access denied")

    cur.execute(
        "SELECT * FROM transactions WHERE from_account_id=? OR to_account_id=? ORDER BY created_at DESC",
        (account_id, account_id)
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]
