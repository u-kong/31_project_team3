from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from db.database import get_db
import jose.jwt as jwt
import datetime, os

router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = os.environ.get("SECRET_KEY", "supersecret_do_not_change")
ALGORITHM  = "HS256"  # [VULN] none 알고리즘 허용 안 하지만 secret 노출 위험

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None


# ──────────────────────────────────────────
# [VULN] SQLi: username/password 입력값을 직접 SQL에 삽입
# [VULN] Insecure Design: 로그인 실패 횟수 제한 없음, 2FA 없음
# ──────────────────────────────────────────
@router.post("/login")
def login(req: LoginRequest):
    conn = get_db()
    cur  = conn.cursor()

    # ❗ SQL Injection 취약 쿼리
    query = f"SELECT * FROM users WHERE username='{req.username}' AND password='{req.password}'"
    try:
        cur.execute(query)
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

    user = cur.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # [VULN] JWT payload에 role 포함 → 클라이언트에서 변조 가능
    payload = {
        "sub":  str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }


# ──────────────────────────────────────────
# [VULN] Insecure Design: 비밀번호 복잡도 검증 없음, 평문 저장
# ──────────────────────────────────────────
@router.post("/register")
def register(req: RegisterRequest):
    conn = get_db()
    cur  = conn.cursor()

    # ❗ 비밀번호 복잡도 검증 없음, 평문 저장
    try:
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (req.username, req.password, req.email)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    conn.close()
    return {"message": "Registration successful"}


# ──────────────────────────────────────────
# JWT 검증 헬퍼 (취약: algorithm 미검증)
# ──────────────────────────────────────────
def decode_token(token: str):
    try:
        # [VULN] algorithms 리스트를 고정하지 않으면 none 공격 가능
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
