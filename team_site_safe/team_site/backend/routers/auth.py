from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from db.database import get_db
import jose.jwt as jwt
import datetime, os, re
from passlib.context import CryptContext

router = APIRouter(prefix="/auth", tags=["auth"])

# [PATCH] 기본값 제거 → 미설정 시 서버 기동 차단
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY 환경변수가 설정되지 않았습니다.")
ALGORITHM = "HS256"

# [PATCH] bcrypt 해시 컨텍스트
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# [PATCH] 로그인 실패 횟수 제한 (15분 내 5회)
_login_attempts: dict[str, list[datetime.datetime]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _check_rate_limit(username: str):
    now = datetime.datetime.utcnow()
    window = now - datetime.timedelta(minutes=LOCKOUT_MINUTES)
    attempts = [t for t in _login_attempts.get(username, []) if t > window]
    _login_attempts[username] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail=f"로그인 시도가 너무 많습니다. {LOCKOUT_MINUTES}분 후 다시 시도하세요.")


def _record_failure(username: str):
    _login_attempts.setdefault(username, []).append(datetime.datetime.utcnow())


def _clear_attempts(username: str):
    _login_attempts.pop(username, None)


# [PATCH] 비밀번호 복잡도 검증
def _validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="비밀번호는 최소 8자 이상이어야 합니다.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="비밀번호에 대문자가 포함되어야 합니다.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="비밀번호에 소문자가 포함되어야 합니다.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="비밀번호에 숫자가 포함되어야 합니다.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(status_code=400, detail="비밀번호에 특수문자가 포함되어야 합니다.")


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None


# [PATCH] SQLi → 파라미터 바인딩
# [PATCH] 로그인 횟수 제한
# [PATCH] bcrypt 검증
@router.post("/login")
def login(req: LoginRequest):
    _check_rate_limit(req.username) # 테스트 중 비활성화
    print(f"[DEBUG] username={req.username}, password={req.password}")
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (req.username,))
    user = cur.fetchone()
    conn.close()

    if not user or not pwd_context.verify(req.password, user["password"]):
        _record_failure(req.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    _clear_attempts(req.username)

    # [PATCH] JWT payload에서 role 제거 → 권한 확인은 DB에서
    payload = {
        "sub":      str(user["id"]),
        "username": user["username"],
        "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=2),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user["id"], "username": user["username"]}
    }
    


# [PATCH] 비밀번호 복잡도 검증 + bcrypt 해시 저장
@router.post("/register")
def register(req: RegisterRequest):
    _validate_password(req.password)

    hashed = pwd_context.hash(req.password)
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (req.username, hashed, req.email)
        )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    conn.close()
    return {"message": "Registration successful"}


# [PATCH] none 알고리즘 제거
def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
