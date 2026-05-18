import sqlite3
import os
from passlib.context import CryptContext

DB_PATH = os.environ.get("DB_PATH", "./data/neobank.db")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            transfer_pin TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # [PATCH] 기존 테이블에 transfer_pin 컬럼 없으면 추가
    try:
        cur.execute("ALTER TABLE users ADD COLUMN transfer_pin TEXT")
    except Exception:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0.0,
            account_type TEXT DEFAULT 'checking',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account_id INTEGER,
            to_account_id INTEGER,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 시드 비밀번호 bcrypt 해시 적용
    # 실제 비밀번호: Alice@1234 / Bob@5678 / Charlie@9999 / Admin@Secure1
    # 이체 PIN: 1234 (모든 계정 동일, 테스트용)
    transfer_pin_hash = pwd_context.hash("1234")

    users = [
        (1, "alice",   pwd_context.hash("Alice@1234"),   "alice@neobank.io",   "user",  transfer_pin_hash),
        (2, "bob",     pwd_context.hash("Bob@5678"),     "bob@neobank.io",     "user",  transfer_pin_hash),
        (3, "charlie", pwd_context.hash("Charlie@9999"), "charlie@neobank.io", "user",  transfer_pin_hash),
        (4, "admin",   pwd_context.hash("Admin@Secure1"),"admin@neobank.io",   "admin", transfer_pin_hash),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO users (id,username,password,email,role,transfer_pin) VALUES (?,?,?,?,?,?)",
        users
    )

    # 기존 유저 transfer_pin 업데이트
    cur.execute("UPDATE users SET transfer_pin=? WHERE transfer_pin IS NULL", (transfer_pin_hash,))

    accounts = [
        (1, 1, "110-2024-000001", 1500000.0,  "checking"),
        (2, 2, "110-2024-000002",  830000.0,  "checking"),
        (3, 3, "110-2024-000003", 3200000.0,  "savings"),
        (4, 4, "110-2024-000004", 50000000.0, "admin"),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO accounts (id,user_id,account_number,balance,account_type) VALUES (?,?,?,?,?)",
        accounts
    )

    transactions_data = [
        (1, 2, 100000, "월세 이체"),
        (2, 1,  50000, "커피값 정산"),
        (3, 1, 200000, "급여"),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO transactions (from_account_id,to_account_id,amount,description) VALUES (?,?,?,?)",
        transactions_data
    )

    conn.commit()
    conn.close()
    print("[DB] Initialized successfully.")
