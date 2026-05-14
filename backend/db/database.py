import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "./data/neobank.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    # ── 유저 테이블 (비밀번호 평문 저장 - Insecure Design)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ── 계좌 테이블
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

    # ── 거래 내역 테이블
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

    # ── 시드 데이터
    users = [
        (1, "alice",   "alice1234",   "alice@neobank.io",  "user"),
        (2, "bob",     "bob5678",     "bob@neobank.io",    "user"),
        (3, "charlie", "charlie9999", "charlie@neobank.io","user"),
        (4, "admin",   "admin_secret","admin@neobank.io",  "admin"),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO users (id,username,password,email,role) VALUES (?,?,?,?,?)",
        users
    )

    # 유저당 계좌 1개 (IDOR: id=1~4 순서대로 다른 유저 계좌)
    accounts = [
        (1, 1, "110-2024-000001", 1500000.0,  "checking"),  # alice
        (2, 2, "110-2024-000002", 830000.0,   "checking"),  # bob
        (3, 3, "110-2024-000003", 3200000.0,  "savings"),   # charlie
        (4, 4, "110-2024-000004", 50000000.0, "admin"),     # admin
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO accounts (id,user_id,account_number,balance,account_type) VALUES (?,?,?,?,?)",
        accounts
    )

    transactions_data = [
        (1, 2, 100000, "월세 이체"),
        (2, 1, 50000,  "커피값 정산"),
        (3, 1, 200000, "급여"),
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO transactions (from_account_id,to_account_id,amount,description) VALUES (?,?,?,?)",
        transactions_data
    )

    conn.commit()
    conn.close()
    print("[DB] Initialized successfully.")
