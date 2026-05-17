import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db.database import init_db
from routers import auth, accounts, transfer, exchange, admin

app = FastAPI(
    title="RookiesBanK API",
    description="Virtual Vulnerable Banking Platform - For Security Training Only",
    version="1.0.0"
)

# [PATCH] CORS: 와일드카드 제거, 환경변수로 허용 출처 관리
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
'''
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
'''

@app.on_event("startup")
def startup():
    init_db()


app.include_router(auth.router)
app.include_router(accounts.router)
app.include_router(transfer.router)
app.include_router(exchange.router)
app.include_router(admin.router)


@app.get("/")
def root():
    return {"message": "NeoBanK API is running", "docs": "/docs"}
