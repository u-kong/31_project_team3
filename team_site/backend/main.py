from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db.database import init_db
from routers import auth, accounts, transfer, exchange, admin

app = FastAPI(
    title="NeoBanK API",
    description="Virtual Vulnerable Banking Platform - For Security Training Only",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # [VULN] 모든 출처 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
