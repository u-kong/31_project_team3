"""
SQL Injection (SQL 인젝션) 스캐너 — 자리 표시자(placeholder)
-------------------------------------------------------------
공격팀에서 SQL Injection 스크립트를 주면 여기에 연결합니다.
그 전까지는 더미 결과를 반환합니다.

공격팀에게 요청할 것:
  - 파일 이름: sql_injection.py (또는 SQLi.py 등)
  - 필수 함수: run_scan(base_url) → dict (표준 형식)
  - 또는: 기존 함수명을 알려주면 아래 래퍼에서 연결해드림
"""
from datetime import datetime


def run_scan(base_url: str) -> dict:
    """
    ⚠️ 더미 데이터입니다.
    공격팀 SQL Injection 스크립트를 연결하면 실제 결과로 교체됩니다.
    """
    return {
        "scan_id": "SQL_INJECTION",
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [
            {
                "id": "SQLI-001",
                "type": "SQL Injection",
                "severity": "Critical",
                "status": "취약",
                "owasp": "A03:2021 - Injection",
                "endpoint": "/auth/login",
                "payload": "' OR '1'='1' --",
                "detected_keywords": ["syntax error", "mysql", "OR 1=1"],
                "evidence": "[더미] 인증 우회 성공 — 200 OK 응답 수신",
                "description": "[더미 데이터] 공격팀 SQL Injection 스크립트를 받으면 실제 스캔으로 교체됩니다."
            }
        ]
    }
