"""
SSRF 스캐너 래퍼 — Scanner/ssrf_check.py 연결
"""
import sys
import os

# Scanner/ 폴더 경로를 Python 검색 경로에 추가
_scanner_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Scanner")
sys.path.insert(0, _scanner_dir)

from ssrf_check import ssrf_check

def run_scan(base_url: str) -> dict:
    return ssrf_check(base_url)
