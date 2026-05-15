"""
Insecure Design (불안전한 설계) 스캐너 래퍼 — Scanner/insecure_check.py 연결
"""
import sys
import os

_scanner_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Scanner")
sys.path.insert(0, _scanner_dir)

from insecure_check import insecure_check

def run_scan(base_url: str) -> dict:
    return insecure_check(base_url)
