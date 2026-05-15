"""
BOLA 스캐너 래퍼 — Scanner/bola_check.py 연결
"""
import sys
import os

_scanner_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Scanner")
sys.path.insert(0, _scanner_dir)

from bola_check import bola_check

def run_scan(base_url: str) -> dict:
    return bola_check(base_url)
