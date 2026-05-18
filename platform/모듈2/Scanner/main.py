import json
import sys
from ssrf_check import ssrf_check
from idor_check import idor_check
from bola_check import bola_check
from insecure_check import insecure_check
from sqli_check import sqli_check
from bfla_admin_check import bfla_check
from datetime import datetime

def run_scan(base_url):
    print(f"\n[*] 루키즈은행 취약점 진단 시작")
    print(f"[*] 대상: {base_url}\n")

    results = {
        "target": base_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules": []
    }
    results["modules"].append(insecure_check(base_url))
    results["modules"].append(ssrf_check(base_url))
    results["modules"].append(idor_check(base_url))
    results["modules"].append(bola_check(base_url))
    results["modules"].append(sqli_check(base_url))
    results["modules"].append(bfla_check(base_url))

    print("\n[*] 전체 스캔 완료")
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        base_url = input("대상 URL 입력 (예: http://52.79.242.217:8000): ").strip()
    else:
        base_url = sys.argv[1]

    result = run_scan(base_url)
    print(json.dumps(result, ensure_ascii=False, indent=2))