"""상세 가이드 정의용 도우미. 각 guides_part*.py 가 D 에 항목을 채우고 gen_guides.py 가 data/guides.json 에 합친다."""
D = {}
ROLLBACK = "조치 전 스냅샷(도구의 '복구' 메뉴 또는 --restore)으로 파일과 서비스 상태를 되돌립니다. 수동으로 조치했다면 위 '조치 방법'에서 바꾼 파일의 백업본(.bak)을 복사해 되돌리세요."


def g(iid, purpose, threat, good, vuln, check, steps, impact, verify, caution="", decide=None, rollback=ROLLBACK):
    """check/steps: [(설명, 명령)]  /  verify: [문장]  /  decide: [(이름, 설명, 자리표시자)]"""
    D[iid] = {
        "purpose": purpose, "summary": threat,
        "criteria": {"good": good, "vuln": vuln},
        "check": [{"desc": a, "cmd": b} for a, b in check],
        "decide": [{"name": n, "desc": d, "placeholder": p} for n, d, p in (decide or [])],
        "steps": [{"desc": a, "cmd": b} for a, b in steps],
        "impact": impact, "verify": verify, "rollback": rollback, "caution": caution,
        "ref": f"주통2026 {iid}",
    }
