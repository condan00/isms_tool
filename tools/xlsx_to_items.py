#!/usr/bin/env python3
"""직접 정리한 가이드 엑셀(Linux 시트)을 data/items.json 으로 변환한다.

사용법: python3 tools/xlsx_to_items.py <엑셀파일> [출력 JSON]

엑셀 열 → 항목 정의 규칙
  쉘스크립트 가능 O → type=auto   (자동 적용, 아래 APPROVE 목록은 승인 후 적용으로 승격)
  쉘스크립트 가능 ? → type=approve (수정 스크립트는 만들되 TUI 에서 확인 후 적용)
  쉘스크립트 가능 X → type=guide   (점검 + 가이드 + 목록(list) 스크립트만. 직접 적용하지 않음)
  전체 파일 검색 항목(HEAVY: U-15,23,25,26)은 유형은 엑셀 값을 따르고 heavy=true 로 기본 선택에서만 제외한다
  백업 가능 / 패키지 확인 필요 → 그대로 보존(backup, pkg)
"""
import json
import re
import sys
from pathlib import Path

import openpyxl

APPROVE = {"U-01", "U-02", "U-03", "U-06", "U-37", "U-41", "U-54"}     # 승인 후 적용(로그인/서비스 영향)
HEAVY = {"U-15", "U-23", "U-25", "U-26"}                                # 전체 파일 검색(시간이 걸려 기본 선택 제외. 유형은 엑셀 값을 따른다)
SHELL_OVERRIDE = {c: "?" for c in ("U-05", "U-08", "U-10", "U-14", "U-22", "U-36", "U-67")}   # 엑셀 재검토 결과: ? (확인 후 적용)
# 자동 적용 항목의 분류(TUI '분류별 선택'). guide 유형(조치를 도구가 하지 않는 항목)은 항상 "guide".
FILE_GROUP = {"U-16", "U-17", "U-18", "U-19", "U-20", "U-21", "U-22", "U-24", "U-27", "U-31", "U-37", "U-63", "U-67"}
SERVICE_GROUP = {"U-34", "U-36", "U-38", "U-39", "U-41", "U-42", "U-43", "U-44", "U-52", "U-54", "U-58"}
GROUP_NAMES = {"file": "파일 소유자·권한", "config": "설정 파일 값", "service": "서비스 비활성화", "guide": "가이드 전용"}


def fix_group(code, typ):
    if typ == "guide":
        return "guide"
    return "file" if code in FILE_GROUP else "service" if code in SERVICE_GROUP else "config"


# 항목이 바꾸는 파일의 초기값. 스크립트를 구현하면서 확정/수정한다.
TOUCHES = {
    "U-01": ["/etc/ssh/sshd_config"], "U-02": ["/etc/security/pwquality.conf"],
    "U-13": ["/etc/login.defs"], "U-16": ["/etc/passwd"], "U-18": ["/etc/shadow"],
    "U-19": ["/etc/hosts"], "U-21": ["/etc/rsyslog.conf"],
    "U-63": ["/etc/sudoers"],
}


def category(n):
    if n <= 13:
        return "계정 관리"
    if n <= 33:
        return "파일 및 디렉토리 관리"
    if n <= 63:
        return "서비스 관리"
    if n == 64:
        return "패치 관리"
    return "로그 관리"


def main(src, dst):
    ws = openpyxl.load_workbook(src)["Linux"]
    items, warn = [], []
    for r in ws.iter_rows(min_row=3, values_only=True):
        code = r[1]
        if not (isinstance(code, str) and re.fullmatch(r"U-\d{2}", code)):
            continue
        _, _, sev, _, title, F, G, H, P, A = r[:10]
        m = re.match(r"\s*(\d)", str(A)) if A is not None else None
        apply_no = int(m.group(1)) if m else None
        F = SHELL_OVERRIDE.get(code, F)
        if F not in ("O", "?", "X"):
            warn.append(f"{code}: 쉘스크립트 가능 열 값({F!r})이 올바르지 않아 guide 로 처리했습니다")
            F = "X"
        if F == "X":
            typ = "guide"
        elif F == "?" or code in APPROVE:
            typ = "approve"
        else:
            typ = "auto"
        it = {
            "id": code, "title": " ".join(str(title).split()), "category": category(int(code[2:])),
            "severity": sev, "type": typ, "fix_group": fix_group(code, typ), "heavy": code in HEAVY,
            "excel": {"shell": F, "guide": G, "backup": H, "pkg": P, "apply": None if A is None else str(A)},
            "touches": {"files": TOUCHES.get(code, [])},
            "supported_os": ["rocky9"],
            "fix_supported_os": ["rocky9"] if typ != "guide" else [],
            "guide": {},
        }
        items.append(it)
    Path(dst).write_text(json.dumps({"schema": 1, "source": Path(src).name, "items": items},
                                    ensure_ascii=False, indent=2), encoding="utf-8")
    from collections import Counter
    print(f"{len(items)}개 항목 → {dst}", dict(Counter(i["type"] for i in items)))
    for w in warn:
        print("경고:", w)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "code/data/items.json")
