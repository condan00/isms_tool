#!/usr/bin/env python3
"""data/guides.json 생성: tools/guides_part*.py 의 항목별 상세 가이드(점검 목적·보안 위협·판단 기준·점검 방법·조치 방법·조치 영향)를 합친다.
사용: python3 tools/gen_guides.py   (가이드를 고칠 때는 guides_part*.py 를 고치고 다시 실행)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gdef  # noqa: E402
import guides_part1, guides_part2, guides_part3, guides_part4  # noqa: E402,F401


def main():
    p = Path(__file__).resolve().parent.parent / "code" / "data" / "guides.json"
    data = {"schema": 2, "guides": dict(sorted(gdef.D.items()))}
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("가이드:", len(gdef.D))


if __name__ == "__main__":
    main()
