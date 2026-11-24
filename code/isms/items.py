"""항목 정의(items.json) 로드와 검증.

스크립트 경로는 JSON 에서 읽지 않고 항목 코드로만 만든다(scripts/items/<ID>.sh).
JSON 이 변조되어도 임의 경로의 파일이 root 로 실행되지 않게 하기 위해서다.
"""
import json
from pathlib import Path

from .util import ID_RE

TYPES = ("auto", "approve", "guide")
SEVERITIES = ("상", "중", "하")


class ItemError(ValueError):
    pass


def _check_paths(item, key, paths):
    for p in paths:
        if not isinstance(p, str) or not p.startswith("/") or ".." in Path(p).parts:
            raise ItemError(f"{item['id']}: touches.{key} 경로가 올바르지 않습니다: {p!r}")


def validate(item):
    iid = item.get("id", "")
    if not ID_RE.match(iid):
        raise ItemError(f"항목 코드가 올바르지 않습니다: {iid!r}")
    for k in ("title", "category", "severity", "type"):
        if not item.get(k):
            raise ItemError(f"{iid}: '{k}' 가 없습니다")
    if item["severity"] not in SEVERITIES:
        raise ItemError(f"{iid}: severity 는 {SEVERITIES} 중 하나여야 합니다")
    if item["type"] not in TYPES:
        raise ItemError(f"{iid}: type 은 {TYPES} 중 하나여야 합니다")
    touches = item.get("touches", {})
    _check_paths(item, "files", touches.get("files", []))
    _check_paths(item, "dirs", touches.get("dirs", []))
    return item


# 엑셀 원본의 오타. 엑셀은 그대로 두고 불러올 때 고쳐서 보고서·가이드에 바른 표기가 나오게 한다.
TYPOS = {"싱행": "실행"}


def fix_typos(text):
    for a, b in TYPOS.items():
        text = text.replace(a, b)
    return text


def load_items(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data["items"] if isinstance(data, dict) else data
    seen = set()
    out = []
    gp = Path(path).with_name("guides.json")            # 항목별 조치 가이드(엑셀 변환과 분리해 보관)
    guides = json.loads(gp.read_text(encoding="utf-8")).get("guides", {}) if gp.is_file() else {}
    for it in items:
        validate(it)
        it["title"] = fix_typos(it["title"])
        if it["id"] in seen:
            raise ItemError(f"항목 코드가 중복되었습니다: {it['id']}")
        seen.add(it["id"])
        it.setdefault("script", False)
        it.setdefault("heavy", False)
        it.setdefault("fix_group", "guide" if it["type"] == "guide" else "config")
        it.setdefault("touches", {})
        it.setdefault("supported_os", ["rocky9"])
        it.setdefault("fix_supported_os", ["rocky9"] if it["type"] != "guide" else [])
        if not it.get("guide"):
            it["guide"] = guides.get(it["id"], {})
        out.append(it)
    return out


def filter_items(items, severity=None, categories=None, ids=None):
    """severity: '상' 또는 '상중' 같은 문자열 / categories: 분류 이름 목록 / ids: 코드 목록"""
    res = []
    for it in items:
        if severity and it["severity"] not in severity:
            continue
        if categories and it["category"] not in categories:
            continue
        if ids and it["id"] not in ids:
            continue
        res.append(it)
    return res


def can_fix(item, info):
    """이 항목을 이 환경에서 도구가 직접 조치할 수 있는지 판단한다. (가능 여부, 사유)

    info 는 os_info.detect_os() 결과다. 확장 테스트 OS 에서는 항목의 fix_supported_os 에
    그 OS 가 적혀 있는 항목만 조치할 수 있다.
    """
    if item["type"] == "guide":
        return False, "가이드 전용 항목입니다"
    if not item["script"]:
        return False, "조치 스크립트가 아직 없습니다"
    if not info["policy"]["run"]:
        return False, "실행 권한이 없습니다"
    if info.get("os_override"):
        return False, "테스트 모드에서는 조치가 비활성화됩니다"
    import os_info
    if info["os_key"] not in item["fix_supported_os"] and not os_info.family_ok(info):
        return False, f"{info['os_key']} 에서는 조치가 검증되지 않았습니다"
    return True, ""


def is_required(item):
    """'조치 필수 항목': 가이드 엑셀에서 쉘스크립트 가능 열을 O 로 표시한 항목(? 와 X 는 제외)."""
    return (item.get("excel") or {}).get("shell") == "O"
