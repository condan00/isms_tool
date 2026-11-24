"""조치 가이드 .txt 파일 생성: isms-guid/yy-mm-dd_hh-mm/U-XX_(제목)_guid.txt

대상: 조치 스크립트로 처리되지 않은 항목 중 양호가 아닌 것
  - 가이드 전용 항목(type=guide), 스크립트가 없는 항목, 조치를 선택하지 않은 취약 항목,
    조치가 실패/차단된 항목, 수동점검·오류 항목
  - 스크립트로 조치에 성공한 항목, 양호·해당없음 항목은 만들지 않는다.
"""
import re

from . import guide as guidemod
from .messages import t, state_text
from .util import app_dir, make_run_dir, write_files

NEED_STATES = ("VULN", "MANUAL", "ERROR")
SHOW_MAX = 100          # 가이드 파일에 적는 목록 최대 줄 수(넘으면 건수만 표시)
_BAD = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def safe_name(title, limit=40):
    s = _BAD.sub("_", title).strip(" .")
    s = re.sub(r"\s+", "_", s)
    return s[:limit] or "항목"


def needs_guide(r):
    """이 결과 항목에 가이드가 필요한가."""
    if r.get("fix_state") == "FIXED":
        return False
    return r["state"] in NEED_STATES or r.get("fix_state") in ("FAILED", "BLOCKED")


def _fallback(r):
    """항목 정의에 guide 블록이 아직 없을 때 쓰는 기본 안내."""
    return {"id": r["id"], "title": r["title"], "current": r.get("evidence", ""), "summary": "",
            "criteria": {}, "decide": [], "steps": [], "verify": [], "rollback": "",
            "caution": "", "ref": f"주통2026 {r['id']}", "mode": r.get("type", "guide")}


def render(r, items):
    gd = r.get("guide") or guidemod.build(items[r["id"]], r) if items.get(r["id"], {}).get("guide") else _fallback(r)
    gd = dict(gd)
    gd["current"] = r.get("evidence") or gd.get("current", "")
    text = guidemod.render_text(gd)
    extra = []
    if r.get("fix_note"):
        extra.append(f"  조치 결과  : {r['fix_note']}")
    if not (items.get(r["id"], {}).get("guide")):
        extra.append("  안내      : 이 항목의 상세 가이드가 아직 작성되지 않았습니다. 주통2026 가이드의 해당 항목을 참고하세요.")
    hits = [ln for ln in (r.get("detail") or []) if ln.strip()]
    if hits:
        extra.append(f"  점검에서 걸린 항목({len(hits)}건):")
        extra += [f"    {ln.replace(chr(9), '  ')}" for ln in hits[:SHOW_MAX]]
        if len(hits) > SHOW_MAX:
            extra.append(f"    … 외 {len(hits) - SHOW_MAX}건 (전체는 점검 리포트의 detail 참고)")
    rest = [ln for ln in (r.get("list") or []) if ln not in hits]
    if rest:
        extra.append("  관련 파일 목록(점검 대상, 경로·소유자·권한):")
        extra += [f"    {ln.replace(chr(9), '  ')}" for ln in rest[:SHOW_MAX]]
        if len(rest) > SHOW_MAX:
            extra.append(f"    … 외 {len(rest) - SHOW_MAX}건")
    head = f"판정: {state_text(r)}   중요도: {r['severity']}   분류: {r['category']}\n"
    return head + text + ("\n" + "\n".join(extra) if extra else "") + "\n"


def write_guides(results, items, base=None, stamp=None):
    """가이드 파일을 만들고 (폴더, 만든 파일 목록, 안내 문구) 를 돌려준다. 만들 항목이 없으면 폴더를 만들지 않는다."""
    targets = [r for r in results if needs_guide(r)]
    if not targets:
        return None, [], ""
    d, note = make_run_dir(base or app_dir() / "isms-guid", "isms-guid", stamp)
    files = {f"{r['id']}_{safe_name(r['title'])}_guid.txt": render(r, items) for r in targets}
    return d, write_files(d, files), note
