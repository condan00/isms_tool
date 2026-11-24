"""조치 권고 가이드 생성.

항목 정의의 guide 블록(요약, 결정할 값, 단계, 확인, 원복, 주의)을 읽어 같은 틀로 출력한다.
점검에서 읽은 실제 값은 {current} 자리에 넣고, 사용자가 정할 값은 <...> 자리표시자로 남긴다.
"""
import textwrap
import unicodedata

from .messages import t


def applies(item, state):
    g = item.get("guide") or {}
    if not g:
        return False
    show = g.get("show_when", "VULN")
    return state in (show if isinstance(show, list) else [show])


def build(item, result):
    """가이드를 구조화된 dict 로 만든다(리포트가 HTML/텍스트로 다시 렌더링한다)."""
    g = item.get("guide") or {}
    cur = result.get("evidence", "")
    return {
        "id": item["id"],
        "title": item["title"],
        "current": cur,
        "purpose": g.get("purpose", ""),
        "summary": g.get("summary", ""),
        "check": g.get("check", []),
        "impact": g.get("impact", ""),
        "criteria": g.get("criteria", {}),
        "decide": g.get("decide", []),
        "steps": g.get("steps", []),
        "verify": g.get("verify", []),
        "rollback": g.get("rollback", ""),
        "caution": g.get("caution", ""),
        "ref": g.get("ref", f"주통2026 {item['id']}"),
        "mode": g.get("mode", item["type"]),
    }


def _w(text):
    """화면 표시 폭(한글 등 전각 문자는 2칸)."""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _wrap(label, text, width):
    """'  라벨: 본문' 형태로 긴 문장을 들여쓰기를 맞춰 줄바꿈한다."""
    head = f"  {label}: "
    pad = " " * _w(head)
    lines = textwrap.wrap(text, width=max(20, (width - _w(head)) // 2 + 10), break_long_words=False) or [""]
    return [head + lines[0]] + [pad + ln for ln in lines[1:]]


def _cmds(L, rows):
    for i, s in enumerate(rows, 1):
        L.append(f"    {i}. {s.get('desc', '')}")
        for c in str(s.get("cmd", "")).split("\n"):
            if c:
                L.append(f"       $ {c}")


def render_text(gd, width=88):
    L = [f"[{gd['id']}] {gd['title']}  ({t('type_' + gd['mode'])})"]
    if gd["current"]:
        L += _wrap("현재 상태", gd["current"], width)
    if gd.get("purpose"):
        L += _wrap("점검 목적", gd["purpose"], width)
    if gd["summary"]:
        L += _wrap("보안 위협", gd["summary"], width)
    crit = gd["criteria"]
    if crit:
        L += _wrap("양호 기준", crit.get("good", ""), width)
        L += _wrap("취약 기준", crit.get("vuln", ""), width)
    if gd.get("check"):
        L.append("  점검 방법:")
        _cmds(L, gd["check"])
    if gd["decide"]:
        L.append("  결정할 값:")
        for d in gd["decide"]:
            L.append(f"    - {d.get('name', '')}: {d.get('desc', '')}  {d.get('placeholder', '')}")
    if gd["steps"]:
        L.append("  조치 방법:")
        _cmds(L, gd["steps"])
    if gd.get("impact"):
        L += _wrap("조치 영향", gd["impact"], width)
    if gd["verify"]:
        L.append("  적용 후 확인:")
        for v in gd["verify"]:
            L.append(f"    - {v}")
    if gd["rollback"]:
        L += _wrap("원복", gd["rollback"], width)
    if gd["caution"]:
        L += _wrap("주의", gd["caution"], width)
    L.append(f"  출처: {gd['ref']}")
    return "\n".join(L)
