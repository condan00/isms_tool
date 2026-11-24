"""점검·조치 결과를 JSON 원본에서 여러 형식(JSON/HTML/TXT/CSV/XLSX)으로 변환한다.

모든 형식은 build_report() 가 만든 dict 하나에서 만들어진다(원본이 하나라 형식 간 불일치가 없다).
출력 파일은 0600 으로 만들고, 같은 이름이 있으면 덮어쓰지 않는다.
"""
import csv
import html
import io
import json
import re
from collections import Counter
from pathlib import Path

from .guide import render_text
from .messages import t, MESSAGES, state_text
from .util import (now_stamp, now_iso, write_private, ensure_private_dir, mask_text, sudo_user, as_user,
                   app_dir, make_run_dir, write_files)

STATE_ORDER = {"VULN": 0, "FAILED": 0, "MANUAL": 1, "ERROR": 2, "GOOD": 3, "FIXED": 3, "NA": 4, "SKIP": 5, "BLOCKED": 1}
SEV_ORDER = {"상": 0, "중": 1, "하": 2}
SCOPES = ("vuln", "good", "all")
GOOD_STATES = ("GOOD",)


def build_report(info, results, kind="scan", before=None):
    """results: 점검(또는 조치 후 재점검) 결과 목록. before: 조치 전 결과(있으면 전후 비교를 넣는다)."""
    counts = Counter(r["state"] for r in results)
    rep = {
        "schema": 1, "kind": kind, "generated": now_iso(),
        "host": {k: info.get(k) for k in ("hostname", "os_name", "os_key", "kernel", "arch",
                                          "selinux", "firewalld", "pkg_manager")},
        "summary": dict(counts), "total": len(results),
        "results": [_clean(r) for r in results],
    }
    if before:
        bmap = {r["id"]: r["state"] for r in before}
        rep["comparison"] = {
            "before": dict(Counter(bmap.values())), "after": dict(counts),
            "changed": [{"id": r["id"], "from": bmap[r["id"]], "to": r["state"]}
                        for r in results if r["id"] in bmap and bmap[r["id"]] != r["state"]],
        }
    return rep


def _clean(r):
    keep = ("id", "title", "category", "severity", "type", "state", "evidence", "detail",
            "fix_state", "fix_note", "fixable", "snapshot", "guide", "list")
    out = {k: r.get(k) for k in keep if k in r}
    out["evidence"] = mask_text(out.get("evidence", ""))
    return out


def filter_scope(rep, scope):
    if scope not in SCOPES:
        raise ValueError(f"scope 는 {SCOPES} 중 하나여야 합니다")
    rows = rep["results"]
    if scope == "vuln":
        rows = [r for r in rows if r["state"] in ("VULN", "MANUAL", "ERROR") or r.get("fix_state") == "FAILED"]
    elif scope == "good":
        rows = [r for r in rows if r["state"] in GOOD_STATES or r.get("fix_state") == "FIXED"]
    out = dict(rep)
    out["results"] = sorted(rows, key=lambda r: (SEV_ORDER.get(r["severity"], 9),
                                                  STATE_ORDER.get(r["state"], 9), r["id"]))
    out["scope"] = scope
    return out


def _label(state):
    return t("st_" + state) if ("st_" + state) in MESSAGES["ko"] else state


# ---------------- 형식별 변환 ----------------
def to_json(rep):
    return json.dumps(rep, ensure_ascii=False, indent=2)


def to_txt(rep):
    h = rep["host"]
    L = ["=" * 70, f" ISMS 점검 결과  ({rep['kind']})   {rep['generated']}",
         f" 호스트: {h['hostname']}   OS: {h['os_name']}   커널: {h['kernel']}", "=" * 70]
    L.append(" 요약: " + ", ".join(f"{_label(k)} {v}" for k, v in sorted(rep["summary"].items())))
    cmp_ = rep.get("comparison")
    if cmp_:
        L.append(" 조치 전: " + ", ".join(f"{_label(k)} {v}" for k, v in sorted(cmp_["before"].items())))
        L.append(" 조치 후: " + ", ".join(f"{_label(k)} {v}" for k, v in sorted(cmp_["after"].items())))
    L.append("")
    for r in rep["results"]:
        fx = f" → {_label(r['fix_state'])}" if r.get("fix_state") else ""
        L.append(f"[{r['severity']}] {r['id']} {r['title']}: {state_text(r)}{fx}")
        if r.get("evidence"):
            L.append(f"      근거: {r['evidence']}")
        if r.get("fix_note"):
            L.append(f"      조치: {r['fix_note']}")
    gl = [r for r in rep["results"] if r.get("guide")]
    if gl:
        L += ["", "-" * 70, " 조치 권고 가이드", "-" * 70]
        for r in gl:
            L += [render_text(r["guide"]), ""]
    return "\n".join(L) + "\n"


_CSS = ("body{font-family:system-ui,'Malgun Gothic',sans-serif;margin:24px;color:#1b2430}"
        "h1{font-size:20px}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #cfd6df;padding:6px 8px;font-size:13px;vertical-align:top}"
        "th{background:#12375e;color:#fff}.VULN,.FAILED{background:#fde2e2}.GOOD,.FIXED{background:#e1f4e5}"
        ".MANUAL,.BLOCKED{background:#fff3d6}.ERROR{background:#eee}.NA,.SKIP{color:#777}"
        ".cards span{display:inline-block;margin:0 8px 8px 0;padding:6px 12px;border-radius:6px;background:#eef2f7}"
        "pre{background:#0f1720;color:#e6edf3;padding:10px;border-radius:6px;overflow:auto;font-size:12px}"
        "details{margin:6px 0}code{font-family:ui-monospace,Consolas,monospace}")


def to_html(rep):
    e = html.escape
    h = rep["host"]
    P = ["<!doctype html><html lang='ko'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>ISMS 점검 결과 - {e(str(h['hostname']))}</title><style>{_CSS}</style></head><body>",
         f"<h1>ISMS 점검 결과 ({e(rep['kind'])})</h1>",
         f"<p>호스트 <b>{e(str(h['hostname']))}</b> · {e(str(h['os_name']))} · 커널 {e(str(h['kernel']))}"
         f" · 생성 {e(rep['generated'])}</p><div class='cards'>"]
    for k, v in sorted(rep["summary"].items()):
        P.append(f"<span class='{e(k)}'>{e(_label(k))} <b>{v}</b></span>")
    P.append("</div>")
    cmp_ = rep.get("comparison")
    if cmp_:
        P.append("<p>조치 전: " + e(", ".join(f"{_label(k)} {v}" for k, v in sorted(cmp_["before"].items())))
                 + "<br>조치 후: " + e(", ".join(f"{_label(k)} {v}" for k, v in sorted(cmp_["after"].items()))) + "</p>")
    P.append("<table><tr><th>중요도</th><th>코드</th><th>항목</th><th>판정</th><th>근거</th><th>조치</th></tr>")
    for r in rep["results"]:
        fx = _label(r["fix_state"]) if r.get("fix_state") else ""
        P.append(f"<tr class='{e(r['state'])}'><td>{e(r['severity'])}</td><td>{e(r['id'])}</td>"
                 f"<td>{e(r['title'])}</td><td>{e(state_text(r))}</td>"
                 f"<td>{e(r.get('evidence', ''))}</td><td>{e(fx)} {e(r.get('fix_note') or '')}</td></tr>")
    P.append("</table>")
    gl = [r for r in rep["results"] if r.get("guide")]
    if gl:
        P.append("<h2>조치 권고 가이드</h2>")
        for r in gl:
            P.append(f"<details><summary>{e(r['id'])} {e(r['title'])}</summary><pre>{e(render_text(r['guide']))}</pre></details>")
    P.append("</body></html>")
    return "".join(P)


_FORMULA = re.compile(r"^[=+\-@\t\r]")


def _safe_cell(v):
    """엑셀/CSV 에서 수식으로 해석되지 않게 앞에 작은따옴표를 붙인다(수식 주입 방지)."""
    s = "" if v is None else str(v)
    return "'" + s if _FORMULA.match(s) else s


def _rows(rep):
    yield ["중요도", "코드", "분류", "항목", "판정", "근거", "조치 결과", "조치 메모"]
    for r in rep["results"]:
        yield [r["severity"], r["id"], r["category"], r["title"], state_text(r),
               r.get("evidence", ""), _label(r["fix_state"]) if r.get("fix_state") else "", r.get("fix_note") or ""]


def to_csv(rep):
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    for i, row in enumerate(_rows(rep)):
        w.writerow(row if i == 0 else [_safe_cell(c) for c in row])
    return ("﻿" + buf.getvalue()).encode("utf-8")          # BOM: 엑셀에서 한글이 깨지지 않게


def to_xlsx(rep):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    wb = Workbook()
    ws = wb.active
    ws.title = "점검 결과"
    fills = {"취약": "FDE2E2", "양호": "E1F4E5", "수동점검": "FFF3D6"}
    for i, row in enumerate(_rows(rep)):
        ws.append(row if i == 0 else [_safe_cell(c) for c in row])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="12375E")
    for row in ws.iter_rows(min_row=2):
        col = fills.get(row[4].value)
        if col:
            row[4].fill = PatternFill("solid", fgColor=col)
    for col, w_ in zip("ABCDEFGH", (8, 8, 14, 40, 10, 50, 12, 40)):
        ws.column_dimensions[col].width = w_
    ws.freeze_panes = "A2"
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


REPORTERS = {"json": ("JSON 원본", to_json, "json"), "html": ("HTML 리포트", to_html, "html"),
             "txt": ("텍스트 요약", to_txt, "txt"), "csv": ("CSV (엑셀용)", to_csv, "csv"),
             "xlsx": ("엑셀 체크리스트(.xlsx)", to_xlsx, "xlsx")}


def save(rep, fmt, out_dir, scope="all"):
    """리포트를 저장한다. sudo 로 실행했다면 저장하는 동안 실행한 사용자 권한으로 쓰므로
    파일이 그 사용자 소유(0600)로 만들어지고, 사용자가 심은 링크로 시스템 파일을 덮어쓸 수 없다."""
    if fmt not in REPORTERS:
        raise ValueError(f"지원하지 않는 형식: {fmt}")
    rep = filter_scope(rep, scope)
    host = re.sub(r"[^A-Za-z0-9._-]", "_", str(rep["host"].get("hostname") or "host"))[:40]
    _, fn, ext = REPORTERS[fmt]
    content = fn(rep)                                  # 변환은 root 권한으로, 쓰기만 사용자 권한으로
    with as_user(sudo_user()):
        out = ensure_private_dir(out_dir)
        return write_private(out / f"{now_stamp()}_{host}_{rep['kind']}.{ext}", content)


def save_run(rep, fmts, scope="all", base=None, stamp=None):
    """선택한 형식을 모두 isms-report/<yy-mm-dd_hh-mm>/ 한 폴더에 저장한다.
    (폴더, 만든 파일 목록, 안내 문구) 를 돌려준다."""
    bad = [f for f in fmts if f not in REPORTERS]
    if bad:
        raise ValueError(f"지원하지 않는 형식: {bad}")
    rep = filter_scope(rep, scope)
    host = re.sub(r"[^A-Za-z0-9._-]", "_", str(rep["host"].get("hostname") or "host"))[:40]
    files = {f"{host}_{rep['kind']}.{REPORTERS[f][2]}": REPORTERS[f][1](rep) for f in fmts}
    d, note = make_run_dir(base or app_dir() / "isms-report", "isms-report", stamp)
    return d, write_files(d, files), note
