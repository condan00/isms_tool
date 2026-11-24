"""이전 점검 결과 찾기·열기 (화면과 무관). isms-report/<yy-mm-dd_hh-mm>/ 안의 JSON 리포트와 마지막 점검 결과를 다룬다.

리포트 파일은 일반 사용자 소유라 내용은 '데이터'로만 취급한다(크기 제한, 구조 검사). 링크·폴더가 아닌 일반 파일만 연다."""
import json
from pathlib import Path

from .util import app_dir, sudo_user

MAX_BYTES = 20 * 1024 * 1024
ROW_KEYS = ("id", "title", "severity", "state")


class HistoryError(ValueError):
    pass


def report_bases():
    """결과 폴더 후보: 도구 폴더 옆 isms-report, sudo 사용자 홈의 isms-report(쓰기 실패 시 대체 위치)."""
    bases = [Path(app_dir()) / "isms-report"]
    u = sudo_user()
    if u:
        bases.append(Path(u[3]) / "isms-report")
    out, seen = [], set()
    for b in bases:
        try:
            key = b.resolve()
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            out.append(b)
    return out


def list_runs(bases=None, limit=50):
    """저장된 실행 결과 목록(최신순): [{name, dir, json, files}]. JSON 리포트가 있는 폴더만."""
    runs = []
    for base in (bases if bases is not None else report_bases()):
        base = Path(base)
        if base.is_symlink() or not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir(), reverse=True)
        except OSError:
            continue
        for d in entries:
            if d.is_symlink() or not d.is_dir():
                continue
            try:
                files = sorted(p for p in d.iterdir() if p.is_file() and not p.is_symlink())
            except OSError:
                continue
            js = [p for p in files if p.suffix == ".json"]
            if js:
                runs.append({"name": d.name, "dir": str(d), "json": str(js[0]),
                             "files": [p.name for p in files]})
    runs.sort(key=lambda r: r["name"], reverse=True)
    return runs[:limit]


def load_report(path):
    """JSON 리포트를 읽어 검증한 뒤 돌려준다. 잘못된 파일이면 HistoryError."""
    p = Path(path)
    try:
        if p.is_symlink() or not p.is_file():
            raise HistoryError("일반 파일이 아닙니다")
        if p.stat().st_size > MAX_BYTES:
            raise HistoryError("파일이 너무 큽니다")
        rep = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise HistoryError(f"읽을 수 없습니다: {e}") from e
    rows = rep.get("results") if isinstance(rep, dict) else None
    if not isinstance(rows, list) or not all(isinstance(r, dict) and all(k in r for k in ROW_KEYS) for r in rows):
        raise HistoryError("점검 결과 형식이 아닙니다")
    for r in rows:
        r.setdefault("evidence", "")
    return rep


def describe(rep):
    """목록에 보여 줄 한 줄 설명."""
    kind = {"scan": "점검", "fix": "점검+조치"}.get(rep.get("kind"), rep.get("kind") or "결과")
    host = (rep.get("host") or {}).get("hostname") or ""
    s = rep.get("summary") or {}
    return f"{kind} · {host} · 취약 {s.get('VULN', 0)} · 수동 {s.get('MANUAL', 0)} · 양호 {s.get('GOOD', 0)} · 전체 {rep.get('total', len(rep.get('results', [])))}"
