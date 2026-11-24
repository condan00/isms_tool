"""항목 스크립트 실행기.

스크립트 계약
  실행:   bash scripts/items/<ID>.sh check|apply|list
  출력:   stdout 마지막 줄  =  STATE|근거      (STATE: GOOD VULN MANUAL NA ERROR)
          그 앞의 줄은 상세 목록(대상 파일 등)으로 취급한다.
  종료코드: 0 = 정상 종료, 그 외 = ERROR
  list  는 읽기 전용: 관련 파일 목록을 줄마다 "/절대경로<TAB>설명" 으로 출력하고 마지막 줄은 GOOD|건수.
          서비스 항목은 "@service<TAB>유닛<TAB>enabled=상태<TAB>active=상태" 줄도 출력한다(복구용).
          apply 가 바꿀 파일(스냅샷 대상)이거나, 가이드 전용 항목에서 사용자가 확인할 목록이다.
  check 는 시스템을 변경하면 안 된다. apply 는 엔진이 스냅샷을 만든 뒤에만 호출된다.
"""
import os
import re
import signal
import subprocess
from pathlib import Path

from .util import is_trusted, mask_text, ID_RE

STATES = ("GOOD", "VULN", "MANUAL", "NA", "ERROR")
_LINE = re.compile(r"^(GOOD|VULN|MANUAL|NA|ERROR)\|(.*)$")
MAX_OUT = 1024 * 1024          # 스크립트 출력 상한 (1MB)
MAX_DETAIL_LINES = 500
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


DEBIAN_FAMILY = ("ubuntu", "debian")


def script_path(scripts_dir, item_id, info=None):
    """항목 스크립트 경로. 우분투/데비안이면 scripts/ubuntu/items/ 에 같은 이름의 전용 스크립트가 있을 때 그것을 쓰고,
    없으면 공통 scripts/items/ 의 스크립트를 쓴다(공통 스크립트는 rpm/dpkg 둘 다 처리한다)."""
    if not ID_RE.match(item_id):
        raise ValueError(f"잘못된 항목 코드: {item_id!r}")
    if info and info.get("os_id") in DEBIAN_FAMILY:
        sp = Path(scripts_dir) / "ubuntu" / "items" / f"{item_id}.sh"
        if sp.is_file():
            return sp
    return Path(scripts_dir) / "items" / f"{item_id}.sh"


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_item(item, mode, info, scripts_dir, strict_trust=True, timeout=None):
    """항목 스크립트를 실행하고 {state, evidence, detail, rc} 를 돌려준다. 예외는 던지지 않는다."""
    assert mode in ("check", "apply", "list")
    res = {"state": "ERROR", "evidence": "", "detail": [], "rc": None}
    try:
        sp = script_path(scripts_dir, item["id"], info)
    except ValueError as e:
        res["evidence"] = str(e)
        return res
    if not sp.is_file():
        res["state"] = "MANUAL"
        res["evidence"] = "점검 스크립트가 없습니다(수동 확인 필요)"
        return res
    if strict_trust:
        for target in (sp, sp.parent):
            ok, why = is_trusted(target)
            if not ok:
                res["evidence"] = f"신뢰할 수 없는 스크립트 경로({target}): {why}"
                return res

    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "HOME": "/root",
           "ISMS_ITEM_ID": item["id"], "ISMS_OS_KEY": info.get("os_key", "unknown"),
           "ISMS_PKG_MANAGER": info.get("pkg_manager", "unknown"),
           "ISMS_INVOKER": re.sub(r"[^A-Za-z0-9._-]", "", os.environ.get("SUDO_USER", ""))[:64]}
    if timeout is None:
        timeout = 900 if item.get("heavy") else 120
    try:
        proc = subprocess.Popen(["bash", str(sp), mode], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                env=env, cwd="/", start_new_session=True)
    except OSError as e:
        res["evidence"] = f"실행 실패: {e}"
        return res
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.communicate()
        res["evidence"] = f"시간 초과({timeout}초)"
        return res
    res["rc"] = proc.returncode
    text = out[:MAX_OUT].decode("utf-8", "replace")
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    last = lines[-1] if lines else ""
    m = _LINE.match(last)
    if proc.returncode != 0 or not m:
        why = err[:300].decode("utf-8", "replace").strip()
        res["evidence"] = mask_text(f"스크립트 오류(코드 {proc.returncode}): {why or last[:200] or '출력 없음'}")
        return res
    res["state"] = m.group(1)
    res["evidence"] = mask_text(m.group(2).strip())[:500]
    res["detail"] = [mask_text(ln)[:300] for ln in lines[:-1][:MAX_DETAIL_LINES]]
    return res


def listed_paths(detail, limit=2000):
    """list 모드 출력(detail 줄)에서 경로만 골라 낸다. 절대 경로이고 '..' 와 제어문자가 없는 것만 인정한다."""
    out = []
    for ln in detail:
        p = ln.split("\t", 1)[0].strip()
        if p.startswith("/") and ".." not in Path(p).parts and p.isprintable():
            out.append(p)
        if len(out) >= limit:
            break
    return list(dict.fromkeys(out))


_UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,100}\.(service|socket|timer|path|target)$")
_STATE_RE = re.compile(r"^[a-z-]{1,30}$")


def listed_services(detail, limit=200):
    """list 출력의 서비스 상태 줄 '@service<TAB>유닛<TAB>enabled=상태<TAB>active=상태' 를 읽는다.
    형식이 어긋나거나 유닛 이름이 올바르지 않은 줄은 버린다. [(유닛, 부팅상태, 동작상태)] 를 돌려준다."""
    out = []
    for ln in detail:
        parts = ln.split("\t")
        if len(parts) != 4 or parts[0] != "@service":
            continue
        unit = parts[1].strip()
        en = parts[2].removeprefix("enabled=").strip()
        ac = parts[3].removeprefix("active=").strip()
        if _UNIT_RE.match(unit) and _STATE_RE.match(en) and _STATE_RE.match(ac):
            out.append((unit, en, ac))
        if len(out) >= limit:
            break
    return out
