"""공용 유틸리티: 경로 신뢰 검사, 비공개 파일 쓰기, 민감정보 마스킹, 감사 로그."""
import contextlib
import json
import os
import pwd
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

ID_RE = re.compile(r"^[A-Z]{1,4}-\d{2}$")


def now_stamp():
    return time.strftime("%Y%m%d-%H%M%S")


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def is_trusted(path):
    """root 권한으로 실행할 파일/디렉터리가 안전한지 확인한다.

    심볼릭 링크가 아니고, 소유자가 root(또는 실행 사용자)이며,
    그룹/기타 사용자가 쓸 수 없어야 한다.
    """
    try:
        st = os.lstat(path)
    except OSError as e:
        return False, str(e)
    if stat.S_ISLNK(st.st_mode):
        return False, "심볼릭 링크는 허용하지 않습니다"
    if st.st_uid not in (0, os.geteuid()):
        return False, f"소유자(uid={st.st_uid})가 root/실행 사용자가 아닙니다"
    if st.st_mode & 0o022:
        return False, f"그룹/기타 사용자에게 쓰기 권한이 있습니다({stat.S_IMODE(st.st_mode):04o})"
    return True, ""


def untrusted_scripts(scripts_dir):
    """스크립트 폴더와 그 안의 .sh 중 신뢰 검사에 걸리는 것을 [(경로, 이유)] 로 돌려준다(실행 전에 한 번 점검해 안내하려는 용도)."""
    root = Path(scripts_dir)
    bad = []
    dirs = [root / "items", root / "ubuntu", root / "ubuntu" / "items"]
    for p in [root, *dirs, *sorted(d for x in dirs for d in x.glob("*.sh"))]:
        if not os.path.lexists(p):
            continue
        ok, why = is_trusted(p)
        if not ok:
            bad.append((str(p), why))
    return bad


def ensure_private_dir(path):
    """0700 디렉터리를 만들고(없으면), 소유자와 심볼릭 링크 여부를 검증한다."""
    p = Path(path)
    if p.is_symlink():
        raise PermissionError(f"심볼릭 링크 디렉터리는 사용할 수 없습니다: {p}")
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(p)
    if st.st_uid != os.geteuid():
        raise PermissionError(f"디렉터리 소유자가 현재 사용자가 아닙니다: {p}")
    if st.st_mode & 0o077:
        os.chmod(p, 0o700)
    return p


def write_private(path, data, unique=True):
    """0600 권한으로 새 파일을 만든다. 같은 이름이 있으면 -2, -3 … 을 붙인다(덮어쓰지 않음)."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    for n in range(1, 100):
        cand = path if n == 1 else path.with_name(f"{path.stem}-{n}{path.suffix}")
        try:
            fd = os.open(cand, flags, 0o600)
        except FileExistsError:
            if not unique:
                raise
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return cand
    raise FileExistsError(f"사용 가능한 파일 이름이 없습니다: {path}")


def atomic_write_json(path, obj):
    """임시 파일에 쓴 뒤 교체한다(0600). 중간에 끊겨도 기존 파일이 깨지지 않는다."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# community 지시어는 공백 구분, 나머지는 '=' 또는 ':' 구분일 때만 값을 가린다
# ('/etc/passwd 권한 …' 같은 일반 문장이 가려지지 않도록)
_MASK_COMMUNITY = re.compile(r"(?i)(?<![/\w])((?:ro|rw)community6?|com2sec\s+\S+\s+\S+)(\s+)(\S+)")
_MASK_KV = re.compile(
    r"(?i)(?<![/\w])(password|passwd|passphrase|secret|token|api[_-]?key|community)(\s*[=:]\s*)(\S+)")


def mask_text(s):
    """리포트에 남기면 안 되는 값(비밀번호, community 문자열 등)을 가린다."""
    if not s:
        return s
    s = _MASK_COMMUNITY.sub(lambda m: f"{m.group(1)}{m.group(2)}****", s)
    s = _MASK_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}****", s)
    return s


def audit(data_dir, event, **kw):
    """조치/복구 같은 변경 작업을 감사 로그(JSON Lines, 0600)에 남긴다."""
    rec = {"time": now_iso(), "event": event,
           "user": os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.geteuid())}
    rec.update(kw)
    fd = os.open(Path(data_dir) / "audit.log",
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------- sudo 로 실행했을 때 실제 사용자 처리 ----------------
def sudo_user(environ=None):
    """sudo 로 실행된 경우 (uid, gid, 이름, 홈) 을 돌려준다. 그 밖에는 None.

    root 로 직접 로그인했거나 SUDO_UID 가 없거나 0 이면 None 이다.
    환경 변수만 믿지 않고 passwd 에 실제로 있는 사용자인지, 이름이 일치하는지 확인한다.
    """
    env = os.environ if environ is None else environ
    if os.geteuid() != 0:
        return None
    try:
        uid, gid = int(env["SUDO_UID"]), int(env.get("SUDO_GID", ""))
    except (KeyError, ValueError):
        return None
    if uid == 0:
        return None
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return None
    if env.get("SUDO_USER") and env["SUDO_USER"] != pw.pw_name:
        return None
    return uid, gid, pw.pw_name, pw.pw_dir


@contextlib.contextmanager
def as_user(user):
    """블록 안에서만 파일 권한을 실행한 사용자로 낮춘다(user 가 None 이면 아무것도 안 한다).

    chown 으로 소유자만 바꾸면 root 가 사용자 폴더에 쓰는 동안 심볼릭 링크 바꿔치기로
    시스템 파일을 덮어쓰게 만들 수 있다. 커널이 사용자 권한으로 검사하게 하면 그 공격이 막힌다.
    """
    if not user:
        yield
        return
    uid, gid, name, _ = user
    old_groups = os.getgroups()
    try:
        os.initgroups(name, gid)
        os.setegid(gid)
        os.seteuid(uid)
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)
        os.setgroups(old_groups)


def default_report_dir(data_dir):
    """리포트 기본 저장 폴더. sudo 사용자는 자기 홈 아래(root 전용 폴더는 일반 사용자가 못 읽는다)."""
    u = sudo_user()
    return Path(u[3]) / "isms-reports" if u else Path(data_dir) / "reports"


# ---------------- 실행 결과 폴더 (isms-report / isms-guid) ----------------
def run_stamp():
    """결과 폴더 이름: yy-mm-dd_hh-mm"""
    return time.strftime("%y-%m-%d_%H-%M")


def app_dir():
    """결과 폴더(isms-report, isms-guid)를 둘 위치 = 도구 폴더(isms_tool) 옆.

    PyInstaller 실행 파일이면 실행 파일이 있는 폴더(build.sh 가 도구 폴더 옆에 설치한다).
    소스로 실행하면 도구 폴더(…/isms_tool/code/isms/util.py 기준 두 단계 위)의 부모 폴더.
    번들 내부(_MEIPASS)는 종료하면 사라지는 임시 폴더라 쓰지 않는다."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2].parent


def make_run_dir(base, fallback_name, stamp=None):
    """base/<yy-mm-dd_hh-mm> 를 0700 으로 만든다. sudo 실행이면 실행한 사용자 권한으로 만들고,
    거기에 못 만들면 그 사용자 홈의 fallback_name 아래로 옮긴다. (폴더, 안내 문구) 를 돌려준다."""
    stamp = stamp or run_stamp()
    user = sudo_user()

    def unique(parent):    # 같은 분에 다시 실행하면 이전 결과를 덮지 않도록 _2, _3 ... 을 붙인다
        name, n = stamp, 1
        while (Path(parent) / name).exists():
            n += 1
            name = f"{stamp}_{n}"
        return Path(parent) / name

    try:
        with as_user(user):
            ensure_private_dir(base)
            return ensure_private_dir(unique(base)), ""
    except OSError as e:
        if not user:
            raise
        fb = Path(user[3]) / fallback_name
        with as_user(user):
            ensure_private_dir(fb)
            d = ensure_private_dir(unique(fb))
        return d, f"{base} 에 쓸 수 없어({e.strerror or e}) {fb} 에 저장했습니다"


def write_files(directory, files):
    """{파일 이름: 내용} 을 0600 으로 쓴다(sudo 실행이면 실행한 사용자 권한). 만든 경로 목록을 돌려준다."""
    with as_user(sudo_user()):
        return [write_private(Path(directory) / name, data) for name, data in files.items()]


RESTART_MARK = "[수동 재시작 필요"


def restart_notices(results):
    """조치 결과 중 '수동 재시작 필요' 표시가 있는 항목 → [(항목코드, 안내문)]. 서비스를 자동으로 재시작하지 않은 항목이다."""
    out = []
    for r in results or []:
        note = r.get("fix_note") or ""
        i = note.find(RESTART_MARK)
        if r.get("fix_state") == "FIXED" and i >= 0:
            out.append((r["id"], note[i:].strip("[] ")))
    return out
