"""날짜별 스냅샷 생성과 복구.

조치 직전에 항목이 선언한 대상(touches.files)을 복사해 두고, 복구 시 그 시점으로 되돌린다.
- 파일 내용, 소유자(uid/gid), 권한을 복원한다. 조치 때 새로 생긴 파일은 복구 시 제거한다.
- 복구 전에는 해시로 백업이 손상되지 않았는지 검증한다.
- 심볼릭 링크는 따라가지 않고 링크 자체를 기록한다(링크를 이용한 엉뚱한 파일 덮어쓰기 방지).
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from .util import ensure_private_dir, now_stamp, now_iso, atomic_write_json, audit

MAX_FILE = 50 * 1024 * 1024      # 파일 하나 50MB 초과는 백업하지 않는다
KEEP_DEFAULT = 20                # 보관할 스냅샷 개수


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class SnapshotStore:
    systemctl = ["systemctl"]        # 테스트에서 가짜 명령으로 바꿀 수 있다
    selinuxenabled = ["selinuxenabled"]
    restorecon = ["restorecon", "-F"]

    def __init__(self, data_dir, root_prefix=""):
        """root_prefix 는 테스트용이다. 대상 경로 앞에 붙여 실제 시스템 대신 시험용 디렉터리를 쓴다."""
        self.data_dir = Path(data_dir)
        self.root = ensure_private_dir(self.data_dir / "snapshots")
        self.prefix = root_prefix

    def _real(self, path):
        return Path(self.prefix + path) if self.prefix else Path(path)

    # ---------- 생성 ----------
    def create(self, item_ids, files_by_item, note="", services_by_item=None):
        """files_by_item: {항목코드: [파일 경로, ...]}. 생성한 스냅샷 id 를 돌려준다."""
        sid = now_stamp()
        base = sid
        n = 2
        while (self.root / sid).exists():
            sid = f"{base}-{n}"
            n += 1
        sdir = ensure_private_dir(self.root / sid)
        files_dir = ensure_private_dir(sdir / "files")
        entries = []
        seen = {}
        for iid in item_ids:
            for p in files_by_item.get(iid, []):
                if p in seen:
                    seen[p]["items"].append(iid)
                    continue
                e = self._record(p, files_dir, len(entries))
                e["items"] = [iid]
                seen[p] = e
                entries.append(e)
        svc = {}
        for iid in item_ids:
            for unit, en, ac in (services_by_item or {}).get(iid, []):
                svc.setdefault(unit, {"unit": unit, "enabled": en, "active": ac, "items": []})["items"].append(iid)
        manifest = {"schema": 1, "id": sid, "created": now_iso(), "note": note,
                    "items": list(item_ids), "entries": entries, "services": list(svc.values())}
        atomic_write_json(sdir / "manifest.json", manifest)
        audit(self.data_dir, "snapshot_create", id=sid, items=list(item_ids), files=len(entries))
        return sid

    def _record(self, path, files_dir, idx):
        real = self._real(path)
        e = {"path": path, "existed": False}
        try:
            st = os.lstat(real)
        except FileNotFoundError:
            return e
        e["existed"] = True
        e["mode"] = stat.S_IMODE(st.st_mode)
        e["uid"], e["gid"] = st.st_uid, st.st_gid
        if stat.S_ISLNK(st.st_mode):
            e["kind"] = "symlink"
            e["target"] = os.readlink(real)
            return e
        if not stat.S_ISREG(st.st_mode):
            e["kind"] = "other"          # 디렉터리 등은 권한만 기록한다
            return e
        if st.st_size > MAX_FILE:
            e["kind"] = "toolarge"
            return e
        e["kind"] = "file"
        name = f"{idx:04d}.bak"
        dst = files_dir / name
        with open(real, "rb") as src:
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(src, out)
        e["backup"] = name
        e["sha256"] = _sha256(dst)
        return e

    # ---------- 조회 ----------
    def list(self):
        out = []
        for d in sorted(self.root.iterdir(), reverse=True):
            mf = d / "manifest.json"
            if d.is_dir() and not d.is_symlink() and mf.is_file():
                try:
                    m = json.loads(mf.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                out.append({"id": m["id"], "created": m["created"], "items": m["items"],
                            "files": len(m["entries"]), "note": m.get("note", "")})
        return out

    def load(self, sid):
        if not sid or "/" in sid or sid.startswith("."):
            raise ValueError("잘못된 스냅샷 id")
        mf = self.root / sid / "manifest.json"
        return json.loads(mf.read_text(encoding="utf-8"))

    # ---------- 복구 ----------
    def verify(self, sid):
        """백업 파일이 손상되지 않았는지 확인한다. 문제 목록(빈 리스트면 정상)을 돌려준다."""
        m = self.load(sid)
        problems = []
        for e in m["entries"]:
            if e.get("kind") == "file":
                b = self.root / sid / "files" / e["backup"]
                if not b.is_file() or _sha256(b) != e["sha256"]:
                    problems.append(f"{e['path']}: 백업 파일이 손상되었거나 없습니다")
        return problems

    def restore(self, sid, only_items=None):
        """스냅샷 시점으로 복구한다. {ok:[...], fail:[(경로, 사유)]} 를 돌려준다."""
        problems = self.verify(sid)
        if problems:
            return {"ok": [], "fail": [(p, "검증 실패") for p in problems]}
        m = self.load(sid)
        ok, fail = [], []
        for e in m["entries"]:
            if only_items and not set(e["items"]) & set(only_items):
                continue
            try:
                self._restore_one(sid, e)
                ok.append(e["path"])
            except OSError as ex:
                fail.append((e["path"], str(ex)))
        self._relabel([p for p in ok if not p.startswith("service:")])
        for sv in m.get("services", []):
            if only_items and not set(sv["items"]) & set(only_items):
                continue
            try:
                self._restore_service(sv)
                ok.append(f"service:{sv['unit']}")
            except (OSError, subprocess.SubprocessError, ValueError) as ex:
                fail.append((f"service:{sv['unit']}", str(ex)))
        audit(self.data_dir, "snapshot_restore", id=sid, ok=len(ok), fail=len(fail))
        return {"ok": ok, "fail": fail}

    def _relabel(self, paths):
        """복구한 파일의 SELinux 라벨을 정책 기본값으로 맞춘다(라벨이 틀리면 로그인 등이 거부될 수 있다).
        SELinux 가 꺼져 있거나 명령이 없으면 조용히 넘어간다. 테스트용 root_prefix 사용 시에는 하지 않는다."""
        if self.prefix or not paths:
            return
        try:
            if subprocess.run(self.selinuxenabled, capture_output=True, timeout=10, check=False).returncode != 0:
                return
            for i in range(0, len(paths), 50):
                subprocess.run(self.restorecon + paths[i:i + 50], capture_output=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError):
            pass

    def _sc(self, *args):
        r = subprocess.run(self.systemctl + list(args), capture_output=True, text=True, timeout=60, check=False)
        return r

    def _restore_service(self, sv):
        """서비스를 조치 전 상태(부팅 시 자동 시작 여부, 동작 여부)로 되돌린다."""
        from .runner import _UNIT_RE, _STATE_RE
        unit, en, ac = sv["unit"], sv["enabled"], sv["active"]
        if not (_UNIT_RE.match(unit) and _STATE_RE.match(en) and _STATE_RE.match(ac)):
            raise ValueError("서비스 정보가 올바르지 않습니다")
        cur = self._sc("is-enabled", unit).stdout.strip()
        if en == "masked" and cur != "masked":
            self._sc("mask", unit)
        elif en != "masked" and cur == "masked":
            self._sc("unmask", unit)
        if en == "enabled" and cur != "enabled":
            r = self._sc("enable", unit)
        elif en == "disabled" and cur not in ("disabled", "masked"):
            r = self._sc("disable", unit)
        else:
            r = None
        if r is not None and r.returncode != 0:
            raise OSError(f"{unit}: 부팅 설정 복구 실패: {r.stderr.strip()[:100]}")
        now_active = self._sc("is-active", unit).stdout.strip() == "active"
        if ac == "active" and not now_active:
            r = self._sc("start", unit)
        elif ac in ("inactive", "failed") and now_active:
            r = self._sc("stop", unit)
        else:
            r = None
        if r is not None and r.returncode != 0:
            raise OSError(f"{unit}: 동작 상태 복구 실패: {r.stderr.strip()[:100]}")

    def _restore_one(self, sid, e):
        real = self._real(e["path"])
        if not e["existed"]:
            # 조치 전에는 없던 파일 → 조치로 생겼다면 제거
            if os.path.isdir(real) and not os.path.islink(real):
                os.rmdir(real)               # 조치로 만든 빈 디렉터리(예: 새 홈 디렉터리)만 제거. 내용이 있으면 실패로 남긴다
            elif os.path.lexists(real):
                os.unlink(real)
            return
        kind = e.get("kind")
        if kind == "file":
            src = self.root / sid / "files" / e["backup"]
            if os.path.islink(real):
                os.unlink(real)              # 링크를 따라 쓰지 않는다
            tmp = real.with_name(f".{real.name}.isms-restore")
            shutil.copyfile(src, tmp)
            os.chown(tmp, e["uid"], e["gid"])
            os.chmod(tmp, e["mode"])
            os.replace(tmp, real)
        elif kind == "symlink":
            if os.path.lexists(real):
                os.unlink(real)
            os.symlink(e["target"], real)
            os.lchown(real, e["uid"], e["gid"])
        elif kind == "other":
            os.chown(real, e["uid"], e["gid"])
            os.chmod(real, e["mode"])
        else:
            raise OSError("백업되지 않은 대상이라 복구할 수 없습니다(용량 초과 등)")

    # ---------- 정리 ----------
    def prune(self, keep=KEEP_DEFAULT):
        snaps = self.list()
        for s in snaps[keep:]:
            shutil.rmtree(self.root / s["id"], ignore_errors=True)
        return max(0, len(snaps) - keep)
