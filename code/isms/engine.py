"""엔진: 점검 → (스냅샷) → 조치 → 재점검 → 복구. 화면(TUI/CLI)을 전혀 모른다."""
import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path

from . import guide as guidemod
from .items import can_fix
from .runner import run_item, listed_paths, listed_services
from .snapshot import SnapshotStore
from .util import ensure_private_dir, atomic_write_json, audit, now_iso

META_KEYS = ("id", "title", "category", "severity", "type")


class EngineBusy(RuntimeError):
    pass


class Engine:
    def __init__(self, scripts_dir, data_dir, info, items, strict_trust=True, root_prefix=""):
        self.scripts_dir = Path(scripts_dir)
        self.data_dir = ensure_private_dir(data_dir)
        self.info = info
        self.items = {it["id"]: it for it in items}
        self.order = [it["id"] for it in items]
        self.strict = strict_trust
        self.snaps = SnapshotStore(self.data_dir, root_prefix=root_prefix)

    # ---------- 동시 실행 방지 ----------
    @contextmanager
    def _lock(self):
        fd = os.open(self.data_dir / "engine.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise EngineBusy("다른 점검/조치 작업이 진행 중입니다") from None
            yield
        finally:
            os.close(fd)

    # ---------- 점검 (읽기 전용) ----------
    def check_one(self, iid):
        it = self.items[iid]
        r = {k: it[k] for k in META_KEYS}
        run = run_item(it, "check", self.info, self.scripts_dir, self.strict)
        r.update(state=run["state"], evidence=run["evidence"], detail=run["detail"])
        ok, why = can_fix(it, self.info)
        r["fixable"] = ok
        if not ok and it["type"] != "guide":
            r["fix_note"] = why
        if it.get("script") and r["state"] in ("VULN", "MANUAL"):
            if it.get("heavy") and run["detail"]:
                r["list"] = list(run["detail"])      # 전체 검색 항목: 점검 결과가 곧 목록이라 한 번 더 검색하지 않는다
            else:
                lst = run_item(it, "list", self.info, self.scripts_dir, self.strict)   # 가이드용 관련 파일 목록(읽기 전용)
                if lst["state"] in ("GOOD", "NA") and lst["detail"]:
                    r["list"] = lst["detail"][:200]
        if guidemod.applies(it, r["state"]):
            r["guide"] = guidemod.build(it, r)
        return r

    def scan(self, ids=None, progress=None):
        ids = [i for i in (ids or self.order) if i in self.items]
        out = []
        for n, iid in enumerate(ids, 1):
            if progress:
                progress(n, len(ids), iid)
            out.append(self.check_one(iid))
        return out

    def save_last(self, results):
        atomic_write_json(self.data_dir / "last_scan.json",
                          {"saved": now_iso(), "info": {k: self.info.get(k) for k in
                           ("hostname", "os_name", "os_key", "kernel", "arch", "selinux", "firewalld", "pkg_manager")},
                           "results": results})

    def load_last(self):
        p = self.data_dir / "last_scan.json"
        if not p.is_file():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    # ---------- 조치 ----------
    def fixable_vulns(self, results):
        return [r for r in results if r["state"] == "VULN" and r.get("fixable")]

    GROUP_ORDER = ("file", "config", "service", "guide")

    def group_of(self, iid):
        return self.items[iid].get("fix_group") or "config"

    def optional_vulns(self, results):
        """엑셀 쉘스크립트 가능이 ? 인 취약 항목(조치 가능한 것만). 환경에 따라 달라 확인 후 적용하는 항목."""
        return [r for r in self.fixable_vulns(results)
                if (self.items[r["id"]].get("excel") or {}).get("shell") != "O"]

    def by_group(self, results):
        """이번 점검에서 취약으로 나온 항목을 4개 분류로 묶는다. {분류: {"fix": [결과...], "guide": [결과...]}}"""
        out = {g: {"fix": [], "guide": []} for g in self.GROUP_ORDER}
        fixable = {r["id"] for r in self.fixable_vulns(results)}
        for r in results:
            if r["state"] != "VULN":
                continue
            if r["id"] in fixable:
                out[self.group_of(r["id"])]["fix"].append(r)
            else:
                out["guide"]["guide"].append(r)
        return out

    def select_fixes(self, results, mode="required", groups=None, with_optional=False, ids=None):
        """조치할 항목 코드 목록을 고른다.
        required: O 항목만(기본) / all: O + ? / groups: 선택한 분류(with_optional 이면 ? 도) / ids: 직접 지정"""
        vulns = self.fixable_vulns(results)
        opt = {r["id"] for r in self.optional_vulns(results)}
        if mode == "required":
            sel = [r for r in vulns if r["id"] not in opt]
        elif mode == "all":
            sel = vulns
        elif mode == "groups":
            sel = [r for r in vulns if self.group_of(r["id"]) in set(groups or ())
                   and (with_optional or r["id"] not in opt)]
        elif mode == "ids":
            sel = [r for r in vulns if r["id"] in set(ids or ())]
        else:
            raise ValueError(f"알 수 없는 조치 범위: {mode}")
        return [r["id"] for r in sel]

    def required_vulns(self, results):
        """조치 필수 항목: 엑셀 '쉘스크립트 가능' 이 O 이고 이번 점검에서 취약으로 나온 항목(조치 가능한 것만)."""
        return [r for r in self.fixable_vulns(results)
                if (self.items[r["id"]].get("excel") or {}).get("shell") == "O"]

    def apply(self, ids, progress=None):
        """선택한 항목을 조치한다. (조치 후 결과 목록, 스냅샷 id) 를 돌려준다.

        1) 항목마다 직전에 다시 점검해 여전히 취약인 것만 대상으로 삼는다.
        2) 대상 파일을 스냅샷으로 저장한다.
        3) 조치 → 재점검. 조치가 실패하면 그 항목의 파일만 자동으로 되돌린다.
        """
        with self._lock():
            targets, results = [], {}
            for iid in ids:
                if iid not in self.items:
                    continue
                it = self.items[iid]
                ok, why = can_fix(it, self.info)
                cur = self.check_one(iid)
                if not ok:
                    cur.update(fix_state="BLOCKED", fix_note=why)
                elif cur["state"] != "VULN":
                    cur.update(fix_state="SKIP", fix_note="이미 취약 상태가 아니어서 건너뜀")
                else:
                    targets.append(iid)
                results[iid] = cur

            sid = None
            if targets:
                files, services = {}, {}
                for i in targets:       # 고정 목록(touches.files) + 스크립트가 알려 주는 대상(list)
                    dyn = run_item(self.items[i], "list", self.info, self.scripts_dir, self.strict)
                    extra = listed_paths(dyn["detail"]) if dyn["state"] in ("GOOD", "NA") else []
                    files[i] = list(dict.fromkeys(self.items[i]["touches"].get("files", []) + extra))
                    services[i] = listed_services(dyn["detail"]) if dyn["state"] in ("GOOD", "NA") else []
                sid = self.snaps.create(targets, files, note="조치 전 자동 스냅샷", services_by_item=services)

            for n, iid in enumerate(targets, 1):
                if progress:
                    progress(n, len(targets), iid)
                it = self.items[iid]
                run = run_item(it, "apply", self.info, self.scripts_dir, self.strict)
                after = self.check_one(iid)
                after["snapshot"] = sid
                if run["state"] in ("GOOD", "NA") and after["state"] == "GOOD":
                    after.update(fix_state="FIXED", fix_note=run["evidence"])
                elif run["state"] == "GOOD" and after["state"] == "MANUAL":
                    # 자동 조치 가능한 부분은 끝났고 나머지는 사람이 확인해야 하는 항목(예: U-40)
                    after.update(fix_state="FIXED", fix_note=f"{run['evidence']} (남은 부분은 수동 확인 필요)")
                else:
                    rb = self.snaps.restore(sid, only_items=[iid])
                    note = f"조치 실패: {run['evidence'] or after['evidence']}"
                    note += " → 자동 원복함" if not rb["fail"] else f" → 자동 원복 일부 실패({len(rb['fail'])}건)"
                    after = self.check_one(iid)
                    after.update(fix_state="FAILED", fix_note=note, snapshot=sid)
                audit(self.data_dir, "apply", item=iid, result=after["fix_state"], snapshot=sid)
                results[iid] = after
            return [results[i] for i in ids if i in results], sid

    # ---------- 조치 후 재점검 (조치를 했으면 항상 실행한다) ----------
    def recheck(self, after, before=None):
        """조치를 실행한 항목(FIXED/FAILED)을 처음부터 다시 점검해 결과를 돌려준다.
        after 안의 결과는 재점검 값으로 갱신한다(조치 결과 fix_state/fix_note/snapshot 은 유지).
        조치는 성공이라 했는데 재점검이 양호(또는 남은 수동 확인)가 아니면 FAILED 로 바꾼다.
        반환: [{id, title, before, after, evidence, ok}]"""
        bmap = {r["id"]: r for r in (before or [])}
        rows = []
        for r in after:
            if r.get("fix_state") not in ("FIXED", "FAILED"):
                continue
            new = self.check_one(r["id"])
            keep = {k: r.get(k) for k in ("fix_state", "fix_note", "snapshot") if r.get(k) is not None}
            r.update(new)
            r.update(keep)
            r["rechecked"] = True
            if r.get("fix_state") == "FIXED" and r["state"] not in ("GOOD", "MANUAL", "NA"):
                r["fix_state"] = "FAILED"
                r["fix_note"] = f"{r.get('fix_note', '')} (재점검 결과 {r['state']}: {r['evidence']})".strip()
            ok = r["state"] in ("GOOD", "NA") or (r["state"] == "MANUAL" and r.get("fix_state") == "FIXED")
            rows.append({"id": r["id"], "title": r["title"], "before": (bmap.get(r["id"]) or {}).get("state", "VULN"),
                         "after": r["state"], "evidence": r.get("evidence", ""), "ok": ok})
        return rows

    # ---------- 복구 ----------
    def restore(self, sid, only_items=None):
        """스냅샷 복구. only_items(항목 코드 목록)를 주면 그 항목이 바꾼 파일·서비스만 복구한다."""
        with self._lock():
            return self.snaps.restore(sid, only_items=only_items)
