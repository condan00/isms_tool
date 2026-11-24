import re
import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os_info
from isms import report, util
from isms.engine import Engine, EngineBusy
from isms.items import ItemError, load_items, validate, can_fix
from isms.runner import run_item
from isms.snapshot import SnapshotStore

INFO = {"os_key": "rocky9", "pkg_manager": "dnf", "hostname": "t", "os_name": "Rocky", "kernel": "k",
        "is_root": True, "os_override": False, "support_level": "supported",
        "policy": {"run": True, "fix": True, "reason": "supported"}}


def mk_item(iid, typ="auto", files=(), **kw):
    it = {"id": iid, "title": f"테스트 {iid}", "category": "t", "severity": "상", "type": typ,
          "script": True, "heavy": False, "touches": {"files": list(files)}, "supported_os": ["rocky9"],
          "fix_supported_os": ["rocky9"], "guide": {}}
    it.update(kw)
    return it


@pytest.fixture
def env(tmp_path):
    scripts = tmp_path / "scripts"
    (scripts / "items").mkdir(parents=True)
    target = tmp_path / "target.conf"
    target.write_text("original\n")
    os.chmod(target, 0o666)
    t = str(target)

    def script(iid, body):
        p = scripts / "items" / f"{iid}.sh"
        p.write_text("#!/bin/bash\nset -u\n" + textwrap.dedent(body))
        return p

    # F-01: 권한이 644 를 넘으면 취약, apply 는 chmod 644
    script("F-01", f"""
        m=$(stat -c %a {t}); over=$(( 8#$m & ~8#644 & 8#7777 ))
        case "$1" in
          check) [ $over -ne 0 ] && echo "VULN|mode=$m" || echo "GOOD|mode=$m";;
          apply) chmod 644 {t}; echo "GOOD|fixed";;
        esac""")
    # F-02: apply 가 파일을 망가뜨리고 실패 → 엔진이 자동 원복해야 함
    script("F-02", f"""
        case "$1" in
          check) grep -q original {t} && echo "VULN|needs fix" || echo "VULN|corrupted";;
          apply) echo broken > {t}; chmod 600 {t}; echo "ERROR|boom"; exit 1;;
        esac""")
    script("F-03", 'echo "GOOD|ok"')
    script("F-04", 'sleep 5; echo "GOOD|late"')
    script("F-05", 'echo "debug line"; echo "VULN|password=hunter2 rocommunity secretstring"')
    script("F-06", 'echo "this is not the contract"')
    items = [mk_item("F-01", files=[t]), mk_item("F-02", files=[t]), mk_item("F-03"),
             mk_item("F-05"), mk_item("F-06"), mk_item("G-01", typ="guide", script=False,
                                                       guide={"summary": "s", "show_when": "VULN"})]
    eng = Engine(scripts, tmp_path / "data", INFO, items, strict_trust=False)
    return eng, items, scripts, target, tmp_path


# ---------------- 항목 정의 검증 ----------------
def test_validate_rejects_bad_items():
    with pytest.raises(ItemError):
        validate(mk_item("../../etc/x"))
    with pytest.raises(ItemError):
        validate(mk_item("U-01", files=["relative/path"]))
    with pytest.raises(ItemError):
        validate(mk_item("U-01", files=["/etc/../root/x"]))
    with pytest.raises(ItemError):
        validate(mk_item("U-01", typ="exec"))


def test_real_items_json_loads():
    items = load_items(Path(__file__).resolve().parents[1] / "data" / "items.json")
    assert len(items) == 58 and {i["type"] for i in items} <= {"auto", "approve", "guide"}


# ---------------- 실행기 ----------------
def test_runner_parses_and_masks(env):
    eng, items, scripts, *_ = env
    r = run_item(items[3], "check", INFO, scripts, strict_trust=False)
    assert r["state"] == "VULN" and r["detail"] == ["debug line"]
    assert "hunter2" not in r["evidence"] and "secretstring" not in r["evidence"]


def test_runner_bad_contract_and_missing_and_timeout(env):
    eng, items, scripts, *_ = env
    assert run_item(items[4], "check", INFO, scripts, strict_trust=False)["state"] == "ERROR"
    assert run_item(mk_item("Z-99"), "check", INFO, scripts, strict_trust=False)["state"] == "MANUAL"
    r = run_item(mk_item("F-04"), "check", INFO, scripts, strict_trust=False, timeout=1)
    assert r["state"] == "ERROR" and "시간 초과" in r["evidence"]


def test_runner_rejects_untrusted_script(env):
    eng, items, scripts, *_ = env
    sp = scripts / "items" / "F-03.sh"
    os.chmod(sp, 0o666)                                        # 누구나 쓸 수 있는 스크립트
    r = run_item(items[2], "check", INFO, scripts, strict_trust=True)
    assert r["state"] == "ERROR" and "신뢰" in r["evidence"]


def test_runner_env_is_sanitized(env):
    eng, items, scripts, *_ = env
    (scripts / "items" / "F-03.sh").write_text('echo "GOOD|${SECRET_TOKEN:-unset}"')
    os.environ["SECRET_TOKEN"] = "leak"
    try:
        r = run_item(items[2], "check", INFO, scripts, strict_trust=False)
    finally:
        del os.environ["SECRET_TOKEN"]
    assert r["evidence"] == "unset"


# ---------------- 스냅샷 ----------------
def test_snapshot_restore_content_mode_and_new_file(tmp_path):
    store = SnapshotStore(tmp_path / "d")
    f, new = tmp_path / "a.conf", tmp_path / "created.conf"
    f.write_text("v1")
    os.chmod(f, 0o640)
    sid = store.create(["X-01"], {"X-01": [str(f), str(new)]})
    f.write_text("v2-changed")
    os.chmod(f, 0o777)
    new.write_text("made by fix")
    r = store.restore(sid)
    assert not r["fail"] and f.read_text() == "v1"
    assert stat.S_IMODE(f.stat().st_mode) == 0o640 and not new.exists()


def test_snapshot_detects_tampering_and_does_not_follow_symlink(tmp_path):
    store = SnapshotStore(tmp_path / "d")
    f, victim = tmp_path / "a.conf", tmp_path / "victim.txt"
    f.write_text("v1")
    victim.write_text("do not touch")
    sid = store.create(["X-01"], {"X-01": [str(f)]})
    f.unlink()
    f.symlink_to(victim)                                     # 복구 직전에 링크로 바꿔치기
    assert not store.restore(sid)["fail"]
    assert victim.read_text() == "do not touch" and f.read_text() == "v1" and not f.is_symlink()
    bak = next((tmp_path / "d" / "snapshots" / sid / "files").iterdir())
    bak.write_text("tampered")
    r = store.restore(sid)
    assert r["fail"] and f.read_text() == "v1"               # 손상된 백업으로는 복구하지 않는다


def test_snapshot_permissions_private(tmp_path):
    store = SnapshotStore(tmp_path / "d")
    f = tmp_path / "a"
    f.write_text("x")
    sid = store.create(["X-01"], {"X-01": [str(f)]})
    base = tmp_path / "d" / "snapshots" / sid
    assert stat.S_IMODE(base.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in base.rglob("*") if p.is_file())


# ---------------- 엔진 ----------------
def test_apply_fixes_then_restore(env):
    eng, items, scripts, target, tmp = env
    res = eng.scan(["F-01"])
    assert res[0]["state"] == "VULN" and res[0]["fixable"]
    after, sid = eng.apply(["F-01"])
    assert after[0]["fix_state"] == "FIXED" and stat.S_IMODE(target.stat().st_mode) == 0o644
    eng.restore(sid)
    assert stat.S_IMODE(target.stat().st_mode) == 0o666       # 날짜 기준 스냅샷으로 복구


def test_failed_apply_auto_rolls_back(env):
    eng, items, scripts, target, tmp = env
    after, sid = eng.apply(["F-02"])
    assert after[0]["fix_state"] == "FAILED" and "자동 원복" in after[0]["fix_note"]
    assert target.read_text() == "original\n" and stat.S_IMODE(target.stat().st_mode) == 0o666


def test_guide_blocked_and_already_good_skipped(env):
    eng, *_ = env
    after, sid = eng.apply(["G-01", "F-03"])
    by = {r["id"]: r for r in after}
    assert by["G-01"]["fix_state"] == "BLOCKED" and by["F-03"]["fix_state"] == "SKIP" and sid is None


def test_no_fix_in_override_or_unverified_os(env):
    eng, items, *_ = env
    assert can_fix(items[0], dict(INFO, os_override=True))[0] is False
    assert can_fix(items[0], dict(INFO, os_key="ubuntu24"))[0] is False
    assert can_fix(items[0], INFO)[0] is True


def test_engine_lock(env):
    eng, *_ = env
    with eng._lock():
        with pytest.raises(EngineBusy):
            eng.restore("x")


def test_guide_generated_for_vuln_guide_item(env):
    eng, *_ = env
    eng.items["G-01"]["guide"] = {"summary": "위험함", "show_when": "VULN", "steps": [{"desc": "d", "cmd": "c"}]}
    # G-01 은 스크립트가 없어 MANUAL → VULN 에서만 보이는 가이드는 나오지 않는다
    assert "guide" not in eng.check_one("G-01")
    eng.items["G-01"]["guide"]["show_when"] = ["VULN", "MANUAL"]
    assert eng.check_one("G-01")["guide"]["steps"][0]["cmd"] == "c"


# ---------------- 리포트 ----------------
def rep_with(evidence, title="t"):
    r = {"id": "U-01", "title": title, "category": "c", "severity": "상", "type": "auto",
         "state": "VULN", "evidence": evidence, "detail": []}
    return report.build_report(INFO, [r])


def test_html_escapes_everything():
    rep = rep_with("<script>alert(1)</script>", title="<img src=x onerror=alert(2)>")
    h = report.to_html(rep)
    assert "<script>alert" not in h and "<img src=x" not in h and "&lt;script&gt;" in h


def test_csv_xlsx_formula_injection():
    rep = rep_with("=cmd|' /C calc'!A0")
    assert b"'=cmd" in report.to_csv(rep)
    import io
    from openpyxl import load_workbook
    ws = load_workbook(io.BytesIO(report.to_xlsx(rep))).active
    assert str(ws["F2"].value).startswith("'=")


def test_report_masks_secrets_and_scope_filter():
    rep = rep_with("rocommunity s3cret 10.0.0.0/8 password=abc123")
    txt = report.to_txt(rep)
    assert "s3cret" not in txt and "abc123" not in txt
    assert "/etc/passwd 권한" in util.mask_text("/etc/passwd 권한 666")      # 일반 문장은 가리지 않는다
    good = {"id": "U-02", "title": "x", "category": "c", "severity": "중", "type": "auto", "state": "GOOD", "evidence": ""}
    rep = report.build_report(INFO, [rep["results"][0], good])
    assert [r["id"] for r in report.filter_scope(rep, "vuln")["results"]] == ["U-01"]
    assert [r["id"] for r in report.filter_scope(rep, "good")["results"]] == ["U-02"]
    assert sorted(r["id"] for r in report.filter_scope(rep, "all")["results"]) == ["U-01", "U-02"]
    with pytest.raises(ValueError):
        report.filter_scope(rep, "high")


def test_report_files_private_and_not_overwritten(tmp_path):
    rep = rep_with("e")
    p1 = report.save(rep, "json", tmp_path / "out")
    p1.with_name(p1.name)                                   # 같은 초에 두 번 저장해도 덮어쓰지 않는다
    p2 = report.save(rep, "json", tmp_path / "out")
    assert p1 != p2 or p1.exists()
    assert stat.S_IMODE(p1.stat().st_mode) == 0o600
    assert json.loads(p1.read_text())["total"] == 1


def test_write_private_refuses_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "out.txt"
    link.symlink_to(victim)
    p = util.write_private(link, "new")                      # O_EXCL: 링크를 따라 쓰지 않고 새 이름을 쓴다
    assert victim.read_text() == "keep" and p != link


# ---------------- 신뢰 검사 / OS ----------------
def test_is_trusted(tmp_path):
    f = tmp_path / "s.sh"
    f.write_text("x")
    os.chmod(f, 0o755)
    assert util.is_trusted(f)[0]
    os.chmod(f, 0o777)
    assert not util.is_trusted(f)[0]
    l = tmp_path / "l.sh"
    l.symlink_to(f)
    assert not util.is_trusted(l)[0]


def test_os_info_classify():
    assert os_info.classify({"detect_ok": True, "os_key": "rocky9"}) == "supported"
    assert os_info.classify({"detect_ok": False, "os_key": "rocky9"}) == "unknown"


# ---------------- sudo 사용자 소유 저장 ----------------
NOBODY = 65534


@pytest.fixture
def open_base():
    """일반 사용자(nobody)가 지나갈 수 있는 임시 폴더. pytest 기본 임시 폴더의 상위는 root 전용이다."""
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="isms-sudo-"))
    os.chmod(base, 0o755)
    yield base
    shutil.rmtree(base, ignore_errors=True)


def _sudo_env(monkeypatch):
    monkeypatch.setenv("SUDO_UID", str(NOBODY))
    monkeypatch.setenv("SUDO_GID", str(NOBODY))
    monkeypatch.setenv("SUDO_USER", "nobody")


@pytest.mark.skipif(os.geteuid() != 0, reason="root 로 실행할 때만 의미가 있다")
def test_sudo_user_detection(monkeypatch):
    for k in ("SUDO_UID", "SUDO_GID", "SUDO_USER"):
        monkeypatch.delenv(k, raising=False)
    assert util.sudo_user() is None                                   # root 직접 로그인
    _sudo_env(monkeypatch)
    assert util.sudo_user()[:3] == (NOBODY, NOBODY, "nobody")
    monkeypatch.setenv("SUDO_USER", "someone-else")
    assert util.sudo_user() is None                                   # 이름 불일치 → 무시
    monkeypatch.setenv("SUDO_USER", "nobody")
    monkeypatch.setenv("SUDO_UID", "0")
    assert util.sudo_user() is None
    monkeypatch.setenv("SUDO_UID", "4242424")
    assert util.sudo_user() is None                                   # 없는 사용자


@pytest.mark.skipif(os.geteuid() != 0, reason="root 로 실행할 때만 의미가 있다")
def test_report_saved_as_sudo_user_and_privileges_restored(open_base, monkeypatch):
    _sudo_env(monkeypatch)
    home = open_base / "home"
    home.mkdir()
    os.chown(home, NOBODY, NOBODY)
    p = report.save(rep_with("e"), "json", home / "isms-reports")
    st = p.stat()
    assert st.st_uid == NOBODY and st.st_gid == NOBODY and stat.S_IMODE(st.st_mode) == 0o600
    assert (os.geteuid(), os.getegid()) == (0, 0)                      # 권한이 원래대로 복구됨
    # 실패해도 복구된다
    with pytest.raises(OSError):
        report.save(rep_with("e"), "json", "/proc/not-writable/x")
    assert os.geteuid() == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="root 로 실행할 때만 의미가 있다")
def test_symlink_planted_by_user_cannot_hijack_root_write(open_base, monkeypatch):
    _sudo_env(monkeypatch)
    home = open_base / "home"
    home.mkdir()
    os.chown(home, NOBODY, NOBODY)
    secret_dir = open_base / "rootonly"
    secret_dir.mkdir(mode=0o700)                                       # root 전용 폴더
    (home / "isms-reports").symlink_to(secret_dir)                     # 사용자가 심은 링크
    with pytest.raises(OSError):
        report.save(rep_with("e"), "json", home / "isms-reports")
    assert list(secret_dir.iterdir()) == []                            # root 폴더에 아무것도 안 써짐


def test_default_report_dir(monkeypatch, tmp_path):
    for k in ("SUDO_UID", "SUDO_GID", "SUDO_USER"):
        monkeypatch.delenv(k, raising=False)
    assert util.default_report_dir(tmp_path) == tmp_path / "reports"


def test_run_dirs_report_and_guides(tmp_path):
    import re
    from isms import guidefiles
    rep = rep_with("e")
    good = {"id": "U-02", "title": "x", "category": "c", "severity": "중", "type": "auto", "state": "GOOD", "evidence": ""}
    rep = report.build_report(INFO, [rep["results"][0], good])
    d, files, _ = report.save_run(rep, ["json", "txt"], scope="good", base=tmp_path / "isms-report", stamp="261113-10-20-30")
    assert re.fullmatch(r"\d{2}-\d{2}-\d{2}_\d{2}-\d{2}", util.run_stamp())
    assert sorted(f.suffix for f in files) == [".json", ".txt"]
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    assert "U-02" in files[0].read_text(encoding="utf-8") and "U-01" not in files[0].read_text(encoding="utf-8")
    res = rep["results"]
    gd, gfiles, _ = guidefiles.write_guides(res, {}, base=tmp_path / "isms-guid", stamp="261113-10-20-30")
    assert [f.name for f in gfiles] == [f"U-01_{guidefiles.safe_name(res[0]['title'])}_guid.txt"]   # 양호 항목은 만들지 않음
    assert guidefiles.write_guides([res[1]], {}, base=tmp_path / "g2")[0] is None


def test_required_vulns(env):
    eng, items, *_ = env
    items[0]["excel"] = {"shell": "O"}
    eng.items["F-01"]["excel"] = {"shell": "O"}
    eng.items["F-02"]["excel"] = {"shell": "?"}
    res = eng.scan(["F-01", "F-02", "F-03"])
    assert [r["id"] for r in eng.required_vulns(res)] == ["F-01"]          # ? 와 양호는 제외
    assert {r["id"] for r in eng.fixable_vulns(res)} == {"F-01", "F-02"}


def test_list_mode_extends_snapshot_and_guide(env):
    """list 모드가 알려 준 파일이 스냅샷에 들어가 복구되고, 가이드 전용 항목의 결과에는 목록이 붙는다."""
    eng, items, scripts, target, tmp = env
    dyn = tmp / "dyn.conf"
    dyn.write_text("x")
    os.chmod(dyn, 0o666)
    d = str(dyn)
    p = scripts / "items" / "F-07.sh"
    p.write_text("#!/bin/bash\nset -u\n" + textwrap.dedent(f"""
        case "$1" in
          list) printf '%s\\tinfo\\n' {d}; echo "GOOD|1개 파일";;
          check) [ "$(stat -c %a {d})" = 666 ] && echo "VULN|mode 666" || echo "GOOD|ok";;
          apply) chmod 600 {d}; echo "GOOD|fixed";;
        esac"""))
    it = mk_item("F-07")                       # touches.files 비어 있음 → list 로만 스냅샷 대상이 정해진다
    eng.items["F-07"] = it
    eng.order.append("F-07")
    res, sid = eng.apply(["F-07"])
    assert res[0]["fix_state"] == "FIXED" and stat.S_IMODE(dyn.stat().st_mode) == 0o600
    eng.restore(sid)
    assert stat.S_IMODE(dyn.stat().st_mode) == 0o666                 # list 로 알려 준 파일이 복구됨
    r = eng.check_one("F-07")
    assert r["state"] == "VULN" and r["list"] == [f"{d}\tinfo"]
    from isms.runner import listed_paths
    assert listed_paths(["/a/b\tx", "../x", "/a/../b", "rel", "/ok"]) == ["/a/b", "/ok"]


def test_generated_scripts_have_package_check():
    root = Path(__file__).resolve().parent.parent / "scripts" / "items"
    for iid in ("U-20", "U-21"):
        text = (root / f"{iid}.sh").read_text(encoding="utf-8")
        assert "pkg_any" in text and "점검 대상이 아닙니다" in text
    assert "pkg_any" not in (root / "U-19.sh").read_text(encoding="utf-8")        # 기본 설치 항목은 확인하지 않음


def test_select_fixes_modes_and_groups(env):
    eng, items, scripts, target, tmp = env
    eng.items["F-01"].update(excel={"shell": "O"}, fix_group="file")
    eng.items["F-02"].update(excel={"shell": "?"}, fix_group="service")
    eng.items["F-05"].update(excel={"shell": "O"}, fix_group="config")
    res = eng.scan(["F-01", "F-02", "F-03", "F-05"])
    vul = {r["id"] for r in eng.fixable_vulns(res)}
    assert {"F-01", "F-02"} <= vul
    assert eng.select_fixes(res, "required") == [i for i in ["F-01", "F-05"] if i in vul]      # ? 제외
    assert set(eng.select_fixes(res, "all")) == vul
    assert eng.select_fixes(res, "groups", groups=["service"]) == []                          # 분류만 고르면 O 만
    assert eng.select_fixes(res, "groups", groups=["service"], with_optional=True) == ["F-02"]
    assert eng.select_fixes(res, "groups", groups=["file", "service"], with_optional=True) == ["F-01", "F-02"]
    assert eng.select_fixes(res, "ids", ids=["F-02", "F-03"]) == ["F-02"]                    # 양호는 대상 아님
    grp = eng.by_group(res)
    assert [r["id"] for r in grp["file"]["fix"]] == ["F-01"]
    with pytest.raises(ValueError):
        eng.select_fixes(res, "bogus")


def test_service_state_restored(tmp_path):
    """list 가 알려 준 서비스 상태(부팅/동작)를 스냅샷에 기록하고 복구 때 되돌린다(가짜 systemctl 사용)."""
    state = tmp_path / "state"
    state.write_text("enabled active")
    fake = tmp_path / "systemctl"
    fake.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        read en ac < {state}
        case "$1" in
          is-enabled) echo $en;;
          is-active) echo $ac;;
          enable) echo "enabled $ac" > {state};;
          disable) echo "disabled $ac" > {state};;
          start) echo "$en active" > {state};;
          stop) echo "$en inactive" > {state};;
        esac"""))
    fake.chmod(0o755)
    store = SnapshotStore(tmp_path / "data")
    store.systemctl = [str(fake)]
    sid = store.create(["S-01"], {"S-01": []}, services_by_item={"S-01": [("foo.service", "enabled", "active")]})
    state.write_text("disabled inactive")                         # 조치로 꺼졌다고 가정
    r = store.restore(sid)
    assert not r["fail"] and "service:foo.service" in r["ok"]
    assert state.read_text().split() == ["enabled", "active"]
    from isms.runner import listed_services
    assert listed_services(["@service\tfoo.service\tenabled=enabled\tactive=active",
                            "@service\t../x\tenabled=a\tactive=b", "@service\tbad unit.service\tenabled=a\tactive=b"]) \
        == [("foo.service", "enabled", "active")]


def test_all_items_have_script_and_guide():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    items = json.loads((root / "data" / "items.json").read_text(encoding="utf-8"))
    items = items.get("items", items)
    guides = json.loads((root / "data" / "guides.json").read_text(encoding="utf-8"))["guides"]
    for it in items:
        assert (root / "scripts" / "items" / f"{it['id']}.sh").is_file(), it["id"]
        assert it["id"] in guides, it["id"]


def test_restart_notices():
    from isms.util import restart_notices
    r = [{"id": "U-46", "fix_state": "FIXED", "fix_note": "조치 완료 [수동 재시작 필요: sendmail — systemctl restart sendmail]"},
         {"id": "U-48", "fix_state": "FAILED", "fix_note": "[수동 재시작 필요: sendmail]"},
         {"id": "U-35", "fix_state": "FIXED", "fix_note": "조치 완료"}]
    assert restart_notices(r) == [("U-46", "수동 재시작 필요: sendmail — systemctl restart sendmail")]


def test_state_text_manual_fix_label():
    from isms.messages import state_text
    assert state_text({"state": "VULN", "type": "guide"}) == "취약 (수동점검 필요)"
    assert state_text({"state": "VULN", "type": "auto"}) == "취약"
    assert state_text({"state": "VULN", "type": "guide", "fix_state": "FIXED"}, use_fix=True) == "조치됨"


def test_untrusted_scripts_preflight(tmp_path):
    import os
    from isms import util
    items = tmp_path / "scripts" / "items"
    items.mkdir(parents=True)
    f = items / "U-99.sh"
    f.write_text("#!/bin/bash\n")
    os.chmod(tmp_path / "scripts", 0o755); os.chmod(items, 0o755)
    os.chmod(f, 0o775)                      # 그룹 쓰기 → 신뢰 불가
    bad = util.untrusted_scripts(tmp_path / "scripts")
    assert any(p.endswith("U-99.sh") for p, _ in bad)
    os.chmod(f, 0o755)
    assert not [b for b in util.untrusted_scripts(tmp_path / "scripts") if b[0].endswith("U-99.sh")]


def test_guide_file_shows_hits_and_list():
    """가이드 파일에는 점검에서 걸린 항목(detail)과 관련 파일 목록(list)이 함께 적힌다."""
    from isms import guidefiles
    r = {"id": "U-25", "title": "world writable 파일 점검", "category": "c", "severity": "상", "type": "approve",
         "state": "VULN", "evidence": "2건", "detail": ["/opt/a\t소유자=root 권한=666", "/opt/b\t소유자=root 권한=666"],
         "list": ["/opt/a\t소유자=root 권한=666", "/opt/c\t소유자=root 권한=644"]}
    txt = guidefiles.render(r, {})
    assert "점검에서 걸린 항목(2건)" in txt and "/opt/a  소유자=root 권한=666" in txt
    assert "관련 파일 목록" in txt and "/opt/c" in txt
    assert txt.count("/opt/a") == 1                       # 걸린 항목은 목록에서 중복해 적지 않는다


def test_heavy_items_are_fixable_types():
    """전체 검색 항목(15,23,25,26)과 22 는 엑셀 ? 이므로 승인 후 적용(approve) 이고 apply 를 지원한다."""
    items = {i["id"]: i for i in load_items(Path(__file__).resolve().parents[1] / "data" / "items.json")}
    for i in ("U-15", "U-22", "U-23", "U-25", "U-26"):
        assert items[i]["type"] == "approve", i
        assert "usage: %s.sh check|apply|list" % i in (Path(__file__).resolve().parents[1] / "scripts" / "items" / f"{i}.sh").read_text(encoding="utf-8")


def test_recheck_after_apply(env):
    """조치를 했으면 재점검이 항상 실행되고, 재점검 결과가 표에 쓸 행으로 돌아온다."""
    eng, items, scripts, target, tmp = env
    res = eng.scan(["F-01", "F-03"])
    after, sid = eng.apply(["F-01"])
    rows = eng.recheck(after, res)
    assert [x["id"] for x in rows] == ["F-01"]
    assert rows[0]["before"] == "VULN" and rows[0]["after"] == "GOOD" and rows[0]["ok"]
    assert after[0]["rechecked"] and after[0]["fix_state"] == "FIXED"


def test_reviewed_items_are_approve_with_apply():
    """엑셀 재검토로 ? 가 된 항목은 승인 후 적용이고 apply 를 지원한다."""
    root = Path(__file__).resolve().parents[1]
    items = {i["id"]: i for i in load_items(root / "data" / "items.json")}
    for i in ("U-05", "U-08", "U-10", "U-14", "U-22", "U-36", "U-67"):
        assert items[i]["type"] == "approve" and items[i]["excel"]["shell"] == "?", i
        assert f"{i}.sh check|apply|list" in (root / "scripts" / "items" / f"{i}.sh").read_text(encoding="utf-8"), i


def test_ubuntu_uses_own_script_else_common(tmp_path):
    from isms.runner import script_path
    s = tmp_path / "scripts"
    (s / "items").mkdir(parents=True)
    (s / "ubuntu" / "items").mkdir(parents=True)
    (s / "items" / "U-01.sh").write_text("x")
    (s / "items" / "U-03.sh").write_text("x")
    (s / "ubuntu" / "items" / "U-03.sh").write_text("y")
    ub = {"os_id": "ubuntu"}
    assert script_path(s, "U-03", ub) == s / "ubuntu" / "items" / "U-03.sh"   # 전용이 있으면 전용
    assert script_path(s, "U-01", ub) == s / "items" / "U-01.sh"              # 없으면 공통
    assert script_path(s, "U-03", {"os_id": "rocky"}) == s / "items" / "U-03.sh"
    assert script_path(s, "U-03") == s / "items" / "U-03.sh"


def test_ubuntu_scripts_exist_and_valid_syntax():
    import subprocess
    d = Path(__file__).resolve().parents[1] / "scripts" / "ubuntu" / "items"
    files = sorted(d.glob("U-*.sh"))
    assert [f.stem for f in files] == ["U-02", "U-03", "U-66"]
    for f in files:
        assert subprocess.run(["bash", "-n", str(f)]).returncode == 0


def test_supported_families_are_fixable_others_blocked():
    import os_info
    items = load_items(str(Path(__file__).resolve().parents[1] / "data" / "items.json"))
    fixable = [i for i in items if i["type"] != "guide"]
    for osid, major in (("rocky", "9"), ("rocky", "10"), ("centos", "9"), ("centos", "10"),
                        ("ubuntu", "20"), ("ubuntu", "22"), ("ubuntu", "24"), ("ubuntu", "26")):
        info = dict(INFO, os_id=osid, os_version_major=major, os_key=osid + major, detect_ok=True)
        assert os_info.classify(info) in ("supported", "extended"), (osid, major)
        assert all(can_fix(dict(i, script=True), info)[0] for i in fixable), (osid, major)
        assert not can_fix(dict(items[0], script=True, type="guide"), info)[0]
    for osid, major in (("ubuntu", "18"), ("rocky", "8"), ("centos", "8"), ("debian", "12"), ("fedora", "40")):
        info = dict(INFO, os_id=osid, os_version_major=major, os_key=osid + major, detect_ok=True)
        assert os_info.classify(info) == "unsupported", (osid, major)
        assert not can_fix(dict(fixable[0], script=True), info)[0], (osid, major)


def test_cli_saves_json_and_txt_by_default(tmp_path):
    """--format 을 주지 않아도 비대화형 실행은 json+txt 리포트를 저장한다(스냅샷과 짝이 되는 기록)."""
    import os, subprocess, sys
    if os.geteuid() != 0:
        pytest.skip("root 권한이 필요합니다")
    root = Path(__file__).resolve().parent.parent
    env = dict(os.environ, ISMS_ALLOW_UNTRUSTED="1")
    r = subprocess.run([sys.executable, str(root / "main.py"), "--scan-only", "--ids", "U-16", "--out", str(tmp_path / "rep")],
                       capture_output=True, text=True, env=env, cwd=root, timeout=120)
    saved = sorted(p.suffix for p in (tmp_path / "rep").rglob("*") if p.is_file())
    assert saved == [".json", ".txt"], (saved, r.stdout[-300:], r.stderr[-300:])


def test_isms_lite_check_is_standalone_and_up_to_date(tmp_path):
    """isms_lite_check.sh 는 다른 파일 없이 동작하고, 생성기 결과와 같다(스크립트를 고치고 생성기를 안 돌리면 여기서 걸린다)."""
    import importlib.util, subprocess
    root = Path(__file__).resolve().parent.parent.parent
    spec = importlib.util.spec_from_file_location("gen_lite_check", root / "tools" / "gen_lite_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.OUT = tmp_path / "isms_lite_check.sh"
    mod.main()
    real = root / "isms_lite_check.sh"
    assert real.read_text(encoding="utf-8") == mod.OUT.read_text(encoding="utf-8"), "python3 tools/gen_lite_check.py 를 다시 실행하세요"
    assert subprocess.run(["bash", "-n", str(real)]).returncode == 0
    text = real.read_text(encoding="utf-8")
    assert 'dirname "$0"' not in text and '"$S"' not in text     # 같은 폴더의 다른 파일을 읽지 않는다
    assert len(re.findall(r"^chk_U\d+\(\) \(", text, re.M)) == 58


def test_restore_relabels_selinux_context(tmp_path):
    """복구한 파일은 restorecon 으로 SELinux 라벨을 맞춘다(SELinux 가 꺼져 있으면 건너뜀)."""
    log = tmp_path / "log"
    on = tmp_path / "on.sh"
    on.write_text("#!/bin/sh\nexit 0\n")
    off = tmp_path / "off.sh"
    off.write_text("#!/bin/sh\nexit 1\n")
    rc = tmp_path / "rc.sh"
    rc.write_text(f'#!/bin/sh\necho "$@" >> {log}\n')
    for f in (on, off, rc):
        f.chmod(0o755)
    store = SnapshotStore(tmp_path / "data")
    store.restorecon = [str(rc)]
    store.selinuxenabled = [str(off)]
    store._relabel(["/etc/a"])
    assert not log.exists()
    store.selinuxenabled = [str(on)]
    store._relabel(["/etc/a", "/etc/b"])
    assert log.read_text().split() == ["/etc/a", "/etc/b"]
