#!/usr/bin/env python3
"""GUI 화면 흐름 점검(수동 실행용, pytest 가 모으지 않는다). 가짜 스크립트로 엔진을 만들고 화면을 차례로 띄워 스크린샷을 남긴다.

  xvfb-run -a -s "-screen 0 1280x800x24" python3 tests/gui_smoke.py [스크린샷 폴더]
tkinter 가 있는 파이썬이 필요하다(Rocky 9: sudo dnf install python3-tkinter)."""
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from isms.engine import Engine          # noqa: E402
from isms import gui                    # noqa: E402

INFO = {"os_key": "rocky9", "pkg_manager": "dnf", "hostname": "smoke", "os_name": "Rocky Linux 9.4", "kernel": "5.14", "arch": "x86_64",
        "is_root": True, "os_override": False, "support_level": "supported", "warnings": [],
        "policy": {"run": True, "fix": True, "reason": "supported"}}


def mk(iid, title, cat, sev="상", typ="auto", heavy=False, files=(), shell="O"):
    return {"id": iid, "title": title, "category": cat, "severity": sev, "type": typ, "script": True, "heavy": heavy,
            "touches": {"files": list(files)}, "supported_os": ["rocky9"], "fix_supported_os": ["rocky9"], "fix_group": "file",
            "excel": {"shell": shell}, "guide": {"summary": "권한을 644 이하로 맞춥니다.", "show_when": ["VULN", "MANUAL"]}}


def main(outdir):
    tmp = Path(tempfile.mkdtemp())
    sc = tmp / "scripts" / "items"
    sc.mkdir(parents=True)
    target = tmp / "t.conf"
    target.write_text("original\n")
    os.chmod(target, 0o666)

    def script(iid, body):
        (sc / f"{iid}.sh").write_text("#!/bin/bash\nset -u\n" + textwrap.dedent(body))
    script("U-01", f'm=$(stat -c %a {target}); o=$(( 8#$m & ~8#644 & 8#7777 )); case "$1" in check) [ $o -ne 0 ] && echo "VULN|mode=$m" || echo "GOOD|mode=$m";; apply) chmod 644 {target}; echo "GOOD|fixed";; list) printf "{target}\\t설정 파일\\n"; echo "GOOD|1";; esac')
    script("U-02", 'echo "GOOD|ok"')
    script("U-03", 'echo "MANUAL|사람이 확인"')
    script("U-04", 'echo "VULN|guide only"')
    script("U-05", f'case "$1" in check) echo "VULN|needs"; ;; apply) echo "ERROR|boom"; exit 1;; list) echo "GOOD|0";; esac')
    script("U-15", 'echo "GOOD|slow"')
    items = [mk("U-01", "파일 권한 설정", "파일 및 디렉터리 관리", files=[str(target)]),
             mk("U-02", "비밀번호 관리 정책", "계정 관리", "중"), mk("U-03", "수동 확인 항목", "계정 관리", "중"),
             mk("U-04", "가이드 전용 항목", "서비스 관리", "하", typ="guide", shell="X"),
             mk("U-05", "조치가 실패하는 항목", "서비스 관리", "상", shell="?"),
             mk("U-15", "전체 파일 검색 항목", "파일 및 디렉터리 관리", "상", heavy=True, shell="?")]
    eng = Engine(tmp / "scripts", tmp / "data", INFO, items, strict_trust=False)
    from isms import report as _rp, guidefiles as _gf, history as _hs
    for mod in (_rp, _gf, _hs):
        mod.app_dir = lambda: tmp                                    # 리포트·가이드는 임시 폴더에 저장
    gui.messagebox.askyesno = lambda *a, **k: True                    # 확인창은 자동으로 '예'
    gui.messagebox.showinfo = lambda *a, **k: None
    app = gui.App(eng, INFO)
    app.root.geometry("1120x720+0+0")
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    def pump(sec=0.4, until=None, timeout=20):
        end = time.time() + (timeout if until else sec)
        while time.time() < end:
            app.root.update()
            if until and until():
                break
            time.sleep(0.03)
        app.root.update()

    def asciize():
        """한글 글꼴이 없는 화면(예: 가상 화면)에서 글자 폭만 비슷하게 확인하려고 한글을 M 으로 바꿔 그린다(ASCIIZE=1)."""
        import re
        conv = lambda x: re.sub(r"[\uac00-\ud7a3]", "M", x) if isinstance(x, str) else x

        def walk(w):
            try:
                if "text" in w.keys() and isinstance(w.cget("text"), str):
                    w.configure(text=conv(w.cget("text")))
            except Exception:
                pass
            if isinstance(w, gui.ttk.Treeview):
                for col in w["columns"]:
                    w.heading(col, text=conv(w.heading(col, "text")))
                w.heading("#0", text=conv(w.heading("#0", "text")))
                stack = list(w.get_children(""))
                while stack:
                    i = stack.pop()
                    w.item(i, text=conv(w.item(i, "text")), values=[conv(v) for v in w.item(i, "values")])
                    stack += list(w.get_children(i))
            if isinstance(w, gui.tk.Text):
                st = w.cget("state"); w.configure(state="normal"); w.insert("1.0", ""); t = w.get("1.0", "end"); w.delete("1.0", "end"); w.insert("1.0", conv(t)); w.configure(state=st)
            for c in w.winfo_children():
                walk(c)
        for top in [app.root] + [c for c in app.root.winfo_children() if isinstance(c, gui.tk.Toplevel)]:
            walk(top)

    def shot(name):
        pump(0.3)
        if os.environ.get("ASCIIZE"):
            asciize()
            pump(0.2)
        subprocess.run(["import", "-window", "root", str(out / f"{name}.png")], check=False)
        print("shot", name)

    app.show_home(); shot("01_home")
    app.show_select(); shot("02_select")
    app.start_scan(["U-01", "U-02", "U-03", "U-04", "U-05"]); pump(until=lambda: not app.busy)
    shot("03_results")
    app.show_detail(app.s["results"][0]); shot("04_detail")
    for w in app.root.winfo_children():
        if isinstance(w, gui.tk.Toplevel):
            w.destroy()
    app.show_fix_select(); shot("05_fix_select")
    app.start_fix(["U-01", "U-05"]); pump(until=lambda: not app.busy and "rechecks" in app.s)
    shot("06_fix_result")
    assert [x["after"] for x in app.s["rechecks"]] == ["GOOD", "VULN"], app.s["rechecks"]
    assert app.s["rechecks"][0]["ok"] and not app.s["rechecks"][1]["ok"]
    app.show_save(); shot("07_save")
    btn = [w for w in app.body.winfo_children()[0].winfo_children()[-1].winfo_children() if w.cget("text") == "저장"][0]
    btn.invoke(); pump(until=lambda: not app.busy)
    assert list((tmp / "isms-report").glob("*/*.json")) and list((tmp / "isms-guid").glob("*/U-*_guid.txt")), "저장 실패"
    shot("07b_saved")
    app.show_history(); shot("08_history")
    app.show_restore_list(); shot("09_restore_list")
    snap = eng.snaps.list()[0]
    app.show_restore_items(snap); shot("10_restore_items")
    os.chmod(target, 0o600)
    btn = [w for w in app.body.winfo_children()[0].winfo_children()[-1].winfo_children() if w.cget("text") == "복구 실행"][0]
    btn.invoke(); pump(until=lambda: not app.busy)
    assert oct(os.stat(target).st_mode)[-3:] == "666", oct(os.stat(target).st_mode)      # 조치 전(666)으로 복구됨
    shot("10b_restored")
    app.show_results(readonly=True, results=app.s["results"], back=app.show_history, header="smoke"); shot("11_readonly")
    # Esc = 뒤로/취소
    app.show_fix_select(); app.root.event_generate("<Escape>"); pump(0.3)
    assert "3. 결과" in app.crumb.cget("text"), app.crumb.cget("text")
    app.root.destroy()
    print("SMOKE OK")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/gui_shots")
