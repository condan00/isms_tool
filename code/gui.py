#!/usr/bin/env python3
"""ISMS 점검·조치 도구 GUI 진입점 (클릭형). 실행:  sudo ./isms_run_gui   (소스로: sudo python3 gui.py)

main.py(터미널 화면)와 같은 엔진·스크립트·데이터를 쓰고 화면만 다르다.
sudo 로 띄우면 root 가 사용자의 화면에 접속해야 해서, 실행한 사용자의 화면 인증 파일을 찾아 DISPLAY/XAUTHORITY 를 맞춘다."""
import glob
import os
import pwd
import sys

import os_info
from isms import messages
from isms.items import ItemError


def prepare_display():
    """sudo 로 실행했을 때 사용자의 화면(X11/XWayland)에 접속할 수 있게 환경 변수를 맞춘다."""
    user = os.environ.get("SUDO_USER")
    if os.geteuid() != 0 or not user:
        return
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return
    if not os.environ.get("DISPLAY"):
        os.environ["DISPLAY"] = ":0"
    if not os.environ.get("XAUTHORITY"):
        cands = sorted(glob.glob(f"/run/user/{pw.pw_uid}/.mutter-Xwaylandauth.*")) + [
            f"/run/user/{pw.pw_uid}/gdm/Xauthority", os.path.join(pw.pw_dir, ".Xauthority")]
        for c in cands:
            if os.path.isfile(c):
                os.environ["XAUTHORITY"] = c
                break
    os.environ.setdefault("HOME", pw.pw_dir)


def popup(title, msg):
    """창을 띄울 수 있으면 대화상자로, 아니면 터미널에 알린다."""
    print(f"[{title}] {msg}", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(title, msg)
        r.destroy()
    except Exception:
        pass


def main(argv=None):
    try:
        import tkinter  # noqa: F401
    except ImportError as e:
        print(f"[오류] tkinter 를 불러오지 못했습니다({e}).\n"
              "       빌드한 PC 에 설치 후 다시 빌드하세요:  sudo dnf install -y python3-tkinter", file=sys.stderr)
        return 2
    prepare_display()
    import main as cli
    args = cli.parse_args(argv if argv is not None else sys.argv[1:])
    messages.LANG = args.lang if args.lang in messages.MESSAGES else "ko"
    try:
        info, engine = cli.build_engine(args)
    except SystemExit:
        popup("실행할 수 없음", "스크립트 경로를 신뢰할 수 없습니다. 터미널에 출력된 해결 방법(chown/chmod)을 확인하세요.")
        return 2
    except (os_info.OSDetectError, ItemError, OSError, ValueError) as e:
        popup("오류", str(e))
        return 2
    if not info["policy"]["run"]:
        popup("root 권한 필요", messages.t("need_root") + "\n\n터미널에서:  sudo ./isms_run_gui")
        return 2
    try:
        from isms.gui import App
        app = App(engine, info)
    except Exception as e:
        import tkinter
        if isinstance(e, tkinter.TclError):
            print(f"[오류] 화면에 연결하지 못했습니다: {e}\n"
                  "  · sudo 로 실행했다면 사용자 화면 접근을 허용하세요:  xhost +SI:localuser:root   (사용자 계정으로 한 번 실행)\n"
                  "  · SSH 접속 중이라면 ssh -X 로 접속하거나 서버 화면에서 실행하세요.", file=sys.stderr)
            return 2
        raise
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
