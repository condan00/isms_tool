#!/usr/bin/env python3
"""[GUI(클릭 화면)] 단일 실행 파일 빌드.  일반 계정(sudo 가능)에서 실행하세요:   python3 build-GUI.py

  결과  : 도구 폴더(isms_tool)와 같은 폴더에 실행 파일 isms_run_gui 가 생깁니다(이름 변경: --name 이름).
  실행  : sudo ./isms_run_gui      (클릭으로 점검·조치·이전 결과 보기·스냅샷 복구. 풀기/chown 불필요)
  준비  : tkinter·venv·binutils 가 없으면 자동으로 설치합니다(sudo 암호를 물어봄). Rocky: python3-tkinter / 우분투: python3-tk, python3-venv
          (화면이 있는 환경(데스크톱)에서 실행합니다. 터미널(CLI)만 쓰려면 build.sh 를 쓰세요)
  개발  : python3 build-GUI.py --run     빌드 없이 소스로 바로 실행(sudo 로 실행해야 점검·조치가 됩니다)

build.sh 와 같은 방식으로 빌드합니다: 번들할 scripts/·data/ 를 권한을 정리한 임시 폴더에 복사 -> venv 에서 PyInstaller ->
실행 파일을 root 소유 0755 로 설치(sudo 암호를 한 번 물어봄). 실행 파일은 root 소유 비공개 임시 폴더에 풀려 '스크립트 신뢰 검사'를 통과합니다.
가장 오래된 대상 OS(Rocky 9)에서 빌드하세요(glibc 호환)."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOP = Path(__file__).resolve().parent
CODE = TOP / "code"
VENV = TOP / ".venv-build-gui"


def die(msg, code=1):
    print(f"오류: {msg}", file=sys.stderr)
    sys.exit(code)


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def _can(py, code):
    return subprocess.run([str(py), "-c", code], capture_output=True).returncode == 0


def ensure_prereqs():
    """빌드에 필요한 시스템 패키지(tkinter, venv, binutils)가 없으면 sudo 로 자동 설치한다."""
    need = []
    if not _can(sys.executable, "import tkinter"):
        need.append("tk")
    if not _can(sys.executable, "import venv, ensurepip"):
        need.append("venv")
    if not shutil.which("objdump"):
        need.append("binutils")
    if not need:
        return
    if shutil.which("dnf") or shutil.which("yum"):
        mgr = "dnf" if shutil.which("dnf") else "yum"
        names = {"tk": "python3-tkinter", "venv": "python3", "binutils": "binutils"}
        cmd = [mgr, "-y", "install"]
    elif shutil.which("apt-get"):
        names = {"tk": "python3-tk", "venv": "python3-venv", "binutils": "binutils"}
        cmd = ["apt-get", "-y", "install"]
    else:
        die("필요한 패키지(tkinter, venv, binutils)를 자동으로 설치할 수 없는 OS 입니다. 직접 설치한 뒤 다시 실행하세요.")
    pkgs = sorted({names[n] for n in need})
    print(f"필요한 패키지를 설치합니다: {' '.join(pkgs)}  (sudo 암호를 물어볼 수 있습니다)")
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            die(f"sudo 가 없습니다. root 로 다음을 실행하세요: {' '.join(cmd + pkgs)}")
        cmd = ["sudo"] + cmd
    if "apt-get" in cmd:
        subprocess.run(cmd[:cmd.index("apt-get") + 1] + ["update"], check=False)
    if subprocess.run(cmd + pkgs).returncode != 0:
        die(f"패키지 설치에 실패했습니다. 직접 실행해 보세요: {' '.join(cmd + pkgs)}")


def check_tk(py):
    r = subprocess.run([str(py), "-c", "import tkinter"], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"{py} 에서 tkinter 를 불러올 수 없습니다. 배포판 기본 파이썬(/usr/bin/python3)으로 실행했는지 확인하세요"
            " (직접 설치한 파이썬은 배포판 tkinter 패키지를 쓰지 못합니다).\n       설치 명령:\n         sudo dnf install -y python3-tkinter\n"
            "       (Debian/Ubuntu: sudo apt install python3-tk)")


def stage_bundle(dst):
    """번들할 scripts/·data/ 를 권한을 정리해 복사한다(그룹·기타 쓰기 제거, 캐시 제외)."""
    for name in ("scripts", "data"):
        shutil.copytree(CODE / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for p in [dst] + list(dst.rglob("*")):
        p.chmod(0o755 if p.is_dir() else 0o644)


def build(out_name):
    if not (CODE / "gui.py").is_file():
        die(f"{CODE}/gui.py 가 없습니다. build-GUI.py 는 isms_tool 폴더 최상위에서 실행하세요.")
    out = TOP.parent / out_name
    if out.is_dir():
        die(f"{out} 는 폴더입니다. --name 다른이름 으로 지정하세요.")
    ensure_prereqs()
    check_tk(sys.executable)
    work = Path(tempfile.mkdtemp(prefix="isms-gui-build-"))
    try:
        stage = work / "stage"
        stage.mkdir()
        stage_bundle(stage)
        if not (VENV / "bin" / "python").is_file():
            run([sys.executable, "-m", "venv", VENV])
        py = VENV / "bin" / "python"
        check_tk(py)
        run([py, "-m", "pip", "install", "-q", "-r", CODE / "requirements.txt", "pyinstaller"])
        run([py, "-m", "PyInstaller", "--onefile", "--clean", "--name", "isms_gui",
             "--distpath", work / "dist", "--workpath", work / "build", "--specpath", work,
             "--add-data", f"{stage / 'scripts'}:scripts", "--add-data", f"{stage / 'data'}:data",
             "--exclude-module", "numpy", "--exclude-module", "pandas",
             "--paths", CODE, CODE / "gui.py"], cwd=TOP)
        built = work / "dist" / "isms_gui"
        if not built.is_file():
            die("PyInstaller 결과 파일이 없습니다.")
        # root 소유 0755 로 설치 (sudo 가 없거나 거부되면 현재 사용자 소유로 복사)
        if os.geteuid() == 0:
            run(["install", "-o", "root", "-g", "root", "-m", "755", built, out])
        elif shutil.which("sudo") and subprocess.run(["sudo", "install", "-o", "root", "-g", "root", "-m", "755", str(built), str(out)]).returncode == 0:
            pass
        else:
            print(f"[안내] sudo 설치에 실패해 현재 사용자 소유로 복사합니다. 나중에: sudo chown root:root {out}", file=sys.stderr)
            shutil.copy2(built, out)
            out.chmod(0o755)
    finally:
        shutil.rmtree(work, ignore_errors=True)      # 중간 산출물 정리(.venv-build-gui 는 재빌드용으로 남김)
    print(f"완료.  실행:  sudo {out}")
    print("  · 화면이 안 뜨면(sudo 로 사용자 화면에 접속하지 못함) 사용자 계정으로 한 번:  xhost +SI:localuser:root")


def main():
    ap = argparse.ArgumentParser(description="ISMS 점검·조치 도구 GUI 빌드")
    ap.add_argument("--name", default="isms_run_gui", help="만들 실행 파일 이름(기본 isms_run_gui)")
    ap.add_argument("--run", action="store_true", help="빌드하지 않고 소스로 바로 GUI 실행")
    args = ap.parse_args()
    if args.run:
        os.chdir(CODE)
        os.execv(sys.executable, [sys.executable, str(CODE / "gui.py")])
    build(args.name)


if __name__ == "__main__":
    main()
