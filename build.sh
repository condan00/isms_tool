#!/bin/bash
# [CLI(터미널 화면)] 단일 실행 파일 빌드. 일반 계정(sudo 가능)에서 실행하세요:  ./build.sh   (클릭하는 GUI 는 build-GUI.py)
#  - 결과: 도구 폴더(isms_tool)와 같은 폴더에 실행 파일 isms_run 이 생긴다(이름은 OUT_NAME=이름 ./build.sh 로 변경).
#  - 실행:  sudo ./isms_run        (풀기/chown 필요 없음. 점검 결과 isms-report/·isms-guid/ 도 실행 파일 옆에 생긴다)
#  - 신뢰: 번들에는 권한을 정리한 scripts/·data/ 가 들어 있고, 실행할 때 root 소유의 비공개(0700) 임시 폴더에 풀려
#          '스크립트 신뢰 검사'를 그대로 통과한다. 실행 파일 자체도 root 소유(0755)로 설치한다(sudo 암호를 한 번 물어봄).
# 가장 오래된 대상 OS(Rocky 9)에서 빌드하세요(glibc 호환).
set -euo pipefail
cd "$(dirname "$0")"
TOOL_DIR=$(pwd -P)
OUT_DIR=$(dirname "$TOOL_DIR")
OUT_NAME=${OUT_NAME:-isms_run}
OUT="$OUT_DIR/$OUT_NAME"
[ -d "$OUT" ] && { echo "오류: $OUT 는 폴더입니다. OUT_NAME=다른이름 ./build.sh 로 지정하세요." >&2; exit 1; }

# 0) 빌드에 필요한 시스템 패키지(venv, binutils)가 없으면 자동 설치 (Rocky: dnf / 우분투: apt-get)
need=()
python3 -c 'import venv, ensurepip' 2>/dev/null || need+=(venv)
command -v objdump >/dev/null 2>&1 || need+=(binutils)
if [ "${#need[@]}" -gt 0 ]; then
  SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
  if command -v apt-get >/dev/null 2>&1; then
    pk=(); for n in "${need[@]}"; do [ "$n" = venv ] && pk+=(python3-venv) || pk+=("$n"); done
    echo "필요한 패키지를 설치합니다: ${pk[*]}"; $SUDO apt-get update -qq; $SUDO apt-get -y install "${pk[@]}" || { echo "오류: 패키지 설치 실패" >&2; exit 1; }
  elif command -v dnf >/dev/null 2>&1; then
    pk=(); for n in "${need[@]}"; do [ "$n" = venv ] && pk+=(python3) || pk+=("$n"); done
    echo "필요한 패키지를 설치합니다: ${pk[*]}"; $SUDO dnf -y install "${pk[@]}" || { echo "오류: 패키지 설치 실패" >&2; exit 1; }
  else echo "오류: ${need[*]} 가 필요합니다. 직접 설치하세요." >&2; exit 1; fi
fi

# 1) 번들할 파일을 권한을 정리한 임시 폴더로 복사(그룹·기타 쓰기 제거, 캐시 제외)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/scripts" "$STAGE/data"
cp -r code/scripts/. "$STAGE/scripts/"
cp -r code/data/. "$STAGE/data/"
find "$STAGE" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +

# 2) 빌드
python3 -m venv .venv-build
. .venv-build/bin/activate
pip install -q -r code/requirements.txt pyinstaller
pyinstaller --onefile --clean --name isms_tool \
  --add-data "$STAGE/scripts:scripts" --add-data "$STAGE/data:data" \
  --exclude-module tkinter --exclude-module numpy --exclude-module pandas \
  --paths code code/main.py

# 3) 도구 폴더 옆에 설치: root 소유 0755 (sudo 가 없거나 거부되면 현재 사용자 소유로 복사)
if [ "$(id -u)" -eq 0 ]; then
  install -o root -g root -m 755 dist/isms_tool "$OUT"
elif command -v sudo >/dev/null 2>&1 && sudo install -o root -g root -m 755 dist/isms_tool "$OUT"; then
  :
else
  echo "[안내] sudo 설치에 실패해 현재 사용자 소유로 복사합니다. 나중에: sudo chown root:root $OUT" >&2
  install -m 755 dist/isms_tool "$OUT"
fi
rm -rf build dist isms_tool.spec     # 중간 산출물 정리(.venv-build 는 재빌드용으로 남김)
ls -l "$OUT"
echo "완료.  실행:  sudo $OUT"
echo "점검만 해 보기:  sudo $OUT --scan-only --ids U-04,U-16"
