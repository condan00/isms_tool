#!/bin/bash
# detect_os.sh - 실행 환경(OS) 정보 수집 스크립트 (읽기 전용, 시스템 변경 없음)
#
# 출력 규칙
#   stdout : 한 줄 JSON (다른 출력 금지 - Python이 그대로 파싱한다)
#   stderr : 경고/오류 메시지
#   종료코드: 0 = 정상 (OS 판별 실패 시에도 0, detect_ok=false / os_id="unknown")
#             2 = 잘못된 옵션
#
# 사용법
#   ./detect_os.sh
#   ./detect_os.sh --os-release <파일>   # 테스트용: 지정한 os-release 파일로 판별

# 명령어 출력 언어에 따라 결과가 달라지지 않도록 고정
export LC_ALL=C
set -u

usage() {
  cat >&2 <<'EOF'
usage: detect_os.sh [--os-release FILE]
  --os-release FILE   /etc/os-release 대신 FILE을 읽는다 (테스트용)
EOF
}

OS_RELEASE_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --os-release)
      if [ $# -lt 2 ]; then
        echo "error: --os-release requires a file path" >&2
        exit 2
      fi
      OS_RELEASE_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# JSON 문자열용 이스케이프: 개행/탭은 공백으로, 나머지 제어문자는 제거,
# 역슬래시와 큰따옴표는 이스케이프
json_escape() {
  printf '%s' "$1" \
    | tr '\n\r\t' '   ' \
    | tr -d '\000-\037' \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# os-release 파일은 source 하지 않고 필요한 키만 읽는다 (파일 내용을 실행하지 않기 위해)
os_val() {
  local line v
  line=$(grep -m1 -E "^$1=" "$OSREL" 2>/dev/null) || { printf ''; return 0; }
  v=${line#*=}
  v=${v#\"}; v=${v%\"}
  v=${v#\'}; v=${v%\'}
  printf '%s' "$v"
}

# ---- 1. os-release 선택 ----
OSREL=""
os_override=false
if [ -n "$OS_RELEASE_FILE" ]; then
  os_override=true
  echo "warn: OS 판별을 $OS_RELEASE_FILE 로 대체했습니다 (테스트 모드, 조치 비활성화)" >&2
  if [ -r "$OS_RELEASE_FILE" ]; then
    OSREL="$OS_RELEASE_FILE"
  else
    echo "warn: cannot read $OS_RELEASE_FILE" >&2
  fi
elif [ -r /etc/os-release ]; then
  OSREL=/etc/os-release
elif [ -r /usr/lib/os-release ]; then
  OSREL=/usr/lib/os-release
fi

os_id=""; os_version_id=""; os_name=""; id_like=""
if [ -n "$OSREL" ]; then
  os_id=$(os_val ID | tr '[:upper:]' '[:lower:]')
  os_version_id=$(os_val VERSION_ID)
  os_name=$(os_val PRETTY_NAME)
  id_like=$(os_val ID_LIKE)
else
  echo "warn: os-release file not found; OS is treated as unknown" >&2
fi

# 메이저 버전: "9.4" -> "9", 숫자가 아니면 비움
os_major=${os_version_id%%.*}
case "$os_major" in
  ''|*[!0-9]*) os_major="" ;;
esac

# os_key: 항목 정의의 supported_os와 비교할 키 (예: rocky9, ubuntu24)
if [ -n "$os_id" ]; then
  os_key="${os_id}${os_major}"
else
  os_key="unknown"
  os_id="unknown"
fi

# ---- 2. 커널/하드웨어/호스트 ----
kernel_name=$(uname -s 2>/dev/null || echo unknown)
kernel=$(uname -r 2>/dev/null || echo unknown)
arch=$(uname -m 2>/dev/null || echo unknown)
host=$(uname -n 2>/dev/null || echo unknown)   # hostname 명령은 최소 설치에 없을 수 있어 uname 사용

if [ "$kernel_name" != "Linux" ]; then
  echo "warn: not a Linux kernel ($kernel_name)" >&2
fi

if [ "$os_id" != "unknown" ] && [ "$kernel_name" = "Linux" ]; then
  detect_ok=true
else
  detect_ok=false
fi

# ---- 3. 실행 권한 ----
if [ "$(id -u 2>/dev/null)" = "0" ]; then
  is_root=true
else
  is_root=false
fi

# ---- 4. 서비스 관리자 / 패키지 관리자 ----
if [ -d /run/systemd/system ]; then
  init_system=systemd
else
  init_system=other
fi

pkg_manager=unknown
for cmd in dnf yum apt-get zypper apk; do
  if command -v "$cmd" >/dev/null 2>&1; then
    pkg_manager=$cmd
    break
  fi
done

# ---- 5. SELinux / firewalld 상태 ----
if command -v getenforce >/dev/null 2>&1; then
  selinux=$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')
  [ -n "$selinux" ] || selinux=unknown
else
  selinux=not_installed
fi

if [ "$init_system" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl cat firewalld.service >/dev/null 2>&1; then
    firewalld=$(systemctl is-active firewalld 2>/dev/null)
    [ -n "$firewalld" ] || firewalld=unknown
  else
    firewalld=not_installed
  fi
else
  firewalld=unknown
fi

timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || echo unknown)

# ---- 6. JSON 출력 (stdout에는 이 한 줄만) ----
printf '{"schema":1,"detect_ok":%s,"os_id":"%s","os_version_id":"%s","os_version_major":"%s","os_key":"%s","os_name":"%s","id_like":"%s","kernel_name":"%s","kernel":"%s","arch":"%s","hostname":"%s","is_root":%s,"os_override":%s,"init_system":"%s","pkg_manager":"%s","selinux":"%s","firewalld":"%s","timestamp":"%s"}\n' \
  "$detect_ok" \
  "$(json_escape "$os_id")" \
  "$(json_escape "$os_version_id")" \
  "$(json_escape "$os_major")" \
  "$(json_escape "$os_key")" \
  "$(json_escape "$os_name")" \
  "$(json_escape "$id_like")" \
  "$(json_escape "$kernel_name")" \
  "$(json_escape "$kernel")" \
  "$(json_escape "$arch")" \
  "$(json_escape "$host")" \
  "$is_root" \
  "$os_override" \
  "$init_system" \
  "$pkg_manager" \
  "$selinux" \
  "$firewalld" \
  "$(json_escape "$timestamp")"

exit 0
