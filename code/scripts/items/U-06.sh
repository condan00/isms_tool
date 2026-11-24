#!/bin/bash
# U-06 사용자 계정 su 기능 제한
# 기준: su 를 특정 그룹(wheel)만 쓰도록 제한 (pam_wheel 또는 /usr/bin/su 그룹·권한). 일반 사용자가 없으면 불필요
# 계약: bash U-06.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 이 파일은 tools/gen_config_scripts*.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }
pkg_gate() { local label=$1 pkgs=$2 rc l; shift 2; pkg_any $pkgs; rc=$?; [ "$rc" -eq 1 ] || return 0
  l=$(leftover "$@" | head -5 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then state MANUAL "$label 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
  else state NA "$label 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi; exit 0; }
pkg_has() { pkg_any "$@"; [ $? -ne 1 ]; }

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다
safe_fix() { local f=$1 own=${2:-} mod=${3:-} a b rc=0
  [ -L "$f" ] && return 1
  { exec 9<"$f"; } 2>/dev/null || return 1
  a=$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null); b=$(stat -c '%d:%i' "$f" 2>/dev/null)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    [ -n "$own" ] && { chown "$own" /proc/self/fd/9 || rc=1; }
    [ -n "$mod" ] && { chmod "$mod" /proc/self/fd/9 || rc=1; }
  else rc=1; fi
  exec 9<&-; return $rc; }

# 서비스 재적용 도우미: svc_list(스냅샷이 서비스 상태를 복구하도록 알림), svc_act(동작 중인 유닛만 reload/restart)
acted=(); failed_svc=""
svc_list() {
  have systemctl || return 0
  local u
  for u in "$@"; do
    [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] || continue
    printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
  done
  return 0
}
svc_act() {    # svc_act reload|restart 유닛... : 동작 중인 유닛만 처리, 처리 후 동작하지 않으면 1(failed_svc 에 유닛 이름)
  local a=$1 u; shift
  have systemctl || return 0
  for u in "$@"; do
    systemctl is-active "$u" >/dev/null 2>&1 || continue
    systemctl "$a" "$u" >/dev/null 2>&1; sleep 1
    systemctl is-active "$u" >/dev/null 2>&1 || { failed_svc=$u; return 1; }
    acted+=("$a:$u")
  done
  return 0
}

nl_end() { [ -s "$1" ] && [ -n "$(tail -c1 "$1")" ] && echo >> "$1"; return 0; }

# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열
kv_get() {
  awk -v k="$2" '/^[[:space:]]*#/ {next}
    { if (match($0, "^[[:space:]]*" k "([[:space:]]*=[[:space:]]*|[[:space:]]+)")) { v = substr($0, RLENGTH + 1); sub(/[[:space:]]+$/, "", v); r = v; f = 1 } }
    END { if (f) print r }' "$1" 2>/dev/null
}

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가
kv_set() {
  local f=$1 k=$2 v=$3 sep=$4
  if grep -Eq "^[[:space:]]*$k([[:space:]]*=|[[:space:]])" "$f"; then
    sed -i -E "s~^[[:space:]]*$k([[:space:]]*=[[:space:]]*|[[:space:]]+).*~$k$sep$v~" "$f"
  else
    nl_end "$f"; printf '%s%s%s\n' "$k" "$sep" "$v" >> "$f"
  fi
}

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력
login_users() {
  local u uid gid home shell
  while IFS=: read -r u _ uid gid _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    printf '%s\t%s\t%s\n' "$u" "$home" "$gid"
  done < <(getent passwd)
}

PAMSU=/etc/pam.d/su
SU=/usr/bin/su
[ -f "$PAMSU" ] || [ -e "$SU" ] || { state NA "su 설정이 없습니다"; exit 0; }

grp=""; for g in wheel sudo; do getent group "$g" >/dev/null 2>&1 && { grp=$g; break; }; done
users() { awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ && $1 != "nobody" {print $1}' /etc/passwd; }
pam_on() { grep -Eqs '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAMSU"; }
bin_on() { [ -e "$SU" ] || return 1; read -r g m < <(stat -c '%G %a' "$SU"); [ "$g" != root ] && [ $(( 8#$m & 8#0007 )) -eq 0 ]; }

case "${1:-}" in
  list) [ -f "$PAMSU" ] && printf '%s\tPAM su 설정\n' "$PAMSU"; [ -e "$SU" ] && printf '%s\tsu 실행 파일(소유 그룹/권한)\n' "$(readlink -f "$SU")"; state GOOD "목록" ;;
  check)
    mapfile -t u < <(users)
    if [ "${#u[@]}" -eq 0 ]; then state GOOD "일반 사용자 계정이 없어 su 제한이 필요하지 않음(root 만 사용)"
    elif pam_on; then state GOOD "pam_wheel 로 su 사용 그룹이 제한됨"
    elif bin_on; then state GOOD "su 실행 권한이 특정 그룹으로 제한됨"
    else state VULN "su 명령을 모든 사용자가 사용할 수 있음 (일반 사용자 ${#u[@]}명)"; fi ;;
  apply)
    [ -n "$grp" ] || { state ERROR "wheel/sudo 그룹이 없어 자동 설정할 수 없음(그룹을 만든 뒤 가이드대로 설정)"; exit 1; }
    [ -f "$PAMSU" ] || { state ERROR "$PAMSU 가 없어 PAM 방식으로 설정할 수 없음"; exit 1; }
    if grep -Eq '^[[:space:]]*#[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAMSU"; then
      sed -i -E "0,/^[[:space:]]*#[[:space:]]*(auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so.*)/s//\1/" "$PAMSU"
    else
      line="auth            required        pam_wheel.so use_uid"; [ "$grp" != wheel ] && line="auth            required        pam_wheel.so use_uid group=$grp"
      if grep -Eq 'pam_rootok\.so' "$PAMSU"; then sed -i -E "0,/pam_rootok\.so/s//&\n$line/" "$PAMSU"; else nl_end "$PAMSU"; echo "$line" >> "$PAMSU"; fi
    fi
    if pam_on; then state GOOD "조치 완료: su 를 $grp 그룹으로 제한 (wheel 그룹 구성원은 재로그인 후 su 가능)"
    else state ERROR "조치 후에도 su 제한이 적용되지 않음"; exit 1; fi ;;
  *) echo "usage: U-06.sh check|apply|list" >&2; exit 2 ;;
esac
