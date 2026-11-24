#!/bin/bash
# U-65 NTP 및 시각 동기화 설정
# 기준: NTP 서비스(chronyd/ntpd/systemd-timesyncd)가 켜져 있고 서버가 설정됨
# 계약: bash U-65.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

have systemctl || { state MANUAL "systemctl 이 없어 NTP 서비스 상태를 확인할 수 없습니다"; exit 0; }
CANDS=(chronyd.service chrony.service ntpd.service ntp.service ntpsec.service systemd-timesyncd.service)
installed=(); for u in "${CANDS[@]}"; do [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] && installed+=("$u"); done
on_units() { for u in "${installed[@]}"; do [ "$(systemctl is-active "$u" 2>/dev/null)" = active ] && echo "$u"; done; }
# 동기화 서버 수. chrony 는 Ubuntu 25+ 에서 서버를 sources.d/*.sources 로 옮겼고(NTS), DHCP 가 알려 준 서버는 /run/chrony-dhcp 에 둔다
servers() { grep -Ehs '^[[:space:]]*(server|pool|peer)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources /run/chrony-dhcp/*.sources /etc/ntp.conf /etc/ntpsec/ntp.conf /etc/ntpsec/ntp.d/*.conf 2>/dev/null | wc -l; }
# systemd-timesyncd 는 서버를 안 적어도 내장 기본 서버(FallbackNTP)를 쓰므로 정상이다. 따로 지정했으면 그 수를 알려 준다
ts_servers() { cat /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null | grep -E '^[[:space:]]*NTP[[:space:]]*=[[:space:]]*[^[:space:]]' | wc -l; }
srv_note() { if [ "$1" = systemd-timesyncd.service ]; then local t; t=$(ts_servers); [ "$t" -gt 0 ] && echo "NTP= 지정 ${t}건" || echo "내장 기본 서버(FallbackNTP) 사용"; else echo "서버 설정 $(servers)건"; fi; }
srv_ok() { [ "$1" = systemd-timesyncd.service ] || [ "$(servers)" -gt 0 ]; }
case "${1:-}" in
  list) for u in "${installed[@]}"; do printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"; done
        state GOOD "NTP 유닛 ${#installed[@]}개" ;;
  check)
    [ "${#installed[@]}" -gt 0 ] || { state MANUAL "NTP 서비스(chrony/ntp)가 설치되어 있지 않습니다. 패키지를 설치한 뒤 설정하세요(도구는 설치하지 않음)"; exit 0; }
    mapfile -t on < <(on_units)
    if [ "${#on[@]}" -eq 0 ]; then state VULN "NTP 서비스가 설치되어 있으나 동작하지 않음(${installed[*]})"
    elif ! srv_ok "${on[0]}"; then state VULN "${on[0]} 동작 중이나 동기화 서버(server/pool) 설정이 없음"
    else state GOOD "${on[0]} 동작 중($(srv_note "${on[0]}"))"; fi ;;
  apply)
    [ "${#installed[@]}" -gt 0 ] || { state ERROR "NTP 서비스가 설치되어 있지 않음"; exit 1; }
    for u in "${installed[@]}"; do systemctl enable --now "$u" >/dev/null 2>&1 && break; done
    sleep 1; mapfile -t on < <(on_units)
    if [ "${#on[@]}" -gt 0 ] && srv_ok "${on[0]}"; then state GOOD "조치 완료: ${on[0]} 활성화($(srv_note "${on[0]}"))"
    else state ERROR "서비스를 켰으나 서버 설정이 없어 기준 미충족(수동으로 server/pool 추가 필요)"; exit 1; fi ;;
  *) echo "usage: U-65.sh check|apply|list" >&2; exit 2 ;;
esac
