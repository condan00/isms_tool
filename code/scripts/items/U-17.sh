#!/bin/bash
# U-17 시스템 시작 스크립트 권한 설정
# 기준: 시작 스크립트 소유자 root, 일반 사용자(other) 쓰기 권한 없음
# 계약: bash U-17.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상: /etc/rc.d/init.d, /etc/rc.d/rc*.d, /etc/rc.local, /etc/systemd/system 아래(2단계까지)의 파일.
#       링크는 따라가 실제 파일을 보되 /etc, /usr/lib/systemd, /lib/systemd 안의 일반 파일만 인정한다(/dev/null 등 제외).
set -u
export LC_ALL=C
shopt -s nullglob

state() { printf '%s|%s\n' "$1" "$2"; }
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

collect() {
  local c r
  { for c in /etc/rc.d/init.d/* /etc/init.d/* /etc/rc.d/rc*.d/* /etc/rc[0-6S].d/* /etc/rc.local /etc/rc.d/rc.local; do echo "$c"; done
    [ -d /etc/systemd/system ] && find /etc/systemd/system -maxdepth 2 \( -type f -o -type l \) 2>/dev/null
  } | while IFS= read -r c; do
    [ -e "$c" ] || continue
    r=$(readlink -f -- "$c" 2>/dev/null) || continue
    [ -f "$r" ] || continue
    case "$r" in /etc/*|/usr/lib/systemd/*|/lib/systemd/*) printf '%s\n' "$r" ;; esac
  done | sort -u
}

mapfile -t targets < <(collect)
bad=(); bad_info=()
scan_bad() {
  bad=(); bad_info=()
  local f owner mode
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    if [ "$owner" != "root" ] || [ $(( 8#$mode & 8#0002 )) -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}

if [ "${#targets[@]}" -eq 0 ]; then state NA "시작 스크립트 대상 파일이 없습니다"; exit 0; fi

case "${1:-}" in
  list)
    for f in "${targets[@]}"; do read -r o m < <(stat -c '%U %a' "$f"); printf '%s\t소유자=%s 권한=%s\n' "$f" "$o" "$m"; done
    state GOOD "${#targets[@]}개 파일" ;;
  check)
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달 (기준: 소유자 root, other 쓰기 금지)"
    else state GOOD "${#targets[@]}개 파일 모두 기준 충족"; fi ;;
  apply)
    scan_bad
    for f in "${bad[@]}"; do
      read -r owner mode < <(stat -c '%U %a' "$f")
      [ "$owner" != "root" ] && safe_fix "$f" root
      [ $(( 8#$mode & 8#0002 )) -ne 0 ] && safe_fix "$f" "" o-w
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#targets[@]}개 파일 기준 충족" ;;
  *) echo "usage: U-17.sh check|apply|list" >&2; exit 2 ;;
esac
