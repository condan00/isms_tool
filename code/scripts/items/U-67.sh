#!/bin/bash
# U-67 로그 디렉터리 소유자 및 권한 설정  (엑셀 ?: 확인 후 적용)
# 기준: /var/log 안 로그 파일의 소유자가 root 이고 권한이 644 이하
# 조치: 기준 미달 파일의 소유자를 root 로 바꾸고(그룹은 그대로), 644 를 넘는 권한 비트만 제거한다.
#       주의: 서비스 전용 계정(chrony, sssd 등)이 쓰는 로그는 소유자가 root 가 되면 그 서비스가 로그를 못 쓸 수 있다(logrotate 가 다시 만들면 원래 소유자로 돌아간다).
# 계약: bash U-67.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상: /var/log 와 그 아래 1단계 하위 폴더의 일반 파일(링크 제외). list 는 조치 대상(기준 미달)만 보여 스냅샷이 큰 로그 전체를 복사하지 않게 한다.
# 손으로 쓴 스크립트다(tools/ 생성기 없음).
set -u
export LC_ALL=C
shopt -s nullglob
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

safe_fix() { local f=$1 own=${2:-} mod=${3:-} a b rc=0
  [ -L "$f" ] && return 1
  { exec 9<"$f"; } 2>/dev/null || return 1
  a=$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null); b=$(stat -c '%d:%i' "$f" 2>/dev/null)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    [ -n "$own" ] && { chown "$own" /proc/self/fd/9 || rc=1; }
    [ -n "$mod" ] && { chmod "$mod" /proc/self/fd/9 || rc=1; }
  else rc=1; fi
  exec 9<&-; return $rc; }
[ -d /var/log ] || { state NA "/var/log 없음"; exit 0; }
mapfile -t targets < <(find /var/log -maxdepth 2 -type f 2>/dev/null | sort)
[ "${#targets[@]}" -gt 0 ] || { state NA "로그 파일이 없습니다"; exit 0; }
bad=(); info=()
scan() { bad=(); info=(); local f o m over
  for f in "${targets[@]}"; do
    read -r o m < <(stat -c '%U %a' "$f" 2>/dev/null) || continue
    over=$(( 8#$m & ~8#644 & 8#7777 ))
    if [ "$o" != "root" ] || [ "$over" -ne 0 ]; then bad+=("$f"); info+=("$f"$'\t'"소유자=$o 권한=$m"); fi
  done; }
scan
case "${1:-}" in
  list) [ "${#info[@]}" -gt 0 ] && printf '%s\n' "${info[@]}"; state GOOD "${#bad[@]}개 파일(기준 미달만 표시)" ;;
  check) [ "${#info[@]}" -gt 0 ] && printf '%s\n' "${info[@]}"
    if [ "${#bad[@]}" -gt 0 ]; then state VULN "${#bad[@]}개 로그 파일이 기준 미달 (기준: root, 644 이하)"; else state GOOD "${#targets[@]}개 로그 파일 모두 기준 충족"; fi ;;
  apply)
    for f in "${bad[@]}"; do
      read -r o m < <(stat -c '%U %a' "$f" 2>/dev/null) || continue
      [ "$o" != root ] && safe_fix "$f" root
      m=$(stat -c '%a' "$f"); [ $(( 8#$m & ~8#644 & 8#7777 )) -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$m & 8#644 )))"
    done
    scan
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: 로그 파일 소유자 root, 권한 644 이하" ;;
  *) echo "usage: U-67.sh check|apply|list" >&2; exit 2 ;;
esac
