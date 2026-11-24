#!/bin/bash
# U-21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# 기준: 소유자 root(또는 bin, sys), 권한 640 이하
# 계약: bash U-21.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 권한은 숫자 == 비교가 아니라 '허용 범위를 넘는 비트'로 판정한다(이미 더 엄격하면 양호).
# 이 파일은 tools/gen_perm_scripts.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

PATTERNS=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf)
OWNERS=" root bin sys "
MAX_MODE=640

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

# 패키지 설치 여부: 0=설치됨, 1=미설치, 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
pkg_any() {
  local p
  if command -v rpm >/dev/null 2>&1; then
    for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif command -v dpkg >/dev/null 2>&1; then
    for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
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
if [ "${1:-}" = check ] || [ "${1:-}" = apply ] || [ "${1:-}" = list ]; then
  pkg_gate "rsyslog/syslog-ng" "rsyslog syslog-ng" "/etc/rsyslog.conf" "/etc/rsyslog.d" "/etc/syslog-ng/syslog-ng.conf" "/etc/syslog.conf"
fi

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

case "${1:-}" in
  list)
    for f in "${targets[@]}"; do
      read -r owner mode < <(stat -c '%U %a' "$f"); printf '%s\t소유자=%s 권한=%s\n' "$f" "$owner" "$mode"
    done
    state GOOD "${#targets[@]}개 파일"
    ;;
  check)
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then
      printf '%s\n' "${bad_info[@]}"
      state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root/bin/sys, 640 이하)"
    else
      state GOOD "${#targets[@]}개 파일 모두 기준 충족"
    fi
    ;;
  apply)
    # 스냅샷은 엔진이 이미 만들었다(list 로 알려 준 파일). 기준 미달 파일만 최소 변경한다.
    scan_bad
    for f in "${bad[@]}"; do
      read -r owner mode < <(stat -c '%U %a' "$f")
      case "$OWNERS" in *" $owner "*) ;; *) safe_fix "$f" root ;; esac
      over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
      [ "$over" -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$mode & 8#$MAX_MODE )))"
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#targets[@]}개 파일 기준 충족"
    ;;
  *)
    echo "usage: U-21.sh check|apply|list" >&2; exit 2 ;;
esac
