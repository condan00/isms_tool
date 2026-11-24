#!/bin/bash
# U-19 /etc/hosts 파일 소유자 및 권한 설정
# 기준: 소유자 root, 권한 644 이하
# 계약: bash U-19.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 권한은 숫자 == 비교가 아니라 '허용 범위를 넘는 비트'로 판정한다(이미 더 엄격하면 양호).
# 이 파일은 tools/gen_perm_scripts.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

PATTERNS=(/etc/hosts)
OWNERS=" root "
MAX_MODE=644

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
      state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 644 이하)"
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
    echo "usage: U-19.sh check|apply|list" >&2; exit 2 ;;
esac
