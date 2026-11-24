#!/bin/bash
# U-31 홈 디렉토리 소유자 및 권한 설정
# 기준: 홈 디렉터리 소유자가 해당 계정이고, 타 사용자(other) 쓰기 권한이 없음
# 계약: bash U-31.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상: 로그인 가능한 계정(UID 0 또는 1000 이상)의 홈 디렉터리. 없는 디렉터리는 U-32 에서 다룬다. 하위 파일은 건드리지 않는다.
set -u
export LC_ALL=C

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

collect() {   # 줄마다: 홈경로<TAB>계정
  local u uid home shell
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    case "$home" in /|"") continue ;; esac
    [ -d "$home" ] && [ ! -L "$home" ] && printf '%s\t%s\n' "$home" "$u"
  done < <(getent passwd)
}

mapfile -t rows < <(collect)
bad=(); bad_user=(); bad_info=()
scan_bad() {
  bad=(); bad_user=(); bad_info=()
  local row d u owner mode
  for row in "${rows[@]}"; do
    d=${row%%$'\t'*}; u=${row#*$'\t'}
    read -r owner mode < <(stat -c '%U %a' "$d")
    if [ "$owner" != "$u" ] || [ $(( 8#$mode & 8#002 )) -ne 0 ]; then
      bad+=("$d"); bad_user+=("$u"); bad_info+=("$d"$'\t'"계정=$u 소유자=$owner 권한=$mode")
    fi
  done
}

if [ "${#rows[@]}" -eq 0 ]; then state NA "점검할 홈 디렉터리가 없습니다"; exit 0; fi

case "${1:-}" in
  list)
    for row in "${rows[@]}"; do d=${row%%$'\t'*}; read -r o m < <(stat -c '%U %a' "$d"); printf '%s\t소유자=%s 권한=%s\n' "$d" "$o" "$m"; done
    state GOOD "${#rows[@]}개 디렉터리" ;;
  check)
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 홈 디렉터리가 기준 미달 (기준: 소유자=해당 계정, other 쓰기 금지)"
    else state GOOD "${#rows[@]}개 홈 디렉터리 모두 기준 충족"; fi ;;
  apply)
    scan_bad
    for i in "${!bad[@]}"; do
      d=${bad[$i]}; u=${bad_user[$i]}
      read -r owner mode < <(stat -c '%U %a' "$d")
      [ "$owner" != "$u" ] && safe_fix "$d" "$u"
      [ $(( 8#$mode & 8#002 )) -ne 0 ] && safe_fix "$d" "" o-w
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 홈 디렉터리가 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#rows[@]}개 홈 디렉터리 기준 충족" ;;
  *) echo "usage: U-31.sh check|apply|list" >&2; exit 2 ;;
esac
