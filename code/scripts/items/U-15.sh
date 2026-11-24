#!/bin/bash
# U-15 파일 및 디렉터리 소유자 설정  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
# 기준: 소유자(nouser)나 그룹(nogroup)이 없는 파일·디렉터리가 없음. 조치는 삭제하지 않고 소유자/그룹을 root 로 바꾼다.
# 계약: bash U-15.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 로컬 파일시스템만(-xdev), /proc /sys /dev /run 제외. 대상이 MAXN 건을 넘으면 자동 조치하지 않고 수동 점검(MANUAL)으로 둔다.
# 이 파일은 손으로 쓴 스크립트다(tools/ 생성기 없음).
set -u
export LC_ALL=C
MAXN=300
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
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

scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -n $((MAXN + 1)); }
show() { local p o m; for p in "$@"; do { read -r o m < <(stat -c '%u:%g %a' "$p" 2>/dev/null); } && printf '%s\t소유자(uid:gid)=%s 권한=%s\n' "$p" "$o" "$m"; done; }
case "${1:-}" in
  list) mapfile -t f < <(scan); show "${f[@]:0:$MAXN}"; state GOOD "${#f[@]}개 항목" ;;
  check)
    mapfile -t f < <(scan)
    show "${f[@]:0:$MAXN}"
    if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "소유자/그룹이 없는 항목이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
    elif [ "${#f[@]}" -gt 0 ]; then state VULN "소유자/그룹이 없는 파일·디렉터리 ${#f[@]}건"
    else state GOOD "소유자/그룹이 없는 파일 없음"; fi ;;
  apply)
    P='\( -path /proc -o -path /sys -o -path /dev -o -path /run \)'
    # -execdir: 해당 디렉터리 안에서 상대 경로로 실행하고 -h 로 링크는 따라가지 않는다. 삭제는 하지 않는다.
    eval "find / -xdev $P -prune -o -nouser -execdir chown -h root -- {} +" 2>/dev/null
    eval "find / -xdev $P -prune -o -nogroup -execdir chown -h :root -- {} +" 2>/dev/null
    mapfile -t f < <(scan)
    if [ "${#f[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#f[@]}건이 남았습니다"; exit 1; fi
    state GOOD "조치 완료: 소유자/그룹이 없던 항목의 소유자·그룹을 root 로 변경" ;;
  *) echo "usage: U-15.sh check|apply|list" >&2; exit 2 ;;
esac
