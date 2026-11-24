#!/bin/bash
# U-25 world writable 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
# 기준: 모든 사용자가 쓸 수 있는 일반 파일이 없음(/tmp·/var/tmp 제외). 조치는 other 쓰기 비트만 제거(chmod o-w).
# 계약: bash U-25.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -n $((MAXN + 1)); }
show() { local p o m; for p in "$@"; do { read -r o m < <(stat -c '%U %a' "$p" 2>/dev/null); } && printf '%s\t소유자=%s 권한=%s\n' "$p" "$o" "$m"; done; }
case "${1:-}" in
  list) mapfile -t f < <(scan); show "${f[@]:0:$MAXN}"; state GOOD "${#f[@]}개 파일" ;;
  check) mapfile -t f < <(scan); show "${f[@]:0:$MAXN}"
    if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "world writable 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
    elif [ "${#f[@]}" -gt 0 ]; then state VULN "world writable 파일 ${#f[@]}건 (/tmp·/var/tmp 제외)"
    else state GOOD "world writable 일반 파일 없음"; fi ;;
  apply) mapfile -t f < <(scan)
    [ "${#f[@]}" -gt "$MAXN" ] && { state ERROR "대상이 ${MAXN}건을 넘어 조치하지 않았습니다"; exit 1; }
    for p in "${f[@]}"; do safe_fix "$p" "" "o-w" || echo "변경 실패: $p" >&2; done
    mapfile -t f < <(scan)
    if [ "${#f[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#f[@]}건이 남았습니다"; exit 1; fi
    state GOOD "조치 완료: world writable 파일의 other 쓰기 권한 제거" ;;
  *) echo "usage: U-25.sh check|apply|list" >&2; exit 2 ;;
esac
