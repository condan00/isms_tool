#!/bin/bash
# U-26 /dev에 존재하지 않는 device 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
# 기준: /dev 에 장치 파일이 아닌 일반 파일이 없음(shm, mqueue 등 정상 항목 제외). 조치는 해당 일반 파일 삭제(50MB 이하만, 조치 전 스냅샷으로 내용 복구 가능). 더 큰 파일은 수동 확인.
# 계약: bash U-26.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

[ -d /dev ] || { state NA "/dev 없음"; exit 0; }
LIMIT=$((50 * 1024 * 1024))     # 스냅샷이 백업하는 최대 크기와 같다
scan() { find /dev \( -path /dev/shm -o -path /dev/mqueue -o -path /dev/hugepages -o -path /dev/pts \) -prune -o -type f -print 2>/dev/null | head -n $((MAXN + 1)); }
small=(); big=(); lines=()
analyze() { small=(); big=(); lines=(); local p o m s
  mapfile -t f < <(scan)
  for p in "${f[@]:0:$MAXN}"; do
    { read -r o m s < <(stat -c '%U %a %s' "$p" 2>/dev/null); } || continue
    if [ "$s" -le "$LIMIT" ]; then small+=("$p"); lines+=("$p"$'\t'"소유자=$o 권한=$m 크기=${s}B (삭제 대상)")
    else big+=("$p"); lines+=("$p"$'\t'"소유자=$o 권한=$m 크기=${s}B (50MB 초과: 수동 확인)"); fi
  done; }
case "${1:-}" in
  list) analyze; [ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}"; state GOOD "${#f[@]}개 파일" ;;
  check) analyze; [ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}"
    if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "/dev 안의 일반 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
    elif [ "${#small[@]}" -gt 0 ]; then state VULN "/dev 안에 장치 파일이 아닌 일반 파일 ${#small[@]}건(삭제 대상)"
    elif [ "${#big[@]}" -gt 0 ]; then state MANUAL "/dev 안의 일반 파일 ${#big[@]}건이 50MB 를 넘어 수동 확인이 필요합니다"
    else state GOOD "/dev 안에 일반 파일 없음"; fi ;;
  apply) analyze
    [ "${#f[@]}" -gt "$MAXN" ] && { state ERROR "대상이 ${MAXN}건을 넘어 조치하지 않았습니다"; exit 1; }
    for p in "${small[@]}"; do [ -f "$p" ] && [ ! -L "$p" ] && rm -f -- "$p"; done
    analyze
    if [ "${#small[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#small[@]}건이 남았습니다"; exit 1; fi
    state GOOD "조치 완료: /dev 안의 일반 파일 삭제(조치 전 스냅샷에 내용 보관)" ;;
  *) echo "usage: U-26.sh check|apply|list" >&2; exit 2 ;;
esac
