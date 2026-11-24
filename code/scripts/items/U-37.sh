#!/bin/bash
# U-37 crontab 설정 파일 권한 설정 미흡
# 기준: crontab/at 명령어 소유자 root + 권한 750 이하(SUID 없음), cron/at 설정·작업 파일 권한 640 이하
# 계약: bash U-37.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 주의: crontab 의 SUID 를 제거하면 일반 사용자는 crontab 명령을 쓸 수 없다(그래서 승인 후 적용).
#       /var/spool/cron, /var/spool/at 의 작업 파일은 소유자를 바꾸지 않고 권한만 본다(사용자별 파일이라 소유자가 root 가 아님).
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

# 줄마다: 경로<TAB>최대권한<TAB>소유자검사(1/0)
collect() {
  local f
  for f in /usr/bin/crontab /usr/bin/at; do [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\t750\t1\n' "$f"; done
  for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\t640\t1\n' "$f"
  done
  for f in /var/spool/cron/* /var/spool/cron/crontabs/* /var/spool/at/* /var/spool/cron/atjobs/*; do
    [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\t640\t0\n' "$f"
  done
}

mapfile -t rows < <(collect)
bad=(); bad_max=(); bad_chk=(); bad_info=()
scan_bad() {
  bad=(); bad_max=(); bad_chk=(); bad_info=()
  local row f rest max chk owner mode over
  for row in "${rows[@]}"; do
    IFS=$'\t' read -r f max chk <<<"$row"
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$max & 8#7777 ))
    if [ "$over" -ne 0 ] || { [ "$chk" -eq 1 ] && [ "$owner" != "root" ]; }; then
      bad+=("$f"); bad_max+=("$max"); bad_chk+=("$chk"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode (기준 ${max} 이하)")
    fi
  done
}

if [ "${#rows[@]}" -eq 0 ]; then state NA "cron/at 관련 파일이 없습니다"; exit 0; fi

case "${1:-}" in
  list)
    for row in "${rows[@]}"; do f=${row%%$'\t'*}; read -r o m < <(stat -c '%U %a' "$f"); printf '%s\t소유자=%s 권한=%s\n' "$f" "$o" "$m"; done
    state GOOD "${#rows[@]}개 파일" ;;
  check)
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달"
    else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi ;;
  apply)
    scan_bad
    for i in "${!bad[@]}"; do
      f=${bad[$i]}; max=${bad_max[$i]}
      read -r owner mode < <(stat -c '%U %a' "$f")
      [ "${bad_chk[$i]}" -eq 1 ] && [ "$owner" != "root" ] && safe_fix "$f" root
      mode=$(stat -c '%a' "$f")
      over=$(( 8#$mode & ~8#$max & 8#7777 ))
      [ "$over" -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$mode & 8#$max )))"
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#rows[@]}개 파일 기준 충족" ;;
  *) echo "usage: U-37.sh check|apply|list" >&2; exit 2 ;;
esac
