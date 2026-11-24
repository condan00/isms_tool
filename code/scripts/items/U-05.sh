#!/bin/bash
# U-05 root 이외의 UID가 '0' 금지  (엑셀 ?: 확인 후 적용)
# 기준: root 계정과 동일한 UID(0)를 갖는 계정이 없음. 조치는 그 계정의 UID 를 사용 중인 UID 중 가장 뒤 번호(최대값+1)로 바꾼다.
# 계약: bash U-05.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# UID 는 /etc/passwd 의 3번째 칸을 직접 바꾸고(usermod 는 UID 0 계정에 root 프로세스가 있으면 항상 거부), 홈·메일함 안의 예전 UID 소유 항목만 새 UID 로 바꾼다. 실패하면 이미 바꾼 것도 되돌린 뒤 ERROR.
# 손으로 쓴 스크립트다(tools/ 생성기 없음).
set -u
export LC_ALL=C
shopt -s nullglob
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# 새 UID: 현재 쓰는 UID(60000 미만) 중 가장 큰 값 + 1 (1000 미만이면 1000)
next_uid() { awk -F: '$3 < 60000 && $3 > m { m = $3 } END { print (m < 999 ? 1000 : m + 1) }' /etc/passwd; }
home_of() { getent passwd "$1" | cut -d: -f6; }
# chuid 계정 새UID : /etc/passwd 의 UID 만 바꾸고(usermod 는 UID 0 계정에 root 프로세스가 있으면 항상 거부하므로 직접 고친다),
# 홈과 메일함 안에서 예전 UID 소유였던 것만 새 UID 로 바꾼다. 다른 계정과 홈을 같이 쓰거나 홈이 / , /root 이면 홈은 건드리지 않는다.
chuid() { local name=$1 new=$2 old tmp home
  old=$(id -u "$name" 2>/dev/null) || return 1
  tmp=$(mktemp) || return 1
  if awk -F: -v OFS=: -v n="$name" -v u="$new" '$1 == n { $3 = u } { print }' /etc/passwd > "$tmp" && [ -s "$tmp" ]; then cat "$tmp" > /etc/passwd; else rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  [ "$(id -u "$name" 2>/dev/null)" = "$new" ] || return 1
  home=$(home_of "$name")
  if [ -n "$home" ] && [ -d "$home" ] && [ ! -L "$home" ] && [ "$home" != / ] && [ "$home" != /root ] \
     && [ "$(awk -F: -v h="$home" -v n="$name" '$6 == h && $1 != n' /etc/passwd | wc -l)" -eq 0 ]; then
    chown -R -h --from="$old" "$new" "$home" 2>/dev/null
  fi
  [ -f "/var/spool/mail/$name" ] && [ ! -L "/var/spool/mail/$name" ] && chown -h --from="$old" "$new" "/var/spool/mail/$name" 2>/dev/null
  return 0; }
# 되돌릴 수 있게 바꾼 계정을 기록: moved 배열에 "계정:옛UID"
moved=()
move_uid() { local name=$1 old new; old=$(id -u "$name" 2>/dev/null) || return 1; new=$(next_uid)
  chuid "$name" "$new" || return 1
  moved+=("$name:$old"); return 0; }
revert_moves() { local m; for m in "${moved[@]}"; do chuid "${m%%:*}" "${m#*:}" >/dev/null 2>&1; done; }

mapfile -t rows < <(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
case "${1:-}" in
  list)
    printf '/etc/passwd\t계정 정보(UID 0 계정 %s개)\n' "${#rows[@]}"
    for u in "${rows[@]}"; do h=$(home_of "$u"); [ -n "$h" ] && [ -d "$h" ] && printf '%s\t%s 의 홈(소유자 변경 대상, 안의 파일은 복구 대상 아님)\n' "$h" "$u"; [ -f "/var/spool/mail/$u" ] && printf '/var/spool/mail/%s\t메일함\n' "$u"; done
    state GOOD "UID 0 계정 목록" ;;
  check)
    if [ "${#rows[@]}" -gt 0 ]; then printf 'UID 0 계정: %s\n' "${rows[@]}"; state VULN "root 외 UID 0 계정 ${#rows[@]}개 (${rows[*]})"
    else state GOOD "UID 0 계정은 root 뿐"; fi ;;
  apply)
    for u in "${rows[@]}"; do move_uid "$u" || { revert_moves; state ERROR "$u 의 UID 를 바꾸지 못했습니다(/etc/passwd 를 고치지 못함)"; exit 1; }; done
    mapfile -t rows < <(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [ "${#rows[@]}" -gt 0 ]; then revert_moves; state ERROR "조치 후에도 UID 0 계정이 남았습니다: ${rows[*]}"; exit 1; fi
    state GOOD "조치 완료: ${moved[*]} (계정:옛UID) 를 새 UID 로 변경" ;;
  *) echo "usage: U-05.sh check|apply|list" >&2; exit 2 ;;
esac
