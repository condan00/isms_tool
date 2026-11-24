#!/bin/bash
# U-10 동일한 UID 금지  (엑셀 ?: 확인 후 적용)
# 기준: 동일한 UID 를 사용하는 계정이 없음
# 조치 규칙(중복 UID 마다):
#   · UID 0           : root 는 그대로, 나머지는 새 UID 로
#   · UID 3000 미만   : 프로토콜/배포판 기본 계정이면 UID 를 유지하고 그렇지 않은 계정을 새 UID 로
#                       (기본 계정이 없으면 /etc/passwd 에서 위에 있는 계정이 유지, 기본 계정이 둘 이상이면 자동 조치하지 않고 수동 점검)
#   · UID 3000 이상   : /etc/passwd 에서 위에 있는 계정이 UID 를 유지하고 나머지는 새 UID 로
#   · 새 UID          : 사용 중인 UID(60000 미만)의 최대값+1 부터 차례로(1000 미만이면 1000 부터)
# 계약: bash U-10.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

DEFAULTS=' root bin daemon adm lp sync shutdown halt mail operator games ftp nobody dbus tss polkitd sssd rpc rpcuser sshd chrony unbound systemd-coredump systemd-resolve systemd-network systemd-timesync setroubleshoot pipewire geoclue flatpak colord clevis gdm gnome-initial-setup tcpdump cockpit-ws cockpit-wsinstance libstoragemgmt rtkit saslauth abrt avahi dnsmasq nfsnobody uucp news proxy www-data backup list irc gnats _apt messagebus syslog '
# plan 배열: "이동할계정|UID|유지계정" / manual 배열: 자동 판단 불가 그룹 설명
plan=(); manual=()
build_plan() { plan=(); manual=(); local uid keep m defs first
  while read -r uid; do
    mapfile -t members < <(awk -F: -v u="$uid" '$3 == u {print $1}' /etc/passwd)
    keep=""
    if [ "$uid" -eq 0 ]; then keep=root
    elif [ "$uid" -lt 3000 ]; then
      defs=(); for m in "${members[@]}"; do case "$DEFAULTS" in *" $m "*) defs+=("$m") ;; esac; done
      if [ "${#defs[@]}" -gt 1 ]; then manual+=("UID $uid: 기본 계정이 둘 이상(${defs[*]})"); continue
      elif [ "${#defs[@]}" -eq 1 ]; then keep=${defs[0]}; else keep=${members[0]}; fi
    else keep=${members[0]}; fi
    for m in "${members[@]}"; do [ "$m" = "$keep" ] || plan+=("$m|$uid|$keep"); done
  done < <(awk -F: '{c[$3]++} END{for(u in c) if(c[u]>1) print u}' /etc/passwd | sort -n); }
build_plan
dups_left() { awk -F: '{c[$3]++} END{n=0; for(u in c) if(c[u]>1) n++; print n}' /etc/passwd; }
case "${1:-}" in
  list)
    printf '/etc/passwd\t계정 정보(중복 UID 조치 대상 %s개 계정)\n' "${#plan[@]}"
    for x in "${plan[@]}"; do u=${x%%|*}; h=$(home_of "$u"); [ -n "$h" ] && [ -d "$h" ] && printf '%s\t%s 의 홈(소유자 변경 대상, 안의 파일은 복구 대상 아님)\n' "$h" "$u"; [ -f "/var/spool/mail/$u" ] && printf '/var/spool/mail/%s\t메일함\n' "$u"; done
    state GOOD "UID 중복 조치 대상 ${#plan[@]}개 계정" ;;
  check)
    n=$(dups_left)
    if [ "$n" -eq 0 ]; then state GOOD "중복 UID 없음"
    else
      for x in "${plan[@]}"; do printf 'UID %s 중복: %s 의 UID 를 새 번호로 변경 예정(유지 계정: %s)\n' "$(echo "$x" | cut -d'|' -f2)" "${x%%|*}" "${x##*|}"; done
      [ "${#manual[@]}" -gt 0 ] && printf '%s\n' "${manual[@]}"
      if [ "${#plan[@]}" -gt 0 ]; then state VULN "UID 가 중복된 그룹 ${n}개 (변경 대상 계정 ${#plan[@]}개${manual[0]:+, 수동 판단 ${#manual[@]}개})"
      else state MANUAL "UID 가 중복되었으나 기본 계정끼리 겹쳐 자동 판단할 수 없습니다: ${manual[*]}"; fi
    fi ;;
  apply)
    for x in "${plan[@]}"; do u=${x%%|*}; move_uid "$u" || { revert_moves; state ERROR "$u 의 UID 를 바꾸지 못했습니다(/etc/passwd 를 고치지 못함)"; exit 1; }; done
    n=$(dups_left)
    if [ "$n" -gt 0 ] && [ "${#manual[@]}" -eq 0 ]; then revert_moves; state ERROR "조치 후에도 중복 UID 가 ${n}개 남았습니다"; exit 1; fi
    state GOOD "조치 완료: ${moved[*]} (계정:옛UID) 를 새 UID 로 변경${manual[0]:+ · 수동 판단 필요 ${#manual[@]}개 남음}" ;;
  *) echo "usage: U-10.sh check|apply|list" >&2; exit 2 ;;
esac
