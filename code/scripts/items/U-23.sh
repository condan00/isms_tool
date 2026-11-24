#!/bin/bash
# U-23 SUID, SGID, Sticky bit 설정 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
# 기준: 패키지 소유가 아니거나 /home·/tmp·/var/tmp·/dev/shm·/mnt·/media 아래에 있는 SUID/SGID 파일이 없음. 조치는 해당 파일의 SUID/SGID 비트만 제거(chmod u-s,g-s). 패키지가 둔 기본 SUID/SGID 는 건드리지 않고 목록으로 검토만 요청한다.
# 계약: bash U-23.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort | head -n $((MAXN + 1)); }
# 배포판이 기본으로 두는 일반적인 SUID/SGID(패키지 소유일 때만 '정상' 으로 본다)
KNOWN='^/usr/(bin|sbin|libexec|lib)/(passwd|chage|gpasswd|newgrp|chsh|chfn|su|sudo|mount|umount|pkexec|crontab|at|ssh-agent|write|wall|locate|expiry|unix_chkpwd|newuidmap|newgidmap|fusermount3?|staprun|userhelper|Xorg\.wrap|dbus-daemon-launch-helper|pam_timestamp_check|lockdev|mount\.nfs|umount\.nfs|utempter|ksu|ssh-keysign|polkit-agent-helper-1|sendmail\.postfix|usernetctl|grub2-set-bootflag|mount\.cifs|umount\.cifs|chronyd|postdrop|postqueue|netreport|pt_chown|cockpit-session|sudoedit)$|^/usr/(libexec|lib)/(openssh/ssh-keysign|dbus-1/dbus-daemon-launch-helper|utempter/utempter|polkit-1/polkit-agent-helper-1|cockpit-session|ssh-keysign)$'
RISKY='^/(home|tmp|var/tmp|dev/shm|mnt|media)(/|$)'
owned() { if have rpm; then rpm -qf "$1" >/dev/null 2>&1 && return 0; return 1
  elif have dpkg; then dpkg -S "$1" >/dev/null 2>&1 && return 0; return 1; fi; return 2; }
# classify 경로 → remove(제거 대상) / review(검토) / ok
classify() { local p=$1 rc
  if printf '%s' "$p" | grep -Eq "$RISKY"; then echo remove; return; fi
  owned "$p"; rc=$?
  if [ "$rc" -eq 1 ]; then echo remove; return; fi
  if [ "$rc" -eq 2 ] || ! printf '%s' "$p" | grep -Eq "$KNOWN"; then echo review; return; fi
  echo ok; }
rm_list=(); rv=0; n=0; lines=()
analyze() { rm_list=(); rv=0; n=0; lines=(); local p c o m
  mapfile -t f < <(scan); n=${#f[@]}
  for p in "${f[@]:0:$MAXN}"; do
    { read -r o m < <(stat -c '%U %a' "$p" 2>/dev/null); } || continue
    c=$(classify "$p"); tag=""
    case "$c" in remove) rm_list+=("$p"); tag=" (제거 대상: 패키지 소유 아님 또는 임시·홈 경로)" ;; review) rv=$((rv+1)); tag=" (검토)" ;; esac
    lines+=("$p"$'\t'"소유자=$o 권한=$m$tag")
  done; }
case "${1:-}" in
  list) analyze; printf '%s\n' "${lines[@]}"; state GOOD "${n}개 파일" ;;
  check) analyze; [ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}"
    if [ "$n" -gt "$MAXN" ]; then state MANUAL "SUID/SGID 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
    elif [ "${#rm_list[@]}" -gt 0 ]; then state VULN "부적절한 SUID/SGID 파일 ${#rm_list[@]}개(패키지 소유 아님·임시/홈 경로), 검토 필요 ${rv}개"
    elif [ "$rv" -gt 0 ]; then state MANUAL "SUID/SGID 파일 ${n}개 중 (검토) 표시 ${rv}개: 불필요한 파일인지 확인 필요"
    elif [ "$n" -gt 0 ]; then state GOOD "SUID/SGID 파일 ${n}개 모두 배포판 기본 파일"
    else state GOOD "SUID/SGID 파일 없음"; fi ;;
  apply) analyze
    [ "$n" -gt "$MAXN" ] && { state ERROR "대상이 ${MAXN}건을 넘어 조치하지 않았습니다"; exit 1; }
    for p in "${rm_list[@]}"; do safe_fix "$p" "" "u-s,g-s" || echo "변경 실패: $p" >&2; done
    analyze
    if [ "${#rm_list[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#rm_list[@]}개가 남았습니다"; exit 1; fi
    state GOOD "조치 완료: 부적절한 SUID/SGID 비트 제거(검토 대상 ${rv}개는 그대로 둠)" ;;
  *) echo "usage: U-23.sh check|apply|list" >&2; exit 2 ;;
esac
