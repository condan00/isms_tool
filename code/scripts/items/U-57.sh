#!/bin/bash
# U-57 Ftpusers 파일 설정
# 기준: FTP 에서 root 직접 접속 차단(ftpusers/user_list 에 root, proftpd RootLogin off)
# 계약: bash U-57.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 이 파일은 tools/gen_config_scripts*.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
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

# 서비스 재적용 도우미: svc_list(스냅샷이 서비스 상태를 복구하도록 알림), svc_act(동작 중인 유닛만 reload/restart)
acted=(); failed_svc=""
svc_list() {
  have systemctl || return 0
  local u
  for u in "$@"; do
    [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] || continue
    printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
  done
  return 0
}
svc_act() {    # svc_act reload|restart 유닛... : 동작 중인 유닛만 처리, 처리 후 동작하지 않으면 1(failed_svc 에 유닛 이름)
  local a=$1 u; shift
  have systemctl || return 0
  for u in "$@"; do
    systemctl is-active "$u" >/dev/null 2>&1 || continue
    systemctl "$a" "$u" >/dev/null 2>&1; sleep 1
    systemctl is-active "$u" >/dev/null 2>&1 || { failed_svc=$u; return 1; }
    acted+=("$a:$u")
  done
  return 0
}

nl_end() { [ -s "$1" ] && [ -n "$(tail -c1 "$1")" ] && echo >> "$1"; return 0; }

# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열
kv_get() {
  awk -v k="$2" '/^[[:space:]]*#/ {next}
    { if (match($0, "^[[:space:]]*" k "([[:space:]]*=[[:space:]]*|[[:space:]]+)")) { v = substr($0, RLENGTH + 1); sub(/[[:space:]]+$/, "", v); r = v; f = 1 } }
    END { if (f) print r }' "$1" 2>/dev/null
}

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가
kv_set() {
  local f=$1 k=$2 v=$3 sep=$4
  if grep -Eq "^[[:space:]]*$k([[:space:]]*=|[[:space:]])" "$f"; then
    sed -i -E "s~^[[:space:]]*$k([[:space:]]*=[[:space:]]*|[[:space:]]+).*~$k$sep$v~" "$f"
  else
    nl_end "$f"; printf '%s%s%s\n' "$k" "$sep" "$v" >> "$f"
  fi
}

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력
login_users() {
  local u uid gid home shell
  while IFS=: read -r u _ uid gid _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    printf '%s\t%s\t%s\n' "$u" "$home" "$gid"
  done < <(getent passwd)
}

pkg_gate "FTP 서버" "vsftpd proftpd pure-ftpd ftpd wu-ftpd" "/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd" "/etc/ftpusers"
LISTS=(); for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do [ -f "$f" ] && [ ! -L "$f" ] && LISTS+=("$f"); done
VCONF=""; for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do [ -f "$f" ] && VCONF=$f && break; done
if [ -n "$VCONF" ] && [ "$(kv_get "$VCONF" userlist_enable | tr a-z A-Z)" = YES ]; then
  for f in /etc/vsftpd/user_list /etc/vsftpd.user_list; do [ -f "$f" ] && [ ! -L "$f" ] && LISTS+=("$f"); done
fi
PCONF=""; for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && PCONF=$f && break; done
[ "${#LISTS[@]}" -gt 0 ] || [ -n "$PCONF" ] || { state MANUAL "root 차단 설정 파일(ftpusers 등)을 찾지 못했습니다. 수동 확인 필요"; exit 0; }
has_root() { grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$1"; }
probs=()
scan() {
  probs=(); local f
  for f in "${LISTS[@]}"; do has_root "$f" || probs+=("$f: root 가 차단 목록에 없음"); done
  if [ -n "$PCONF" ]; then v=$(kv_get "$PCONF" RootLogin | tr A-Z a-z); [ "$v" = on ] && probs+=("$PCONF: RootLogin on"); fi
}
case "${1:-}" in
  list) for f in "${LISTS[@]}" "$PCONF"; do [ -n "$f" ] && printf '%s\tFTP root 차단 설정\n' "$f"; done
        svc_list vsftpd.service proftpd.service; state GOOD "목록" ;;
  check) scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "root 접속 차단 미설정 ${#probs[@]}건"; else state GOOD "FTP root 접속이 차단됨"; fi ;;
  apply)
    for f in "${LISTS[@]}"; do
      has_root "$f" && continue
      if grep -Eq '^[[:space:]]*#[[:space:]]*root([[:space:]]|$)' "$f"; then sed -i -E '0,/^[[:space:]]*#[[:space:]]*(root([[:space:]]|$).*)/s//\1/' "$f"
      else nl_end "$f"; echo root >> "$f"; fi
    done
    [ -n "$PCONF" ] && [ "$(kv_get "$PCONF" RootLogin | tr A-Z a-z)" = on ] && kv_set "$PCONF" RootLogin off " "
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 남음"; exit 1; fi
    [ -n "$PCONF" ] && have proftpd && ! proftpd -t >/dev/null 2>&1 && { state ERROR "proftpd 설정 검사 실패(엔진이 원복합니다)"; exit 1; }
    svc_act restart vsftpd.service proftpd.service || { state ERROR "FTP 서비스 재시작 실패($failed_svc) — 원복하면 이전 상태로 되돌립니다"; exit 1; }
    state GOOD "조치 완료: FTP root 접속 차단${acted[*]:+ (재적용: ${acted[*]})}" ;;
  *) echo "usage: U-57.sh check|apply|list" >&2; exit 2 ;;
esac
