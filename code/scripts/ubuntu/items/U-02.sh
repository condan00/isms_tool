#!/bin/bash
# U-02 비밀번호 관리 정책  [우분투 전용: pam-auth-update 프로필로 pam_pwhistory 적용]
# 기준: pwquality(최소 8자, 숫자·대소문자·특수문자 각 1자 이상, root 포함), PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1, 기억 4회 이상
# 계약: bash U-02.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

PWQ=/etc/security/pwquality.conf
PWQD=/etc/security/pwquality.conf.d
LOGINDEFS=/etc/login.defs
PWH=/etc/security/pwhistory.conf
PROF=/usr/share/pam-configs/isms-pwhistory
CPW=/etc/pam.d/common-password

[ -f "$LOGINDEFS" ] || { state NA "/etc/login.defs 가 없습니다"; exit 0; }

pwq_files=(); [ -f "$PWQ" ] && pwq_files+=("$PWQ"); for f in "$PWQD"/*.conf; do [ -f "$f" ] && pwq_files+=("$f"); done
pwq_get() { local v r=""; for f in "${pwq_files[@]}"; do v=$(kv_get "$f" "$1"); [ -n "$v" ] && r=$v; done; printf '%s' "$r"; }
pwq_enforce_root() { for f in "${pwq_files[@]}"; do grep -Eq '^[[:space:]]*enforce_for_root' "$f" && return 0; done; return 1; }
hist_get() {   # pwhistory.conf 또는 PAM 줄의 remember 값
  local v=""; [ -f "$PWH" ] && v=$(kv_get "$PWH" remember)
  [ -z "$v" ] && v=$(grep -hEs 'pam_pwhistory\.so' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -v '^[[:space:]]*#' | grep -Eo 'remember=[0-9]+' | head -1 | cut -d= -f2)
  printf '%s' "$v"
}
num() { case "$1" in ''|*[!0-9-]*) echo ""; ;; *) echo "$1";; esac; }

probs=()
scan() {
  probs=(); local v
  grep -Eqs '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$CPW" || probs+=("PAM 에 pam_pwquality 없음(libpam-pwquality 설치 필요)")
  v=$(num "$(pwq_get minlen)"); { [ -n "$v" ] && [ "$v" -ge 8 ]; } || probs+=("minlen<8(현재 ${v:-미설정})")
  for k in dcredit ucredit lcredit ocredit; do v=$(num "$(pwq_get $k)"); { [ -n "$v" ] && [ "$v" -le -1 ]; } || probs+=("$k 가 -1 이하가 아님(현재 ${v:-미설정})"); done
  pwq_enforce_root || probs+=("enforce_for_root 미설정")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MAX_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 90 ]; } || probs+=("PASS_MAX_DAYS>90(현재 ${v:-미설정})")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MIN_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ]; } || probs+=("PASS_MIN_DAYS<1(현재 ${v:-미설정})")
  v=$(num "$(hist_get)"); { [ -n "$v" ] && [ "$v" -ge 4 ]; } || probs+=("비밀번호 기억(remember) 4회 미만(현재 ${v:-미설정})")
}

case "${1:-}" in
  list) for f in "${pwq_files[@]}" "$LOGINDEFS" "$PWH"; do [ -f "$f" ] && printf '%s\t비밀번호 정책 설정\n' "$f"; done; [ -f "$PWQ" ] || printf '%s\t비밀번호 정책 설정(없음, 생성될 수 있음)\n' "$PWQ"; [ -f "$PWH" ] || printf '%s\t비밀번호 기억 설정(없음, 생성될 수 있음)\n' "$PWH"; printf '%s\tPAM 비밀번호 설정(조치 시 pam-auth-update 가 수정)\n' "$CPW"; printf '%s\tpam-auth-update 프로필(조치 시 생성)\n' "$PROF"; state GOOD "목록" ;;
  check)
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "비밀번호 정책 미충족 ${#probs[@]}건: ${probs[0]} 등"
    else state GOOD "비밀번호 정책이 기준을 충족"; fi ;;
  apply)
    [ -f "$PWQ" ] || { : > "$PWQ"; chmod 644 "$PWQ"; }
    pwq_files=("$PWQ"); for f in "$PWQD"/*.conf; do [ -f "$f" ] && pwq_files+=("$f"); done
    kv_set "$PWQ" minlen 8 " = "
    for k in dcredit ucredit lcredit ocredit; do kv_set "$PWQ" $k -1 " = "; done
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWQ" || { nl_end "$PWQ"; echo enforce_for_root >> "$PWQ"; }
    kv_set "$LOGINDEFS" PASS_MAX_DAYS 90 " "
    kv_set "$LOGINDEFS" PASS_MIN_DAYS 1 " "
    [ -f "$PWH" ] || { : > "$PWH"; chmod 644 "$PWH"; }
    kv_set "$PWH" remember 4 " = "
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWH" || { nl_end "$PWH"; echo enforce_for_root >> "$PWH"; }
    if ! grep -Eqs '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so' "$CPW"; then
      have pam-auth-update || { state ERROR "pam-auth-update 가 없어 PAM 에 pam_pwhistory 를 켤 수 없음(libpam-runtime 필요)"; exit 1; }
      cat > "$PROF" <<'EOP'
Name: ISMS password history
Default: yes
Priority: 1024
Password-Type: Primary
Password:
	requisite	pam_pwhistory.so use_authtok
EOP
      chmod 644 "$PROF"
      if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable isms-pwhistory >/dev/null 2>&1; then
        rm -f "$PROF"; state ERROR "pam-auth-update 적용 실패(프로필을 제거함, 엔진이 원복합니다)"; exit 1; fi
    fi
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 미충족: ${probs[0]}"; exit 1; fi
    state GOOD "조치 완료: 비밀번호 정책 적용 (기존 계정의 만료 기간은 chage 로 따로 적용, pam-auth-update 로 PAM 에 pam_pwhistory 적용)" ;;
  *) echo "usage: U-02.sh check|apply|list" >&2; exit 2 ;;
esac
