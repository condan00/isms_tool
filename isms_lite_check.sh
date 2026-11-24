#!/bin/bash
# ISMS 점검 lite - 여러 서버에 돌려서 취약한 항목만 모으기 위한 점검 전용 쉘 파일 하나(시스템을 바꾸지 않는다).
#   sudo bash isms_lite_check.sh [1|2|auto]   1.Rocky 2.Ubuntu 3.Windows. 번호를 안 주면 터미널에서는 메뉴, 아니면(Ansible 등) OS 자동 판별
#   옵션: -v 모든 항목 출력 / --ids U-04,U-16 일부만 / --heavy 전체 파일 검색 항목(U-15,23,25,26)도
# 출력(취약한 것만):  <호스트>  U-02  근거...   마지막 줄  <호스트>  vuln: U-02, U-18  (없으면 vuln: X)
#   점검이 실패한 항목은  <호스트>  U-XX  ERROR ...  로 표시한다. 취약·오류가 있으면 종료 코드 1, 실행할 수 없으면 2.
# 이 파일 하나로 동작한다(다른 파일 필요 없음). 아래 '항목 점검' 부분은 code/scripts 의 점검 규칙을 그대로 옮긴 것이므로
# 직접 고치지 말고 tools/gen_lite_check.py 로 다시 만든다.
set -u; export LC_ALL=C; shopt -s nullglob
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HEAVY=" U-15 U-23 U-25 U-26 "; ALL="U-01 U-02 U-03 U-04 U-05 U-06 U-08 U-10 U-13 U-14 U-15 U-16 U-17 U-18 U-19 U-20 U-21 U-22 U-23 U-24 U-25 U-26 U-27 U-28 U-30 U-31 U-32 U-34 U-35 U-36 U-37 U-38 U-39 U-40 U-41 U-42 U-43 U-44 U-45 U-46 U-47 U-48 U-49 U-50 U-51 U-52 U-54 U-55 U-57 U-58 U-59 U-60 U-61 U-63 U-64 U-65 U-66 U-67"; HOST=$(hostname -s 2>/dev/null || echo host)
die() { echo "$HOST  오류: $*" >&2; exit 2; }

sel=""; verbose=0; heavy=0; only=""
while [ $# -gt 0 ]; do case "$1" in
  1|2|3|auto) sel=$1 ;; -v) verbose=1 ;; --heavy) heavy=1 ;; --ids) shift; only=${1:-} ;;
  -h|--help) sed -n '2,8p' "$0"; exit 0 ;; *) die "알 수 없는 옵션: $1" ;;
esac; shift; done
[ "$(id -u)" -eq 0 ] || die "root 권한이 필요합니다.  sudo bash isms_lite_check.sh"

# OS 확인: 번호를 주면 서버와 맞는지 확인, 안 주면(터미널이면 메뉴) 자동 판별
id=$(. /etc/os-release; echo "${ID:-}"); ver=$(. /etc/os-release; echo "${VERSION_ID:-}"); major=${ver%%.*}
if [ -z "$sel" ] && [ -t 0 ]; then printf '운영체제를 선택하세요\n  1. Rocky\n  2. Ubuntu\n  3. Windows\n번호 입력: '; read -r sel; fi
[ "$sel" = 3 ] && { echo "Windows 는 아직 지원하지 않습니다(준비 중)."; exit 0; }
case "$id" in rocky|centos) os=1 ;; ubuntu) os=2 ;; *) os=0 ;; esac
case "$os:$major" in 1:9|1:10|2:20|2:22|2:24|2:26) ;; *) die "지원하지 않는 OS 입니다 ($id $ver). Rocky/CentOS 9·10, Ubuntu 20·22·24·26" ;; esac
[ -z "$sel" ] || [ "$sel" = auto ] || [ "$sel" = "$os" ] || die "선택한 번호와 이 서버($id $ver)가 맞지 않습니다"
command -v apt-get >/dev/null && PKG=apt-get || PKG=dnf
export ISMS_OS_KEY="$id$major" ISMS_PKG_MANAGER="$PKG" ISMS_INVOKER=$(printf %s "${SUDO_USER:-}" | tr -cd 'A-Za-z0-9._-')

# ======================= 공통 함수 =======================
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }
pkg_gate() { local label=$1 pkgs=$2 rc l; shift 2; pkg_any $pkgs; rc=$?; [ "$rc" -eq 1 ] || return 0
  l=$(leftover "$@" | head -5 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then state MANUAL "$label 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
  else state NA "$label 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi; exit 0; }
pkg_has() { pkg_any "$@"; [ $? -ne 1 ]; }
safe_fix() { local f=$1 own=${2:-} mod=${3:-} a b rc=0
  [ -L "$f" ] && return 1
  { exec 9<"$f"; } 2>/dev/null || return 1
  a=$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null); b=$(stat -c '%d:%i' "$f" 2>/dev/null)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    [ -n "$own" ] && { chown "$own" /proc/self/fd/9 || rc=1; }
    [ -n "$mod" ] && { chmod "$mod" /proc/self/fd/9 || rc=1; }
  else rc=1; fi
  exec 9<&-; return $rc; }
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
kv_get() {
  awk -v k="$2" '/^[[:space:]]*#/ {next}
    { if (match($0, "^[[:space:]]*" k "([[:space:]]*=[[:space:]]*|[[:space:]]+)")) { v = substr($0, RLENGTH + 1); sub(/[[:space:]]+$/, "", v); r = v; f = 1 } }
    END { if (f) print r }' "$1" 2>/dev/null
}
kv_set() {
  local f=$1 k=$2 v=$3 sep=$4
  if grep -Eq "^[[:space:]]*$k([[:space:]]*=|[[:space:]])" "$f"; then
    sed -i -E "s~^[[:space:]]*$k([[:space:]]*=[[:space:]]*|[[:space:]]+).*~$k$sep$v~" "$f"
  else
    nl_end "$f"; printf '%s%s%s\n' "$k" "$sep" "$v" >> "$f"
  fi
}
login_users() {
  local u uid gid home shell
  while IFS=: read -r u _ uid gid _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    printf '%s\t%s\t%s\n' "$u" "$home" "$gid"
  done < <(getent passwd)
}
pwq_get() { local v r=""; for f in "${pwq_files[@]}"; do v=$(kv_get "$f" "$1"); [ -n "$v" ] && r=$v; done; printf '%s' "$r"; }
pwq_enforce_root() { for f in "${pwq_files[@]}"; do grep -Eq '^[[:space:]]*enforce_for_root' "$f" && return 0; done; return 1; }
hist_get() {   # pwhistory.conf 또는 PAM 줄의 remember 값
  local v=""; [ -f "$PWH" ] && v=$(kv_get "$PWH" remember)
  [ -z "$v" ] && v=$(grep -hEs 'pam_pwhistory\.so' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -v '^[[:space:]]*#' | grep -Eo 'remember=[0-9]+' | head -1 | cut -d= -f2)
  printf '%s' "$v"
}
num() { case "$1" in ''|*[!0-9-]*) echo ""; ;; *) echo "$1";; esac; }
pam_has() { grep -Eqs '^[[:space:]]*auth[[:space:]].*(pam_faillock|pam_tally2?)\.so' "${PAMS[@]}" 2>/dev/null; }
deny_value() {
  local v; v=$(kv_get "$FC" deny)
  [ -z "$v" ] && v=$(grep -hEs 'pam_(faillock|tally2?)\.so' "${PAMS[@]}" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -Eo 'deny=[0-9]+' | head -1 | cut -d= -f2)
  printf '%s' "$v"
}
good() { local v; v=$(deny_value); pam_has && [[ $v =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 10 ]; }
next_uid() { awk -F: '$3 < 60000 && $3 > m { m = $3 } END { print (m < 999 ? 1000 : m + 1) }' /etc/passwd; }
home_of() { getent passwd "$1" | cut -d: -f6; }
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
move_uid() { local name=$1 old new; old=$(id -u "$name" 2>/dev/null) || return 1; new=$(next_uid)
  chuid "$name" "$new" || return 1
  moved+=("$name:$old"); return 0; }
revert_moves() { local m; for m in "${moved[@]}"; do chuid "${m%%:*}" "${m#*:}" >/dev/null 2>&1; done; }
unit_on() {    # 켜져 있으면(부팅 시 시작 또는 동작 중) 0
  local en ac
  en=$(systemctl is-enabled "$1" 2>/dev/null); ac=$(systemctl is-active "$1" 2>/dev/null)
  [ "$en" = masked ] && return 1
  [ "$ac" = active ] || [ "$en" = enabled ] || [ "$en" = enabled-runtime ]
}
xinetd_on() { grep -Eiq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "$1"; }
rules() { cat "${files[@]}" 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)'; }

# ======================= 항목 점검 (code/scripts 에서 옮겨 옴) =======================
# ---- U-01 U-01 root 계정 원격 접속 제한
chk_U01() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
has_admin() {
  local g u h sh hash
  for g in wheel sudo; do
    for u in $(getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
      [ "$u" = root ] && continue
      sh=$(getent passwd "$u" | cut -d: -f7); h=$(getent passwd "$u" | cut -d: -f6)
      case "$sh" in */nologin|*/false|"") continue ;; esac
      hash=$(getent shadow "$u" 2>/dev/null | cut -d: -f2)
      case "$hash" in ''|'!'*|'*'*) [ -s "$h/.ssh/authorized_keys" ] && return 0 ;; *) return 0 ;; esac
    done
  done
  return 1
}
effective() {
  local v=""
  have sshd && v=$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2}')
  if [ -z "$v" ]; then    # sshd -T 를 쓸 수 없으면 설정 파일에서 첫 번째 값을 읽는다(sshd 는 첫 값을 사용)
    v=$(cat "${cfiles[@]}" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*PermitRootLogin[[:space:]]/ {print $2; exit}')
    [ -z "$v" ] && v=prohibit-password
  fi
  printf '%s' "${v,,}"
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

CF=/etc/ssh/sshd_config
DROP=/etc/ssh/sshd_config.d

have sshd || [ -f "$CF" ] || { state NA "SSH 서버(sshd)가 설치되어 있지 않아 점검 대상이 아닙니다"; exit 0; }

cfiles=()
[ -f "$CF" ] && [ ! -L "$CF" ] && cfiles+=("$CF")
for f in "$DROP"/*.conf; do [ -f "$f" ] && [ ! -L "$f" ] && cfiles+=("$f"); done

# root 접속을 막아도 들어올 수 있는 관리자 계정이 있는지: wheel/sudo 그룹 + 로그인 쉘 + (암호 해시 또는 authorized_keys)


eff=$(effective)
if [ "$eff" = no ]; then state GOOD "PermitRootLogin = no"
else state VULN "PermitRootLogin = $eff (기준: no)"; fi
)

# ---- U-02 U-02 비밀번호 관리 정책
chk_U02() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  probs=(); local v
  v=$(num "$(pwq_get minlen)"); { [ -n "$v" ] && [ "$v" -ge 8 ]; } || probs+=("minlen<8(현재 ${v:-미설정})")
  for k in dcredit ucredit lcredit ocredit; do v=$(num "$(pwq_get $k)"); { [ -n "$v" ] && [ "$v" -le -1 ]; } || probs+=("$k 가 -1 이하가 아님(현재 ${v:-미설정})"); done
  pwq_enforce_root || probs+=("enforce_for_root 미설정")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MAX_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 90 ]; } || probs+=("PASS_MAX_DAYS>90(현재 ${v:-미설정})")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MIN_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ]; } || probs+=("PASS_MIN_DAYS<1(현재 ${v:-미설정})")
  v=$(num "$(hist_get)"); { [ -n "$v" ] && [ "$v" -ge 4 ]; } || probs+=("비밀번호 기억(remember) 4회 미만(현재 ${v:-미설정})")
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

PWQ=/etc/security/pwquality.conf
PWQD=/etc/security/pwquality.conf.d
LOGINDEFS=/etc/login.defs
PWH=/etc/security/pwhistory.conf

[ -f "$LOGINDEFS" ] || { state NA "/etc/login.defs 가 없습니다"; exit 0; }

pwq_files=(); [ -f "$PWQ" ] && pwq_files+=("$PWQ"); for f in "$PWQD"/*.conf; do [ -f "$f" ] && pwq_files+=("$f"); done

probs=()

scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "비밀번호 정책 미충족 ${#probs[@]}건: ${probs[0]} 등"
else state GOOD "비밀번호 정책이 기준을 충족"; fi
)

# ---- U-03 U-03 계정 잠금 임계값 설정
chk_U03() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

FC=/etc/security/faillock.conf
PAMS=(/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth)


d=$(deny_value)
if good; then state GOOD "계정 잠금 임계값 deny=$d"
elif ! pam_has; then state VULN "PAM 에 pam_faillock/pam_tally 설정이 없음(계정 잠금 미적용)"
else state VULN "계정 잠금 임계값이 1~10 범위가 아님(deny=${d:-미설정})"; fi
)

# ---- U-04 U-04 비밀번호 파일 보호
chk_U04() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
bad_accounts() { awk -F: '$2 != "x" {print $1}' /etc/passwd; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

[ -f /etc/passwd ] || { state NA "/etc/passwd 가 없습니다"; exit 0; }
mapfile -t b < <(bad_accounts)
if [ ! -f /etc/shadow ]; then state VULN "/etc/shadow 가 없음(쉐도우 비밀번호 미사용)"
elif [ "${#b[@]}" -gt 0 ]; then printf '계정: %s\n' "${b[@]}"; state VULN "passwd 에 암호 필드가 x 가 아닌 계정 ${#b[@]}개"
else state GOOD "모든 계정이 쉐도우 비밀번호 사용"; fi
)

# ---- U-05 U-05 root 이외의 UID가 '0' 금지  (엑셀 ?: 확인 후 적용)
chk_U05() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
moved=()

mapfile -t rows < <(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
if [ "${#rows[@]}" -gt 0 ]; then printf 'UID 0 계정: %s\n' "${rows[@]}"; state VULN "root 외 UID 0 계정 ${#rows[@]}개 (${rows[*]})"
else state GOOD "UID 0 계정은 root 뿐"; fi
)

# ---- U-06 U-06 사용자 계정 su 기능 제한
chk_U06() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
users() { awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ && $1 != "nobody" {print $1}' /etc/passwd; }
pam_on() { grep -Eqs '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAMSU"; }
bin_on() { [ -e "$SU" ] || return 1; read -r g m < <(stat -c '%G %a' "$SU"); [ "$g" != root ] && [ $(( 8#$m & 8#0007 )) -eq 0 ]; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

PAMSU=/etc/pam.d/su
SU=/usr/bin/su
[ -f "$PAMSU" ] || [ -e "$SU" ] || { state NA "su 설정이 없습니다"; exit 0; }

grp=""; for g in wheel sudo; do getent group "$g" >/dev/null 2>&1 && { grp=$g; break; }; done

mapfile -t u < <(users)
if [ "${#u[@]}" -eq 0 ]; then state GOOD "일반 사용자 계정이 없어 su 제한이 필요하지 않음(root 만 사용)"
elif pam_on; then state GOOD "pam_wheel 로 su 사용 그룹이 제한됨"
elif bin_on; then state GOOD "su 실행 권한이 특정 그룹으로 제한됨"
else state VULN "su 명령을 모든 사용자가 사용할 수 있음 (일반 사용자 ${#u[@]}명)"; fi
)

# ---- U-08 U-08 관리자 그룹에 최소한의 계정 포함  (엑셀 ?: 확인 후 적용)
chk_U08() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
members() { getent group "$1" 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' | grep -vx root; }
build() { plan=(); listing=(); over=0; local g m keep inv=${ISMS_INVOKER:-}
  for g in "${GROUPS_[@]}"; do
    getent group "$g" >/dev/null 2>&1 || continue
    mapfile -t mem < <(members "$g"); [ "${#mem[@]}" -gt 0 ] && listing+=("$g: ${mem[*]}")
    [ "${#mem[@]}" -gt 1 ] || continue
    over=$((over+1)); keep=${mem[0]}
    for m in "${mem[@]}"; do [ -n "$inv" ] && [ "$m" = "$inv" ] && keep=$inv; done
    for m in "${mem[@]}"; do [ "$m" = "$keep" ] || plan+=("$g|$m|$keep"); done
  done; }
GROUPS_=(root wheel sudo admin)
# plan: "그룹|제거할계정|남길계정"
plan=(); over=0; listing=()
build
if [ "$over" -gt 0 ]; then printf '%s\n' "${listing[@]}"; state VULN "root 외 구성원이 2명 이상인 관리자 그룹 ${over}개 (그룹당 1명까지 허용)"
else [ "${#listing[@]}" -gt 0 ] && printf '%s\n' "${listing[@]}"; state GOOD "관리자 그룹의 root 외 구성원이 그룹당 1명 이하"; fi
)

# ---- U-10 U-10 동일한 UID 금지  (엑셀 ?: 확인 후 적용)
chk_U10() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
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
dups_left() { awk -F: '{c[$3]++} END{n=0; for(u in c) if(c[u]>1) n++; print n}' /etc/passwd; }
moved=()

DEFAULTS=' root bin daemon adm lp sync shutdown halt mail operator games ftp nobody dbus tss polkitd sssd rpc rpcuser sshd chrony unbound systemd-coredump systemd-resolve systemd-network systemd-timesync setroubleshoot pipewire geoclue flatpak colord clevis gdm gnome-initial-setup tcpdump cockpit-ws cockpit-wsinstance libstoragemgmt rtkit saslauth abrt avahi dnsmasq nfsnobody uucp news proxy www-data backup list irc gnats _apt messagebus syslog '
# plan 배열: "이동할계정|UID|유지계정" / manual 배열: 자동 판단 불가 그룹 설명
plan=(); manual=()
build_plan
n=$(dups_left)
if [ "$n" -eq 0 ]; then state GOOD "중복 UID 없음"
else
  for x in "${plan[@]}"; do printf 'UID %s 중복: %s 의 UID 를 새 번호로 변경 예정(유지 계정: %s)\n' "$(echo "$x" | cut -d'|' -f2)" "${x%%|*}" "${x##*|}"; done
  [ "${#manual[@]}" -gt 0 ] && printf '%s\n' "${manual[@]}"
  if [ "${#plan[@]}" -gt 0 ]; then state VULN "UID 가 중복된 그룹 ${n}개 (변경 대상 계정 ${#plan[@]}개${manual[0]:+, 수동 판단 ${#manual[@]}개})"
  else state MANUAL "UID 가 중복되었으나 기본 계정끼리 겹쳐 자동 판단할 수 없습니다: ${manual[*]}"; fi
fi
)

# ---- U-13 U-13 안전한 비밀번호 암호화 알고리즘 사용
chk_U13() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
method() { local v; v=$(kv_get "$LD" ENCRYPT_METHOD); printf '%s' "${v^^}"; }
ok_method() { case "$(method)" in SHA256|SHA512|YESCRYPT) return 0 ;; *) return 1 ;; esac; }
weak_accounts() { awk -F: '$2 ~ /^\$1\$/ || ($2 != "" && $2 !~ /^[*!]/ && $2 !~ /^\$/) {print $1}' /etc/shadow 2>/dev/null; }
pam_weak() { grep -HEs '^[[:space:]]*password[[:space:]].*pam_unix\.so.*[[:space:]](md5|bigcrypt|des)([[:space:]]|$)' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

LD=/etc/login.defs
[ -f "$LD" ] || { state NA "/etc/login.defs 가 없습니다"; exit 0; }
# 약한 해시: $1$(MD5) 또는 $ 로 시작하지 않는 13자 안팎 값(DES). 해시 값은 출력하지 않고 계정 이름만 쓴다.
# PAM 의 pam_unix 옵션이 md5/bigcrypt/des 이면 login.defs 와 상관없이 실제 해시가 약하다(authselect 관리 파일이라 자동 수정하지 않는다)
if ! ok_method; then state VULN "ENCRYPT_METHOD=$(method) (기준: SHA256/SHA512/YESCRYPT)"
else
  mapfile -t pw < <(pam_weak)
  mapfile -t w < <(weak_accounts)
  if [ "${#pw[@]}" -gt 0 ]; then printf '%s\n' "${pw[@]}"; state MANUAL "PAM pam_unix 에 약한 해시 옵션(md5/bigcrypt/des)이 있습니다(authselect 설정을 직접 확인)"
  elif [ "${#w[@]}" -gt 0 ]; then printf '취약 해시 사용 계정: %s\n' "${w[@]}"; state MANUAL "ENCRYPT_METHOD 는 양호하나 기존 계정 ${#w[@]}개가 MD5/DES 해시를 사용(비밀번호 재설정 필요)"
  else state GOOD "ENCRYPT_METHOD=$(method)"; fi
fi
)

# ---- U-14 U-14 root 홈, 패스 디렉터리 권한 및 패스 설정  (엑셀 ?: 확인 후 적용)
chk_U14() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { bad=(); badfiles=(); local f line val parts n i hit
  for f in "${targets[@]}"; do
    hit=0
    while IFS= read -r line; do
      val=${line#*PATH=}; val=${val%%[;#]*}; val=${val//\"/}; val=${val//\'/}
      IFS=':' read -r -a parts <<<"$val"; n=${#parts[@]}
      for ((i = 0; i < n - 1; i++)); do
        if [ "${parts[$i]}" = "." ] || [ -z "${parts[$i]}" ]; then bad+=("$f"$'\t'"PATH 중간/앞에 '.' 또는 빈 항목: ${line:0:100}"); hit=1; break; fi
      done
      case "$val" in :*) bad+=("$f"$'\t'"PATH 맨 앞이 빈 항목(현재 디렉터리): ${line:0:100}"); hit=1 ;; esac
    done < <(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$f" 2>/dev/null | grep -v '^[[:space:]]*#')
    [ "$hit" -eq 1 ] && badfiles+=("$f")
  done; }
clean_file() {
  awk '
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*(export[[:space:]]+)?PATH=/ {
      i = index($0, "PATH="); pre = substr($0, 1, i + 4); rest = substr($0, i + 5); q = ""
      if (substr(rest, 1, 1) == "\"" || substr(rest, 1, 1) == "\047") { q = substr(rest, 1, 1); rest = substr(rest, 2) }
      if (q != "") { e = index(rest, q) } else { e = match(rest, /[;# \t]/) }
      if (e == 0) { val = rest; tail = "" } else { val = substr(rest, 1, e - 1); tail = substr(rest, e) }
      n = split(val, p, ":"); out = ""; k = 0
      for (j = 1; j <= n; j++) { if (p[j] == "." || p[j] == "") continue; out = (k++ ? out ":" : "") p[j] }
      if (k == 0) { print; next }
      print pre q out tail; next }
    { print }' "$1"
}
FILES=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/profile.d/*.sh /root/.profile /root/.bash_profile /root/.bashrc /root/.bash_login /root/.cshrc)
targets=(); for f in "${FILES[@]}"; do [ -f "$f" ] && [ ! -L "$f" ] && targets+=("$f"); done

bad=(); badfiles=()
scan

# PATH= 대입 줄의 값에서 '.' 과 빈 항목을 뺀다(따옴표·뒤 주석은 유지)

if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad[@]}"; state VULN "PATH 에 '.' 이 앞/중간에 있는 설정 ${#bad[@]}건"
else state GOOD "PATH 에 '.' 이 앞/중간에 없음 (점검 파일 ${#targets[@]}개)"; fi
)

# ---- U-15 U-15 파일 및 디렉터리 소유자 설정  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
chk_U15() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -n $((MAXN + 1)); }
show() { local p o m; for p in "$@"; do { read -r o m < <(stat -c '%u:%g %a' "$p" 2>/dev/null); } && printf '%s\t소유자(uid:gid)=%s 권한=%s\n' "$p" "$o" "$m"; done; }
MAXN=300
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

mapfile -t f < <(scan)
show "${f[@]:0:$MAXN}"
if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "소유자/그룹이 없는 항목이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
elif [ "${#f[@]}" -gt 0 ]; then state VULN "소유자/그룹이 없는 파일·디렉터리 ${#f[@]}건"
else state GOOD "소유자/그룹이 없는 파일 없음"; fi
)

# ---- U-16 U-16 /etc/passwd 파일 소유자 및 권한 설정 (기준: 소유자 root, 권한 644 이하)  -- 참고용 구현 예시
chk_U16() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
is_vuln() { [ "$owner" != "root" ] || [ "$over" -ne 0 ]; }
TARGET=/etc/passwd
MAX_MODE=644


[ -e "$TARGET" ] || { state NA "$TARGET 없음"; exit 0; }
[ -L "$TARGET" ] && { state MANUAL "$TARGET 가 심볼릭 링크입니다(수동 확인)"; exit 0; }

read -r owner mode < <(stat -c '%U %a' "$TARGET")
# 허용 범위를 넘는 비트 = (현재 모드) & ~(허용 모드)
over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))


if is_vuln; then state VULN "소유자=$owner 권한=$mode (기준: root, $MAX_MODE 이하)"
else state GOOD "소유자=$owner 권한=$mode"; fi
)

# ---- U-17 U-17 시스템 시작 스크립트 권한 설정
chk_U17() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
collect() {
  local c r
  { for c in /etc/rc.d/init.d/* /etc/init.d/* /etc/rc.d/rc*.d/* /etc/rc[0-6S].d/* /etc/rc.local /etc/rc.d/rc.local; do echo "$c"; done
    [ -d /etc/systemd/system ] && find /etc/systemd/system -maxdepth 2 \( -type f -o -type l \) 2>/dev/null
  } | while IFS= read -r c; do
    [ -e "$c" ] || continue
    r=$(readlink -f -- "$c" 2>/dev/null) || continue
    [ -f "$r" ] || continue
    case "$r" in /etc/*|/usr/lib/systemd/*|/lib/systemd/*) printf '%s\n' "$r" ;; esac
  done | sort -u
}
scan_bad() {
  bad=(); bad_info=()
  local f owner mode
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    if [ "$owner" != "root" ] || [ $(( 8#$mode & 8#0002 )) -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
mapfile -t targets < <(collect)
bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then state NA "시작 스크립트 대상 파일이 없습니다"; exit 0; fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달 (기준: 소유자 root, other 쓰기 금지)"
else state GOOD "${#targets[@]}개 파일 모두 기준 충족"; fi
)

# ---- U-18 U-18 /etc/shadow 파일 소유자 및 권한 설정
chk_U18() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/shadow)
OWNERS=" root "
MAX_MODE=400

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 400 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-19 U-19 /etc/hosts 파일 소유자 및 권한 설정
chk_U19() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/hosts)
OWNERS=" root "
MAX_MODE=644

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 644 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-20 U-20 /etc/(x)inetd.conf 파일 소유자 및 권한 설정
chk_U20() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {
  local p
  if command -v rpm >/dev/null 2>&1; then
    for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif command -v dpkg >/dev/null 2>&1; then
    for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/*)
OWNERS=" root "
MAX_MODE=600

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

# 패키지 설치 여부: 0=설치됨, 1=미설치, 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
if [ "${1:-}" = check ] || [ "${1:-}" = apply ] || [ "${1:-}" = list ]; then
  pkg_gate "xinetd/inetd" "xinetd openbsd-inetd" "/etc/xinetd.conf" "/etc/xinetd.d" "/etc/inetd.conf"
fi

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 600 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-21 U-21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정
chk_U21() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {
  local p
  if command -v rpm >/dev/null 2>&1; then
    for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif command -v dpkg >/dev/null 2>&1; then
    for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/rsyslog.conf /etc/syslog.conf /etc/syslog-ng/syslog-ng.conf)
OWNERS=" root bin sys "
MAX_MODE=640

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

# 패키지 설치 여부: 0=설치됨, 1=미설치, 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
if [ "${1:-}" = check ] || [ "${1:-}" = apply ] || [ "${1:-}" = list ]; then
  pkg_gate "rsyslog/syslog-ng" "rsyslog syslog-ng" "/etc/rsyslog.conf" "/etc/rsyslog.d" "/etc/syslog-ng/syslog-ng.conf" "/etc/syslog.conf"
fi

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root/bin/sys, 640 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-22 U-22 /etc/services 파일 소유자 및 권한 설정
chk_U22() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/services)
OWNERS=" root "
MAX_MODE=644

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 644 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-23 U-23 SUID, SGID, Sticky bit 설정 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
chk_U23() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort | head -n $((MAXN + 1)); }
owned() { if have rpm; then rpm -qf "$1" >/dev/null 2>&1 && return 0; return 1
  elif have dpkg; then dpkg -S "$1" >/dev/null 2>&1 && return 0; return 1; fi; return 2; }
classify() { local p=$1 rc
  if printf '%s' "$p" | grep -Eq "$RISKY"; then echo remove; return; fi
  owned "$p"; rc=$?
  if [ "$rc" -eq 1 ]; then echo remove; return; fi
  if [ "$rc" -eq 2 ] || ! printf '%s' "$p" | grep -Eq "$KNOWN"; then echo review; return; fi
  echo ok; }
analyze() { rm_list=(); rv=0; n=0; lines=(); local p c o m
  mapfile -t f < <(scan); n=${#f[@]}
  for p in "${f[@]:0:$MAXN}"; do
    { read -r o m < <(stat -c '%U %a' "$p" 2>/dev/null); } || continue
    c=$(classify "$p"); tag=""
    case "$c" in remove) rm_list+=("$p"); tag=" (제거 대상: 패키지 소유 아님 또는 임시·홈 경로)" ;; review) rv=$((rv+1)); tag=" (검토)" ;; esac
    lines+=("$p"$'\t'"소유자=$o 권한=$m$tag")
  done; }
MAXN=300
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

# 배포판이 기본으로 두는 일반적인 SUID/SGID(패키지 소유일 때만 '정상' 으로 본다)
KNOWN='^/usr/(bin|sbin|libexec|lib)/(passwd|chage|gpasswd|newgrp|chsh|chfn|su|sudo|mount|umount|pkexec|crontab|at|ssh-agent|write|wall|locate|expiry|unix_chkpwd|newuidmap|newgidmap|fusermount3?|staprun|userhelper|Xorg\.wrap|dbus-daemon-launch-helper|pam_timestamp_check|lockdev|mount\.nfs|umount\.nfs|utempter|ksu|ssh-keysign|polkit-agent-helper-1|sendmail\.postfix|usernetctl|grub2-set-bootflag|mount\.cifs|umount\.cifs|chronyd|postdrop|postqueue|netreport|pt_chown|cockpit-session|sudoedit)$|^/usr/(libexec|lib)/(openssh/ssh-keysign|dbus-1/dbus-daemon-launch-helper|utempter/utempter|polkit-1/polkit-agent-helper-1|cockpit-session|ssh-keysign)$'
RISKY='^/(home|tmp|var/tmp|dev/shm|mnt|media)(/|$)'
# classify 경로 → remove(제거 대상) / review(검토) / ok
rm_list=(); rv=0; n=0; lines=()
 analyze; [ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}"
if [ "$n" -gt "$MAXN" ]; then state MANUAL "SUID/SGID 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
elif [ "${#rm_list[@]}" -gt 0 ]; then state VULN "부적절한 SUID/SGID 파일 ${#rm_list[@]}개(패키지 소유 아님·임시/홈 경로), 검토 필요 ${rv}개"
elif [ "$rv" -gt 0 ]; then state MANUAL "SUID/SGID 파일 ${n}개 중 (검토) 표시 ${rv}개: 불필요한 파일인지 확인 필요"
elif [ "$n" -gt 0 ]; then state GOOD "SUID/SGID 파일 ${n}개 모두 배포판 기본 파일"
else state GOOD "SUID/SGID 파일 없음"; fi
)

# ---- U-24 U-24 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
chk_U24() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
collect() {
  local f u uid home shell h
  for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/csh.cshrc /etc/csh.login /etc/zshrc /etc/profile.d/*; do
    [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\troot\n' "$f"
  done
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    [ -d "$home" ] && [ ! -L "$home" ] || continue
    for h in "${HOME_FILES[@]}"; do
      f="$home/$h"
      [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\troot %s\n' "$f" "$u"
    done
  done < <(getent passwd)
}
scan_bad() {
  bad=(); bad_info=(); badown=()
  local row f allowed owner mode
  for row in "${rows[@]}"; do
    f=${row%%$'\t'*}; allowed=" ${row#*$'\t'} "
    read -r owner mode < <(stat -c '%U %a' "$f")
    case "$allowed" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
      bad+=("$f"); badown+=("${allowed# }"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
HOME_FILES=(.profile .bash_profile .bash_login .bashrc .bash_logout .zshenv .zprofile .zshrc .zlogin .login .cshrc .tcshrc .kshrc .exrc .env)

# 줄마다: 경로<TAB>허용 소유자(공백 구분)

mapfile -t rows < <(collect)
bad=(); bad_info=(); badown=()

if [ "${#rows[@]}" -eq 0 ]; then state NA "환경변수 파일 대상이 없습니다"; exit 0; fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달 (기준: 소유자 root/해당 계정, 그룹·기타 쓰기 금지)"
else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi
)

# ---- U-25 U-25 world writable 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
chk_U25() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -n $((MAXN + 1)); }
show() { local p o m; for p in "$@"; do { read -r o m < <(stat -c '%U %a' "$p" 2>/dev/null); } && printf '%s\t소유자=%s 권한=%s\n' "$p" "$o" "$m"; done; }
MAXN=300
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

 mapfile -t f < <(scan); show "${f[@]:0:$MAXN}"
if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "world writable 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
elif [ "${#f[@]}" -gt 0 ]; then state VULN "world writable 파일 ${#f[@]}건 (/tmp·/var/tmp 제외)"
else state GOOD "world writable 일반 파일 없음"; fi
)

# ---- U-26 U-26 /dev에 존재하지 않는 device 파일 점검  (엑셀 ?: 확인 후 적용 · 전체 파일 검색 항목이라 시간이 걸린다)
chk_U26() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { find /dev \( -path /dev/shm -o -path /dev/mqueue -o -path /dev/hugepages -o -path /dev/pts \) -prune -o -type f -print 2>/dev/null | head -n $((MAXN + 1)); }
analyze() { small=(); big=(); lines=(); local p o m s
  mapfile -t f < <(scan)
  for p in "${f[@]:0:$MAXN}"; do
    { read -r o m s < <(stat -c '%U %a %s' "$p" 2>/dev/null); } || continue
    if [ "$s" -le "$LIMIT" ]; then small+=("$p"); lines+=("$p"$'\t'"소유자=$o 권한=$m 크기=${s}B (삭제 대상)")
    else big+=("$p"); lines+=("$p"$'\t'"소유자=$o 권한=$m 크기=${s}B (50MB 초과: 수동 확인)"); fi
  done; }
MAXN=300
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

[ -d /dev ] || { state NA "/dev 없음"; exit 0; }
LIMIT=$((50 * 1024 * 1024))     # 스냅샷이 백업하는 최대 크기와 같다
small=(); big=(); lines=()
 analyze; [ "${#lines[@]}" -gt 0 ] && printf '%s\n' "${lines[@]}"
if [ "${#f[@]}" -gt "$MAXN" ]; then state MANUAL "/dev 안의 일반 파일이 ${MAXN}건을 넘어 자동 조치하지 않습니다(수동 점검)"
elif [ "${#small[@]}" -gt 0 ]; then state VULN "/dev 안에 장치 파일이 아닌 일반 파일 ${#small[@]}건(삭제 대상)"
elif [ "${#big[@]}" -gt 0 ]; then state MANUAL "/dev 안의 일반 파일 ${#big[@]}건이 50MB 를 넘어 수동 확인이 필요합니다"
else state GOOD "/dev 안에 일반 파일 없음"; fi
)

# ---- U-27 U-27 $HOME/.rhosts, hosts.equiv 사용 금지
chk_U27() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
collect() {
  [ -f /etc/hosts.equiv ] && [ ! -L /etc/hosts.equiv ] && printf '/etc/hosts.equiv\troot\n'
  login_users | while IFS=$'\t' read -r u h g; do
    [ -f "$h/.rhosts" ] && [ ! -L "$h/.rhosts" ] && printf '%s/.rhosts\troot %s\n' "$h" "$u"
  done
}
scan() {
  bad=(); bad_allowed=(); info=(); local r f allowed owner mode why
  for r in "${rows[@]}"; do
    f=${r%%$'\t'*}; allowed=" ${r#*$'\t'} "; why=""
    read -r owner mode < <(stat -c '%U %a' "$f")
    case "$allowed" in *" $owner "*) ;; *) why="소유자=$owner " ;; esac
    [ $(( 8#$mode & ~8#600 & 8#7777 )) -ne 0 ] && why="${why}권한=$mode "
    grep -Eq '^[[:space:]]*\+' "$f" && why="${why}'+' 설정 있음 "
    [ -n "$why" ] && { bad+=("$f"); bad_allowed+=("${r#*$'\t'}"); info+=("$f"$'\t'"$why"); }
  done
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

# r 계열 패키지가 없어도(Rocky 9 에는 rsh 패키지가 없다) 파일 자체가 점검·조치 대상이다: 파일이 없으면 해당없음, 있으면 기준 점검

# 줄마다: 경로<TAB>허용 소유자(공백 구분)
mapfile -t rows < <(collect)
[ "${#rows[@]}" -gt 0 ] || { state NA "hosts.equiv/.rhosts 파일이 없습니다"; exit 0; }
bad=(); bad_allowed=(); info=()
 scan
if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${info[@]}"; state VULN "기준 미달 파일 ${#bad[@]}개"; else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi
)

# ---- U-28 U-28 접속 IP 및 포트 제한  (엑셀 X: 점검·목록만)
chk_U28() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
found=(); info=()
if [ -f /etc/hosts.deny ] && grep -Eq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny; then found+=("tcp_wrappers"); info+=("/etc/hosts.deny: ALL:ALL"); fi
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then found+=("firewalld"); info+=("firewalld 활성: 기본 zone=$(firewall-cmd --get-default-zone 2>/dev/null)"); fi
if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then found+=("ufw"); info+=("ufw 활성"); fi
if have iptables && [ "$(iptables -S 2>/dev/null | grep -vc '^-P')" -gt 0 ]; then found+=("iptables"); info+=("iptables 규칙 있음"); fi
if have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then found+=("nftables"); info+=("nftables 규칙 있음"); fi

if [ "${#found[@]}" -gt 0 ]; then printf '%s\n' "${info[@]}"; state MANUAL "접근 제어 수단 있음(${found[*]}): 허용 IP·포트 정책이 맞는지 확인 필요"
else state VULN "TCP Wrapper/방화벽 어디에도 접속 제한이 설정되어 있지 않음"; fi
)

# ---- U-30 U-30 UMASK 설정 관리
chk_U30() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
weak_val() { [[ $1 =~ ^[0-7]{3,4}$ ]] || return 1; [ $(( 8#$1 & 8#022 )) -ne $(( 8#022 )) ]; }   # 022 보다 느슨하면 0
scan() {
  probs=(); local v f line
  if [ -f "$LD" ]; then v=$(kv_get "$LD" UMASK); { [ -n "$v" ] && ! weak_val "$v"; } || probs+=("$LD UMASK=${v:-미설정}"); fi
  for f in "${UFILES[@]}"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    while IFS= read -r line; do
      v=$(echo "$line" | sed -E 's/^[[:space:]]*umask[[:space:]]+([0-7]+).*/\1/')
      weak_val "$v" && probs+=("$f: $line")
    done < <(grep -E '^[[:space:]]*umask[[:space:]]+[0-7]+' "$f")
  done
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

LD=/etc/login.defs
UFILES=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh)
probs=()
scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "UMASK 가 022 보다 느슨한 설정 ${#probs[@]}건"
else state GOOD "UMASK 022 이상으로 설정됨"; fi
)

# ---- U-31 U-31 홈 디렉토리 소유자 및 권한 설정
chk_U31() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
collect() {   # 줄마다: 홈경로<TAB>계정
  local u uid home shell
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    case "$home" in /|"") continue ;; esac
    [ -d "$home" ] && [ ! -L "$home" ] && printf '%s\t%s\n' "$home" "$u"
  done < <(getent passwd)
}
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
mapfile -t rows < <(collect)
bad=(); bad_user=(); bad_info=()

if [ "${#rows[@]}" -eq 0 ]; then state NA "점검할 홈 디렉터리가 없습니다"; exit 0; fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 홈 디렉터리가 기준 미달 (기준: 소유자=해당 계정, other 쓰기 금지)"
else state GOOD "${#rows[@]}개 홈 디렉터리 모두 기준 충족"; fi
)

# ---- U-32 U-32 홈 디렉토리로 지정한 디렉토리의 존재 관리
chk_U32() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
missing() { login_users | while IFS=$'\t' read -r u h g; do { [ -z "$h" ] || [ ! -d "$h" ]; } && printf '%s\t%s\t%s\n' "$u" "$h" "$g"; done; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

mapfile -t m < <(missing)
if [ "${#m[@]}" -gt 0 ]; then for r in "${m[@]}"; do IFS=$'\t' read -r u h g <<<"$r"; printf '계정 %s: 홈 %s 없음\n' "$u" "${h:-없음}"; done; state VULN "홈 디렉터리가 없는 계정 ${#m[@]}개"
else state GOOD "모든 로그인 계정의 홈 디렉터리가 존재"; fi
)

# ---- U-34 U-34 Finger 서비스 비활성화
chk_U34() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("finger.service" "finger.socket" "fingerd.service")
PKGS=("finger-server" "fingerd" "efingerd" "cfingerd")
XINETD=("finger")
INETD=("finger")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=()
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: Finger 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-35 U-35 공유 서비스에 대한 익명 접근 제한 설정
chk_U35() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  probs=(); local v
  if [ -n "$VSFTPD" ]; then v=$(kv_get "$VSFTPD" anonymous_enable); [ "${v^^}" = YES ] && probs+=("$VSFTPD: anonymous_enable=YES"); fi
  if [ -n "$PROFTPD" ] && grep -Eq '^[[:space:]]*<Anonymous' "$PROFTPD"; then probs+=("$PROFTPD: <Anonymous> 블록 활성"); fi
  if [ -f "$EXPORTS" ] && grep -Ev '^[[:space:]]*#' "$EXPORTS" | grep -Eq 'anon(uid|gid)='; then probs+=("$EXPORTS: anonuid/anongid 옵션 사용"); fi
  if [ -f "$SMB" ] && grep -Ev '^[[:space:]]*[#;]' "$SMB" | grep -Eiq '^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*(yes|true|1)'; then probs+=("$SMB: guest ok/public = yes"); fi
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "FTP/NFS/Samba" "vsftpd proftpd nfs-utils nfs-kernel-server samba" "/etc/vsftpd*" "/etc/proftpd*" "/etc/exports" "/etc/samba/smb.conf"
VSFTPD=""; for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do [ -f "$f" ] && VSFTPD=$f && break; done
PROFTPD=""; for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && PROFTPD=$f && break; done
EXPORTS=/etc/exports; SMB=/etc/samba/smb.conf
[ -n "$VSFTPD$PROFTPD" ] || [ -f "$EXPORTS" ] || [ -f "$SMB" ] || { state NA "점검할 공유 서비스 설정 파일이 없습니다"; exit 0; }

probs=()
 scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "익명 접근이 허용된 설정 ${#probs[@]}건"; else state GOOD "익명 접근이 제한되어 있음"; fi
)

# ---- U-36 U-36 r 계열 서비스 비활성화
chk_U36() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("rlogin.socket" "rlogin.service" "rsh.socket" "rsh.service" "rexec.socket" "rexec.service" "rsh-server.service")
PKGS=("rsh-server" "rsh-redone-server" "rsh")
XINETD=("rsh" "rlogin" "rexec" "shell" "login" "exec")
INETD=("shell" "login" "exec" "rsh" "rlogin" "rexec")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/etc/hosts.equiv" "/root/.rhosts" "/home/*/.rhosts")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: rlogin, rsh, rexec 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-37 U-37 crontab 설정 파일 권한 설정 미흡
chk_U37() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
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
mapfile -t rows < <(collect)
bad=(); bad_max=(); bad_chk=(); bad_info=()

if [ "${#rows[@]}" -eq 0 ]; then state NA "cron/at 관련 파일이 없습니다"; exit 0; fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달"
else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi
)

# ---- U-38 U-38 DoS공격에 취약한 서비스 비활성화
chk_U38() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("echo.service" "echo.socket" "echo-dgram.socket" "echo-stream.socket" "discard.service" "discard.socket" "discard-dgram.socket" "discard-stream.socket" "daytime.service" "daytime.socket" "daytime-dgram.socket" "daytime-stream.socket" "chargen.service" "chargen.socket" "chargen-dgram.socket" "chargen-stream.socket")
PKGS=("xinetd" "openbsd-inetd")
XINETD=("echo" "echo-dgram" "echo-stream" "discard" "discard-dgram" "discard-stream" "daytime" "daytime-dgram" "daytime-stream" "chargen" "chargen-dgram" "chargen-stream")
INETD=("echo" "discard" "daytime" "chargen")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=()
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: echo, discard, daytime, chargen 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-39 U-39 불필요한 NFS 서비스 비활성화
chk_U39() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("nfs-server.service" "nfs-mountd.service" "nfs-idmapd.service" "nfs-blkmap.service" "nfsdcld.service")
PKGS=("nfs-utils" "nfs-kernel-server")
XINETD=()
INETD=()
GUARD_UNITS=()
GUARD_EXPORTS="/etc/exports"
LEFTOVER=("/etc/exports")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: NFS 서비스 데몬이 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-40 U-40 NFS 접근 통제
chk_U40() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
perm_bad() { read -r o m < <(stat -c '%U %a' "$EXPORTS"); [ "$o" != root ] || [ $(( 8#$m & ~8#644 & 8#7777 )) -ne 0 ]; }
open_entries() { grep -Ev '^[[:space:]]*(#|$)' "$EXPORTS" | awk '{ n=0; for (i=2;i<=NF;i++) { h=$i; sub(/\(.*/, "", h); if (h == "" || h == "*") n++ } if (NF < 2 || n > 0) c++ } END{print c+0}'; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

EXPORTS=/etc/exports
[ -f "$EXPORTS" ] || { state NA "/etc/exports 가 없습니다"; exit 0; }
[ -L "$EXPORTS" ] && { state MANUAL "/etc/exports 가 심볼릭 링크입니다(수동 확인)"; exit 0; }
# 호스트가 없거나 * 인 공유 항목 수
read -r o m < <(stat -c '%U %a' "$EXPORTS"); n=$(open_entries)
if perm_bad; then echo "exports 소유자=$o 권한=$m, 접근 제한이 없는 공유 항목 ${n}건"; state VULN "/etc/exports 소유자/권한 기준 미달(소유자=$o 권한=$m)"
elif [ "$n" -gt 0 ]; then state MANUAL "접근 제한이 없는(*) 공유 항목 ${n}건: 허용할 호스트를 수동으로 지정하세요"
else state GOOD "소유자 root, 권한 $m, 공유 항목이 호스트로 제한됨"; fi
)

# ---- U-41 U-41 불필요한 automountd 제거
chk_U41() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("autofs.service" "automount.service")
PKGS=("autofs")
XINETD=()
INETD=()
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/etc/auto.master" "/etc/autofs.conf" "/etc/auto.master.d")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: autofs(automountd)가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-42 U-42 불필요한 RPC 서비스 비활성화
chk_U42() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("rpcbind.service" "rpcbind.socket" "rpc-statd.service" "rpc-statd-notify.service" "rpc.statd.service")
PKGS=("rpcbind")
XINETD=("rpc-statd" "rpc.statd" "rstatd" "rusersd" "rquotad" "sprayd" "walld")
INETD=("rstatd" "rusersd" "rquotad" "sprayd" "walld" "rpc.cmsd")
GUARD_UNITS=("nfs-server.service" "nfs-mountd.service" "ypbind.service" "ypserv.service")
GUARD_EXPORTS=""
LEFTOVER=()
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: 불필요한 RPC 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-43 U-43 NIS, NIS+ 점검
chk_U43() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("ypserv.service" "ypbind.service" "ypxfrd.service" "yppasswdd.service" "ypupdated.service" "rpc-yppasswdd.service")
PKGS=("ypserv" "ypbind" "yp-tools" "nis")
XINETD=()
INETD=()
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/etc/yp.conf" "/var/yp")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: NIS 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-44 U-44 tftp, talk 서비스 비활성화
chk_U44() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("tftp.service" "tftp.socket" "tftpd-hpa.service" "talk.service" "talk.socket" "ntalk.service" "ntalk.socket" "talkd.service")
PKGS=("tftp-server" "tftpd-hpa" "tftpd" "talk-server" "talkd")
XINETD=("tftp" "talk" "ntalk")
INETD=("tftp" "talk" "ntalk")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/var/lib/tftpboot" "/srv/tftp" "/tftpboot")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: tftp, talk, ntalk 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-45 U-45 메일 서비스 버전 점검  (엑셀 X: 점검·목록만)
chk_U45() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_ver() { if have rpm; then rpm -q "$1" 2>/dev/null | grep -v 'not installed'; elif have dpkg; then dpkg -s "$1" 2>/dev/null | awk -F': ' '/^Status:/{s=$2} /^Version:/{v=$2} END{if (s ~ /installed/) print "'"$1"'-" v}'; fi; }
pkg_any() { [ "${#found[@]}" -gt 0 ] && return 0; return 1; }
found=()
for p in sendmail postfix exim exim4; do v=$(pkg_ver "$p"); [ -n "$v" ] && found+=("$v"); done
# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
pkg_gate "메일 서비스" "x" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
 printf '%s\n' "${found[@]}"; state MANUAL "메일 서비스 설치됨(${found[*]}): 최신 보안 패치인지 벤더 공지와 비교 확인 필요 (미사용이면 서비스 중지)"
)

# ---- U-46 U-46 일반 사용자의 메일 서비스 실행 방지
chk_U46() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  probs=()
  [ -f "$SMCF" ] && ! grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF" | grep -q 'restrictqrun' && probs+=("$SMCF: PrivacyOptions 에 restrictqrun 없음")
  for f in "${tools[@]}"; do [ $(( 8#$(stat -c '%a' "$f") & 8#001 )) -ne 0 ] && probs+=("$f: 일반 사용자 실행 권한 있음"); done
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "메일 서비스" "sendmail postfix exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
# 설치된 패키지별로만 점검·조치한다(미설치 패키지는 건너뜀)
SMCF=""; pkg_has sendmail && [ -f /etc/mail/sendmail.cf ] && SMCF=/etc/mail/sendmail.cf
tools=()
pkg_has postfix && [ -f /usr/sbin/postsuper ] && tools+=("$(readlink -f /usr/sbin/postsuper)")
pkg_has exim exim4 && [ -f /usr/sbin/exiqgrep ] && tools+=("$(readlink -f /usr/sbin/exiqgrep)")
[ -n "$SMCF" ] || [ "${#tools[@]}" -gt 0 ] || { state NA "설치된 메일 패키지에 점검할 설정/도구가 없습니다"; exit 0; }
probs=()
 scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "일반 사용자의 메일 큐 실행 방지가 미설정 ${#probs[@]}건"; else state GOOD "일반 사용자의 메일 큐 실행이 제한됨"; fi
)

# ---- U-47 U-47 스팸 메일 릴레이 제한  (엑셀 X: 점검·목록만)
chk_U47() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
pkg_gate "메일 서비스" "postfix sendmail exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
CF=/etc/postfix/main.cf; SM=/etc/mail/access
if pkg_has postfix && have postconf && [ -f "$CF" ]; then
  rr=$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | tr '\n' ' '); mn=$(postconf -h mynetworks 2>/dev/null)
  echo "postfix smtpd_*_restrictions: ${rr:0:150}"; echo "postfix mynetworks: ${mn:0:100}"
  if echo "$mn" | grep -Eq '(^|[ ,])0\.0\.0\.0/0([ ,]|$)'; then state VULN "postfix mynetworks 가 0.0.0.0/0 으로 모든 대상을 릴레이 허용"
  elif echo "$rr" | grep -q 'reject_unauth_destination'; then state GOOD "postfix 가 reject_unauth_destination 으로 외부 릴레이를 거부"
  else state VULN "postfix 에 reject_unauth_destination 설정이 없음(릴레이 제한 미흡 가능)"; fi
else
  inst=(); pkg_has postfix && inst+=(postfix); pkg_has sendmail && inst+=(sendmail); pkg_has exim exim4 && inst+=(exim)
  state MANUAL "설치된 메일 서비스(${inst[*]:-없음})는 설정 파일에서 릴레이 제한 여부를 수동 확인해야 합니다"
fi
)

# ---- U-48 U-48 expn, vrfy 명령어 제한
chk_U48() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  probs=(); local po
  if [ "$use_sm" -eq 1 ]; then po=$(grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF")
    echo "$po" | grep -q goaway || { echo "$po" | grep -q noexpn && echo "$po" | grep -q novrfy; } || probs+=("$SMCF: noexpn/novrfy(goaway) 미설정"); fi
  if [ "$use_pf" -eq 1 ]; then [ "$(postconf -h disable_vrfy_command 2>/dev/null)" = yes ] || probs+=("$PFCF: disable_vrfy_command 가 yes 가 아님"); fi
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "메일 서비스" "sendmail postfix exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
SMCF=/etc/mail/sendmail.cf; PFCF=/etc/postfix/main.cf
# 설치된 패키지별로만 점검·조치한다(미설치 패키지는 건너뜀)
use_sm=0; pkg_has sendmail && [ -f "$SMCF" ] && use_sm=1
use_pf=0; pkg_has postfix && have postconf && [ -f "$PFCF" ] && use_pf=1
exim=0; pkg_has exim exim4 && exim=1
[ "$use_sm" -eq 1 ] || [ "$use_pf" -eq 1 ] || [ "$exim" -eq 1 ] || { state NA "점검할 메일 설정 파일이 없습니다"; exit 0; }
probs=()
 scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "expn/vrfy 제한 미설정 ${#probs[@]}건"
elif [ "$exim" -eq 1 ] && [ "$use_sm" -eq 0 ] && [ "$use_pf" -eq 0 ]; then state MANUAL "exim 은 acl_smtp_vrfy/acl_smtp_expn 설정을 수동 확인해야 합니다"
else state GOOD "expn/vrfy 가 제한되어 있음"; fi
)

# ---- U-49 U-49 DNS 보안 버전 패치  (엑셀 X: 점검·목록만)
chk_U49() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
ver=""
if have rpm && rpm -q bind >/dev/null 2>&1; then ver=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} (설치일 %{INSTALLTIME:date})' bind 2>/dev/null)
elif have dpkg && dpkg -s bind9 2>/dev/null | grep -q 'install ok installed'; then ver="bind9-$(dpkg -s bind9 | awk -F': ' '/^Version:/{print $2}')"; fi
if [ -z "$ver" ]; then   # 패키지가 없을 때: 설정이 남아 있으면 점검 필요, 아무것도 없으면 해당없음
  l=""; for f in /etc/named.conf /etc/bind /etc/named; do
    if [ -d "$f" ] && [ -n "$(ls -A "$f" 2>/dev/null)" ]; then l="$l $f"
    elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then l="$l $f"; fi
  done
  if [ -n "${l// /}" ]; then state MANUAL "BIND 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요):$l"
  else state NA "BIND(named) 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
  exit 0
fi
 echo "$ver"; state MANUAL "DNS 서비스 설치됨($ver): 최신 보안 패치 여부를 확인하세요 (미사용이면 서비스 중지)"
)

# ---- U-50 U-50 DNS Zone Transfer 설정  (엑셀 X: 점검·목록만)
chk_U50() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
pkg_gate "BIND(named)" "bind bind9" "/etc/named.conf" "/etc/bind" "/etc/named"
CONFS=(); for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/named/*.conf; do [ -f "$f" ] && CONFS+=("$f"); done
[ "${#CONFS[@]}" -gt 0 ] || { state NA "named 설정 파일이 없습니다"; exit 0; }
lines=$(grep -hE '^[[:space:]]*allow-transfer' "${CONFS[@]}" 2>/dev/null | grep -v '^[[:space:]]*//' )
echo "allow-transfer: ${lines:-없음}"
if [ -z "$lines" ]; then state VULN "allow-transfer 설정이 없어 Zone Transfer 가 모든 대상에 허용될 수 있음"
elif echo "$lines" | grep -Eq '\bany\b'; then state VULN "allow-transfer 에 any 가 설정되어 있음"
else state GOOD "allow-transfer 가 허가된 대상으로 제한되어 있음"; fi
)

# ---- U-51 U-51 DNS 서비스의 취약한 동적 업데이트 설정 금지
chk_U51() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
open_files() { for f in "${CONFS[@]}"; do tr '\n' ' ' < "$f" | grep -Eq 'allow-update[[:space:]]*\{[^}]*\bany\b[^}]*\}' && echo "$f"; done; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "BIND(named)" "bind bind9" "/etc/named.conf" "/etc/bind" "/etc/named"
CONFS=(); for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local /etc/named/*.conf; do [ -f "$f" ] && [ ! -L "$f" ] && CONFS+=("$f"); done
[ "${#CONFS[@]}" -gt 0 ] || { state NA "named 설정 파일이 없습니다"; exit 0; }
 mapfile -t o < <(open_files)
if [ "${#o[@]}" -gt 0 ]; then printf 'allow-update any: %s\n' "${o[@]}"; state VULN "동적 업데이트가 any 로 허용된 설정 파일 ${#o[@]}개"; else state GOOD "allow-update 가 any 로 열려 있지 않음"; fi
)

# ---- U-52 U-52 Telnet 서비스 비활성화
chk_U52() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("telnet.socket" "telnet.service" "telnetd.service" "telnet@.service")
PKGS=("telnet-server" "telnetd" "inetutils-telnetd")
XINETD=("telnet")
INETD=("telnet")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=()
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: Telnet 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-54 U-54 암호화되지 않는 FTP 서비스 비활성화
chk_U54() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("vsftpd.service" "proftpd.service" "pure-ftpd.service" "ftpd.service" "gssftp.service" "ftp.socket" "wu-ftpd.service")
PKGS=("vsftpd" "proftpd" "pure-ftpd" "ftpd" "krb5-appl-servers")
XINETD=("ftp" "gssftp" "wu-ftpd")
INETD=("ftp")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: 암호화되지 않는 FTP 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-55 U-55 FTP 계정 Shell 제한
chk_U55() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
accts() { awk -F: '$1 == "ftp" || $1 == "anonymous" {print $1 ":" $7}' /etc/passwd; }
bad() { accts | awk -F: '$2 !~ /(nologin|false)$/ {print $1 ":" $2}'; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "FTP 서버" "vsftpd proftpd pure-ftpd ftpd" "/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd" "/etc/ftpusers"
[ -n "$(accts)" ] || { state NA "ftp 계정이 없습니다"; exit 0; }
 mapfile -t b < <(bad)
if [ "${#b[@]}" -gt 0 ]; then printf '계정:쉘 = %s\n' "${b[@]}"; state VULN "FTP 계정 쉘이 제한되지 않음(${b[*]})"; else state GOOD "FTP 계정 쉘이 제한됨"; fi
)

# ---- U-57 U-57 Ftpusers 파일 설정
chk_U57() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
has_root() { grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$1"; }
scan() {
  probs=(); local f
  for f in "${LISTS[@]}"; do has_root "$f" || probs+=("$f: root 가 차단 목록에 없음"); done
  if [ -n "$PCONF" ]; then v=$(kv_get "$PCONF" RootLogin | tr A-Z a-z); [ "$v" = on ] && probs+=("$PCONF: RootLogin on"); fi
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

pkg_gate "FTP 서버" "vsftpd proftpd pure-ftpd ftpd wu-ftpd" "/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd" "/etc/ftpusers"
LISTS=(); for f in /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do [ -f "$f" ] && [ ! -L "$f" ] && LISTS+=("$f"); done
VCONF=""; for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do [ -f "$f" ] && VCONF=$f && break; done
if [ -n "$VCONF" ] && [ "$(kv_get "$VCONF" userlist_enable | tr a-z A-Z)" = YES ]; then
  for f in /etc/vsftpd/user_list /etc/vsftpd.user_list; do [ -f "$f" ] && [ ! -L "$f" ] && LISTS+=("$f"); done
fi
PCONF=""; for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && PCONF=$f && break; done
[ "${#LISTS[@]}" -gt 0 ] || [ -n "$PCONF" ] || { state MANUAL "root 차단 설정 파일(ftpusers 등)을 찾지 못했습니다. 수동 확인 필요"; exit 0; }
probs=()
 scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "root 접속 차단 미설정 ${#probs[@]}건"; else state GOOD "FTP root 접속이 차단됨"; fi
)

# ---- U-58 U-58 불필요한 SNMP 서비스 구동 점검
chk_U58() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}
UNIT_PATTERNS=("snmpd.service" "snmptrapd.service")
PKGS=("net-snmp" "snmpd")
XINETD=()
INETD=()
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=("/etc/snmp")
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d



# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi


bad_units=(); bad_xfiles=(); bad_info=()

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

scan_bad
if [ "${#bad_info[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
  else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: SNMP 서비스가 비활성화)"; fi
else
  state GOOD "대상 서비스가 모두 비활성화되어 있음"
fi
)

# ---- U-59 U-59 안전한 SNMP 버전 사용  (엑셀 X: 점검·목록만)
chk_U59() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
pkg_gate "SNMP" "net-snmp snmpd" "/etc/snmp"
CF=""; for f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do [ -f "$f" ] && CF=$f && break; done
[ -n "$CF" ] || { state NA "snmpd.conf 가 없습니다"; exit 0; }
v12=$(grep -Ecv '^[[:space:]]*(#|$)' <(grep -E '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$CF") 2>/dev/null)
v3=$(grep -Ec '^[[:space:]]*(createUser|rouser|rwuser)[[:space:]]' "$CF")
if [ "${v12:-0}" -gt 0 ]; then state VULN "v1/v2c 커뮤니티 설정 ${v12}건 존재(v3 이상 사용 권장, v3 사용자 ${v3}건)"
elif [ "$v3" -gt 0 ]; then state GOOD "v3 사용자 설정만 있음(${v3}건)"
else state MANUAL "snmpd.conf 에 버전별 접근 설정이 없어 수동 확인 필요"; fi
)

# ---- U-60 U-60 SNMP Community String 복잡성 설정  (엑셀 X: 점검·목록만)
chk_U60() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
strings_() { awk '/^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]/ {print $2} /^[[:space:]]*com2sec6?[[:space:]]/ {print $4}' "$CF"; }
weak() {
  local s=$1 len=${#1}
  case "$s" in public|private) return 0 ;; esac
  local has_a has_d has_s
  [[ $s =~ [A-Za-z] ]] && has_a=1 || has_a=0; [[ $s =~ [0-9] ]] && has_d=1 || has_d=0; [[ $s =~ [^A-Za-z0-9] ]] && has_s=1 || has_s=0
  if [ $has_a -eq 1 ] && [ $has_d -eq 1 ] && [ $has_s -eq 1 ] && [ "$len" -ge 8 ]; then return 1; fi
  if [ $has_a -eq 1 ] && [ $has_d -eq 1 ] && [ "$len" -ge 10 ]; then return 1; fi
  return 0
}
pkg_gate "SNMP" "net-snmp snmpd" "/etc/snmp"
CF=""; for f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do [ -f "$f" ] && CF=$f && break; done
[ -n "$CF" ] || { state NA "snmpd.conf 가 없습니다"; exit 0; }
# community 값 추출: rocommunity/rwcommunity 는 2번째 필드, com2sec 는 4번째 필드
total=0; bad=0
while IFS= read -r s; do [ -z "$s" ] && continue; total=$((total+1)); weak "$s" && bad=$((bad+1)); done < <(strings_)
if [ "$total" -eq 0 ]; then state GOOD "community 문자열 설정 없음(v3 사용 가능성) — v3 비밀번호 복잡도는 수동 확인"
elif [ "$bad" -gt 0 ]; then state VULN "community 문자열 ${total}개 중 ${bad}개가 기본값이거나 복잡도 기준 미달(값은 출력하지 않음)"
else state GOOD "community 문자열 ${total}개 모두 복잡도 기준 충족"; fi
)

# ---- U-61 U-61 SNMP Access Control 설정  (엑셀 X: 점검·목록만)
chk_U61() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
pkg_gate "SNMP" "net-snmp snmpd" "/etc/snmp"
CF=""; for f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do [ -f "$f" ] && CF=$f && break; done
[ -n "$CF" ] || { state NA "snmpd.conf 가 없습니다"; exit 0; }
# rocommunity <문자열> [source]: source 가 없거나 default / 0.0.0.0/0 이면 접근 제어 없음
open=$(awk '/^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]/ { if (NF < 3 || $3 == "default" || $3 == "0.0.0.0/0" || $3 == "::/0") n++ } /^[[:space:]]*com2sec6?[[:space:]]/ { if ($3 == "default" || $3 == "0.0.0.0/0") n++ } END{print n+0}' "$CF")
total=$(grep -Ec '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$CF")
if [ "$open" -gt 0 ]; then state VULN "접근 대상 제한이 없는 community 설정 ${open}건(전체 ${total}건)"
elif [ "$total" -gt 0 ]; then state GOOD "community 설정 ${total}건 모두 접근 대상이 제한됨"
elif grep -Eq '^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]' "$CF"; then state GOOD "v3 사용자 기반 설정(community 없음)"
else state MANUAL "snmpd.conf 에 접근 제어 설정이 없어 수동 확인 필요"; fi
)

# ---- U-63 U-63 sudo 명령어 접근 관리
chk_U63() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan_bad() {
  bad=(); bad_info=()
  local f owner mode over
  for f in "${targets[@]}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}
PATTERNS=(/etc/sudoers)
OWNERS=" root "
MAX_MODE=640

# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다

targets=(); links=0
for f in "${PATTERNS[@]}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()

if [ "${#targets[@]}" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

scan_bad
if [ "${#bad[@]}" -gt 0 ]; then
  printf '%s\n' "${bad_info[@]}"
  state VULN "${#bad[@]}개 파일이 기준 미달 (기준: root, 640 이하)"
else
  state GOOD "${#targets[@]}개 파일 모두 기준 충족"
fi
)

# ---- U-64 U-64 주기적인 보안 패치 및 벤더 권고사항 적용  (엑셀 X: 점검·목록만)
chk_U64() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
auto=""
if have systemctl; then
  for t in dnf-automatic.timer dnf-automatic-install.timer unattended-upgrades.service apt-daily-upgrade.timer yum-cron.service; do
    systemctl is-enabled "$t" 2>/dev/null | grep -q '^enabled' && auto="$t"
  done
fi
last=""
if have rpm; then last=$(rpm -qa --last 2>/dev/null | head -1)
elif have dpkg && [ -f /var/log/dpkg.log ]; then last=$(grep ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -1); fi
echo "커널: $(uname -r)"; echo "가장 최근 패키지 변경: ${last:-확인 불가}"; echo "자동 업데이트: ${auto:-미설정}"
if [ -n "$auto" ]; then state MANUAL "자동 업데이트 설정됨(${auto}). 패치 정책/벤더 권고 확인은 수동으로 필요"
else state VULN "자동 업데이트 설정이 없음: 패치 적용 정책과 주기를 확인하세요 (최근 변경: ${last:0:80})"; fi
)

# ---- U-65 U-65 NTP 및 시각 동기화 설정
chk_U65() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
on_units() { for u in "${installed[@]}"; do [ "$(systemctl is-active "$u" 2>/dev/null)" = active ] && echo "$u"; done; }
servers() { grep -Ehs '^[[:space:]]*(server|pool|peer)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources /run/chrony-dhcp/*.sources /etc/ntp.conf /etc/ntpsec/ntp.conf /etc/ntpsec/ntp.d/*.conf 2>/dev/null | wc -l; }
ts_servers() { cat /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null | grep -E '^[[:space:]]*NTP[[:space:]]*=[[:space:]]*[^[:space:]]' | wc -l; }
srv_note() { if [ "$1" = systemd-timesyncd.service ]; then local t; t=$(ts_servers); [ "$t" -gt 0 ] && echo "NTP= 지정 ${t}건" || echo "내장 기본 서버(FallbackNTP) 사용"; else echo "서버 설정 $(servers)건"; fi; }
srv_ok() { [ "$1" = systemd-timesyncd.service ] || [ "$(servers)" -gt 0 ]; }
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

have systemctl || { state MANUAL "systemctl 이 없어 NTP 서비스 상태를 확인할 수 없습니다"; exit 0; }
CANDS=(chronyd.service chrony.service ntpd.service ntp.service ntpsec.service systemd-timesyncd.service)
installed=(); for u in "${CANDS[@]}"; do [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] && installed+=("$u"); done
# 동기화 서버 수. chrony 는 Ubuntu 25+ 에서 서버를 sources.d/*.sources 로 옮겼고(NTS), DHCP 가 알려 준 서버는 /run/chrony-dhcp 에 둔다
# systemd-timesyncd 는 서버를 안 적어도 내장 기본 서버(FallbackNTP)를 쓰므로 정상이다. 따로 지정했으면 그 수를 알려 준다
[ "${#installed[@]}" -gt 0 ] || { state MANUAL "NTP 서비스(chrony/ntp)가 설치되어 있지 않습니다. 패키지를 설치한 뒤 설정하세요(도구는 설치하지 않음)"; exit 0; }
mapfile -t on < <(on_units)
if [ "${#on[@]}" -eq 0 ]; then state VULN "NTP 서비스가 설치되어 있으나 동작하지 않음(${installed[*]})"
elif ! srv_ok "${on[0]}"; then state VULN "${on[0]} 동작 중이나 동기화 서버(server/pool) 설정이 없음"
else state GOOD "${on[0]} 동작 중($(srv_note "${on[0]}"))"; fi
)

# ---- U-66 U-66 정책에 따른 시스템 로깅 설정
chk_U66() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  miss=(); local r; r=$(rules)
  echo "$r" | grep -Eq '\*\.info.*[[:space:]]-?/var/log/messages' || miss+=("*.info;mail.none;authpriv.none;cron.none  /var/log/messages")
  echo "$r" | grep -Eq 'authpriv\.\*.*[[:space:]]-?/var/log/secure' || miss+=("authpriv.*  /var/log/secure")
  echo "$r" | grep -Eq 'mail\.\*.*[[:space:]]-?/var/log/maillog' || miss+=("mail.*  -/var/log/maillog")
  echo "$r" | grep -Eq 'cron\.\*.*[[:space:]]-?/var/log/cron' || miss+=("cron.*  /var/log/cron")
  echo "$r" | grep -Eq '\*\.emerg[[:space:]]+(:omusrmsg:)?\*' || miss+=("*.emerg  :omusrmsg:*")
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

RS=/etc/rsyslog.conf; RSD=/etc/rsyslog.d; NEWF=/etc/rsyslog.d/90-isms-logging.conf
have rsyslogd || [ -f "$RS" ] || { state MANUAL "rsyslog 가 설치되어 있지 않습니다(journald 만 사용). 로깅 정책은 수동으로 확인하세요"; exit 0; }
files=(); [ -f "$RS" ] && files+=("$RS"); for f in "$RSD"/*.conf; do [ -f "$f" ] && files+=("$f"); done
miss=()
 scan
act=1; have systemctl && [ "$(systemctl is-active rsyslog.service 2>/dev/null)" != active ] && act=0
if [ "$act" -eq 0 ]; then state VULN "rsyslog 서비스가 동작하지 않음"
elif [ "${#miss[@]}" -gt 0 ]; then printf '누락 규칙: %s\n' "${miss[@]}"; state VULN "필수 로깅 규칙 ${#miss[@]}개가 설정되어 있지 않음"
else state GOOD "로깅 정책 규칙이 모두 설정되어 있음"; fi
)

# ---- U-67 U-67 로그 디렉터리 소유자 및 권한 설정  (엑셀 ?: 확인 후 적용)
chk_U67() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
scan() { bad=(); info=(); local f o m over
  for f in "${targets[@]}"; do
    read -r o m < <(stat -c '%U %a' "$f" 2>/dev/null) || continue
    over=$(( 8#$m & ~8#644 & 8#7777 ))
    if [ "$o" != "root" ] || [ "$over" -ne 0 ]; then bad+=("$f"); info+=("$f"$'\t'"소유자=$o 권한=$m"); fi
  done; }
[ -d /var/log ] || { state NA "/var/log 없음"; exit 0; }
mapfile -t targets < <(find /var/log -maxdepth 2 -type f 2>/dev/null | sort)
[ "${#targets[@]}" -gt 0 ] || { state NA "로그 파일이 없습니다"; exit 0; }
bad=(); info=()
scan
 [ "${#info[@]}" -gt 0 ] && printf '%s\n' "${info[@]}"
if [ "${#bad[@]}" -gt 0 ]; then state VULN "${#bad[@]}개 로그 파일이 기준 미달 (기준: root, 644 이하)"; else state GOOD "${#targets[@]}개 로그 파일 모두 기준 충족"; fi
)

# ---- U-02 U-02 비밀번호 관리 정책  [우분투 전용: pam-auth-update 프로필로 pam_pwhistory 적용] (Ubuntu 전용)
chk_ubuntu_U02() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
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
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

PWQ=/etc/security/pwquality.conf
PWQD=/etc/security/pwquality.conf.d
LOGINDEFS=/etc/login.defs
PWH=/etc/security/pwhistory.conf
PROF=/usr/share/pam-configs/isms-pwhistory
CPW=/etc/pam.d/common-password

[ -f "$LOGINDEFS" ] || { state NA "/etc/login.defs 가 없습니다"; exit 0; }

pwq_files=(); [ -f "$PWQ" ] && pwq_files+=("$PWQ"); for f in "$PWQD"/*.conf; do [ -f "$f" ] && pwq_files+=("$f"); done

probs=()

scan
if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "비밀번호 정책 미충족 ${#probs[@]}건: ${probs[0]} 등"
else state GOOD "비밀번호 정책이 기준을 충족"; fi
)

# ---- U-03 U-03 [우분투 전용: pam-auth-update 프로필로 pam_faillock 적용] 계정 잠금 임계값 설정 (Ubuntu 전용)
chk_ubuntu_U03() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

FC=/etc/security/faillock.conf
PROF1=/usr/share/pam-configs/isms-faillock
PROF2=/usr/share/pam-configs/isms-faillock-notify
PAMS=(/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth)


d=$(deny_value)
if good; then state GOOD "계정 잠금 임계값 deny=$d"
elif ! pam_has; then state VULN "PAM 에 pam_faillock/pam_tally 설정이 없음(계정 잠금 미적용)"
else state VULN "계정 잠금 임계값이 1~10 범위가 아님(deny=${d:-미설정})"; fi
)

# ---- U-66 U-66 [우분투 전용: 로그 파일 syslog/auth.log/mail.log/cron.log] 정책에 따른 시스템 로깅 설정 (Ubuntu 전용)
chk_ubuntu_U66() (
set -- check     # 원본 스크립트의 ${1:-} 점검용
pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}
scan() {
  miss=(); local r; r=$(rules)
  echo "$r" | grep -Eq '\*\.\*;auth,authpriv\.none.*[[:space:]]-?/var/log/syslog' || miss+=("*.*;auth,authpriv.none  -/var/log/syslog")
  echo "$r" | grep -Eq '(auth,authpriv|authpriv|auth)\.\*.*[[:space:]]-?/var/log/auth\.log' || miss+=("auth,authpriv.*  /var/log/auth.log")
  echo "$r" | grep -Eq 'mail\.\*.*[[:space:]]-?/var/log/mail\.log' || miss+=("mail.*  -/var/log/mail.log")
  echo "$r" | grep -Eq 'cron\.\*.*[[:space:]]-?/var/log/cron' || miss+=("cron.*  /var/log/cron.log")
  echo "$r" | grep -Eq '\*\.emerg[[:space:]]+(:omusrmsg:)?\*' || miss+=("*.emerg  :omusrmsg:*")
}
acted=(); failed_svc=""


# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력

RS=/etc/rsyslog.conf; RSD=/etc/rsyslog.d; NEWF=/etc/rsyslog.d/90-isms-logging.conf
have rsyslogd || [ -f "$RS" ] || { state MANUAL "rsyslog 가 설치되어 있지 않습니다(journald 만 사용). 로깅 정책은 수동으로 확인하세요"; exit 0; }
files=(); [ -f "$RS" ] && files+=("$RS"); for f in "$RSD"/*.conf; do [ -f "$f" ] && files+=("$f"); done
miss=()
 scan
act=1; have systemctl && [ "$(systemctl is-active rsyslog.service 2>/dev/null)" != active ] && act=0
if [ "$act" -eq 0 ]; then state VULN "rsyslog 서비스가 동작하지 않음"
elif [ "${#miss[@]}" -gt 0 ]; then printf '누락 규칙: %s\n' "${miss[@]}"; state VULN "필수 로깅 규칙 ${#miss[@]}개가 설정되어 있지 않음"
else state GOOD "로깅 정책 규칙이 모두 설정되어 있음"; fi
)

export -f state have leftover pkg_gate pkg_has safe_fix svc_list svc_act nl_end kv_get kv_set login_users pwq_get pwq_enforce_root hist_get num pam_has deny_value good next_uid home_of chuid move_uid revert_moves unit_on xinetd_on rules chk_U01 chk_U02 chk_U03 chk_U04 chk_U05 chk_U06 chk_U08 chk_U10 chk_U13 chk_U14 chk_U15 chk_U16 chk_U17 chk_U18 chk_U19 chk_U20 chk_U21 chk_U22 chk_U23 chk_U24 chk_U25 chk_U26 chk_U27 chk_U28 chk_U30 chk_U31 chk_U32 chk_U34 chk_U35 chk_U36 chk_U37 chk_U38 chk_U39 chk_U40 chk_U41 chk_U42 chk_U43 chk_U44 chk_U45 chk_U46 chk_U47 chk_U48 chk_U49 chk_U50 chk_U51 chk_U52 chk_U54 chk_U55 chk_U57 chk_U58 chk_U59 chk_U60 chk_U61 chk_U63 chk_U64 chk_U65 chk_U66 chk_U67 chk_ubuntu_U02 chk_ubuntu_U03 chk_ubuntu_U66

# ======================= 실행 =======================
list=""
for i in $ALL; do
  case "$HEAVY" in *" $i "*) [ $heavy = 1 ] || continue ;; esac
  [ -z "$only" ] || case ",$only," in *",$i,"*) ;; *) continue ;; esac
  list="$list $i"; done
[ -n "$list" ] || die "점검할 항목이 없습니다"

# 항목 점검 실행 → R_STATE(GOOD/VULN/MANUAL/NA/ERROR), R_EV(근거). 항목마다 따로 떨어진 프로세스에서, 300초 제한
run() {
  local n=${1//-/} fn out rc last
  fn=chk_$n; [ "$os" = 2 ] && declare -F "chk_ubuntu_$n" >/dev/null && fn=chk_ubuntu_$n
  out=$(cd / && timeout 300 bash -c "$fn" </dev/null 2>/dev/null); rc=$?
  last=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -n 1)
  if [ $rc -ne 0 ] || ! [[ "$last" =~ ^(GOOD|VULN|MANUAL|NA|ERROR)\| ]]; then R_STATE=ERROR; R_EV="점검 오류(코드 $rc): ${last:0:80}"
  else R_STATE=${last%%|*}; R_EV=${last#*|}; fi
}

vulns=(); errs=()
for i in $list; do
  run "$i"
  case "$R_STATE" in
    VULN)  printf '%s  %s  %s\n' "$HOST" "$i" "${R_EV:0:100}"; vulns+=("$i") ;;
    ERROR) printf '%s  %s  ERROR %s\n' "$HOST" "$i" "$R_EV"; errs+=("$i") ;;
    *)     [ $verbose = 1 ] && printf '%s  %s  %s %s\n' "$HOST" "$i" "${R_STATE/GOOD/양호}" "${R_EV:0:80}" ;;
  esac
done

j() { printf '%s, ' "$@" | sed 's/, $//'; }
[ ${#vulns[@]} -eq 0 ] && echo "$HOST  vuln: X" || echo "$HOST  vuln: $(j "${vulns[@]}")"
[ ${#errs[@]} -gt 0 ] && echo "$HOST  error: $(j "${errs[@]}")"
[ ${#vulns[@]} -eq 0 ] && [ ${#errs[@]} -eq 0 ]
