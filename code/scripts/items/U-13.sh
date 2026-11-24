#!/bin/bash
# U-13 안전한 비밀번호 암호화 알고리즘 사용
# 기준: login.defs ENCRYPT_METHOD 가 SHA256/SHA512/YESCRYPT, 기존 계정이 MD5·DES 해시를 쓰지 않음
# 계약: bash U-13.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

LD=/etc/login.defs
[ -f "$LD" ] || { state NA "/etc/login.defs 가 없습니다"; exit 0; }
method() { local v; v=$(kv_get "$LD" ENCRYPT_METHOD); printf '%s' "${v^^}"; }
ok_method() { case "$(method)" in SHA256|SHA512|YESCRYPT) return 0 ;; *) return 1 ;; esac; }
# 약한 해시: $1$(MD5) 또는 $ 로 시작하지 않는 13자 안팎 값(DES). 해시 값은 출력하지 않고 계정 이름만 쓴다.
weak_accounts() { awk -F: '$2 ~ /^\$1\$/ || ($2 != "" && $2 !~ /^[*!]/ && $2 !~ /^\$/) {print $1}' /etc/shadow 2>/dev/null; }
# PAM 의 pam_unix 옵션이 md5/bigcrypt/des 이면 login.defs 와 상관없이 실제 해시가 약하다(authselect 관리 파일이라 자동 수정하지 않는다)
pam_weak() { grep -HEs '^[[:space:]]*password[[:space:]].*pam_unix\.so.*[[:space:]](md5|bigcrypt|des)([[:space:]]|$)' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null; }
case "${1:-}" in
  list) printf '%s\t암호화 알고리즘 설정\n' "$LD"; state GOOD "목록" ;;
  check)
    if ! ok_method; then state VULN "ENCRYPT_METHOD=$(method) (기준: SHA256/SHA512/YESCRYPT)"
    else
      mapfile -t pw < <(pam_weak)
      mapfile -t w < <(weak_accounts)
      if [ "${#pw[@]}" -gt 0 ]; then printf '%s\n' "${pw[@]}"; state MANUAL "PAM pam_unix 에 약한 해시 옵션(md5/bigcrypt/des)이 있습니다(authselect 설정을 직접 확인)"
      elif [ "${#w[@]}" -gt 0 ]; then printf '취약 해시 사용 계정: %s\n' "${w[@]}"; state MANUAL "ENCRYPT_METHOD 는 양호하나 기존 계정 ${#w[@]}개가 MD5/DES 해시를 사용(비밀번호 재설정 필요)"
      else state GOOD "ENCRYPT_METHOD=$(method)"; fi
    fi ;;
  apply)
    kv_set "$LD" ENCRYPT_METHOD SHA512 " "
    if ok_method; then state GOOD "조치 완료: ENCRYPT_METHOD SHA512 (이미 있는 계정은 비밀번호를 다시 설정해야 새 방식 적용)"
    else state ERROR "조치 후에도 ENCRYPT_METHOD=$(method)"; exit 1; fi ;;
  *) echo "usage: U-13.sh check|apply|list" >&2; exit 2 ;;
esac
