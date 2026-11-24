#!/usr/bin/env python3
"""설정 값 묶음 스크립트 생성기 (1/2): U-01, 02, 03, 04, 06, 13, 30, 32.

공통 함수(config_lib.sh)를 각 스크립트 앞에 붙여 단독으로 동작하는 파일을 만든다.
고칠 때는 이 파일과 config_lib.sh 를 고치고 다시 만든다.  사용: python3 tools/gen_config_scripts.py [출력 폴더]
나머지 설정 항목(U-27, 35, 40, 46, 48, 51, 55, 57, 65, 66)은 gen_config_scripts2.py 에 있다.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB = (HERE / "config_lib.sh").read_text(encoding="utf-8")

# id: (제목, 기준, 모드 목록(apply 포함 여부), 본문)
S = {}

S["U-01"] = ("root 계정 원격 접속 제한", "SSH 의 PermitRootLogin 이 no (유효 설정 기준, sshd_config 와 sshd_config.d 모두 확인)", True, r'''
CF=/etc/ssh/sshd_config
DROP=/etc/ssh/sshd_config.d

have sshd || [ -f "$CF" ] || { state NA "SSH 서버(sshd)가 설치되어 있지 않아 점검 대상이 아닙니다"; exit 0; }

cfiles=()
[ -f "$CF" ] && [ ! -L "$CF" ] && cfiles+=("$CF")
for f in "$DROP"/*.conf; do [ -f "$f" ] && [ ! -L "$f" ] && cfiles+=("$f"); done

# root 접속을 막아도 들어올 수 있는 관리자 계정이 있는지: wheel/sudo 그룹 + 로그인 쉘 + (암호 해시 또는 authorized_keys)
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

case "${1:-}" in
  list) for f in "${cfiles[@]}"; do printf '%s\tsshd 설정 파일\n' "$f"; done; state GOOD "${#cfiles[@]}개 파일" ;;
  check)
    eff=$(effective)
    if [ "$eff" = no ]; then state GOOD "PermitRootLogin = no"
    else state VULN "PermitRootLogin = $eff (기준: no)"; fi ;;
  apply)
    eff=$(effective)
    [ "$eff" = no ] && { state GOOD "이미 PermitRootLogin = no"; exit 0; }
    has_admin || { state ERROR "root 대신 쓸 관리자(wheel/sudo 그룹, 로그인 쉘, 암호 또는 SSH 키가 있는 계정)가 없어 변경하지 않습니다(로그인 잠김 방지). 예: useradd -m -G wheel <계정>; passwd <계정> 후 그 계정으로 로그인되는지 확인"; exit 1; }
    have sshd && ! sshd -t 2>/dev/null && { state ERROR "현재 sshd 설정에 문법 오류가 있어 변경하지 않습니다"; exit 1; }
    set_in=0
    for f in "${cfiles[@]}"; do   # 값이 있는 파일은 no 로 바꾼다
      if grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]' "$f"; then
        sed -i -E 's~^([[:space:]]*)PermitRootLogin[[:space:]].*~\1PermitRootLogin no~I' "$f"; set_in=1
      fi
    done
    if [ "$set_in" -eq 0 ] && [ -f "$CF" ]; then   # 어디에도 없으면 첫 Match 블록 앞(없으면 끝)에 추가
      tmp=$(mktemp) && awk '/^[[:space:]]*Match[[:space:]]/ && !d {print "PermitRootLogin no"; d=1} {print} END{if(!d) print "PermitRootLogin no"}' "$CF" > "$tmp" && cat "$tmp" > "$CF"; rm -f "$tmp"
    fi
    if have sshd && ! sshd -t 2>/dev/null; then state ERROR "변경 후 sshd 문법 검사 실패(엔진이 원복합니다)"; exit 1; fi
    if have systemctl; then for s in sshd ssh; do systemctl is-active "$s" >/dev/null 2>&1 && systemctl reload "$s" >/dev/null 2>&1; done; fi
    eff=$(effective)
    if [ "$eff" = no ]; then state GOOD "조치 완료: PermitRootLogin = no (기존 SSH 연결은 유지, 새 연결부터 적용)"
    else state ERROR "조치 후에도 PermitRootLogin = $eff"; exit 1; fi ;;
''')

S["U-02"] = ("비밀번호 관리 정책", "pwquality(최소 8자, 숫자·대소문자·특수문자 각 1자 이상, root 포함), PASS_MAX_DAYS<=90, PASS_MIN_DAYS>=1, 기억 4회 이상", True, r'''
PWQ=/etc/security/pwquality.conf
PWQD=/etc/security/pwquality.conf.d
LOGINDEFS=/etc/login.defs
PWH=/etc/security/pwhistory.conf

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
  v=$(num "$(pwq_get minlen)"); { [ -n "$v" ] && [ "$v" -ge 8 ]; } || probs+=("minlen<8(현재 ${v:-미설정})")
  for k in dcredit ucredit lcredit ocredit; do v=$(num "$(pwq_get $k)"); { [ -n "$v" ] && [ "$v" -le -1 ]; } || probs+=("$k 가 -1 이하가 아님(현재 ${v:-미설정})"); done
  pwq_enforce_root || probs+=("enforce_for_root 미설정")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MAX_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 90 ]; } || probs+=("PASS_MAX_DAYS>90(현재 ${v:-미설정})")
  v=$(num "$(kv_get "$LOGINDEFS" PASS_MIN_DAYS)"); { [ -n "$v" ] && [ "$v" -ge 1 ]; } || probs+=("PASS_MIN_DAYS<1(현재 ${v:-미설정})")
  v=$(num "$(hist_get)"); { [ -n "$v" ] && [ "$v" -ge 4 ]; } || probs+=("비밀번호 기억(remember) 4회 미만(현재 ${v:-미설정})")
}

case "${1:-}" in
  list) for f in "${pwq_files[@]}" "$LOGINDEFS" "$PWH"; do [ -f "$f" ] && printf '%s\t비밀번호 정책 설정\n' "$f"; done; [ -f "$PWQ" ] || printf '%s\t비밀번호 정책 설정(없음, 생성될 수 있음)\n' "$PWQ"; [ -f "$PWH" ] || printf '%s\t비밀번호 기억 설정(없음, 생성될 수 있음)\n' "$PWH"; state GOOD "목록" ;;
  check)
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "비밀번호 정책 미충족 ${#probs[@]}건: ${probs[0]} 등"
    else state GOOD "비밀번호 정책이 기준을 충족"; fi ;;
  apply)
    [ -f "$PWQ" ] || { : > "$PWQ"; chmod 644 "$PWQ"; }
    kv_set "$PWQ" minlen 8 " = "
    for k in dcredit ucredit lcredit ocredit; do kv_set "$PWQ" $k -1 " = "; done
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWQ" || { nl_end "$PWQ"; echo enforce_for_root >> "$PWQ"; }
    kv_set "$LOGINDEFS" PASS_MAX_DAYS 90 " "
    kv_set "$LOGINDEFS" PASS_MIN_DAYS 1 " "
    [ -f "$PWH" ] || { : > "$PWH"; chmod 644 "$PWH"; }
    kv_set "$PWH" remember 4 " = "
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWH" || { nl_end "$PWH"; echo enforce_for_root >> "$PWH"; }
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 미충족: ${probs[0]}"; exit 1; fi
    state GOOD "조치 완료: 비밀번호 정책 적용 (기존 계정의 만료 기간은 chage 로 따로 적용, pam_pwhistory 가 PAM 에 있어야 기억 설정이 동작)" ;;
''')

S["U-03"] = ("계정 잠금 임계값 설정", "계정 잠금 임계값(deny)이 1~10회 (faillock 또는 pam_tally2)", True, r'''
FC=/etc/security/faillock.conf
PAMS=(/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth)

pam_has() { grep -Eqs '^[[:space:]]*auth[[:space:]].*(pam_faillock|pam_tally2?)\.so' "${PAMS[@]}" 2>/dev/null; }
deny_value() {
  local v; v=$(kv_get "$FC" deny)
  [ -z "$v" ] && v=$(grep -hEs 'pam_(faillock|tally2?)\.so' "${PAMS[@]}" 2>/dev/null | grep -v '^[[:space:]]*#' | grep -Eo 'deny=[0-9]+' | head -1 | cut -d= -f2)
  printf '%s' "$v"
}
good() { local v; v=$(deny_value); pam_has && [[ $v =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 10 ]; }

case "${1:-}" in
  list)
    for f in "$FC" "${PAMS[@]}"; do [ -e "$f" ] && printf '%s\t계정 잠금 설정\n' "$(readlink -f "$f")"; done
    if have authselect; then for f in /etc/authselect/*; do [ -f "$f" ] && printf '%s\tauthselect 설정\n' "$f"; done; fi
    state GOOD "목록" ;;
  check)
    d=$(deny_value)
    if good; then state GOOD "계정 잠금 임계값 deny=$d"
    elif ! pam_has; then state VULN "PAM 에 pam_faillock/pam_tally 설정이 없음(계정 잠금 미적용)"
    else state VULN "계정 잠금 임계값이 1~10 범위가 아님(deny=${d:-미설정})"; fi ;;
  apply)
    if ! pam_has; then
      if have authselect; then
        authselect enable-feature with-faillock >/dev/null 2>&1 && authselect apply-changes >/dev/null 2>&1 \
          || { state ERROR "authselect 로 faillock 적용에 실패(수동 설정 필요)"; exit 1; }
        authselect check >/dev/null 2>&1 || { state ERROR "authselect 적용 후 검증(authselect check) 실패: 로그인이 막힐 수 있어 원복합니다"; exit 1; }
      else state ERROR "authselect 가 없어 PAM 을 자동 수정할 수 없음(가이드 참고)"; exit 1; fi
    fi
    [ -f "$FC" ] || { : > "$FC"; chmod 644 "$FC"; }
    kv_set "$FC" deny 10 " = "
    kv_set "$FC" unlock_time 120 " = "
    if good; then state GOOD "조치 완료: 계정 잠금 deny=10, unlock_time=120 (로그인이 막히지 않는지 별도 세션에서 확인)"
    else state ERROR "조치 후에도 기준 미충족(deny=$(deny_value))"; exit 1; fi ;;
''')

S["U-04"] = ("비밀번호 파일 보호", "쉐도우 비밀번호 사용 (/etc/passwd 의 암호 필드가 x, /etc/shadow 존재)", True, r'''
[ -f /etc/passwd ] || { state NA "/etc/passwd 가 없습니다"; exit 0; }
bad_accounts() { awk -F: '$2 != "x" {print $1}' /etc/passwd; }
case "${1:-}" in
  list) printf '/etc/passwd\t계정 파일\n/etc/shadow\t비밀번호 파일\n'; state GOOD "목록" ;;
  check)
    mapfile -t b < <(bad_accounts)
    if [ ! -f /etc/shadow ]; then state VULN "/etc/shadow 가 없음(쉐도우 비밀번호 미사용)"
    elif [ "${#b[@]}" -gt 0 ]; then printf '계정: %s\n' "${b[@]}"; state VULN "passwd 에 암호 필드가 x 가 아닌 계정 ${#b[@]}개"
    else state GOOD "모든 계정이 쉐도우 비밀번호 사용"; fi ;;
  apply)
    have pwconv || { state ERROR "pwconv 명령이 없습니다"; exit 1; }
    pwconv >/dev/null 2>&1
    mapfile -t b < <(bad_accounts)
    if [ -f /etc/shadow ] && [ "${#b[@]}" -eq 0 ]; then state GOOD "조치 완료: pwconv 로 쉐도우 비밀번호 적용"
    else state ERROR "조치 후에도 쉐도우 비밀번호 미적용 계정 ${#b[@]}개"; exit 1; fi ;;
''')

S["U-06"] = ("사용자 계정 su 기능 제한", "su 를 특정 그룹(wheel)만 쓰도록 제한 (pam_wheel 또는 /usr/bin/su 그룹·권한). 일반 사용자가 없으면 불필요", True, r'''
PAMSU=/etc/pam.d/su
SU=/usr/bin/su
[ -f "$PAMSU" ] || [ -e "$SU" ] || { state NA "su 설정이 없습니다"; exit 0; }

grp=""; for g in wheel sudo; do getent group "$g" >/dev/null 2>&1 && { grp=$g; break; }; done
users() { awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ && $1 != "nobody" {print $1}' /etc/passwd; }
pam_on() { grep -Eqs '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAMSU"; }
bin_on() { [ -e "$SU" ] || return 1; read -r g m < <(stat -c '%G %a' "$SU"); [ "$g" != root ] && [ $(( 8#$m & 8#0007 )) -eq 0 ]; }

case "${1:-}" in
  list) [ -f "$PAMSU" ] && printf '%s\tPAM su 설정\n' "$PAMSU"; [ -e "$SU" ] && printf '%s\tsu 실행 파일(소유 그룹/권한)\n' "$(readlink -f "$SU")"; state GOOD "목록" ;;
  check)
    mapfile -t u < <(users)
    if [ "${#u[@]}" -eq 0 ]; then state GOOD "일반 사용자 계정이 없어 su 제한이 필요하지 않음(root 만 사용)"
    elif pam_on; then state GOOD "pam_wheel 로 su 사용 그룹이 제한됨"
    elif bin_on; then state GOOD "su 실행 권한이 특정 그룹으로 제한됨"
    else state VULN "su 명령을 모든 사용자가 사용할 수 있음 (일반 사용자 ${#u[@]}명)"; fi ;;
  apply)
    [ -n "$grp" ] || { state ERROR "wheel/sudo 그룹이 없어 자동 설정할 수 없음(그룹을 만든 뒤 가이드대로 설정)"; exit 1; }
    [ -f "$PAMSU" ] || { state ERROR "$PAMSU 가 없어 PAM 방식으로 설정할 수 없음"; exit 1; }
    if grep -Eq '^[[:space:]]*#[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAMSU"; then
      sed -i -E "0,/^[[:space:]]*#[[:space:]]*(auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so.*)/s//\1/" "$PAMSU"
    else
      line="auth            required        pam_wheel.so use_uid"; [ "$grp" != wheel ] && line="auth            required        pam_wheel.so use_uid group=$grp"
      if grep -Eq 'pam_rootok\.so' "$PAMSU"; then sed -i -E "0,/pam_rootok\.so/s//&\n$line/" "$PAMSU"; else nl_end "$PAMSU"; echo "$line" >> "$PAMSU"; fi
    fi
    if pam_on; then state GOOD "조치 완료: su 를 $grp 그룹으로 제한 (wheel 그룹 구성원은 재로그인 후 su 가능)"
    else state ERROR "조치 후에도 su 제한이 적용되지 않음"; exit 1; fi ;;
''')

S["U-13"] = ("안전한 비밀번호 암호화 알고리즘 사용", "login.defs ENCRYPT_METHOD 가 SHA256/SHA512/YESCRYPT, 기존 계정이 MD5·DES 해시를 쓰지 않음", True, r'''
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
''')

S["U-30"] = ("UMASK 설정 관리", "UMASK 가 022 이상(그룹·기타 쓰기 금지): login.defs UMASK, /etc/profile·/etc/bashrc 의 umask", True, r'''
LD=/etc/login.defs
UFILES=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/*.sh)
weak_val() { [[ $1 =~ ^[0-7]{3,4}$ ]] || return 1; [ $(( 8#$1 & 8#022 )) -ne $(( 8#022 )) ]; }   # 022 보다 느슨하면 0
probs=()
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
case "${1:-}" in
  list) for f in "$LD" "${UFILES[@]}"; do [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\tumask 설정 파일\n' "$f"; done; state GOOD "목록" ;;
  check)
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "UMASK 가 022 보다 느슨한 설정 ${#probs[@]}건"
    else state GOOD "UMASK 022 이상으로 설정됨"; fi ;;
  apply)
    [ -f "$LD" ] && kv_set "$LD" UMASK 022 " "
    for f in "${UFILES[@]}"; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      while IFS= read -r v; do weak_val "$v" && sed -i -E "s~^([[:space:]]*umask[[:space:]]+)$v([^0-9].*)?$~\1022\2~" "$f"; done < <(grep -E '^[[:space:]]*umask[[:space:]]+[0-7]+' "$f" | sed -E 's/^[[:space:]]*umask[[:space:]]+([0-7]+).*/\1/')
    done
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 UMASK 미충족 ${#probs[@]}건"; exit 1; fi
    state GOOD "조치 완료: UMASK 022 (새 로그인부터 적용)" ;;
''')

S["U-32"] = ("홈 디렉토리로 지정한 디렉토리의 존재 관리", "로그인 가능한 계정의 홈 디렉터리가 모두 존재", True, r'''
missing() { login_users | while IFS=$'\t' read -r u h g; do { [ -z "$h" ] || [ ! -d "$h" ]; } && printf '%s\t%s\t%s\n' "$u" "$h" "$g"; done; }
mapfile -t m < <(missing)
case "${1:-}" in
  list) for r in "${m[@]}"; do IFS=$'\t' read -r u h g <<<"$r"; [ -n "$h" ] && [ "${h#/}" != "$h" ] && printf '%s\t홈 디렉터리 없음(계정 %s, 조치 시 생성)\n' "$h" "$u"; done; state GOOD "${#m[@]}개 계정" ;;
  check)
    if [ "${#m[@]}" -gt 0 ]; then for r in "${m[@]}"; do IFS=$'\t' read -r u h g <<<"$r"; printf '계정 %s: 홈 %s 없음\n' "$u" "${h:-없음}"; done; state VULN "홈 디렉터리가 없는 계정 ${#m[@]}개"
    else state GOOD "모든 로그인 계정의 홈 디렉터리가 존재"; fi ;;
  apply)
    for r in "${m[@]}"; do
      IFS=$'\t' read -r u h g <<<"$r"
      case "$h" in /|""|/dev/null|/nonexistent) continue ;; /*) ;; *) continue ;; esac
      [ -L "$h" ] && continue
      mkdir -p "$h" && safe_fix "$h" "$u:$g" 700
    done
    mapfile -t m < <(missing)
    if [ "${#m[@]}" -eq 0 ]; then state GOOD "조치 완료: 없던 홈 디렉터리를 만들고 소유자 지정(700). 계정을 지우는 조치는 하지 않음"
    else state ERROR "조치 후에도 홈 디렉터리가 없는 계정 ${#m[@]}개"; exit 1; fi ;;
''')


def build(iid, spec=None):
    title, crit, has_apply, body = (spec or S)[iid]
    word = "apply|" if has_apply else ""
    head = (f"#!/bin/bash\n# {iid} {title}\n# 기준: {crit}\n"
            f"# 계약: bash {iid}.sh check|{word}list  →  stdout 마지막 줄 \"STATE|근거\" (docs/SCRIPT_CONTRACT.md)\n"
            f"# 이 파일은 tools/gen_config_scripts*.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.\n")
    tail = f'  *) echo "usage: {iid}.sh check|{word}list" >&2; exit 2 ;;\nesac\n'
    return head + LIB + body.rstrip("\n") + "\n" + tail


def main(out, ids=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for iid in (ids or S):
        (out / f"{iid}.sh").write_text(build(iid), encoding="utf-8")
        print("생성:", out / f"{iid}.sh")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else HERE.parent / "code" / "scripts" / "items")
