#!/usr/bin/env python3
"""설정 값 묶음 스크립트 생성기 (2/2): U-27, 35, 40, 46, 48, 51, 55, 57, 65, 66.
공통 함수는 config_lib.sh, 틀은 gen_config_scripts.py 와 같다.  사용: python3 tools/gen_config_scripts2.py [출력 폴더]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_config_scripts as base  # noqa: E402

S = {}

S["U-27"] = ("$HOME/.rhosts, hosts.equiv 사용 금지", "hosts.equiv/.rhosts 소유자가 root 또는 해당 계정, 권한 600 이하, '+' 설정 없음 (r 계열 서비스 설치 시)", True, r'''
# r 계열 패키지가 없어도(Rocky 9 에는 rsh 패키지가 없다) 파일 자체가 점검·조치 대상이다: 파일이 없으면 해당없음, 있으면 기준 점검

# 줄마다: 경로<TAB>허용 소유자(공백 구분)
collect() {
  [ -f /etc/hosts.equiv ] && [ ! -L /etc/hosts.equiv ] && printf '/etc/hosts.equiv\troot\n'
  login_users | while IFS=$'\t' read -r u h g; do
    [ -f "$h/.rhosts" ] && [ ! -L "$h/.rhosts" ] && printf '%s/.rhosts\troot %s\n' "$h" "$u"
  done
}
mapfile -t rows < <(collect)
[ "${#rows[@]}" -gt 0 ] || { state NA "hosts.equiv/.rhosts 파일이 없습니다"; exit 0; }
bad=(); bad_allowed=(); info=()
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
case "${1:-}" in
  list) for r in "${rows[@]}"; do printf '%s\t%s\n' "${r%%$'\t'*}" "r 계열 인증 파일"; done; state GOOD "${#rows[@]}개 파일" ;;
  check) scan
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${info[@]}"; state VULN "기준 미달 파일 ${#bad[@]}개"; else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi ;;
  apply) scan
    for i in "${!bad[@]}"; do
      f=${bad[$i]}; read -r _ first rest <<<"x ${bad_allowed[$i]}"; own=${rest:-$first}
      owner=$(stat -c '%U' "$f"); case " ${bad_allowed[$i]} " in *" $owner "*) ;; *) safe_fix "$f" "$own" ;; esac
      mode=$(stat -c '%a' "$f"); [ $(( 8#$mode & ~8#600 & 8#7777 )) -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$mode & 8#600 )))"
      sed -i -E 's/^([[:space:]]*\+)/#\1/' "$f"
    done
    scan
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: 소유자·권한(600) 정리, '+' 설정은 주석 처리" ;;
''')

S["U-35"] = ("공유 서비스에 대한 익명 접근 제한 설정", "vsftpd anonymous_enable=NO, proftpd Anonymous 블록 없음, NFS anonuid/anongid 없음, Samba guest ok=no", True, r'''
pkg_gate "FTP/NFS/Samba" "vsftpd proftpd nfs-utils nfs-kernel-server samba" "/etc/vsftpd*" "/etc/proftpd*" "/etc/exports" "/etc/samba/smb.conf"
VSFTPD=""; for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do [ -f "$f" ] && VSFTPD=$f && break; done
PROFTPD=""; for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && PROFTPD=$f && break; done
EXPORTS=/etc/exports; SMB=/etc/samba/smb.conf
[ -n "$VSFTPD$PROFTPD" ] || [ -f "$EXPORTS" ] || [ -f "$SMB" ] || { state NA "점검할 공유 서비스 설정 파일이 없습니다"; exit 0; }

probs=()
scan() {
  probs=(); local v
  if [ -n "$VSFTPD" ]; then v=$(kv_get "$VSFTPD" anonymous_enable); [ "${v^^}" = YES ] && probs+=("$VSFTPD: anonymous_enable=YES"); fi
  if [ -n "$PROFTPD" ] && grep -Eq '^[[:space:]]*<Anonymous' "$PROFTPD"; then probs+=("$PROFTPD: <Anonymous> 블록 활성"); fi
  if [ -f "$EXPORTS" ] && grep -Ev '^[[:space:]]*#' "$EXPORTS" | grep -Eq 'anon(uid|gid)='; then probs+=("$EXPORTS: anonuid/anongid 옵션 사용"); fi
  if [ -f "$SMB" ] && grep -Ev '^[[:space:]]*[#;]' "$SMB" | grep -Eiq '^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*(yes|true|1)'; then probs+=("$SMB: guest ok/public = yes"); fi
}
case "${1:-}" in
  list) for f in "$VSFTPD" "$PROFTPD" "$EXPORTS" "$SMB"; do [ -n "$f" ] && [ -f "$f" ] && printf '%s\t공유 서비스 설정\n' "$f"; done
        svc_list vsftpd.service proftpd.service smb.service smbd.service; state GOOD "목록" ;;
  check) scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "익명 접근이 허용된 설정 ${#probs[@]}건"; else state GOOD "익명 접근이 제한되어 있음"; fi ;;
  apply)
    [ -n "$VSFTPD" ] && kv_set "$VSFTPD" anonymous_enable NO "="
    [ -n "$PROFTPD" ] && sed -i -E '/^[[:space:]]*<Anonymous/,/^[[:space:]]*<\/Anonymous>/ s/^([^#].*)$/#\1/' "$PROFTPD"
    [ -f "$EXPORTS" ] && sed -i -E '/^[[:space:]]*#/! { s/,?anon(uid|gid)=[0-9]+//g; s/\(,/(/g; s/,\)/)/g; s/,,/,/g }' "$EXPORTS"
    [ -f "$SMB" ] && sed -i -E 's/^([[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*)(yes|true|1)/\1no/I' "$SMB"
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 남음"; exit 1; fi
    # 설정 검사 후 반영: FTP 는 재시작, Samba 는 reload, NFS 는 exportfs -ra
    [ -n "$PROFTPD" ] && have proftpd && ! proftpd -t >/dev/null 2>&1 && { state ERROR "proftpd 설정 검사 실패(엔진이 원복합니다)"; exit 1; }
    have testparm && [ -f "$SMB" ] && ! testparm -s >/dev/null 2>&1 && { state ERROR "Samba 설정 검사 실패(엔진이 원복합니다)"; exit 1; }
    svc_act restart vsftpd.service proftpd.service && svc_act reload smb.service smbd.service || { state ERROR "서비스 재적용 실패($failed_svc) — 원복하면 이전 상태로 되돌립니다"; exit 1; }
    [ -f "$EXPORTS" ] && have exportfs && exportfs -ra >/dev/null 2>&1 && acted+=("exportfs -ra")
    state GOOD "조치 완료: 익명 접근 설정 해제${acted[*]:+ (재적용: ${acted[*]})}" ;;
''')

S["U-40"] = ("NFS 접근 통제", "/etc/exports 소유자 root, 권한 644 이하, 공유 대상 호스트를 제한(* 불가)", True, r'''
EXPORTS=/etc/exports
[ -f "$EXPORTS" ] || { state NA "/etc/exports 가 없습니다"; exit 0; }
[ -L "$EXPORTS" ] && { state MANUAL "/etc/exports 가 심볼릭 링크입니다(수동 확인)"; exit 0; }
perm_bad() { read -r o m < <(stat -c '%U %a' "$EXPORTS"); [ "$o" != root ] || [ $(( 8#$m & ~8#644 & 8#7777 )) -ne 0 ]; }
# 호스트가 없거나 * 인 공유 항목 수
open_entries() { grep -Ev '^[[:space:]]*(#|$)' "$EXPORTS" | awk '{ n=0; for (i=2;i<=NF;i++) { h=$i; sub(/\(.*/, "", h); if (h == "" || h == "*") n++ } if (NF < 2 || n > 0) c++ } END{print c+0}'; }
case "${1:-}" in
  list) printf '%s\tNFS 공유 설정\n' "$EXPORTS"; state GOOD "1개 파일" ;;
  check)
    read -r o m < <(stat -c '%U %a' "$EXPORTS"); n=$(open_entries)
    if perm_bad; then echo "exports 소유자=$o 권한=$m, 접근 제한이 없는 공유 항목 ${n}건"; state VULN "/etc/exports 소유자/권한 기준 미달(소유자=$o 권한=$m)"
    elif [ "$n" -gt 0 ]; then state MANUAL "접근 제한이 없는(*) 공유 항목 ${n}건: 허용할 호스트를 수동으로 지정하세요"
    else state GOOD "소유자 root, 권한 $m, 공유 항목이 호스트로 제한됨"; fi ;;
  apply)
    safe_fix "$EXPORTS" root
    m=$(stat -c '%a' "$EXPORTS"); [ $(( 8#$m & ~8#644 & 8#7777 )) -ne 0 ] && safe_fix "$EXPORTS" "" "$(printf '%o' $(( 8#$m & 8#644 )))"
    if perm_bad; then state ERROR "조치 후에도 /etc/exports 소유자/권한 미충족"; exit 1; fi
    n=$(open_entries)
    state GOOD "조치 완료: 소유자·권한 정리. 접근 제한이 없는 공유 항목 ${n}건은 수동 지정 필요" ;;
''')

S["U-46"] = ("일반 사용자의 메일 서비스 실행 방지", "sendmail PrivacyOptions 에 restrictqrun, postfix postsuper / exim exiqgrep 의 other 실행 권한 제거", True, r'''
pkg_gate "메일 서비스" "sendmail postfix exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
# 설치된 패키지별로만 점검·조치한다(미설치 패키지는 건너뜀)
SMCF=""; pkg_has sendmail && [ -f /etc/mail/sendmail.cf ] && SMCF=/etc/mail/sendmail.cf
tools=()
pkg_has postfix && [ -f /usr/sbin/postsuper ] && tools+=("$(readlink -f /usr/sbin/postsuper)")
pkg_has exim exim4 && [ -f /usr/sbin/exiqgrep ] && tools+=("$(readlink -f /usr/sbin/exiqgrep)")
[ -n "$SMCF" ] || [ "${#tools[@]}" -gt 0 ] || { state NA "설치된 메일 패키지에 점검할 설정/도구가 없습니다"; exit 0; }
probs=()
scan() {
  probs=()
  [ -f "$SMCF" ] && ! grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF" | grep -q 'restrictqrun' && probs+=("$SMCF: PrivacyOptions 에 restrictqrun 없음")
  for f in "${tools[@]}"; do [ $(( 8#$(stat -c '%a' "$f") & 8#001 )) -ne 0 ] && probs+=("$f: 일반 사용자 실행 권한 있음"); done
}
case "${1:-}" in
  list) [ -f "$SMCF" ] && printf '%s\tsendmail 설정\n' "$SMCF"; for f in "${tools[@]}"; do printf '%s\t메일 큐 관리 도구\n' "$f"; done; state GOOD "목록" ;;
  check) scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "일반 사용자의 메일 큐 실행 방지가 미설정 ${#probs[@]}건"; else state GOOD "일반 사용자의 메일 큐 실행이 제한됨"; fi ;;
  apply)
    sm_changed=0
    if [ -f "$SMCF" ] && ! grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF" | grep -q restrictqrun; then
      sed -i -E '/^O[[:space:]]+PrivacyOptions/ s/$/,restrictqrun/' "$SMCF"; sm_changed=1
    fi
    for f in "${tools[@]}"; do safe_fix "$f" "" o-x; done
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 남음"; exit 1; fi
    state GOOD "조치 완료: restrictqrun / other 실행 권한 제거$([ "$sm_changed" -eq 1 ] && echo ' [수동 재시작 필요: sendmail — 업무 영향 확인 후 systemctl restart sendmail]')" ;;
''')

S["U-48"] = ("expn, vrfy 명령어 제한", "sendmail noexpn,novrfy(또는 goaway), postfix disable_vrfy_command=yes (exim 은 수동 확인)", True, r'''
pkg_gate "메일 서비스" "sendmail postfix exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
SMCF=/etc/mail/sendmail.cf; PFCF=/etc/postfix/main.cf
# 설치된 패키지별로만 점검·조치한다(미설치 패키지는 건너뜀)
use_sm=0; pkg_has sendmail && [ -f "$SMCF" ] && use_sm=1
use_pf=0; pkg_has postfix && have postconf && [ -f "$PFCF" ] && use_pf=1
exim=0; pkg_has exim exim4 && exim=1
[ "$use_sm" -eq 1 ] || [ "$use_pf" -eq 1 ] || [ "$exim" -eq 1 ] || { state NA "점검할 메일 설정 파일이 없습니다"; exit 0; }
probs=()
scan() {
  probs=(); local po
  if [ "$use_sm" -eq 1 ]; then po=$(grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF")
    echo "$po" | grep -q goaway || { echo "$po" | grep -q noexpn && echo "$po" | grep -q novrfy; } || probs+=("$SMCF: noexpn/novrfy(goaway) 미설정"); fi
  if [ "$use_pf" -eq 1 ]; then [ "$(postconf -h disable_vrfy_command 2>/dev/null)" = yes ] || probs+=("$PFCF: disable_vrfy_command 가 yes 가 아님"); fi
}
case "${1:-}" in
  list) [ "$use_sm" -eq 1 ] && printf '%s\tsendmail 설정\n' "$SMCF"; [ "$use_pf" -eq 1 ] && printf '%s\tpostfix 설정\n' "$PFCF"; state GOOD "목록" ;;
  check) scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state VULN "expn/vrfy 제한 미설정 ${#probs[@]}건"
    elif [ "$exim" -eq 1 ] && [ "$use_sm" -eq 0 ] && [ "$use_pf" -eq 0 ]; then state MANUAL "exim 은 acl_smtp_vrfy/acl_smtp_expn 설정을 수동 확인해야 합니다"
    else state GOOD "expn/vrfy 가 제한되어 있음"; fi ;;
  apply)
    sm_changed=0
    if [ "$use_sm" -eq 1 ]; then
      po=$(grep -E '^O[[:space:]]+PrivacyOptions' "$SMCF")
      echo "$po" | grep -q goaway || { echo "$po" | grep -q noexpn || { sed -i -E '/^O[[:space:]]+PrivacyOptions/ s/$/,noexpn/' "$SMCF"; sm_changed=1; }
                                       echo "$po" | grep -q novrfy || { sed -i -E '/^O[[:space:]]+PrivacyOptions/ s/$/,novrfy/' "$SMCF"; sm_changed=1; }; }
    fi
    if [ "$use_pf" -eq 1 ]; then postconf -e disable_vrfy_command=yes && postfix reload >/dev/null 2>&1; fi
    scan
    if [ "${#probs[@]}" -gt 0 ]; then printf '%s\n' "${probs[@]}"; state ERROR "조치 후에도 ${#probs[@]}건 남음"; exit 1; fi
    state GOOD "조치 완료: expn/vrfy 제한$([ "$sm_changed" -eq 1 ] && echo ' [수동 재시작 필요: sendmail — 업무 영향 확인 후 systemctl restart sendmail]')" ;;
''')

S["U-51"] = ("DNS 서비스의 취약한 동적 업데이트 설정 금지", "BIND allow-update 가 any 가 아님(필요 없으면 none)", True, r'''
pkg_gate "BIND(named)" "bind bind9" "/etc/named.conf" "/etc/bind" "/etc/named"
CONFS=(); for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local /etc/named/*.conf; do [ -f "$f" ] && [ ! -L "$f" ] && CONFS+=("$f"); done
[ "${#CONFS[@]}" -gt 0 ] || { state NA "named 설정 파일이 없습니다"; exit 0; }
open_files() { for f in "${CONFS[@]}"; do tr '\n' ' ' < "$f" | grep -Eq 'allow-update[[:space:]]*\{[^}]*\bany\b[^}]*\}' && echo "$f"; done; }
case "${1:-}" in
  list) for f in "${CONFS[@]}"; do printf '%s\tBIND 설정\n' "$f"; done; svc_list named.service named-chroot.service bind9.service; state GOOD "${#CONFS[@]}개 파일" ;;
  check) mapfile -t o < <(open_files)
    if [ "${#o[@]}" -gt 0 ]; then printf 'allow-update any: %s\n' "${o[@]}"; state VULN "동적 업데이트가 any 로 허용된 설정 파일 ${#o[@]}개"; else state GOOD "allow-update 가 any 로 열려 있지 않음"; fi ;;
  apply)
    mapfile -t o < <(open_files)
    for f in "${o[@]}"; do sed -z -i -E 's/(allow-update[[:space:]]*\{)[^}]*\bany\b[^}]*(\})/\1 none; \2/g' "$f"; done
    have named-checkconf && ! named-checkconf >/dev/null 2>&1 && { state ERROR "변경 후 named-checkconf 검사 실패(엔진이 원복합니다)"; exit 1; }
    mapfile -t o < <(open_files)
    [ "${#o[@]}" -eq 0 ] || { state ERROR "조치 후에도 any 설정이 남음"; exit 1; }
    svc_act reload named.service named-chroot.service bind9.service || { state ERROR "named reload 실패($failed_svc) — 원복하면 이전 상태로 되돌립니다"; exit 1; }
    state GOOD "조치 완료: allow-update { none; }${acted[*]:+ (재적용: ${acted[*]})}" ;;
''')

S["U-55"] = ("FTP 계정 Shell 제한", "ftp(anonymous) 계정의 로그인 쉘이 /sbin/nologin 또는 /bin/false", True, r'''
pkg_gate "FTP 서버" "vsftpd proftpd pure-ftpd ftpd" "/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd" "/etc/ftpusers"
accts() { awk -F: '$1 == "ftp" || $1 == "anonymous" {print $1 ":" $7}' /etc/passwd; }
bad() { accts | awk -F: '$2 !~ /(nologin|false)$/ {print $1 ":" $2}'; }
[ -n "$(accts)" ] || { state NA "ftp 계정이 없습니다"; exit 0; }
case "${1:-}" in
  list) printf '/etc/passwd\tFTP 계정 쉘 정보\n'; state GOOD "목록" ;;
  check) mapfile -t b < <(bad)
    if [ "${#b[@]}" -gt 0 ]; then printf '계정:쉘 = %s\n' "${b[@]}"; state VULN "FTP 계정 쉘이 제한되지 않음(${b[*]})"; else state GOOD "FTP 계정 쉘이 제한됨"; fi ;;
  apply)
    nologin=/sbin/nologin; [ -x "$nologin" ] || nologin=/usr/sbin/nologin; [ -x "$nologin" ] || nologin=/bin/false
    while IFS=: read -r u s; do [ -n "$u" ] && usermod -s "$nologin" "$u"; done < <(bad)
    mapfile -t b < <(bad)
    if [ "${#b[@]}" -eq 0 ]; then state GOOD "조치 완료: FTP 계정 쉘을 $nologin 로 변경"; else state ERROR "조치 후에도 ${#b[@]}개 계정이 제한되지 않음"; exit 1; fi ;;
''')

S["U-57"] = ("Ftpusers 파일 설정", "FTP 에서 root 직접 접속 차단(ftpusers/user_list 에 root, proftpd RootLogin off)", True, r'''
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
''')

S["U-65"] = ("NTP 및 시각 동기화 설정", "NTP 서비스(chronyd/ntpd/systemd-timesyncd)가 켜져 있고 서버가 설정됨", True, r'''
have systemctl || { state MANUAL "systemctl 이 없어 NTP 서비스 상태를 확인할 수 없습니다"; exit 0; }
CANDS=(chronyd.service chrony.service ntpd.service ntp.service ntpsec.service systemd-timesyncd.service)
installed=(); for u in "${CANDS[@]}"; do [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] && installed+=("$u"); done
on_units() { for u in "${installed[@]}"; do [ "$(systemctl is-active "$u" 2>/dev/null)" = active ] && echo "$u"; done; }
# 동기화 서버 수. chrony 는 Ubuntu 25+ 에서 서버를 sources.d/*.sources 로 옮겼고(NTS), DHCP 가 알려 준 서버는 /run/chrony-dhcp 에 둔다
servers() { grep -Ehs '^[[:space:]]*(server|pool|peer)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources /run/chrony-dhcp/*.sources /etc/ntp.conf /etc/ntpsec/ntp.conf /etc/ntpsec/ntp.d/*.conf 2>/dev/null | wc -l; }
# systemd-timesyncd 는 서버를 안 적어도 내장 기본 서버(FallbackNTP)를 쓰므로 정상이다. 따로 지정했으면 그 수를 알려 준다
ts_servers() { cat /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null | grep -E '^[[:space:]]*NTP[[:space:]]*=[[:space:]]*[^[:space:]]' | wc -l; }
srv_note() { if [ "$1" = systemd-timesyncd.service ]; then local t; t=$(ts_servers); [ "$t" -gt 0 ] && echo "NTP= 지정 ${t}건" || echo "내장 기본 서버(FallbackNTP) 사용"; else echo "서버 설정 $(servers)건"; fi; }
srv_ok() { [ "$1" = systemd-timesyncd.service ] || [ "$(servers)" -gt 0 ]; }
case "${1:-}" in
  list) for u in "${installed[@]}"; do printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"; done
        state GOOD "NTP 유닛 ${#installed[@]}개" ;;
  check)
    [ "${#installed[@]}" -gt 0 ] || { state MANUAL "NTP 서비스(chrony/ntp)가 설치되어 있지 않습니다. 패키지를 설치한 뒤 설정하세요(도구는 설치하지 않음)"; exit 0; }
    mapfile -t on < <(on_units)
    if [ "${#on[@]}" -eq 0 ]; then state VULN "NTP 서비스가 설치되어 있으나 동작하지 않음(${installed[*]})"
    elif ! srv_ok "${on[0]}"; then state VULN "${on[0]} 동작 중이나 동기화 서버(server/pool) 설정이 없음"
    else state GOOD "${on[0]} 동작 중($(srv_note "${on[0]}"))"; fi ;;
  apply)
    [ "${#installed[@]}" -gt 0 ] || { state ERROR "NTP 서비스가 설치되어 있지 않음"; exit 1; }
    for u in "${installed[@]}"; do systemctl enable --now "$u" >/dev/null 2>&1 && break; done
    sleep 1; mapfile -t on < <(on_units)
    if [ "${#on[@]}" -gt 0 ] && srv_ok "${on[0]}"; then state GOOD "조치 완료: ${on[0]} 활성화($(srv_note "${on[0]}"))"
    else state ERROR "서비스를 켰으나 서버 설정이 없어 기준 미충족(수동으로 server/pool 추가 필요)"; exit 1; fi ;;
''')

S["U-66"] = ("정책에 따른 시스템 로깅 설정", "rsyslog 정책: *.info→messages, authpriv→secure, mail→maillog, cron→cron, *.emerg→전체 사용자", True, r'''
RS=/etc/rsyslog.conf; RSD=/etc/rsyslog.d; NEWF=/etc/rsyslog.d/90-isms-logging.conf
have rsyslogd || [ -f "$RS" ] || { state MANUAL "rsyslog 가 설치되어 있지 않습니다(journald 만 사용). 로깅 정책은 수동으로 확인하세요"; exit 0; }
files=(); [ -f "$RS" ] && files+=("$RS"); for f in "$RSD"/*.conf; do [ -f "$f" ] && files+=("$f"); done
rules() { cat "${files[@]}" 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)'; }
miss=()
scan() {
  miss=(); local r; r=$(rules)
  echo "$r" | grep -Eq '\*\.info.*[[:space:]]-?/var/log/messages' || miss+=("*.info;mail.none;authpriv.none;cron.none  /var/log/messages")
  echo "$r" | grep -Eq 'authpriv\.\*.*[[:space:]]-?/var/log/secure' || miss+=("authpriv.*  /var/log/secure")
  echo "$r" | grep -Eq 'mail\.\*.*[[:space:]]-?/var/log/maillog' || miss+=("mail.*  -/var/log/maillog")
  echo "$r" | grep -Eq 'cron\.\*.*[[:space:]]-?/var/log/cron' || miss+=("cron.*  /var/log/cron")
  echo "$r" | grep -Eq '\*\.emerg[[:space:]]+(:omusrmsg:)?\*' || miss+=("*.emerg  :omusrmsg:*")
}
case "${1:-}" in
  list) for f in "${files[@]}"; do printf '%s\trsyslog 설정\n' "$f"; done; [ -f "$NEWF" ] || printf '%s\t추가될 로깅 규칙 파일(조치 시 생성)\n' "$NEWF"
        have systemctl && printf '@service\trsyslog.service\tenabled=%s\tactive=%s\n' "$(systemctl is-enabled rsyslog.service 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active rsyslog.service 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
        state GOOD "${#files[@]}개 파일" ;;
  check) scan
    act=1; have systemctl && [ "$(systemctl is-active rsyslog.service 2>/dev/null)" != active ] && act=0
    if [ "$act" -eq 0 ]; then state VULN "rsyslog 서비스가 동작하지 않음"
    elif [ "${#miss[@]}" -gt 0 ]; then printf '누락 규칙: %s\n' "${miss[@]}"; state VULN "필수 로깅 규칙 ${#miss[@]}개가 설정되어 있지 않음"
    else state GOOD "로깅 정책 규칙이 모두 설정되어 있음"; fi ;;
  apply)
    scan
    if [ "${#miss[@]}" -gt 0 ]; then
      { echo "# ISMS 도구가 추가한 로깅 규칙 (주통2026 U-66)"; printf '%s\n' "${miss[@]}"; } > "$NEWF"; chmod 644 "$NEWF"
      have rsyslogd && ! rsyslogd -N1 >/dev/null 2>&1 && { rm -f "$NEWF"; state ERROR "rsyslog 문법 검사 실패(추가한 규칙을 제거함)"; exit 1; }
    fi
    have systemctl && systemctl enable --now rsyslog.service >/dev/null 2>&1 && systemctl restart rsyslog.service >/dev/null 2>&1
    files=(); [ -f "$RS" ] && files+=("$RS"); for f in "$RSD"/*.conf; do [ -f "$f" ] && files+=("$f"); done
    scan
    if [ "${#miss[@]}" -eq 0 ]; then state GOOD "조치 완료: 로깅 규칙 추가(${NEWF}) 및 rsyslog 재시작"; else state ERROR "조치 후에도 규칙 ${#miss[@]}개 누락"; exit 1; fi ;;
''')


def main(out, ids=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for iid in (ids or S):
        (out / f"{iid}.sh").write_text(base.build(iid, S), encoding="utf-8")
        print("생성:", out / f"{iid}.sh")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "code" / "scripts" / "items")
