#!/bin/bash
# [Ubuntu 22/24 용 — Rocky 는 make_test_vm_vulnerable_rocky.sh] ISMS 도구 시험용: 테스트 VM 을 항목별로 일부러 취약한 상태로 만든다(되돌리기 가능).
#   sudo bash tools/make_test_vm_vulnerable_ubuntu.sh apply --yes-test-vm [--with-admin] [--no-packages]   취약 상태 만들기
#       (기본: 패키지가 필요한 항목은 apt 로 설치해 취약하게 만든다. --no-packages 면 설치 없이 이미 설치된 것만)
#   sudo bash tools/make_test_vm_vulnerable_ubuntu.sh verify                                만든 항목을 도구 스크립트로 점검
#   sudo bash tools/make_test_vm_vulnerable_ubuntu.sh undo                                  원래대로 되돌리기(설치한 패키지는 purge)
# 운영 서버에서는 절대 실행하지 마세요. 변경 내역과 원본 백업은 /root/isms-vuln-seed/ 에 남습니다.
# (참고: apk 는 Alpine 의 패키지 관리자입니다. 우분투는 apt 를 씁니다.)
set -u
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
BK=/root/isms-vuln-seed
MAN=$BK/manifest
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPTS_COMMON=$HERE/../code/scripts/items
SCRIPTS_UBUNTU=$HERE/../code/scripts/ubuntu/items

die() { echo "오류: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "root 로 실행하세요"
. /etc/os-release 2>/dev/null; case "${ID:-}:${ID_LIKE:-}" in ubuntu:*|*debian*) ;; *) die "이 파일은 우분투/데비안 계열용입니다. Rocky 는 tools/make_test_vm_vulnerable_rocky.sh 를 쓰세요";; esac

rec() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$MAN"; }
seen() { grep -q -F "$(printf '%s\t%s\t' "$1" "$2")" "$MAN" 2>/dev/null; }
mark() { printf '%s\n' "$1" >> "$BK/seeded"; echo "  [$1] $2"; }
skip() { echo "  [$1] 건너뜀: $2"; }

bk() { local f=$1; [ -e "$f" ] || return 1; seen F "$f" && return 0
  mkdir -p "$BK/files"; cp -a --parents "$f" "$BK/files/" && rec F "$f"; }
newfile() { local f=$1; [ -e "$f" ] && return 1; rec N "$f"; }
setmode() { local f=$1 m=$2; [ -e "$f" ] || return 1; seen M "$f" || rec M "$f" "$(stat -c %a "$f")"; chmod "$m" "$f"; }
newuser() { local n=$1; shift; id "$n" >/dev/null 2>&1 && return 1; useradd "$@" "$n" && rec U "$n"; }
has_unit() { command -v systemctl >/dev/null && [ -n "$(systemctl list-unit-files "$1" --no-legend 2>/dev/null)" ]; }
svc_off() { local u=$1; has_unit "$u" || return 1
  seen S "$u" || rec S "$u" "$(systemctl is-enabled "$u" 2>/dev/null)|$(systemctl is-active "$u" 2>/dev/null)"; systemctl disable --now "$u" >/dev/null 2>&1; }
svc_on() { local u=$1; has_unit "$u" || return 1
  seen S "$u" || rec S "$u" "$(systemctl is-enabled "$u" 2>/dev/null)|$(systemctl is-active "$u" 2>/dev/null)"
  systemctl enable --now "$u" >/dev/null 2>&1 || systemctl enable "$u" >/dev/null 2>&1; }
installed() { dpkg -s "$1" 2>/dev/null | grep -q '^Status: install ok installed'; }
# 패키지 설치(없을 때만). 우리가 설치한 것만 기록해 undo 때 purge 한다.
pinst() { local p; for p in "$@"; do installed "$p" && continue
  apt-get -y -qq install "$p" >/dev/null 2>&1 && installed "$p" && { rec P "$p"; echo "  패키지 설치: $p"; } || echo "  패키지 설치 실패: $p (저장소/네트워크 확인, apt-get update 필요할 수 있음)"; done; }
xserv() { local n=$1 d=/etc/xinetd.d
  if [ ! -d "$d" ]; then mkdir -p "$d" && rec D "$d"; fi
  newfile "$d/$n" || return 1
  printf 'service %s\n{\n\tdisable = no\n\tsocket_type = stream\n\twait = no\n\tuser = root\n\tserver = /bin/true\n}\n' "$n" > "$d/$n"; chmod 666 "$d/$n"; }

seed() {
  echo "취약 상태 만드는 중..."
  seed_pkgs_base
  # --- 계정 관리 ---
  if [ -d /etc/ssh ] && command -v sshd >/dev/null; then
    d=/etc/ssh/sshd_config.d; mkdir -p "$d"
    if newfile "$d/00-isms-test.conf"; then printf 'PermitRootLogin yes\n' > "$d/00-isms-test.conf"; systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1; mark U-01 "PermitRootLogin yes (sshd_config.d/00-isms-test.conf)"; fi
  else skip U-01 "sshd 없음(openssh-server 미설치)"; fi
  if bk /etc/login.defs; then
    [ -f /etc/security/pwquality.conf ] && bk /etc/security/pwquality.conf && sed -i -E 's/^\s*(minlen|dcredit|ucredit|lcredit|ocredit|minclass|enforce_for_root|remember)\b/#\1/' /etc/security/pwquality.conf
    sed -i -E 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS 99999/; s/^\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS 0/' /etc/login.defs
    mark U-02 "비밀번호 정책 해제(pwquality, PASS_MAX_DAYS)"
  fi
  # 우분투는 기본적으로 PAM 에 pam_faillock 이 없어 U-03 이 이미 취약하다. faillock.conf 가 있으면 deny 를 크게 둔다.
  if [ -f /etc/security/faillock.conf ]; then bk /etc/security/faillock.conf; sed -i -E 's/^\s*#?\s*deny\s*=.*/deny = 50/' /etc/security/faillock.conf; grep -q '^deny = 50' /etc/security/faillock.conf || echo 'deny = 50' >> /etc/security/faillock.conf; mark U-03 "faillock deny = 50 (PAM 에 faillock 이 없으면 원래도 취약)"
  else mark U-03 "PAM 에 pam_faillock 없음(기본 상태)"; fi
  if [ -f /etc/pam.d/su ]; then bk /etc/pam.d/su; sed -i -E 's/^(\s*auth\s+(required|requisite)\s+pam_wheel\.so.*)/#\1/' /etc/pam.d/su; mark U-06 "pam_wheel 주석 처리(su 제한 해제, 기본값도 제한 없음)"; fi
  bk /etc/login.defs && { sed -i -E 's/^\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/' /etc/login.defs; grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo 'ENCRYPT_METHOD MD5' >> /etc/login.defs; mark U-13 "ENCRYPT_METHOD MD5"; }
  newfile /etc/profile.d/zz-isms-test-path.sh && { printf 'export PATH=.:$PATH\n' > /etc/profile.d/zz-isms-test-path.sh; mark U-14 "PATH 맨 앞에 . 추가"; }
  newuser isms_uid0 -o -u 0 -M -s /usr/sbin/nologin && mark U-05 "UID 0 계정 isms_uid0 추가"
  if newuser isms_t1 -m -s /bin/bash; then
    chmod 777 /home/isms_t1; mark U-31 "홈 디렉터리 /home/isms_t1 권한 777"
    newuser isms_t3 -o -u "$(id -u isms_t1)" -M -s /usr/sbin/nologin && mark U-10 "중복 UID 계정 isms_t3 추가"
  fi
  newuser isms_t2 -M -d /home/isms_t2 -s /bin/bash && mark U-32 "홈 디렉터리가 없는 계정 isms_t2 추가"
  if [ "${WITH_ADMIN:-0}" = 1 ]; then
    if newuser isms_adm -m -G sudo -s /bin/bash; then pw=$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | head -c 14); echo "isms_adm:$pw" | chpasswd
      echo "  [U-01 시험용] 관리자 계정 isms_adm(sudo 그룹) / 비밀번호 $pw (되돌리면 삭제됩니다)"; fi
  fi
  # --- 파일·디렉터리 ---
  setmode /etc/passwd 666 && mark U-16 "/etc/passwd 666"
  # 우분투에는 rc.local 이 기본으로 없다. 시험용으로 만든다(되돌리면 삭제).
  if [ -e /etc/rc.local ]; then setmode /etc/rc.local 777 && mark U-17 "rc.local 777"
  elif newfile /etc/rc.local; then printf '#!/bin/sh\nexit 0\n' > /etc/rc.local; chmod 777 /etc/rc.local; mark U-17 "시험용 /etc/rc.local 777"; fi
  setmode /etc/shadow 644 && mark U-18 "/etc/shadow 644"
  setmode /etc/hosts 666 && mark U-19 "/etc/hosts 666"
  [ -f /etc/rsyslog.conf ] && setmode /etc/rsyslog.conf 666 && mark U-21 "/etc/rsyslog.conf 666"
  setmode /etc/services 666 && mark U-22 "/etc/services 666"
  [ -f /root/.bashrc ] && setmode /root/.bashrc 666 && mark U-24 "/root/.bashrc 666"
  if newfile /usr/local/bin/isms_suid_test; then cp /bin/true /usr/local/bin/isms_suid_test; chmod 4755 /usr/local/bin/isms_suid_test; mark U-23 "SUID 파일 /usr/local/bin/isms_suid_test"; fi
  if newfile /opt/isms_test_world_writable; then : > /opt/isms_test_world_writable; chmod 666 /opt/isms_test_world_writable; mark U-25 "world writable 파일"; fi
  if newfile /opt/isms_test_nouser; then : > /opt/isms_test_nouser; chown 59999:59999 /opt/isms_test_nouser; mark U-15 "소유자 없는 파일"; fi
  if newfile /dev/isms_test_regular; then : > /dev/isms_test_regular; mark U-26 "/dev 안 일반 파일"; fi
  [ -f /etc/crontab ] && setmode /etc/crontab 666 && mark U-37 "/etc/crontab 666"
  for lf in /var/log/syslog /var/log/auth.log /var/log/dpkg.log; do
    [ -f "$lf" ] && setmode "$lf" 666 && { mark U-67 "$lf 666"; break; }
  done
  # --- 설정 값 ---
  if bk /etc/login.defs; then
    sed -i -E 's/^\s*UMASK\s+.*/UMASK 000/' /etc/login.defs
    for f in /etc/profile /etc/bash.bashrc; do [ -f "$f" ] && bk "$f" && sed -i -E 's/^(\s*umask\s+)0?[0-7]{2,3}/\1000/' "$f"; done
    mark U-30 "UMASK 000"
  fi
  # U-66: rsyslog 의 auth.log 규칙(50-default.conf)을 주석 처리
  for f in /etc/rsyslog.d/50-default.conf /etc/rsyslog.conf; do
    [ -f "$f" ] && grep -Eq '^\s*(auth,authpriv|authpriv)\.\*' "$f" && { bk "$f"; sed -i -E 's/^(\s*(auth,authpriv|authpriv)\.\*.*)/#\1/' "$f"; mark U-66 "rsyslog auth.log 규칙 주석 처리($f)"; break; }
  done
  if has_unit ufw.service; then svc_off ufw.service; mark U-28 "ufw 중지·비활성화"; fi
  svc_off chrony.service && mark U-65 "chrony 중지·비활성화"
  seed_pkgs
  echo "건너뜀: U-04(shadow 해제는 위험), U-63(sudo 오류 위험), U-64(패치 정책)"
}

# 기본 설치가 아닌 최소 패키지(점검 대상 파일이 생기게 한다)
seed_pkgs_base() {
  [ "${NO_PKG:-0}" = 1 ] && { echo "(--no-packages: 패키지 설치 없이 이미 설치된 것만 시험합니다)"; return; }
  command -v apt-get >/dev/null || { echo "apt-get 이 없어 패키지 설치를 건너뜁니다"; return; }
  echo "기본 패키지 설치 중(저장소 연결 필요)..."
  apt-get -qq update >/dev/null 2>&1
  pinst openssh-server libpam-pwquality rsyslog chrony
}

seed_pkgs() {
  if [ "${NO_PKG:-0}" != 1 ]; then
    command -v apt-get >/dev/null || return
    echo "서비스 패키지 설치 중(저장소 연결 필요, 시간이 걸립니다)..."
    echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections 2>/dev/null
    echo "postfix postfix/mailname string isms-test.local" | debconf-set-selections 2>/dev/null
    pinst xinetd vsftpd nfs-kernel-server autofs rpcbind nis tftpd-hpa bind9 postfix snmpd
  fi
  # --- xinetd 계열(U-20,34,36,38,44,52): disable = no 항목 ---
  if [ -d /etc/xinetd.d ] || installed xinetd; then
    for n in finger rsh rlogin rexec echo discard daytime chargen tftp telnet; do xserv "$n"; done
    mark U-34 "xinetd finger 활성"; mark U-36 "xinetd rsh/rlogin/rexec 활성"; mark U-38 "xinetd echo/discard/daytime/chargen 활성"
    mark U-44 "xinetd tftp 활성"; mark U-52 "xinetd telnet 활성"; mark U-20 "xinetd.d 파일 권한 666"
    [ -f /etc/xinetd.conf ] && setmode /etc/xinetd.conf 666
  fi
  # --- r 계열 신뢰 설정(U-27) ---
  newfile /etc/hosts.equiv && { printf '+ +\n' > /etc/hosts.equiv; chmod 666 /etc/hosts.equiv; mark U-27 "hosts.equiv '+ +' 권한 666"; }
  newfile /root/.rhosts && { printf '+ +\n' > /root/.rhosts; chmod 666 /root/.rhosts; }
  # --- FTP(U-35,54,55,57): vsftpd (/etc/vsftpd.conf, /etc/ftpusers) ---
  if [ -f /etc/vsftpd.conf ]; then
    bk /etc/vsftpd.conf && { sed -i -E 's/^\s*#?\s*anonymous_enable.*/anonymous_enable=YES/' /etc/vsftpd.conf; grep -q '^anonymous_enable' /etc/vsftpd.conf || echo 'anonymous_enable=YES' >> /etc/vsftpd.conf; mark U-35 "vsftpd 익명 접속 허용"; }
    svc_on vsftpd.service && mark U-54 "vsftpd 활성화"
    for f in /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd.user_list; do [ -f "$f" ] && bk "$f" && sed -i -E 's/^(\s*root\b)/#\1/' "$f"; done
    mark U-57 "ftpusers 에서 root 제거"
  fi
  if getent passwd ftp >/dev/null; then rec SH ftp "$(getent passwd ftp | cut -d: -f7)"; usermod -s /bin/bash ftp && mark U-55 "ftp 계정 쉘 /bin/bash"; fi
  # --- NFS / RPC / autofs / NIS / tftp (U-35,39,40,41,42,43,44) ---
  if command -v exportfs >/dev/null; then
    if [ -e /etc/exports ]; then bk /etc/exports; else newfile /etc/exports; fi
    printf '/data *(rw,anonuid=65534,anongid=65534)\n' > /etc/exports; chmod 666 /etc/exports
    mark U-40 "/etc/exports 권한 666, 호스트 * 로 공유"
    svc_on nfs-server.service && mark U-39 "nfs-server 활성화"
    svc_on rpcbind.service && mark U-42 "rpcbind 활성화"
  fi
  svc_on autofs.service && mark U-41 "autofs 활성화"
  installed nis && { svc_on nis.service; mark U-43 "nis 패키지 설치됨"; }
  svc_on tftpd-hpa.service && mark U-44 "tftpd-hpa 활성화"
  # --- 메일(U-45,46,47,48): postfix ---
  if command -v postconf >/dev/null && [ -f /etc/postfix/main.cf ]; then
    bk /etc/postfix/main.cf && postconf -e 'mynetworks = 0.0.0.0/0' 'disable_vrfy_command = no' >/dev/null 2>&1
    mark U-45 "postfix 설치됨(버전 점검)"; mark U-47 "postfix mynetworks 0.0.0.0/0"; mark U-48 "postfix vrfy 허용"
    [ -f /usr/sbin/postsuper ] && setmode /usr/sbin/postsuper 755 && mark U-46 "postsuper other 실행 가능"
  fi
  # --- DNS(U-49,50,51): bind9 (/etc/bind/named.conf.options, named.conf.local) ---
  if [ -f /etc/bind/named.conf.options ] && [ -f /etc/bind/named.conf.local ]; then
    bk /etc/bind/named.conf.options && bk /etc/bind/named.conf.local && {
      sed -i -E '0,/^\s*options\s*\{/ s//options {\n\tallow-transfer { any; };/' /etc/bind/named.conf.options
      printf '\nzone "isms.test" IN {\n\ttype master;\n\tfile "/var/cache/bind/isms.test.zone";\n\tallow-update { any; };\n};\n' >> /etc/bind/named.conf.local
      mark U-49 "bind9 설치됨(버전 점검)"; mark U-50 "allow-transfer { any; }"; mark U-51 "allow-update { any; }"; }
  fi
  # --- SNMP(U-58~61) ---
  if [ -f /etc/snmp/snmpd.conf ]; then
    bk /etc/snmp/snmpd.conf && printf 'rocommunity public\nrwcommunity private\n' >> /etc/snmp/snmpd.conf
    svc_on snmpd.service; mark U-58 "snmpd 활성화"; mark U-59 "SNMP v1/v2c community"; mark U-60 "community public/private"; mark U-61 "접근 제한 없는 community"
  fi
}

verify() {
  [ -f "$BK/seeded" ] || die "먼저 apply 를 실행하세요"
  for id in $(sort -u "$BK/seeded"); do
    f=$SCRIPTS_UBUNTU/$id.sh; [ -f "$f" ] || f=$SCRIPTS_COMMON/$id.sh      # 도구와 같은 규칙: 우분투 전용이 있으면 그것
    printf '%-6s ' "$id"; bash "$f" check 2>&1 | tail -1 | cut -c1-110
  done
}

undo() {
  [ -f "$MAN" ] || die "되돌릴 내역이 없습니다($MAN)"
  tac "$MAN" | while IFS=$'\t' read -r k a b; do
    case "$k" in
      F) cp -a "$BK/files$a" "$a" ;;
      N) rm -f "$a" ;;
      M) chmod "$b" "$a" ;;
      U) userdel -rf "$a" >/dev/null 2>&1 ;;
      D) rmdir "$a" >/dev/null 2>&1 ;;
      SH) usermod -s "$b" "$a" >/dev/null 2>&1 ;;
      P) apt-get -y -qq purge "$a" >/dev/null 2>&1 ;;
      S) en=${b%%|*}; ac=${b##*|}
         if [ "$en" = enabled ]; then systemctl enable "$a" >/dev/null 2>&1; else systemctl disable "$a" >/dev/null 2>&1; fi
         if [ "$ac" = active ]; then systemctl start "$a" >/dev/null 2>&1; else systemctl stop "$a" >/dev/null 2>&1; fi ;;
    esac
  done
  apt-get -y -qq autoremove >/dev/null 2>&1
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1
  mv "$BK" "$BK.undone.$(date +%y%m%d-%H%M%S)"
  echo "원래 상태로 되돌렸습니다."
}

case "${1:-}" in
  apply)
    [ "${2:-}" = "--yes-test-vm" ] || die "테스트 VM 전용입니다. 확인했다면 'apply --yes-test-vm' 으로 실행하세요."
    [ -d "$BK" ] && die "이미 적용되어 있습니다. 먼저 undo 하세요($BK)"
    mkdir -p "$BK"; chmod 700 "$BK"; : > "$MAN"
    for a in "$@"; do case "$a" in --with-admin) WITH_ADMIN=1 ;; --no-packages) NO_PKG=1 ;; esac; done
    seed; echo; echo "완료. 'verify' 로 점검, 시험 후 'undo' 로 되돌리세요." ;;
  verify) verify ;;
  undo) undo ;;
  *) sed -n 2,8p "$0"; exit 2 ;;
esac
