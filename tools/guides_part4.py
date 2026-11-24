from gdef import g
from guides_part3 import svc

g("U-45", "메일 서비스가 알려진 취약점이 없는 최신 보안 패치 상태인지 확인합니다.",
  "구버전 메일 서버는 원격 코드 실행·릴레이 악용 취약점이 자주 공개됩니다.",
  "메일 서비스(sendmail/postfix/exim)가 최신 보안 패치 상태", "취약한 버전을 사용",
  [("설치 버전", "rpm -q sendmail postfix exim"), ("패치 가능 여부", "dnf updateinfo list security | grep -Ei 'sendmail|postfix|exim'")],
  [("보안 패치 적용", "dnf update --security sendmail postfix exim"), ("재시작은 영향 확인 후", "systemctl restart postfix   # 또는 sendmail")],
  "패치 후 재시작 시 메일 수신이 잠시 중단됩니다.",
  ["rpm -q 로 패치된 버전 확인"], "최신 여부는 외부 정보가 필요해 도구는 버전만 보여 줍니다. 메일을 쓰지 않으면 서비스 중지를 권장합니다.")
g("U-46", "일반 사용자가 메일 큐를 조작해 정보를 빼내는 것을 막습니다.",
  "일반 사용자가 메일 큐를 보거나 실행할 수 있으면 다른 사용자의 메일 내용·수신자 정보가 노출됩니다.",
  "sendmail PrivacyOptions 에 restrictqrun, postfix postsuper / exim exiqgrep 의 other 실행 권한 제거", "미설정",
  [("sendmail", "grep -E '^O PrivacyOptions' /etc/mail/sendmail.cf"), ("postfix", "ls -l /usr/sbin/postsuper"), ("exim", "ls -l /usr/sbin/exiqgrep")],
  [("sendmail: restrictqrun 추가", "sed -i -E '/^O\\s+PrivacyOptions/ s/$/,restrictqrun/' /etc/mail/sendmail.cf"), ("postfix: other 실행 제거", "chmod o-x /usr/sbin/postsuper"),
   ("exim: other 실행 제거", "chmod o-x /usr/sbin/exiqgrep"), ("sendmail 반영(수동 재시작)", "systemctl restart sendmail")],
  "일반 사용자가 메일 큐 관리 명령을 쓸 수 없습니다. sendmail 은 재시작해야 반영됩니다.",
  ["PrivacyOptions 에 restrictqrun 포함", "postsuper/exiqgrep 의 other 실행 없음"],
  "도구는 설치된 메일 패키지에만 적용합니다. sendmail 은 자동 재시작하지 않으므로 업무 영향을 확인하고 직접 재시작하세요.")
g("U-47", "메일 서버가 외부 임의 대상으로 메일을 중계(릴레이)하지 않게 합니다.",
  "릴레이가 열려 있으면 스팸 발송에 악용되어 서버 IP 가 차단되고 평판이 떨어집니다.",
  "외부 임의 대상으로의 릴레이를 허용하지 않음", "열린 릴레이",
  [("postfix", "postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions"), ("sendmail", "cat /etc/mail/access"), ("실제 시험", "telnet <서버> 25   # RCPT TO 로 외부 주소 시험")],
  [("postfix: 내부망으로 제한", "postconf -e 'mynetworks=127.0.0.0/8'"), ("postfix: 인증 안 된 외부 수신 거부", "postconf -e 'smtpd_relay_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination'; postfix reload"),
   ("sendmail: access 파일에 내부망만 RELAY", "echo '10.0.0 RELAY' >> /etc/mail/access; makemap hash /etc/mail/access < /etc/mail/access")],
  "정상 외부 클라이언트가 인증 없이 메일을 보내던 경우 거부됩니다.",
  ["외부 주소로의 릴레이 시험이 거부됨"], "점검과 가이드만 제공합니다(환경별 허용 대역이 달라 자동 조치하지 않음).")
g("U-48", "SMTP 의 expn/vrfy 명령으로 계정 존재 여부와 메일 목록이 노출되는 것을 막습니다.",
  "expn/vrfy 로 유효한 계정과 메일링 리스트 구성원을 알아내 사회공학·사전 공격에 쓸 수 있습니다.",
  "sendmail noexpn,novrfy(또는 goaway), postfix disable_vrfy_command=yes (exim 은 수동 확인)", "제한 미설정",
  [("sendmail", "grep -E '^O PrivacyOptions' /etc/mail/sendmail.cf"), ("postfix", "postconf disable_vrfy_command"), ("exim", "grep -E 'acl_smtp_(vrfy|expn)' /etc/exim/exim.conf")],
  [("sendmail", "sed -i -E '/^O\\s+PrivacyOptions/ s/$/,noexpn,novrfy/' /etc/mail/sendmail.cf"), ("postfix", "postconf -e disable_vrfy_command=yes; postfix reload"), ("sendmail 반영(수동 재시작)", "systemctl restart sendmail")],
  "VRFY/EXPN 에 의존하는 모니터링이 있으면 실패합니다. 일반 메일 송수신에는 영향이 없습니다.",
  ["sendmail 은 noexpn,novrfy 포함, postfix 는 yes"], "도구는 설치된 메일 패키지에만 적용하며 exim 은 수동 확인(MANUAL)입니다. sendmail 은 직접 재시작하세요.")
g("U-49", "DNS(BIND) 서비스가 최신 보안 패치 상태인지 확인합니다.",
  "구버전 BIND 는 캐시 포이즈닝, 서비스 거부 등 다수의 취약점이 있습니다.",
  "DNS 서비스를 쓰면 최신 보안 패치 상태", "취약한 버전 사용",
  [("버전·설치일", "named -v; rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} %{INSTALLTIME:date}\\n' bind"), ("패치 확인", "dnf updateinfo list security | grep -i bind")],
  [("보안 패치 적용", "dnf update --security bind"), ("재시작(영향 확인 후)", "systemctl restart named")],
  "재시작 중 DNS 질의가 잠시 실패합니다.", ["named -v 가 패치된 버전"], "최신 여부는 외부 정보가 필요해 도구는 버전과 설치일만 보여 줍니다.")
g("U-50", "DNS Zone Transfer 를 허가된 보조 서버로만 제한합니다.",
  "Zone Transfer 가 열려 있으면 존의 모든 호스트 정보가 한 번에 유출되어 공격 정찰에 쓰입니다.",
  "allow-transfer 가 있고 any 가 아님", "allow-transfer 가 없거나 any",
  [("설정 확인", "grep -rn 'allow-transfer' /etc/named.conf /etc/named/"), ("시험", "dig @<서버> <도메인> AXFR")],
  [("options 또는 zone 에 지정", "allow-transfer { <보조DNS IP>; };"), ("문법 검사", "named-checkconf"), ("반영", "systemctl reload named")],
  "허용하지 않은 보조 서버의 존 전송이 막힙니다.", ["AXFR 시험이 거부됨"], "보조 서버 주소는 환경마다 달라 도구가 자동 조치하지 않습니다.",
  decide=[("보조 DNS", "Zone Transfer 를 허용할 보조 서버 IP", "<보조DNS IP>")])
g("U-51", "DNS 동적 업데이트를 인증된 대상으로만 제한합니다.",
  "allow-update 가 any 이면 누구나 DNS 레코드를 추가·변조해 트래픽을 가로챌 수 있습니다.",
  "BIND allow-update 가 any 가 아님(필요 없으면 none)", "allow-update { any; }",
  [("설정 확인", "grep -rn 'allow-update' /etc/named.conf /etc/named/")],
  [("차단", "sed -z -i -E 's/(allow-update\\s*\\{)[^}]*(\\})/\\1 none; \\2/g' /etc/named.conf"), ("문법 검사", "named-checkconf"), ("무중단 반영", "systemctl reload named")],
  "동적 업데이트를 쓰는 DHCP 연동이 있다면 갱신이 실패합니다. 필요하면 none 대신 허용 IP/키를 지정하세요.",
  ["allow-update 에 any 가 없음"], "named-checkconf 가 실패하면 도구가 원복합니다.")
svc("U-52", "telnet", "telnet", "Telnet 서비스", "Telnet 은 아이디와 비밀번호를 평문으로 전송해 도청에 취약합니다.", "SSH 로 접속하세요. Telnet 으로만 접속하던 장비는 연결이 안 됩니다.")
svc("U-54", "ftp", "vsftpd|proftpd|pure-ftpd|ftpd", "암호화되지 않는 FTP 서비스", "FTP 는 계정·데이터를 평문으로 전송합니다.", "FTP 업로드/다운로드가 중단됩니다. SFTP 로 대체하세요.")
g("U-55", "FTP 계정(ftp)에 로그인 쉘을 주지 않아 쉘 접근을 막습니다.",
  "ftp 계정에 쉘이 있으면 FTP 서비스의 취약점을 통해 시스템 쉘로 이어질 수 있습니다.",
  "ftp(anonymous) 계정의 로그인 쉘이 /sbin/nologin 또는 /bin/false", "정상 쉘이 지정",
  [("확인", "grep '^ftp:' /etc/passwd")], [("쉘 변경", "usermod -s /sbin/nologin ftp")],
  "FTP 서비스 자체에는 영향이 없습니다.", ["grep '^ftp:' /etc/passwd 의 쉘이 nologin"], "FTP 서버 패키지가 있을 때만 점검합니다.")
g("U-57", "FTP 에서 root 계정으로의 직접 접속을 차단합니다.",
  "root 로 FTP 접속이 가능하면 평문으로 root 비밀번호가 노출되고 무차별 대입 대상이 됩니다.",
  "ftpusers/user_list 에 root 가 있고 proftpd 는 RootLogin off", "root 접속이 허용",
  [("목록 확인", "grep -n root /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list 2>/dev/null"), ("proftpd", "grep -i RootLogin /etc/proftpd.conf")],
  [("root 추가", "echo root >> /etc/vsftpd/ftpusers"), ("proftpd", "sed -i -E 's/^\\s*RootLogin.*/RootLogin off/' /etc/proftpd.conf; proftpd -t"), ("반영", "systemctl restart vsftpd proftpd")],
  "root 로 FTP 하던 작업은 일반 계정 + sudo 로 해야 합니다. 재시작 시 FTP 가 잠시 끊깁니다(도구가 자동 재시작).",
  ["root 로 FTP 로그인이 거부됨"], "FTP 서버 패키지가 있을 때만 점검합니다.")
svc("U-58", "snmp", "snmpd|snmptrapd", "불필요한 SNMP 서비스", "SNMP 는 시스템 정보를 노출하고 약한 community 설정이면 변조까지 가능합니다.", "SNMP 로 모니터링하는 서버라면 수집이 중단됩니다. 사용 중이면 U-59~61 을 적용하세요.")
g("U-59", "SNMP 를 암호화·인증이 있는 v3 로만 사용합니다.",
  "v1/v2c 는 community 문자열이 평문이라 도청되면 그대로 접근됩니다.",
  "SNMP 를 v3 이상으로만 사용(커뮤니티 기반 v1/v2c 설정이 없음)", "rocommunity/rwcommunity 등 v1/v2c 설정이 있음",
  [("설정 확인(community 값은 공유 금지)", "grep -nE '^\\s*(rocommunity|rwcommunity|com2sec|createUser|rouser)' /etc/snmp/snmpd.conf")],
  [("v3 사용자 생성", "systemctl stop snmpd; net-snmp-create-v3-user -ro -A <인증암호> -a SHA -X <암호화암호> -x AES <사용자>"), ("community 줄 삭제 또는 주석", "sed -i -E 's/^(\\s*(ro|rw)community)/#\\1/' /etc/snmp/snmpd.conf"), ("시작", "systemctl start snmpd")],
  "v1/v2c 로 수집하던 모니터링 시스템이 v3 로 바뀔 때까지 수집이 안 됩니다.", ["v3 로 snmpwalk 가 성공하고 v2c 는 거부"], "점검과 가이드만 제공합니다. 인증/암호화 암호는 안전하게 보관하세요.")
g("U-60", "SNMP community 문자열을 추측하기 어렵게 설정합니다.",
  "public/private 같은 기본값은 누구나 시도하는 첫 번째 값입니다.",
  "community 문자열이 public/private 이 아니고 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상", "기본값이거나 단순",
  [("설정 확인(문자열은 화면에 공유하지 마세요)", "grep -nE '^\\s*(rocommunity|rwcommunity)' /etc/snmp/snmpd.conf")],
  [("복잡한 문자열로 변경", "rocommunity <복잡한문자열> <허용대역>"), ("재시작", "systemctl restart snmpd"), ("모니터링 측 설정도 함께 변경", "(NMS 에서 community 수정)")],
  "모니터링 시스템의 community 도 같이 바꾸지 않으면 수집이 중단됩니다.", ["새 문자열로만 조회됨"], "도구는 community 값을 출력하지 않으며 점검과 가이드만 제공합니다.")
g("U-61", "SNMP 접근을 허가된 호스트·네트워크로 제한합니다.",
  "접근 제한이 없으면 네트워크의 누구나 SNMP 로 시스템 정보를 조회할 수 있습니다.",
  "community 에 접근 허용 source 지정 또는 v3 사용자만 사용", "source 제한 없이 community 사용",
  [("설정 확인", "grep -nE '^\\s*(rocommunity|rwcommunity|agentaddress)' /etc/snmp/snmpd.conf")],
  [("허용 대역 지정", "rocommunity <문자열> <NMS IP/대역>"), ("방화벽도 제한", "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<NMS IP> port port=161 protocol=udp accept'"), ("재시작", "systemctl restart snmpd")],
  "허용하지 않은 호스트의 조회가 막힙니다.", ["NMS 외 호스트의 snmpwalk 가 거부"], "점검과 가이드만 제공합니다.",
  decide=[("NMS 주소", "SNMP 조회를 허용할 관리 서버", "<NMS IP/대역>")])
g("U-63", "sudo 설정 파일을 root 만 관리하게 해 권한 상승 설정 변조를 막습니다.",
  "sudoers 를 일반 사용자가 고칠 수 있으면 스스로에게 root 권한을 부여할 수 있습니다.",
  "/etc/sudoers 소유자 root, 권한 640 이하", "소유자/권한 미충족",
  [("확인", "ls -l /etc/sudoers /etc/sudoers.d")], [("백업", "cp -p /etc/sudoers /etc/sudoers.bak"), ("소유자·권한", "chown root /etc/sudoers; chmod 440 /etc/sudoers"), ("문법 검사", "visudo -c")],
  "sudo 동작에는 영향이 없습니다(표준 권한은 440).", ["ls -l 이 root 소유, 640 이하", "visudo -c 정상"], "sudoers 를 직접 편집할 때는 반드시 visudo 를 쓰세요.")
g("U-64", "보안 패치를 주기적으로 적용하는 체계를 갖춥니다.",
  "패치가 늦으면 공개된 취약점이 그대로 공격에 쓰입니다.",
  "패치 적용 정책이 있고 주기적으로 패치를 적용함", "정책이 없거나 패치가 장기간 적용되지 않음",
  [("최근 패치 이력", "dnf history | head -20"), ("자동 업데이트 설정", "systemctl status dnf-automatic.timer"), ("남은 보안 업데이트", "dnf updateinfo list security")],
  [("보안 패치 적용", "dnf update --security"), ("자동 보안 업데이트(선택)", "dnf install dnf-automatic; sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf; systemctl enable --now dnf-automatic.timer"), ("커널 갱신은 재부팅 필요", "needs-restarting -r")],
  "패치 후 서비스 재시작이나 재부팅이 필요할 수 있으니 점검 시간에 적용하세요.", ["dnf updateinfo list security 에 남은 항목이 없음"], "정책 유무는 자동 판단이 불가능해 도구는 점검 정보만 보여 줍니다. 운영 서버는 먼저 테스트 환경에서 검증하세요.")
g("U-65", "서버 시간을 NTP 로 동기화해 로그 시각의 신뢰성을 확보합니다.",
  "시간이 어긋나면 로그 분석과 사고 조사에서 사건 순서를 맞출 수 없고 인증서·Kerberos 도 실패합니다.",
  "NTP 서비스(chronyd/ntpd/systemd-timesyncd)가 켜져 있고 동기화 서버가 설정됨", "서비스가 꺼져 있거나 서버 설정이 없음",
  [("동기화 상태", "timedatectl; chronyc sources -v"), ("서버 설정", "grep -E '^(server|pool)' /etc/chrony.conf")],
  [("서버 지정(없으면)", "echo 'pool <NTP서버> iburst' >> /etc/chrony.conf"), ("서비스 시작", "systemctl enable --now chronyd"), ("동기화 확인", "chronyc tracking")],
  "시간이 갑자기 보정되면 시간에 민감한 프로세스(DB 등)에 영향이 있을 수 있습니다.", ["timedatectl 에 System clock synchronized: yes"], "도구는 NTP 패키지를 설치하지 않으며 설치되어 있지 않으면 점검 필요로 표시합니다.",
  decide=[("NTP 서버", "사내 또는 공용 NTP 서버 주소", "<NTP서버>")])
g("U-66", "정책에 맞는 시스템 로그를 남겨 사고 추적을 가능하게 합니다.",
  "필요한 로그가 없으면 침해 사고의 원인과 범위를 알 수 없습니다.",
  "rsyslog 정책: *.info→messages, authpriv→secure, mail→maillog, cron→cron, *.emerg→전체 사용자", "정책 규칙이 누락",
  [("규칙 확인", "grep -rvE '^\\s*(#|$)' /etc/rsyslog.conf /etc/rsyslog.d/"), ("서비스 상태", "systemctl is-active rsyslog")],
  [("누락된 규칙 추가", "printf '*.info;mail.none;authpriv.none;cron.none /var/log/messages\\nauthpriv.* /var/log/secure\\nmail.* -/var/log/maillog\\ncron.* /var/log/cron\\n*.emerg :omusrmsg:*\\n' > /etc/rsyslog.d/90-isms-logging.conf"), ("문법 검사", "rsyslogd -N1"), ("재시작", "systemctl restart rsyslog")],
  "로그가 늘어 디스크 사용량이 증가하므로 logrotate 설정을 확인하세요.", ["로그 파일이 생성되고 규칙이 반영됨"], "도구는 문법 검사 실패 시 추가한 규칙을 제거합니다. journald 만 쓰는 환경은 점검 필요로 표시합니다.")
g("U-67", "로그 디렉터리와 파일을 root 만 수정할 수 있게 해 로그 위·변조를 막습니다.",
  "로그를 일반 사용자가 지우거나 고칠 수 있으면 침입 흔적을 삭제할 수 있습니다.",
  "/var/log 안 로그 파일의 소유자가 root 이고 권한이 644 이하", "소유자가 다르거나 권한이 644 초과",
  [("확인", "find /var/log -xdev -type f \\( ! -user root -o -perm /133 \\) -ls 2>/dev/null")],
  [("소유자", "chown root <로그파일>"), ("권한", "chmod 644 <로그파일>")],
  "서비스별 로그(예: 웹 서버)는 해당 서비스 계정이 써야 하므로 root 소유로 바꾸면 기록이 실패할 수 있습니다.", ["find 결과가 없거나 서비스 전용 로그뿐"], "도구는 기준 미달 로그 파일의 소유자를 root 로 바꾸고 644 를 넘는 권한 비트를 제거합니다(확인 후 적용). 서비스 전용 계정(chrony, sssd 등)이 쓰는 로그는 root 소유가 되면 그 서비스가 로그를 못 쓸 수 있고, logrotate 가 파일을 다시 만들면 원래 소유자로 돌아갑니다.")
