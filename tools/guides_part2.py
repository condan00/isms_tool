from gdef import g

def perm(iid, path, what, owner, mode, extra_threat=""):
    g(iid, f"{what} 파일을 root 만 수정할 수 있게 해 변조를 막습니다.",
      f"{path} 를 일반 사용자가 고칠 수 있으면 {extra_threat or '시스템 설정과 계정 정보가 변조'}될 수 있습니다.",
      f"소유자 {owner}, 권한 {mode} 이하", f"소유자가 {owner} 가 아니거나 권한이 {mode} 를 초과",
      [("소유자·권한 확인", f"ls -l {path}")],
      [("백업", f"cp -p {path} {path}.bak"), ("소유자 변경", f"chown root {path}"), ("권한 변경", f"chmod {mode} {path}")],
      "정상적으로 읽기만 하던 서비스에는 영향이 없습니다. 권한을 지나치게 줄이면 읽어야 하는 서비스가 실패할 수 있으니 기준값(%s)을 지켜 적용하세요." % mode,
      [f"ls -l {path} 가 {owner} 소유, 권한 {mode} 이하"])

perm("U-16", "/etc/passwd", "/etc/passwd", "root", "644", "계정 정보(UID/쉘 등)가 변조")
g("U-17", "시스템 시작 시 실행되는 스크립트를 root 만 수정할 수 있게 해 악성 코드 삽입을 막습니다.",
  "시작 스크립트에 일반 사용자 쓰기 권한이 있으면 부팅 때 root 권한으로 임의 명령이 실행될 수 있습니다.",
  "시작 스크립트 소유자 root, 일반 사용자(other) 쓰기 권한 없음", "소유자가 root 가 아니거나 other 쓰기 권한이 있음",
  [("대상 파일 확인", "ls -lL /etc/rc.d/init.d/* /etc/rc.local /etc/systemd/system/*.service 2>/dev/null"), ("other 쓰기 파일 검색", "find /etc/rc.d /etc/init.d /etc/systemd/system -xdev -perm -0002 ! -type l 2>/dev/null")],
  [("소유자 root 로", "chown root <파일>"), ("other 쓰기 권한 제거", "chmod o-w <파일>")],
  "other 쓰기만 제거하므로 서비스 기동에는 영향이 없습니다.",
  ["find 로 other 쓰기 파일이 나오지 않음"], "심볼릭 링크는 따라가지 않고 실제 파일만 조치합니다. /etc 밖을 가리키는 링크는 대상에서 제외됩니다.")
perm("U-18", "/etc/shadow", "/etc/shadow", "root", "400", "비밀번호 해시가 노출·변조")
perm("U-19", "/etc/hosts", "/etc/hosts", "root", "644", "호스트 이름 해석을 속이는 변조(DNS 스푸핑 유사)")
g("U-20", "(x)inetd 설정을 root 만 수정할 수 있게 해 서비스 추가·변경을 막습니다.",
  "inetd 계열 설정이 변조되면 임의 서비스가 root 권한으로 열릴 수 있습니다.",
  "소유자 root, 권한 600 이하 (xinetd.d 는 안의 파일 기준)", "소유자가 root 가 아니거나 권한이 600 을 초과",
  [("패키지 확인", "rpm -q xinetd openbsd-inetd"), ("권한 확인", "ls -l /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/*")],
  [("소유자 root", "chown root /etc/xinetd.conf /etc/xinetd.d/*"), ("권한 600", "chmod 600 /etc/xinetd.conf /etc/xinetd.d/*")],
  "xinetd 가 root 로 설정을 읽으므로 600 으로 줄여도 동작합니다.",
  ["ls -l 결과가 root 소유, 600 이하"], "xinetd/inetd 패키지가 없으면 점검 대상이 아니라서 건너뜁니다(관련 파일이 남아 있으면 점검 필요로 표시).")
g("U-21", "시스템 로그 설정 파일을 root 만 수정할 수 있게 해 로그 은폐를 막습니다.",
  "로그 설정이 변조되면 침입 흔적이 기록되지 않거나 다른 곳으로 빼돌려질 수 있습니다.",
  "소유자 root(또는 bin, sys), 권한 640 이하", "소유자가 다르거나 권한이 640 을 초과",
  [("권한 확인", "ls -l /etc/rsyslog.conf /etc/rsyslog.d/* /etc/syslog-ng/syslog-ng.conf 2>/dev/null")],
  [("소유자 root", "chown root /etc/rsyslog.conf"), ("권한 640", "chmod 640 /etc/rsyslog.conf /etc/rsyslog.d/*.conf")],
  "rsyslog 는 root 로 설정을 읽으므로 영향이 없습니다.",
  ["ls -l 이 root 소유, 640 이하"], "")
perm("U-22", "/etc/services", "/etc/services", "root", "644", "서비스-포트 매핑이 변조")
g("U-23", "불필요한 SUID/SGID 파일을 찾아 권한 상승 경로를 줄입니다.",
  "SUID/SGID 파일은 실행하는 동안 파일 소유자(보통 root) 권한을 얻으므로 취약점이 있으면 곧바로 권한 상승으로 이어집니다.",
  "불필요한 SUID/SGID 파일이 없음", "업무상 필요 없는 SUID/SGID 파일이 있음",
  [("목록 확인", "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -ls 2>/dev/null")],
  [("필요 여부 검토(패키지 기본 파일인지 확인)", "rpm -qf <파일>"), ("불필요하면 특수 권한 제거", "chmod u-s,g-s <파일>")],
  "passwd, sudo, su 같은 정상 도구의 SUID 를 제거하면 해당 기능이 동작하지 않습니다.",
  ["find 목록이 업무상 필요한 파일뿐"], "도구는 패키지 소유가 아니거나 /home·/tmp·/var/tmp·/dev/shm·/mnt·/media 아래에 있는 SUID/SGID 비트만 제거하고, 패키지가 둔 기본 파일은 (검토) 목록으로만 보여 줍니다(확인 후 적용). 전체 검색은 부하가 큽니다.")
g("U-24", "사용자·시스템 환경변수 파일을 소유자만 수정할 수 있게 해 로그인 시 악성 명령 실행을 막습니다.",
  ".bashrc 등 환경 파일이 타인에게 쓰기 허용이면 그 사용자가 로그인할 때(특히 root) 임의 명령이 실행됩니다.",
  "환경변수 파일 소유자가 root 또는 해당 계정이고 그룹/기타 쓰기 권한이 없음", "소유자가 다르거나 그룹/기타 쓰기 권한이 있음",
  [("대상 확인", "ls -l /root/.bash_profile /root/.bashrc /home/*/.bash_profile /home/*/.bashrc /home/*/.profile /etc/profile /etc/bashrc 2>/dev/null")],
  [("소유자 지정", "chown <계정> /home/<계정>/.bashrc"), ("그룹·기타 쓰기 제거", "chmod go-w /home/<계정>/.bashrc")],
  "사용자 본인의 사용에는 영향이 없고 타인의 쓰기만 막습니다.",
  ["ls -l 이 소유자만 쓰기 가능"], "도구는 열어 둔 파일에 대해서만 소유자·권한을 바꾸며 심볼릭 링크는 건드리지 않습니다.")
g("U-25", "누구나 수정할 수 있는 파일을 찾아 변조 위험을 줄입니다.",
  "world writable 파일은 모든 계정이 내용을 바꿀 수 있어 설정·실행 파일이면 시스템 침해로 이어집니다.",
  "모든 사용자가 쓸 수 있는 일반 파일이 없음(필요한 것은 사유 명시)", "불필요한 world writable 파일이 있음",
  [("검색", "find / -xdev -type f -perm -0002 -ls 2>/dev/null")],
  [("용도 확인", "ls -l <파일>; rpm -qf <파일>"), ("쓰기 권한 제거", "chmod o-w <파일>")],
  "공유 목적 파일이면 쓰기 제거 시 그 기능이 실패할 수 있습니다.",
  ["find 결과가 없거나 사유가 있는 파일뿐"], "도구는 other 쓰기 권한(o-w)만 제거합니다(확인 후 적용, /tmp·/var/tmp 제외, 300건 초과 시 수동). 전체 검색은 부하가 큽니다.")
g("U-26", "/dev 에 장치 파일이 아닌 일반 파일을 찾아 위장·은닉 파일을 제거합니다.",
  "/dev 는 장치 파일만 있어야 하는데 일반 파일이 있으면 공격자가 도구나 백도어를 숨겼을 가능성이 큽니다.",
  "/dev 에 장치가 아닌 일반 파일이 없음(shm, mqueue 등 정상 항목 제외)", "일반 파일이 존재",
  [("검색", "find /dev -type f 2>/dev/null")],
  [("내용 확인", "ls -l <파일>; file <파일>"), ("불필요하면 삭제", "rm <파일>")],
  "정상 장치 파일은 건드리지 않습니다. 삭제 전 반드시 용도를 확인하세요.",
  ["find /dev -type f 결과가 없음"], "도구는 50MB 이하 일반 파일만 삭제하며(확인 후 적용) 조치 전 스냅샷에 내용을 보관해 복구할 수 있습니다. 더 큰 파일은 수동 확인입니다.")
g("U-27", "r 계열 서비스의 신뢰 호스트 설정을 통제해 비밀번호 없는 원격 접속을 막습니다.",
  ".rhosts/hosts.equiv 에 + 가 있으면 누구든 인증 없이 접속할 수 있습니다.",
  "hosts.equiv/.rhosts 소유자가 root 또는 해당 계정, 권한 600 이하, '+' 설정 없음", "기준 미충족",
  [("파일 확인", "ls -l /etc/hosts.equiv /root/.rhosts /home/*/.rhosts 2>/dev/null"), ("+ 설정 확인", "grep -n '^\\s*+' /etc/hosts.equiv /home/*/.rhosts 2>/dev/null")],
  [("소유자·권한", "chown root /etc/hosts.equiv; chmod 600 /etc/hosts.equiv"), ("+ 설정 주석 처리", "sed -i -E 's/^(\\s*\\+)/#\\1/' /etc/hosts.equiv")],
  "r 계열 서비스를 쓰고 있었다면 신뢰 호스트 접속이 막힙니다. 보안상 사용하지 않는 것이 맞습니다.",
  ["권한 600, '+' 없음"], "r 계열 패키지가 없으면 점검 대상이 아니지만 .rhosts 파일이 남아 있으면 점검 필요로 표시합니다. SSH 사용을 권장합니다.")
g("U-28", "접속 가능한 IP 와 포트를 방화벽·TCP Wrapper 로 제한해 불필요한 외부 접근을 막습니다.",
  "접근 제한이 없으면 인터넷 어디서나 서비스에 접속을 시도할 수 있습니다.",
  "TCP Wrapper 또는 방화벽(firewalld/iptables/nftables/ufw)으로 접속 허용 IP·포트를 제한", "접근 제한이 없음",
  [("firewalld 상태", "systemctl is-active firewalld; firewall-cmd --list-all"), ("TCP Wrapper", "cat /etc/hosts.allow /etc/hosts.deny")],
  [("방화벽 활성화", "systemctl enable --now firewalld"), ("허용 대역만 SSH 허용", "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<허용대역> service name=ssh accept'"),
   ("기본 서비스 제거", "firewall-cmd --permanent --remove-service=ssh"), ("반영", "firewall-cmd --reload")],
  "허용 대역을 잘못 지정하면 원격 접속이 막힙니다. 콘솔 접근을 확보한 뒤 적용하세요.",
  ["외부 허용되지 않은 IP 에서 접속이 거부됨"], "자동 조치하지 않는 항목입니다(허용 IP 는 환경마다 다름).",
  decide=[("허용 대역", "접속을 허용할 IP/대역", "<허용대역>")])
