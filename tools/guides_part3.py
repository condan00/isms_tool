from gdef import g

UNITS = {"U-34": "finger.socket", "U-36": "rlogin.socket rsh.socket rexec.socket", "U-38": "echo.socket chargen.socket daytime.socket discard.socket",
         "U-39": "nfs-server.service nfs-mountd.service", "U-41": "autofs.service", "U-42": "rpcbind.socket rpcbind.service rpc-statd.service",
         "U-43": "ypserv.service ypbind.service yppasswdd.service", "U-44": "tftp.socket talk.socket", "U-52": "telnet.socket",
         "U-54": "vsftpd.service", "U-58": "snmpd.service"}


def svc(iid, name, units, what, threat, impact, extra_check=None, extra_steps=None, caution=""):
    chk = [("서비스 상태", f"systemctl list-unit-files | grep -Ei '{units}'"), ("동작/부팅 상태", f"systemctl is-active <유닛>; systemctl is-enabled <유닛>"),
           ("xinetd 기반이면 설정", "grep -H disable /etc/xinetd.d/* 2>/dev/null")] + (extra_check or [])
    stp = [("서비스 중지 및 부팅 시 비활성화", "systemctl disable --now <유닛>"),
           ("xinetd 기반이면 disable = yes", "sed -i -E 's/^(\\s*disable\\s*=\\s*)no/\\1yes/' /etc/xinetd.d/<서비스>; systemctl reload xinetd")] + (extra_steps or [])
    u = UNITS[iid]
    chk = [(a, b.replace("systemctl is-active <유닛>; systemctl is-enabled <유닛>", f"systemctl is-active {u}; systemctl is-enabled {u}")) for a, b in chk]
    stp = [(a, b.replace("<유닛>", u).replace("<서비스>", u.split(".")[0].split()[0])) for a, b in stp]
    g(iid, f"{what}를 꺼서 공격 면을 줄입니다.", threat, f"{what}가 비활성화(중지, 부팅 시 시작 안 함)", f"{what}가 동작 중이거나 부팅 시 시작되도록 설정",
      chk, stp, impact, [f"systemctl is-enabled {u} 이 disabled/masked", f"systemctl is-active {u} 이 inactive"],
      caution or "패키지가 없고 관련 파일도 없으면 점검 대상이 아니라서 건너뜁니다(NA). 패키지가 없는데 설정 파일만 남아 있으면 '점검 필요'로 표시합니다.")

g("U-30", "새로 만드는 파일·디렉터리의 기본 권한(UMASK)을 022 이상으로 두어 그룹/기타 쓰기를 막습니다.",
  "UMASK 가 느슨하면 새 파일이 다른 사용자에게 쓰기 가능한 권한으로 만들어져 정보 변조·노출이 생깁니다.",
  "UMASK 가 022 이상(login.defs UMASK, /etc/profile·/etc/bashrc 의 umask)", "UMASK 가 022 보다 느슨(예: 002, 000)",
  [("현재 값", "umask"), ("설정 위치", "grep -iE '^\\s*(UMASK|umask)' /etc/login.defs /etc/profile /etc/bashrc /etc/profile.d/*.sh")],
  [("login.defs", "sed -i -E 's/^UMASK.*/UMASK 022/' /etc/login.defs"), ("profile 의 umask 도 022 로", "sed -i -E 's/^(\\s*umask\\s+)0?[0-7]{2,3}/\\1022/' /etc/profile /etc/bashrc")],
  "새로 로그인한 세션부터 적용됩니다. 그룹 공동 작업(그룹 쓰기 필요)을 하던 환경은 권한 문제가 생길 수 있습니다.",
  ["새 세션에서 umask 가 0022"], "")
g("U-31", "홈 디렉터리 소유자를 해당 계정으로 하고 타인의 쓰기를 막아 개인 파일을 보호합니다.",
  "홈 디렉터리에 타인 쓰기 권한이 있으면 다른 사용자가 파일을 심거나 바꿀 수 있습니다.",
  "홈 디렉터리 소유자가 해당 계정이고 other 쓰기 권한이 없음", "소유자가 다르거나 other 쓰기 권한이 있음",
  [("확인", "ls -ld /home/*")],
  [("소유자 지정", "chown <계정> /home/<계정>"), ("other 쓰기 제거", "chmod o-w /home/<계정>")],
  "해당 계정 사용에는 영향이 없습니다. 홈을 공유 디렉터리로 쓰는 환경이면 영향이 있습니다.",
  ["ls -ld 가 계정 소유, other 쓰기 없음"], "도구는 심볼릭 링크를 건드리지 않습니다.")
g("U-32", "존재하지 않는 홈 디렉터리를 가진 계정을 정리합니다.",
  "홈이 없으면 로그인 시 / 를 홈으로 쓰게 되어 의도치 않은 파일 생성이 일어납니다.",
  "로그인 가능한 계정의 홈 디렉터리가 모두 존재", "홈 디렉터리가 없는 계정이 있음",
  [("확인", "awk -F: '$7 !~ /(nologin|false)$/ {print $1, $6}' /etc/passwd | while read u h; do [ -d \"$h\" ] || echo \"$u $h\"; done")],
  [("홈 디렉터리 생성", "mkdir -p <홈> && chown <계정>:<그룹> <홈> && chmod 700 <홈>"), ("불필요한 계정이면 잠금/삭제", "usermod -L <계정>; userdel <계정>")],
  "홈을 새로 만들면 설정 파일(.bashrc 등)이 비어 있으니 필요하면 /etc/skel 을 복사하세요.",
  ["모든 로그인 계정의 홈 디렉터리가 존재"], "도구는 디렉터리만 만들고 계정은 삭제하지 않습니다.")
svc("U-34", "finger", "finger", "Finger 서비스", "Finger 는 계정 이름, 마지막 로그인, 홈 디렉터리 같은 사용자 정보를 외부에 알려 줍니다.", "Finger 로 사용자 정보를 조회하던 일이 없다면 영향이 없습니다.")
g("U-35", "FTP·NFS·Samba 같은 공유 서비스에서 익명(인증 없는) 접근을 막습니다.",
  "익명 접근이 열려 있으면 인증 없이 파일을 읽거나 올릴 수 있어 정보 유출·악성 파일 업로드가 발생합니다.",
  "vsftpd anonymous_enable=NO, proftpd Anonymous 블록 없음, NFS anonuid/anongid 없음, Samba guest ok=no", "익명 접근이 허용",
  [("vsftpd", "grep -E '^\\s*anonymous_enable' /etc/vsftpd/vsftpd.conf"), ("NFS", "grep -E 'anon(uid|gid)' /etc/exports"), ("Samba", "grep -iE '(guest ok|public)' /etc/samba/smb.conf")],
  [("vsftpd", "sed -i -E 's/^\\s*anonymous_enable.*/anonymous_enable=NO/' /etc/vsftpd/vsftpd.conf"), ("NFS 옵션 제거", "sed -i -E 's/,?anon(uid|gid)=[0-9]+//g' /etc/exports; exportfs -ra"),
   ("Samba", "sed -i -E 's/(guest ok|public)\\s*=\\s*yes/\\1 = no/I' /etc/samba/smb.conf; systemctl reload smb"), ("FTP 반영(재시작)", "systemctl restart vsftpd")],
  "익명으로 쓰던 업로드/다운로드가 중단됩니다. FTP 재시작 시 접속이 잠시 끊깁니다(도구가 자동 재시작).",
  ["각 서비스에서 익명 로그인이 거부됨"], "패키지가 설치된 서비스에만 적용합니다. 설정 검사(proftpd -t, testparm)가 실패하면 조치하지 않습니다.")
svc("U-36", "r", "rlogin|rsh|rexec", "r 계열 서비스(rlogin, rsh, rexec)", "r 계열은 평문 전송에 호스트 신뢰 기반 인증이라 도청·위장 접속에 취약합니다.", "SSH 로 대체하세요. 이 서비스에 의존하는 오래된 스크립트가 있으면 실패합니다.", caution="도구는 rsh/rlogin/rexec 관련 유닛과 xinetd·inetd 설정을 비활성화합니다(확인 후 적용). 패키지는 삭제하지 않으며, 조치 전 서비스 상태는 스냅샷으로 복구할 수 있습니다.")
g("U-37", "crontab/at 명령과 설정·작업 파일을 root 만 관리하게 해 예약 작업 악용을 막습니다.",
  "cron 파일에 쓸 수 있으면 root 권한으로 실행될 임의 명령을 예약할 수 있습니다.",
  "crontab/at 명령 소유자 root·권한 750 이하(SUID 없음), cron/at 설정·작업 파일 권한 640 이하", "기준 미충족",
  [("명령 확인", "ls -l /usr/bin/crontab /usr/bin/at"), ("설정 파일 확인", "ls -l /etc/crontab /etc/cron.* /var/spool/cron /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null")],
  [("명령 권한", "chown root /usr/bin/crontab /usr/bin/at; chmod 750 /usr/bin/crontab /usr/bin/at"), ("설정 파일 권한", "chmod 640 /etc/crontab /etc/cron.allow /etc/at.allow")],
  "crontab 명령을 일반 사용자가 쓰려면 cron.allow 등록과 그룹 설정이 필요합니다. 750 으로 줄이면 일반 사용자의 crontab 실행이 막힐 수 있습니다.",
  ["명령 750 이하, 설정 파일 640 이하"], "일반 사용자에게 crontab 을 허용해 둔 환경은 승인 후 적용하세요(승인 항목).")
svc("U-38", "echo|discard|daytime|chargen", "echo|discard|daytime|chargen", "DoS 에 취약한 서비스(echo, discard, daytime, chargen)", "응답을 되돌려 주는 레거시 서비스는 증폭 공격과 서비스 거부에 악용됩니다.", "해당 서비스는 거의 쓰이지 않아 영향이 작습니다.", caution="NTP monlist·DNS 재귀 질의 설정은 서비스 용도를 확인한 뒤 수동으로 판단합니다. 방화벽으로 외부 차단도 병행하세요.")
svc("U-39", "nfs", "nfs|rpc-statd|mountd", "불필요한 NFS 서비스", "NFS 는 인증이 약해 설정 오류 시 파일 시스템이 외부에 노출됩니다.", "NFS 공유를 쓰고 있으면 마운트가 끊깁니다. /etc/exports 에 공유가 있으면 자동 조치하지 않습니다.", caution="공유 설정이 남아 있으면 사용 중일 수 있으니 수동으로 확인합니다.")
g("U-40", "NFS 공유를 허가된 호스트로만 제한합니다.",
  "호스트 제한 없이(*) 공유하면 누구나 마운트해 파일을 읽거나 변조할 수 있습니다.",
  "/etc/exports 소유자 root, 권한 644 이하, 공유 대상 호스트를 제한(* 불가)", "소유자/권한 미충족 또는 * 로 공유",
  [("확인", "ls -l /etc/exports; cat /etc/exports")],
  [("소유자·권한", "chown root /etc/exports; chmod 644 /etc/exports"), ("호스트 제한 지정(수동)", "/data   <허용IP/대역>(rw,sync,root_squash)"), ("반영", "exportfs -ra")],
  "허용 호스트를 잘못 지정하면 정상 클라이언트가 마운트하지 못합니다.",
  ["exports 의 모든 공유가 특정 호스트로 제한"], "소유자·권한만 자동 조치하고, 호스트 제한은 사람이 지정해야 해서 '점검 필요'로 남습니다.",
  decide=[("허용 호스트", "마운트를 허용할 IP/대역", "<허용IP/대역>")])
svc("U-41", "autofs", "autofs|automount", "자동 마운트(autofs/automountd)", "autofs 가 취약하면 마운트 정보 노출이나 임의 경로 접근의 위험이 있습니다.", "autofs 로 자동 마운트하던 디렉터리가 접근되지 않습니다.")
svc("U-42", "rpc", "rpcbind|rpc-statd", "불필요한 RPC 서비스", "RPC 서비스는 과거 다수의 원격 취약점이 있었고 포트 정보를 노출합니다.", "NFS/NIS 가 rpcbind 를 쓰고 있으면 함께 중단됩니다. 그런 경우 자동 조치하지 않습니다.")
svc("U-43", "yp", "ypserv|ypbind|yppasswdd", "NIS/NIS+ 서비스", "NIS 는 계정 정보를 평문에 가깝게 전달해 도청과 변조에 취약합니다.", "NIS 로 계정을 중앙 관리하던 환경이면 로그인이 안 될 수 있습니다.")
svc("U-44", "tftp|talk", "tftp|talk|ntalk", "tftp, talk 서비스", "tftp 는 인증이 없고, talk 는 불필요한 원격 메시지 서비스입니다.", "장비 설정 백업 등에 tftp 를 쓰고 있으면 중단됩니다.")
