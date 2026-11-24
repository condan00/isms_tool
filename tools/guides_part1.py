from gdef import g

g("U-01", "root 계정으로 원격 터미널(SSH 등)에 직접 접속하지 못하게 해 관리자 계정 노출을 줄입니다.",
  "root 직접 접속이 허용되면 무차별 대입·사전 공격이 가장 권한이 높은 계정을 곧바로 노립니다. 접속 기록에도 누가 root 를 썼는지 남지 않습니다.",
  "SSH 의 PermitRootLogin 이 no (Telnet 은 사용하지 않음)", "PermitRootLogin 이 yes 이거나 prohibit-password 등 root 접속을 허용",
  [("유효 설정 확인", "sshd -T | grep -i permitrootlogin"), ("설정 파일 확인(드롭인 포함)", "grep -rniE '^\\s*PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/")],
  [("sshd_config 수정(값이 있으면 변경, 없으면 추가)", "sed -i -E 's/^\\s*#?\\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"),
   ("문법 검사", "sshd -t"), ("무중단 반영(기존 연결 유지)", "systemctl reload sshd")],
  "새 접속부터 root 로 로그인할 수 없습니다. root 로만 접속해 쓰던 운영 스크립트나 배치가 있으면 실패합니다.",
  ["sshd -T | grep -i permitrootlogin 이 no", "다른 터미널에서 일반 관리자 계정으로 로그인 후 sudo 가 되는지 확인"],
  "조치 전에 wheel/sudo 그룹의 관리자 계정으로 로그인되는지 먼저 확인하세요. 현재 접속을 끊지 말고 별도 세션을 열어 둔 채 적용합니다. 도구는 이런 관리자 계정이 없으면 조치하지 않습니다.")

g("U-02", "추측하기 쉬운 비밀번호를 쓰지 못하게 복잡도와 사용 기간 정책을 시스템에 강제합니다.",
  "단순하거나 오래 쓴 비밀번호는 사전 공격·유출 비밀번호 대입에 쉽게 뚫립니다.",
  "비밀번호 최소 8자, 영문 대소문자·숫자·특수문자 조합, 최대 사용기간 90일 이하, 최소 사용기간 1일 이상, 최근 비밀번호 4회 기억",
  "위 정책 중 하나라도 설정되어 있지 않음",
  [("복잡도 설정 확인", "grep -E '^\\s*(minlen|dcredit|ucredit|lcredit|ocredit|minclass|enforce_for_root)' /etc/security/pwquality.conf"),
   ("사용기간 확인", "grep -E '^\\s*PASS_(MAX|MIN|WARN)' /etc/login.defs"), ("기억 횟수 확인", "grep -rE 'pam_pwhistory' /etc/pam.d/")],
  [("복잡도 설정(pwquality)", "printf 'minlen = 8\\ndcredit = -1\\nucredit = -1\\nlcredit = -1\\nocredit = -1\\nenforce_for_root\\n' >> /etc/security/pwquality.conf"),
   ("사용기간 설정", "sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs"),
   ("기억 횟수 설정(Rocky 9)", "authselect enable-feature with-pwhistory   # pwhistory.conf 에 remember = 4"),
   ("기존 계정에도 사용기간 적용", "chage -M 90 -m 1 <계정>")],
  "다음 비밀번호 변경부터 정책이 적용되어 기존 약한 비밀번호는 변경 시 거부됩니다. 사용자 공지가 필요하고, 서비스 계정에 일괄 적용하면 비밀번호 만료로 서비스가 멈출 수 있습니다.",
  ["passwd <테스트계정> 에서 약한 비밀번호가 거부됨", "chage -l <계정> 으로 최대/최소 사용기간 확인"],
  "서비스(비로그인) 계정에는 chage 를 적용하지 마세요. 정책을 바꾸기 전 /etc/security/pwquality.conf, /etc/login.defs 를 백업합니다.")

g("U-03", "로그인 실패가 반복되면 계정을 잠가 무차별 대입 공격을 막습니다.",
  "실패 횟수 제한이 없으면 비밀번호를 무제한으로 시도할 수 있습니다.",
  "계정 잠금 임계값(deny)이 1~10회", "임계값이 없거나 10회를 초과",
  [("faillock 설정 확인", "grep -E '^\\s*(deny|unlock_time|fail_interval)' /etc/security/faillock.conf"), ("PAM 적용 확인", "authselect current; grep -r pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth")],
  [("임계값 설정", "sed -i -E 's/^#?\\s*deny\\s*=.*/deny = 10/' /etc/security/faillock.conf"),
   ("잠금 해제 시간(초)", "sed -i -E 's/^#?\\s*unlock_time\\s*=.*/unlock_time = 600/' /etc/security/faillock.conf"),
   ("faillock 사용 활성화(Rocky 9)", "authselect enable-feature with-faillock && authselect apply-changes")],
  "임계값을 넘으면 해당 계정이 일정 시간 로그인할 수 없습니다. 자동화 도구의 잘못된 비밀번호로 서비스 계정이 잠길 수 있습니다.",
  ["faillock --user <계정> 으로 실패 기록 확인", "grep deny /etc/security/faillock.conf 가 10 이하"],
  "잠금 정책을 바꾸다 PAM 설정이 깨지면 로그인이 막힙니다. 반드시 별도 root 세션을 열어 둔 채 적용하세요.")

g("U-04", "비밀번호 해시를 누구나 읽을 수 있는 /etc/passwd 가 아니라 root 만 읽는 /etc/shadow 에 저장합니다.",
  "passwd 에 해시가 있으면 모든 사용자가 해시를 가져가 오프라인으로 해독할 수 있습니다.",
  "/etc/passwd 의 비밀번호 필드가 x 이고 /etc/shadow 가 존재(shadow 사용)", "passwd 에 해시가 직접 저장되어 있음",
  [("passwd 필드 확인", "awk -F: '$2 != \"x\" {print $1\":\"$2}' /etc/passwd"), ("shadow 존재 확인", "ls -l /etc/shadow")],
  [("백업", "cp -p /etc/passwd /etc/passwd.bak; cp -p /etc/shadow /etc/shadow.bak"), ("shadow 로 전환", "pwconv"), ("확인", "awk -F: '$2 != \"x\"' /etc/passwd")],
  "해시가 shadow 로 옮겨지고 일반 사용자는 읽을 수 없습니다. 정상 서비스에는 영향이 없습니다.",
  ["passwd 의 두 번째 필드가 모두 x", "ls -l /etc/shadow 가 root 소유, 권한 400 이하"], "현대 리눅스는 기본 shadow 를 쓰므로 취약이 나오면 계정이 수동 수정되었는지도 확인하세요.")

g("U-05", "root 와 같은 UID 0 을 가진 계정이 없도록 관리해 숨은 관리자 계정을 막습니다.",
  "UID 0 은 root 와 동일한 권한이라, 다른 이름의 UID 0 계정은 흔적을 숨기는 백도어로 쓰입니다.",
  "root 외에 UID 0 인 계정이 없음", "root 가 아닌 UID 0 계정이 있음",
  [("UID 0 계정 확인", "awk -F: '$3 == 0 {print $1}' /etc/passwd")],
  [("해당 계정이 필요한지 확인", "id <계정>; last <계정>"), ("필요 없으면 잠금 후 삭제 검토", "usermod -L <계정>; userdel <계정>"), ("필요하면 새 UID 부여", "usermod -u <새UID> <계정>")],
  "UID 를 바꾸면 그 계정이 소유한 파일의 소유자를 다시 맞춰야 합니다(find / -uid <옛UID> -exec chown). 서비스가 해당 계정으로 돌고 있으면 영향이 큽니다.",
  ["awk -F: '$3==0' /etc/passwd 결과가 root 하나"], "도구는 root 외 UID 0 계정의 UID 를 사용 중인 UID 중 가장 뒤 번호(최대값+1)로 바꿉니다(확인 후 적용). 계정은 삭제하지 않고, 홈·메일함 안의 예전 UID 소유 항목만 새 UID 로 바뀝니다. 그 밖의 위치에 있는 파일 소유자는 그대로이니 필요하면 직접 chown 하세요.")

g("U-06", "su 명령을 관리자 그룹(wheel) 구성원만 쓰게 해 root 전환 시도를 제한합니다.",
  "su 를 모두에게 열어 두면 일반 계정이 탈취될 때 root 비밀번호를 추측하는 공격이 쉬워집니다.",
  "su 를 특정 그룹(wheel)만 사용(pam_wheel 적용 또는 /usr/bin/su 그룹·권한 제한)", "su 사용 제한이 없음",
  [("pam 설정 확인", "grep -n pam_wheel /etc/pam.d/su"), ("su 권한 확인", "ls -l /usr/bin/su"), ("wheel 구성원 확인", "getent group wheel")],
  [("pam_wheel 주석 해제", "sed -i -E 's/^#\\s*(auth\\s+required\\s+pam_wheel.so\\s+use_uid.*)/\\1/' /etc/pam.d/su"), ("관리자를 wheel 에 추가(필수)", "usermod -aG wheel <관리자계정>")],
  "wheel 그룹이 아닌 계정은 su 로 전환할 수 없습니다. wheel 에 아무도 없으면 root 로 전환할 수 없게 되므로 먼저 구성원을 추가하세요.",
  ["wheel 계정은 su 가 되고, 그 외 계정은 거부됨"], "적용 전 현재 사용하는 관리자 계정을 wheel 에 넣었는지 반드시 확인하세요.")

g("U-08", "관리자 그룹에 꼭 필요한 계정만 두어 권한이 과도하게 퍼지는 것을 막습니다.",
  "관리자 그룹 구성원은 시스템 전체 권한을 가지므로 퇴사자·테스트 계정이 남아 있으면 침해 경로가 됩니다.",
  "root/wheel/sudo 그룹에 업무상 필요한 계정만 포함", "불필요한 계정이 관리자 그룹에 포함",
  [("구성원 확인", "getent group root wheel sudo"), ("계정 마지막 접속 확인", "lastlog -u <계정>")],
  [("불필요한 계정을 그룹에서 제거", "gpasswd -d <계정> wheel")],
  "제거된 계정은 sudo/su 로 관리 작업을 할 수 없습니다. 담당자 확인 없이 제거하지 마세요.",
  ["getent group wheel 에 필요한 계정만 있음"], "도구는 관리자 그룹(root, wheel, sudo, admin)마다 root 외 1명만 남기고 나머지를 그룹에서 제거합니다(확인 후 적용). 남기는 계정은 도구를 sudo 로 실행한 계정이 구성원이면 그 계정, 아니면 그룹 목록의 맨 앞 계정입니다. 계정은 삭제하지 않습니다. wheel 에서 빠진 계정은 sudo 를 쓸 수 없으니 SSH 로 작업 중이면 주의하세요.")

g("U-10", "계정마다 고유한 UID 를 쓰게 해 사용자 구분과 감사 추적이 가능하게 합니다.",
  "UID 가 같으면 서로 다른 계정이 같은 파일 권한을 공유하고 로그에서도 구분되지 않습니다.",
  "중복된 UID 가 없음", "동일 UID 를 쓰는 계정이 있음",
  [("중복 UID 확인", "cut -d: -f3 /etc/passwd | sort -n | uniq -d")],
  [("중복 UID 의 계정 확인", "awk -F: '$3==<UID> {print $1}' /etc/passwd"), ("한 계정에 새 UID 부여", "usermod -u <새UID> <계정>"), ("파일 소유자 재설정", "find / -xdev -uid <옛UID> -exec chown <계정> {} +")],
  "UID 변경 시 해당 계정의 파일 소유권을 다시 지정해야 하며, 실행 중인 프로세스는 재시작이 필요합니다.",
  ["cut -d: -f3 /etc/passwd | sort -n | uniq -d 결과가 없음"], "도구는 중복 UID 마다 정해진 규칙으로 계정의 UID 를 바꿉니다(확인 후 적용): UID 0 은 root 유지, 3000 미만은 배포판 기본 계정 유지·그 외 변경(기본 계정끼리 겹치면 수동), 3000 이상은 /etc/passwd 에서 위에 있는 계정 유지. 새 UID 는 사용 중인 UID 의 최대값+1 부터 차례로 부여합니다. 홈·메일함 밖의 예전 UID 소유 파일은 그대로이니 업무 시간 외에 확인하세요. 스냅샷 복구는 /etc/passwd 와 홈 디렉터리 자체만 되돌리며 안의 파일 소유자는 복구하지 못합니다.")

g("U-13", "비밀번호를 안전한 해시 알고리즘으로 저장하게 합니다.",
  "MD5 같은 약한 알고리즘은 해시가 유출되면 빠르게 해독됩니다.",
  "ENCRYPT_METHOD 가 SHA256/SHA512/YESCRYPT 이고 기존 계정이 MD5·DES 해시가 아님", "약한 알고리즘 사용",
  [("설정 확인", "grep ENCRYPT_METHOD /etc/login.defs"), ("계정별 해시 종류", "awk -F: '$2 ~ /^\\$1\\$/ {print $1}' /etc/shadow")],
  [("알고리즘 지정", "sed -i -E 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs"), ("MD5 해시 계정은 비밀번호 재설정", "passwd <계정>")],
  "설정을 바꿔도 기존 해시는 그대로이며 비밀번호를 다시 설정해야 새 알고리즘으로 저장됩니다.",
  ["ENCRYPT_METHOD SHA512", "새로 변경한 계정 해시가 $6$ 로 시작"], "")

g("U-14", "root 의 PATH 에 현재 디렉터리('.')나 빈 항목이 앞쪽에 있어 악성 파일이 먼저 실행되는 것을 막습니다.",
  "PATH 앞쪽에 . 또는 :: 가 있으면 공격자가 둔 같은 이름의 파일이 시스템 명령 대신 실행될 수 있습니다.",
  "root 의 PATH 맨 앞·중간에 . 이나 빈 항목(::)이 없음(맨 끝은 허용)", "PATH 앞/중간에 . 또는 :: 포함",
  [("PATH 확인", "echo $PATH"), ("설정 위치 검색", "grep -n 'PATH' /root/.bash_profile /root/.bashrc /etc/profile /etc/profile.d/*.sh")],
  [("해당 파일에서 . 항목 제거", "vi /root/.bash_profile   # PATH=... 에서 '.' 과 '::' 삭제"), ("재로그인 후 확인", "echo $PATH")],
  "PATH 에서 . 을 빼면 현재 디렉터리의 프로그램을 ./이름 으로 실행해야 합니다.",
  ["echo $PATH 에 . 이나 :: 가 없음"], "도구는 설정 파일의 PATH 대입 줄에서 '.' 과 빈 항목을 제거해 기본 형태로 되돌립니다(확인 후 적용). 다른 줄은 건드리지 않으며, 조치 전 스냅샷으로 복구할 수 있습니다. 현재 셸에는 로그아웃 후 다시 로그인해야 반영됩니다.")

g("U-15", "소유자나 그룹이 없는 파일을 찾아 정리해 의도치 않은 권한 상속을 막습니다.",
  "삭제된 계정의 UID 를 새 계정이 재사용하면 이전 파일을 그대로 소유하게 됩니다.",
  "소유자(nouser)나 그룹(nogroup)이 없는 파일·디렉터리가 없음", "소유자/그룹 없는 파일이 있음",
  [("검색(시간이 걸림)", "find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null")],
  [("파일 용도 확인", "ls -ld <파일>; rpm -qf <파일>"), ("필요하면 소유자 지정, 아니면 삭제", "chown <계정>:<그룹> <파일>   # 또는 rm <파일>")],
  "전체 파일시스템을 검색하므로 디스크 I/O 부하가 생깁니다. 점검 시간대에 실행하세요.",
  ["find 결과가 없음"], "전체 검색이라 시간이 오래 걸립니다. 도구는 삭제하지 않고 소유자/그룹을 root 로만 바꿉니다(확인 후 적용, 300건 초과 시 수동).")
