#!/usr/bin/env python3
"""우분투 전용 스크립트 생성기: code/scripts/ubuntu/items/ 에 U-02, U-03, U-66 을 만든다.

공통 스크립트(code/scripts/items/)는 rpm/dpkg 를 모두 처리하므로 대부분 우분투에서도 그대로 쓴다.
배포판마다 설정 방식이 달라 따로 필요한 항목만 공통 스크립트를 바탕으로 해당 부분을 바꿔 만든다:
  U-02 비밀번호 기억(pam_pwhistory)을 PAM 에 켜는 방법  (RHEL: authselect / 우분투: pam-auth-update 프로필)
  U-03 계정 잠금(pam_faillock)을 PAM 에 켜는 방법        (RHEL: authselect / 우분투: pam-auth-update 프로필)
  U-66 로그 파일 이름                                   (RHEL: messages, secure / 우분투: syslog, auth.log)
사용: python3 tools/gen_ubuntu_scripts.py     (공통 스크립트를 고친 뒤에는 이 생성기를 다시 실행)
"""
from pathlib import Path

TOP = Path(__file__).resolve().parent.parent
SRC = TOP / "code" / "scripts" / "items"
DST = TOP / "code" / "scripts" / "ubuntu" / "items"

PAMCFG = "/usr/share/pam-configs"


def sub(text, old, new):
    assert text.count(old) == 1, f"치환 대상이 1개가 아님: {old[:60]!r} ({text.count(old)})"
    return text.replace(old, new)


def make_u02(t):
    t = sub(t, "# U-02 비밀번호 관리 정책", "# U-02 비밀번호 관리 정책  [우분투 전용: pam-auth-update 프로필로 pam_pwhistory 적용]")
    t = sub(t, '''PWH=/etc/security/pwhistory.conf
''', f'''PWH=/etc/security/pwhistory.conf
PROF={PAMCFG}/isms-pwhistory
CPW=/etc/pam.d/common-password
''')
    t = sub(t, '''[ -f "$PWH" ] || printf '%s\\t비밀번호 기억 설정(없음, 생성될 수 있음)\\n' "$PWH"; state GOOD "목록" ;;''',
            '''[ -f "$PWH" ] || printf '%s\\t비밀번호 기억 설정(없음, 생성될 수 있음)\\n' "$PWH"; printf '%s\\tPAM 비밀번호 설정(조치 시 pam-auth-update 가 수정)\\n' "$CPW"; printf '%s\\tpam-auth-update 프로필(조치 시 생성)\\n' "$PROF"; state GOOD "목록" ;;''')
    t = sub(t, '''    kv_set "$PWH" remember 4 " = "
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWH" || { nl_end "$PWH"; echo enforce_for_root >> "$PWH"; }
''', '''    kv_set "$PWH" remember 4 " = "
    grep -Eq '^[[:space:]]*enforce_for_root' "$PWH" || { nl_end "$PWH"; echo enforce_for_root >> "$PWH"; }
    if ! grep -Eqs '^[[:space:]]*password[[:space:]].*pam_pwhistory\\.so' "$CPW"; then
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
''')
    t = sub(t, "  probs=(); local v\n", "  probs=(); local v\n  grep -Eqs '^[[:space:]]*password[[:space:]].*pam_pwquality\\.so' \"$CPW\" || probs+=(\"PAM 에 pam_pwquality 없음(libpam-pwquality 설치 필요)\")\n")
    t = sub(t, "    [ -f \"$PWQ\" ] || { : > \"$PWQ\"; chmod 644 \"$PWQ\"; }\n", "    [ -f \"$PWQ\" ] || { : > \"$PWQ\"; chmod 644 \"$PWQ\"; }\n    pwq_files=(\"$PWQ\"); for f in \"$PWQD\"/*.conf; do [ -f \"$f\" ] && pwq_files+=(\"$f\"); done\n")
    t = sub(t, "(기존 계정의 만료 기간은 chage 로 따로 적용, pam_pwhistory 가 PAM 에 있어야 기억 설정이 동작)",
            "(기존 계정의 만료 기간은 chage 로 따로 적용, pam-auth-update 로 PAM 에 pam_pwhistory 적용)")
    return t


def make_u03(t):
    t = sub(t, "# U-03 ", "# U-03 [우분투 전용: pam-auth-update 프로필로 pam_faillock 적용] ") if "# U-03 " in t else t
    t = sub(t, "FC=/etc/security/faillock.conf\n", f"FC=/etc/security/faillock.conf\nPROF1={PAMCFG}/isms-faillock\nPROF2={PAMCFG}/isms-faillock-notify\n")
    old_list = '''    if have authselect; then for f in /etc/authselect/*'''
    i = t.index(old_list)
    j = t.index("\n", i)
    t = t[:i] + '''    for f in "$PROF1" "$PROF2"; do printf '%s\\tpam-auth-update 프로필(조치 시 생성)\\n' "$f"; done''' + t[j:]
    old = t[t.index("    if ! pam_has; then\n      if have authselect; then"):t.index("    [ -f \"$FC\" ] ||")]
    new = '''    if ! pam_has; then
      have pam-auth-update || { state ERROR "pam-auth-update 가 없어 PAM 을 자동 수정할 수 없음(가이드 참고)"; exit 1; }
      ls /lib/*/security/pam_faillock.so /usr/lib/*/security/pam_faillock.so >/dev/null 2>&1 \\
        || { state ERROR "pam_faillock 모듈이 없어 적용할 수 없음(libpam-modules 1.4 이상 필요)"; exit 1; }
      cat > "$PROF1" <<'EOP'
Name: ISMS faillock (count failures)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
	sufficient	pam_faillock.so authsucc
Account-Type: Primary
Account:
	required	pam_faillock.so
EOP
      cat > "$PROF2" <<'EOP'
Name: ISMS faillock (check lock before password)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth-Initial:
	required	pam_faillock.so preauth
Auth:
	required	pam_faillock.so preauth
EOP
      chmod 644 "$PROF1" "$PROF2"
      if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable isms-faillock isms-faillock-notify >/dev/null 2>&1 || ! pam_has; then
        rm -f "$PROF1" "$PROF2"; DEBIAN_FRONTEND=noninteractive pam-auth-update --package >/dev/null 2>&1
        state ERROR "pam-auth-update 로 faillock 적용에 실패(프로필을 제거함, 엔진이 원복합니다)"; exit 1; fi
    fi
'''
    t = t.replace(old, new)
    return t


def make_u66(t):
    t = sub(t, "# U-66 ", "# U-66 [우분투 전용: 로그 파일 syslog/auth.log/mail.log/cron.log] ") if "# U-66 " in t else t
    a = t.index("  echo \"$r\" | grep -Eq '\\*\\.info")
    b = t.index("  echo \"$r\" | grep -Eq '\\*\\.emerg")
    t = t[:a] + '''  echo "$r" | grep -Eq '\\*\\.\\*;auth,authpriv\\.none.*[[:space:]]-?/var/log/syslog' || miss+=("*.*;auth,authpriv.none  -/var/log/syslog")
  echo "$r" | grep -Eq '(auth,authpriv|authpriv|auth)\\.\\*.*[[:space:]]-?/var/log/auth\\.log' || miss+=("auth,authpriv.*  /var/log/auth.log")
  echo "$r" | grep -Eq 'mail\\.\\*.*[[:space:]]-?/var/log/mail\\.log' || miss+=("mail.*  -/var/log/mail.log")
  echo "$r" | grep -Eq 'cron\\.\\*.*[[:space:]]-?/var/log/cron' || miss+=("cron.*  /var/log/cron.log")
''' + t[b:]
    return t


def main():
    DST.mkdir(parents=True, exist_ok=True)
    for iid, fn in (("U-02", make_u02), ("U-03", make_u03), ("U-66", make_u66)):
        out = fn((SRC / f"{iid}.sh").read_text(encoding="utf-8"))
        (DST / f"{iid}.sh").write_text(out, encoding="utf-8")
        print("생성:", DST / f"{iid}.sh")


if __name__ == "__main__":
    main()
