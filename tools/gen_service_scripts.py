#!/usr/bin/env python3
"""서비스 비활성화 묶음 스크립트 생성기: U-34, 36, 38, 39, 41, 42, 43, 44, 52, 54, 58.

systemd 유닛 + (x)inetd 항목을 함께 본다. 대상 패키지·유닛·설정이 하나도 없으면 NA(해당없음).
조치는 systemctl disable --now 와 설정 파일 편집(xinetd disable=yes, inetd.conf 주석 처리)만 한다.
서비스 상태(부팅 시 시작/동작 여부)는 list 가 '@service' 줄로 알려 주고 엔진 스냅샷이 복구한다.
사용: python3 tools/gen_service_scripts.py [출력 폴더]
"""
import sys
from pathlib import Path

# id: dict(title, units, pkgs, xinetd, inetd, guard_units, guard_exports, apply, criteria)
SPECS = {
    "U-34": dict(title="Finger 서비스 비활성화", units=["finger.service", "finger.socket", "fingerd.service"],
                 pkgs=["finger-server", "fingerd", "efingerd", "cfingerd"], xinetd=["finger"], inetd=["finger"],
                 apply=True, criteria="Finger 서비스가 비활성화"),
    "U-36": dict(title="r 계열 서비스 비활성화", units=["rlogin.socket", "rlogin.service", "rsh.socket", "rsh.service",
                 "rexec.socket", "rexec.service", "rsh-server.service"],
                 pkgs=["rsh-server", "rsh-redone-server", "rsh"], xinetd=["rsh", "rlogin", "rexec", "shell", "login", "exec"],
                 inetd=["shell", "login", "exec", "rsh", "rlogin", "rexec"], apply=True,
                 criteria="rlogin, rsh, rexec 서비스가 비활성화 (엑셀 ?: 확인 후 비활성화)"),
    "U-38": dict(title="DoS공격에 취약한 서비스 비활성화",
                 units=["echo.service", "echo.socket", "echo-dgram.socket", "echo-stream.socket", "discard.service", "discard.socket",
                        "discard-dgram.socket", "discard-stream.socket", "daytime.service", "daytime.socket", "daytime-dgram.socket",
                        "daytime-stream.socket", "chargen.service", "chargen.socket", "chargen-dgram.socket", "chargen-stream.socket"],
                 pkgs=["xinetd", "openbsd-inetd"],
                 xinetd=["echo", "echo-dgram", "echo-stream", "discard", "discard-dgram", "discard-stream", "daytime",
                         "daytime-dgram", "daytime-stream", "chargen", "chargen-dgram", "chargen-stream"],
                 inetd=["echo", "discard", "daytime", "chargen"], apply=True,
                 criteria="echo, discard, daytime, chargen 서비스가 비활성화 (ntp/dns/snmp 는 필요 여부 확인 후 수동)"),
    "U-39": dict(title="불필요한 NFS 서비스 비활성화",
                 units=["nfs-server.service", "nfs-mountd.service", "nfs-idmapd.service", "nfs-blkmap.service", "nfsdcld.service"],
                 pkgs=["nfs-utils", "nfs-kernel-server"], xinetd=[], inetd=[], apply=True,
                 guard_exports="/etc/exports", criteria="NFS 서비스 데몬이 비활성화 (공유 설정이 있으면 수동 확인)"),
    "U-41": dict(title="불필요한 automountd 제거", units=["autofs.service", "automount.service"],
                 pkgs=["autofs"], xinetd=[], inetd=[], apply=True, criteria="autofs(automountd)가 비활성화"),
    "U-42": dict(title="불필요한 RPC 서비스 비활성화",
                 units=["rpcbind.service", "rpcbind.socket", "rpc-statd.service", "rpc-statd-notify.service", "rpc.statd.service"],
                 pkgs=["rpcbind"], xinetd=["rpc-statd", "rpc.statd", "rstatd", "rusersd", "rquotad", "sprayd", "walld"],
                 inetd=["rstatd", "rusersd", "rquotad", "sprayd", "walld", "rpc.cmsd"], apply=True,
                 guard_units=["nfs-server.service", "nfs-mountd.service", "ypbind.service", "ypserv.service"],
                 criteria="불필요한 RPC 서비스가 비활성화 (NFS/NIS 가 쓰고 있으면 수동 확인)"),
    "U-43": dict(title="NIS, NIS+ 점검",
                 units=["ypserv.service", "ypbind.service", "ypxfrd.service", "yppasswdd.service", "ypupdated.service",
                        "rpc-yppasswdd.service"],
                 pkgs=["ypserv", "ypbind", "yp-tools", "nis"], xinetd=[], inetd=[], apply=True, criteria="NIS 서비스가 비활성화"),
    "U-44": dict(title="tftp, talk 서비스 비활성화",
                 units=["tftp.service", "tftp.socket", "tftpd-hpa.service", "talk.service", "talk.socket", "ntalk.service",
                        "ntalk.socket", "talkd.service"],
                 pkgs=["tftp-server", "tftpd-hpa", "tftpd", "talk-server", "talkd"], xinetd=["tftp", "talk", "ntalk"],
                 inetd=["tftp", "talk", "ntalk"], apply=True, criteria="tftp, talk, ntalk 서비스가 비활성화"),
    "U-52": dict(title="Telnet 서비스 비활성화", units=["telnet.socket", "telnet.service", "telnetd.service", "telnet@.service"],
                 pkgs=["telnet-server", "telnetd", "inetutils-telnetd"], xinetd=["telnet"], inetd=["telnet"], apply=True,
                 criteria="Telnet 서비스가 비활성화"),
    "U-54": dict(title="암호화되지 않는 FTP 서비스 비활성화",
                 units=["vsftpd.service", "proftpd.service", "pure-ftpd.service", "ftpd.service", "gssftp.service", "ftp.socket",
                        "wu-ftpd.service"],
                 pkgs=["vsftpd", "proftpd", "pure-ftpd", "ftpd", "krb5-appl-servers"], xinetd=["ftp", "gssftp", "wu-ftpd"],
                 inetd=["ftp"], apply=True, criteria="암호화되지 않는 FTP 서비스가 비활성화"),
    "U-58": dict(title="불필요한 SNMP 서비스 구동 점검", units=["snmpd.service", "snmptrapd.service"],
                 pkgs=["net-snmp", "snmpd"], xinetd=[], inetd=[], apply=True, criteria="SNMP 서비스가 비활성화"),
}

LEFT = {'U-36': '"/etc/hosts.equiv" "/root/.rhosts" "/home/*/.rhosts"', 'U-39': '"/etc/exports"', 'U-41': '"/etc/auto.master" "/etc/autofs.conf" "/etc/auto.master.d"', 'U-43': '"/etc/yp.conf" "/var/yp"', 'U-44': '"/var/lib/tftpboot" "/srv/tftp" "/tftpboot"', 'U-54': '"/etc/vsftpd*" "/etc/proftpd*" "/etc/pure-ftpd"', 'U-58': '"/etc/snmp"'}

TEMPLATE = r'''#!/bin/bash
# {id} {title}
# 기준: {criteria}
# 계약: bash {id}.sh check|{apply_word}list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상 패키지/유닛/설정이 하나도 없으면 NA. 서비스 상태는 list 의 '@service' 줄로 알려 주며 엔진 스냅샷이 복구한다.
# 이 파일은 tools/gen_service_scripts.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

UNIT_PATTERNS=({units})
PKGS=({pkgs})
XINETD=({xinetd})
INETD=({inetd})
GUARD_UNITS=({guard_units})
GUARD_EXPORTS="{guard_exports}"
LEFTOVER=({leftover})
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d

state() {{ printf '%s|%s\n' "$1" "$2"; }}
have() {{ command -v "$1" >/dev/null 2>&1; }}

pkg_any() {{    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}}

# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${{UNIT_PATTERNS[@]}}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${{units[@]}}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${{XINETD[@]}}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${{#INETD[@]}}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${{INETD[*]}}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi

unit_on() {{    # 켜져 있으면(부팅 시 시작 또는 동작 중) 0
  local en ac
  en=$(systemctl is-enabled "$1" 2>/dev/null); ac=$(systemctl is-active "$1" 2>/dev/null)
  [ "$en" = masked ] && return 1
  [ "$ac" = active ] || [ "$en" = enabled ] || [ "$en" = enabled-runtime ]
}}
xinetd_on() {{ grep -Eiq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "$1"; }}

bad_units=(); bad_xfiles=(); bad_info=()
scan_bad() {{
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${{units[@]}}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${{xfiles[@]}}"; do xinetd_on "$f" && {{ bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }}; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}}

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() {{ local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }}

if [ "${{#units[@]}}" -eq 0 ] && [ "${{#xfiles[@]}}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${{1:-}}" in check|list|apply)
    pkg_any "${{PKGS[@]}}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${{LEFTOVER[@]}}" | head -5 | tr '\n' ' ')
    if [ -n "${{l// /}}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${{GUARD_UNITS[@]}}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

case "${{1:-}}" in
  list)
    for u in "${{units[@]}}"; do
      printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
    done
    for f in "${{xfiles[@]}}"; do printf '%s\txinetd 설정\n' "$f"; done
    [ "$inetd_on" -eq 1 ] && printf '%s\tinetd 설정\n' "$INETD_CONF"
    state GOOD "유닛 ${{#units[@]}}개, xinetd 파일 ${{#xfiles[@]}}개" ;;
  check)
    scan_bad
    if [ "${{#bad_info[@]}}" -gt 0 ]; then
      printf '%s\n' "${{bad_info[@]}}"
      if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
      else state VULN "활성 서비스 ${{#bad_info[@]}}건 (기준: {short})"; fi
    else
      state GOOD "대상 서비스가 모두 비활성화되어 있음"
    fi ;;
{apply_block}  *)
    echo "usage: {id}.sh check|{apply_word}list" >&2; exit 2 ;;
esac
'''

APPLY = r'''  apply)
    scan_bad
    xchanged=${{#bad_xfiles[@]}}
    [ -n "$guard_hit" ] && {{ state ERROR "다른 서비스가 사용 중일 수 있어 자동 조치하지 않습니다($guard_hit)"; exit 1; }}
    for u in "${{bad_units[@]}}"; do
      systemctl disable --now "$u" >/dev/null 2>&1
      systemctl is-active "$u" >/dev/null 2>&1 && systemctl stop "$u" >/dev/null 2>&1
    done
    for f in "${{bad_xfiles[@]}}"; do sed -i -E 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]/\1yes/' "$f"; done
    inetd_changed=0
    if [ "$inetd_on" -eq 1 ]; then
      inetd_changed=1
      pat=$(IFS='|'; echo "${{INETD[*]}}")
      sed -i -E "s/^([[:space:]]*($pat)[[:space:]])/#\1/" "$INETD_CONF"
      inetd_on=0; grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
    fi
    scan_bad
    if [ "${{#bad_info[@]}}" -gt 0 ]; then printf '%s\n' "${{bad_info[@]}}"; state ERROR "조치 후에도 ${{#bad_info[@]}}건이 남아 있음"; exit 1; fi
    note=""
    if [ "$xchanged" -gt 0 ] || [ "$inetd_changed" -eq 1 ]; then
      for u in xinetd.service inetd.service openbsd-inetd.service; do
        have systemctl && systemctl is-active "$u" >/dev/null 2>&1 && systemctl reload "$u" >/dev/null 2>&1 && note=" (재적용: reload $u)"
      done
    fi
    state GOOD "조치 완료: 서비스 비활성화$note" ;;
'''


def q(items):
    return " ".join(f'"{i}"' for i in items)


def render(iid):
    s = SPECS[iid]
    short = s["criteria"].split(" (")[0]
    return TEMPLATE.format(
        id=iid, title=s["title"], criteria=s["criteria"], units=q(s["units"]), pkgs=q(s["pkgs"]), xinetd=q(s["xinetd"]),
        inetd=q(s["inetd"]), guard_units=q(s.get("guard_units", [])), guard_exports=s.get("guard_exports", ""), leftover=LEFT.get(iid, ""),
        short=short, apply_block=APPLY.format() if s["apply"] else "", apply_word="apply|" if s["apply"] else "")


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for iid in SPECS:
        (out / f"{iid}.sh").write_text(render(iid), encoding="utf-8")
        print("생성:", out / f"{iid}.sh")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "code" / "scripts" / "items")
