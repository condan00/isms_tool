#!/usr/bin/env python3
"""isms_lite_check.sh 생성기: 내부 파일 없이 쉘 파일 하나로 모든 항목을 '점검'하는 스크립트를 만든다.

  사용: python3 tools/gen_lite_check.py        (결과: 도구 폴더 맨 위의 isms_lite_check.sh, build.sh 와 같은 위치)

- 점검 로직은 code/scripts 의 항목 스크립트에서 가져온다(점검 규칙이 한 곳에만 있도록).
  - 조치(apply)·목록(list) 분기는 버리고 점검(check) 분기만 남긴다.
  - 여러 스크립트에 똑같이 들어 있는 공통 함수(state, have, pkg_any ...)는 한 번만 넣는다.
  - 항목마다 함수(chk_U04 ...) 하나가 되고, 실행할 때 따로 떨어진 프로세스(timeout 300 bash -c)에서 돌린다.
- 스크립트를 고치면 이 생성기를 다시 돌려야 한다(tests/test_engine.py 가 최신인지 검사한다).
"""
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CODE = ROOT / "code"
OUT = ROOT / "isms_lite_check.sh"
SKIP_LINES = ("#!/bin/bash", "set -u", "export LC_ALL=C", "shopt -s nullglob")
FUNC_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) *\{")
LABEL_RE = re.compile(r"^  (list|check|apply|\*)\)")


def brace_delta(line, q=None):
    """한 줄의 중괄호 균형({ 는 +1, } 는 -1)과 줄 끝의 따옴표 상태. 따옴표 안(여러 줄 포함), 주석, ${...} 는 무시한다."""
    depth = 0
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "\\":
            i += 2
            continue
        elif c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        elif c == "$" and i + 1 < n and line[i + 1] == "{":
            d = 1
            i += 2
            while i < n and d:
                d += (line[i] == "{") - (line[i] == "}")
                i += 1
            continue
        elif c == "{" and (i + 1 == n or line[i + 1] in " \t"):
            depth += 1
        elif c == "}" and (i == 0 or line[i - 1] in " \t;") :
            depth -= 1
        i += 1
    return depth, q


def split_blocks(lines):
    """맨 앞 칸에서 시작하는 함수 정의를 (이름, 줄 목록)으로 떼어 내고, 나머지 줄을 돌려준다."""
    funcs, rest, i = [], [], 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            rest.append(lines[i])
            i += 1
            continue
        depth, j, q = 0, i, None
        while j < len(lines):
            d, q = brace_delta(lines[j], q)
            depth += d
            if depth <= 0 and q is None:
                break
            j += 1
        funcs.append((m.group(1), lines[i:j + 1]))
        i = j + 1
    return funcs, rest


def check_only(rest, name):
    """맨 끝 case "${1:-}" in ... esac 에서 check) 분기만 풀어 쓴다."""
    try:
        s = next(k for k, l in enumerate(rest) if l == 'case "${1:-}" in')
        e = max(k for k, l in enumerate(rest) if l == "esac")
    except (StopIteration, ValueError):
        sys.exit(f"{name}: case \"${{1:-}}\" in ... esac 구조를 찾지 못했습니다")
    branches, cur = {}, None
    for l in rest[s + 1:e]:
        m = LABEL_RE.match(l)
        if m:
            cur = m.group(1)
            branches[cur] = [l[m.end():]]
        elif cur is not None:
            branches[cur].append(l)
    if "check" not in branches:
        sys.exit(f"{name}: check) 분기가 없습니다")
    body = branches["check"]
    # 분기 끝의 ;; 제거
    while body and not body[-1].strip():
        body.pop()
    body[-1] = re.sub(r"\s*;;\s*$", "", body[-1])
    body = [l for l in body]
    if body and not body[0].strip():
        body = body[1:]
    after = [l for l in rest[e + 1:] if l.strip()]
    if after:
        sys.exit(f"{name}: esac 뒤에 코드가 있습니다: {after[:1]}")
    return rest[:s] + [re.sub(r"^    ", "", l, count=1) if l.startswith("    ") else l for l in body]


def title_of(lines):
    return lines[1].lstrip("# ").strip() if len(lines) > 1 and lines[1].startswith("#") else ""


def load(path, name):
    text = path.read_text(encoding="utf-8")
    lines = [l for l in text.split("\n")]
    head_title = title_of(lines)
    lines = [l for l in lines if l.rstrip() not in SKIP_LINES]
    funcs, rest = split_blocks(lines)
    # 앞의 주석 머리말은 버리고(제목은 따로), 점검 분기만 남긴다
    rest = [l for l in rest]
    body = check_only(rest, name)
    # 맨 앞 주석 줄(머리말) 제거
    while body and (body[0].startswith("#") or not body[0].strip()):
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return head_title, funcs, body


def main():
    items_dir = CODE / "scripts" / "items"
    ubuntu_dir = CODE / "scripts" / "ubuntu" / "items"
    entries = []     # (kind, id, title, funcs, body)
    for p in sorted(items_dir.glob("U-*.sh")):
        t, f, b = load(p, p.name)
        entries.append(("common", p.stem, t, f, b))
    for p in sorted(ubuntu_dir.glob("U-*.sh")):
        t, f, b = load(p, "ubuntu/" + p.name)
        entries.append(("ubuntu", p.stem, t, f, b))

    # 공통 함수: 같은 이름이 둘 이상의 스크립트에 있고 내용이 모두 같으면 한 번만 둔다
    seen = OrderedDict()
    for _, _, _, funcs, _ in entries:
        for name, text in funcs:
            seen.setdefault(name, []).append("\n".join(text))
    hoist = OrderedDict((n, v[0]) for n, v in seen.items() if len(v) >= 2 and len(set(v)) == 1)

    parts = []
    for kind, iid, title, funcs, body in entries:
        local = [t for n, t in funcs if n not in hoist]
        fn = ("chk_ubuntu_" if kind == "ubuntu" else "chk_") + iid.replace("-", "")
        inner = []
        for t in local:
            inner += t
        inner += body
        label = f"{iid} {title}" + (" (Ubuntu 전용)" if kind == "ubuntu" else "")
        parts.append(f"# ---- {label}\n{fn}() (\nset -- check     # 원본 스크립트의 ${{1:-}} 점검용\n" + "\n".join(inner) + "\n)\n")

    ids_all = [i for k, i, *_ in entries if k == "common"]
    text = TEMPLATE
    text = text.replace("@HOIST@", "\n".join(hoist.values()))
    text = text.replace("@ITEMS@", "\n".join(parts))
    text = text.replace("@IDS@", " ".join(ids_all))
    text = text.replace("@EXPORT@", " ".join(list(hoist) + [("chk_ubuntu_" if k == "ubuntu" else "chk_") + i.replace("-", "") for k, i, *_ in entries]))
    OUT.write_text(text, encoding="utf-8")
    OUT.chmod(0o755)
    print(f"생성: {OUT}  ({text.count(chr(10)) + 1}줄, {len(text) // 1024}KB, 항목 {len(ids_all)}개 / 공통 함수 {len(hoist)}개)")


TEMPLATE = r'''#!/bin/bash
# ISMS 점검 lite - 여러 서버에 돌려서 취약한 항목만 모으기 위한 점검 전용 쉘 파일 하나(시스템을 바꾸지 않는다).
#   sudo bash isms_lite_check.sh [1|2|auto]   1.Rocky 2.Ubuntu 3.Windows. 번호를 안 주면 터미널에서는 메뉴, 아니면(Ansible 등) OS 자동 판별
#   옵션: -v 모든 항목 출력 / --ids U-04,U-16 일부만 / --heavy 전체 파일 검색 항목(U-15,23,25,26)도
# 출력(취약한 것만):  <호스트>  U-02  근거...   마지막 줄  <호스트>  vuln: U-02, U-18  (없으면 vuln: X)
#   점검이 실패한 항목은  <호스트>  U-XX  ERROR ...  로 표시한다. 취약·오류가 있으면 종료 코드 1, 실행할 수 없으면 2.
# 이 파일 하나로 동작한다(다른 파일 필요 없음). 아래 '항목 점검' 부분은 code/scripts 의 점검 규칙을 그대로 옮긴 것이므로
# 직접 고치지 말고 tools/gen_lite_check.py 로 다시 만든다.
set -u; export LC_ALL=C; shopt -s nullglob
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HEAVY=" U-15 U-23 U-25 U-26 "; ALL="@IDS@"; HOST=$(hostname -s 2>/dev/null || echo host)
die() { echo "$HOST  오류: $*" >&2; exit 2; }

sel=""; verbose=0; heavy=0; only=""
while [ $# -gt 0 ]; do case "$1" in
  1|2|3|auto) sel=$1 ;; -v) verbose=1 ;; --heavy) heavy=1 ;; --ids) shift; only=${1:-} ;;
  -h|--help) sed -n '2,8p' "$0"; exit 0 ;; *) die "알 수 없는 옵션: $1" ;;
esac; shift; done
[ "$(id -u)" -eq 0 ] || die "root 권한이 필요합니다.  sudo bash isms_lite_check.sh"

# OS 확인: 번호를 주면 서버와 맞는지 확인, 안 주면(터미널이면 메뉴) 자동 판별
id=$(. /etc/os-release; echo "${ID:-}"); ver=$(. /etc/os-release; echo "${VERSION_ID:-}"); major=${ver%%.*}
if [ -z "$sel" ] && [ -t 0 ]; then printf '운영체제를 선택하세요\n  1. Rocky\n  2. Ubuntu\n  3. Windows\n번호 입력: '; read -r sel; fi
[ "$sel" = 3 ] && { echo "Windows 는 아직 지원하지 않습니다(준비 중)."; exit 0; }
case "$id" in rocky|centos) os=1 ;; ubuntu) os=2 ;; *) os=0 ;; esac
case "$os:$major" in 1:9|1:10|2:20|2:22|2:24|2:26) ;; *) die "지원하지 않는 OS 입니다 ($id $ver). Rocky/CentOS 9·10, Ubuntu 20·22·24·26" ;; esac
[ -z "$sel" ] || [ "$sel" = auto ] || [ "$sel" = "$os" ] || die "선택한 번호와 이 서버($id $ver)가 맞지 않습니다"
command -v apt-get >/dev/null && PKG=apt-get || PKG=dnf
export ISMS_OS_KEY="$id$major" ISMS_PKG_MANAGER="$PKG" ISMS_INVOKER=$(printf %s "${SUDO_USER:-}" | tr -cd 'A-Za-z0-9._-')

# ======================= 공통 함수 =======================
@HOIST@

# ======================= 항목 점검 (code/scripts 에서 옮겨 옴) =======================
@ITEMS@
export -f @EXPORT@

# ======================= 실행 =======================
list=""
for i in $ALL; do
  case "$HEAVY" in *" $i "*) [ $heavy = 1 ] || continue ;; esac
  [ -z "$only" ] || case ",$only," in *",$i,"*) ;; *) continue ;; esac
  list="$list $i"; done
[ -n "$list" ] || die "점검할 항목이 없습니다"

# 항목 점검 실행 → R_STATE(GOOD/VULN/MANUAL/NA/ERROR), R_EV(근거). 항목마다 따로 떨어진 프로세스에서, 300초 제한
run() {
  local n=${1//-/} fn out rc last
  fn=chk_$n; [ "$os" = 2 ] && declare -F "chk_ubuntu_$n" >/dev/null && fn=chk_ubuntu_$n
  out=$(cd / && timeout 300 bash -c "$fn" </dev/null 2>/dev/null); rc=$?
  last=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -n 1)
  if [ $rc -ne 0 ] || ! [[ "$last" =~ ^(GOOD|VULN|MANUAL|NA|ERROR)\| ]]; then R_STATE=ERROR; R_EV="점검 오류(코드 $rc): ${last:0:80}"
  else R_STATE=${last%%|*}; R_EV=${last#*|}; fi
}

vulns=(); errs=()
for i in $list; do
  run "$i"
  case "$R_STATE" in
    VULN)  printf '%s  %s  %s\n' "$HOST" "$i" "${R_EV:0:100}"; vulns+=("$i") ;;
    ERROR) printf '%s  %s  ERROR %s\n' "$HOST" "$i" "$R_EV"; errs+=("$i") ;;
    *)     [ $verbose = 1 ] && printf '%s  %s  %s %s\n' "$HOST" "$i" "${R_STATE/GOOD/양호}" "${R_EV:0:80}" ;;
  esac
done

j() { printf '%s, ' "$@" | sed 's/, $//'; }
[ ${#vulns[@]} -eq 0 ] && echo "$HOST  vuln: X" || echo "$HOST  vuln: $(j "${vulns[@]}")"
[ ${#errs[@]} -gt 0 ] && echo "$HOST  error: $(j "${errs[@]}")"
[ ${#vulns[@]} -eq 0 ] && [ ${#errs[@]} -eq 0 ]
'''

if __name__ == "__main__":
    main()
