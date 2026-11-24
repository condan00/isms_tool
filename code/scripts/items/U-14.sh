#!/bin/bash
# U-14 root 홈, 패스 디렉터리 권한 및 패스 설정  (엑셀 ?: 확인 후 적용)
# 기준: root 의 PATH 환경변수 맨 앞이나 중간에 '.' 또는 빈 항목(::)이 없음(맨 끝은 허용)
# 조치: 설정 파일의 PATH 대입 줄에서 '.' 과 빈 항목을 모두 제거해 기본 형태(예: PATH=$PATH:$HOME/bin)로 되돌린다. 다른 줄은 건드리지 않는다.
# 계약: bash U-14.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 손으로 쓴 스크립트다(tools/ 생성기 없음).
set -u
export LC_ALL=C
shopt -s nullglob
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

FILES=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/profile.d/*.sh /root/.profile /root/.bash_profile /root/.bashrc /root/.bash_login /root/.cshrc)
targets=(); for f in "${FILES[@]}"; do [ -f "$f" ] && [ ! -L "$f" ] && targets+=("$f"); done

bad=(); badfiles=()
scan() { bad=(); badfiles=(); local f line val parts n i hit
  for f in "${targets[@]}"; do
    hit=0
    while IFS= read -r line; do
      val=${line#*PATH=}; val=${val%%[;#]*}; val=${val//\"/}; val=${val//\'/}
      IFS=':' read -r -a parts <<<"$val"; n=${#parts[@]}
      for ((i = 0; i < n - 1; i++)); do
        if [ "${parts[$i]}" = "." ] || [ -z "${parts[$i]}" ]; then bad+=("$f"$'\t'"PATH 중간/앞에 '.' 또는 빈 항목: ${line:0:100}"); hit=1; break; fi
      done
      case "$val" in :*) bad+=("$f"$'\t'"PATH 맨 앞이 빈 항목(현재 디렉터리): ${line:0:100}"); hit=1 ;; esac
    done < <(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$f" 2>/dev/null | grep -v '^[[:space:]]*#')
    [ "$hit" -eq 1 ] && badfiles+=("$f")
  done; }
scan

# PATH= 대입 줄의 값에서 '.' 과 빈 항목을 뺀다(따옴표·뒤 주석은 유지)
clean_file() {
  awk '
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*(export[[:space:]]+)?PATH=/ {
      i = index($0, "PATH="); pre = substr($0, 1, i + 4); rest = substr($0, i + 5); q = ""
      if (substr(rest, 1, 1) == "\"" || substr(rest, 1, 1) == "\047") { q = substr(rest, 1, 1); rest = substr(rest, 2) }
      if (q != "") { e = index(rest, q) } else { e = match(rest, /[;# \t]/) }
      if (e == 0) { val = rest; tail = "" } else { val = substr(rest, 1, e - 1); tail = substr(rest, e) }
      n = split(val, p, ":"); out = ""; k = 0
      for (j = 1; j <= n; j++) { if (p[j] == "." || p[j] == "") continue; out = (k++ ? out ":" : "") p[j] }
      if (k == 0) { print; next }
      print pre q out tail; next }
    { print }' "$1"
}

case "${1:-}" in
  list) for f in "${targets[@]}"; do printf '%s\t환경 설정 파일\n' "$f"; done; state GOOD "${#targets[@]}개 파일" ;;
  check)
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad[@]}"; state VULN "PATH 에 '.' 이 앞/중간에 있는 설정 ${#bad[@]}건"
    else state GOOD "PATH 에 '.' 이 앞/중간에 없음 (점검 파일 ${#targets[@]}개)"; fi ;;
  apply)
    for f in "${badfiles[@]}"; do
      tmp=$(mktemp) || { state ERROR "임시 파일을 만들지 못했습니다"; exit 1; }
      clean_file "$f" > "$tmp" && [ -s "$tmp" ] && cat "$tmp" > "$f"
      rm -f "$tmp"
    done
    scan
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 PATH 문제가 ${#bad[@]}건 남았습니다"; exit 1; fi
    state GOOD "조치 완료: PATH 설정에서 '.' 과 빈 항목 제거 (${#targets[@]}개 파일 점검)" ;;
  *) echo "usage: U-14.sh check|apply|list" >&2; exit 2 ;;
esac
