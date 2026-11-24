#!/usr/bin/env python3
"""ISMS 점검·조치 도구 진입점.

대화형:   sudo ./isms_tool
자동화:   sudo ./isms_tool --scan-only --severity 상 --format html,json --scope vuln
          sudo ./isms_tool --fix --ids U-16,U-18 --yes
복구:     sudo ./isms_tool --list-snapshots / --restore 20261113-101500 --yes
"""
import argparse
import os
import sys
from pathlib import Path

import os_info
from isms import messages
from isms.engine import Engine, EngineBusy
from isms.items import load_items, filter_items, ItemError
from isms import guidefiles
from isms.report import REPORTERS, build_report, save_run, SCOPES
from isms.runner import script_path
from isms.util import default_report_dir

RISKY = {"U-01", "U-02", "U-03", "U-06", "U-08"}
DEFAULT_DATA = "/var/lib/isms-tool"


DEFAULT_FORMATS = "json,txt"

def parse_args(argv):
    p = argparse.ArgumentParser(prog="isms_tool", description="ISMS(주통2026 Unix) 점검·조치 도구")
    p.add_argument("--scan-only", action="store_true", help="점검만 수행(시스템 변경 없음)")
    p.add_argument("--fix", action="store_true", help="점검 후 조치 (비대화형은 --yes 필요)")
    p.add_argument("--yes", action="store_true", help="확인 질문에 자동으로 예")
    p.add_argument("--allow-risky", action="store_true", help="로그인에 영향을 줄 수 있는 항목(U-01,02,03,06,08)도 비대화형으로 조치")
    p.add_argument("--severity", help="중요도 필터. 예: 상 / 상중")
    p.add_argument("--category", action="append", help="분류 필터(여러 번 지정 가능)")
    p.add_argument("--ids", help="항목 코드 목록. 예: U-01,U-16")
    p.add_argument("--include-heavy", action="store_true", help="전체 파일 검색 항목 포함")
    p.add_argument("--format", default="", help="출력 형식(쉼표 구분): " + ",".join(REPORTERS) + f" (기본: {DEFAULT_FORMATS})")
    p.add_argument("--scope", default="all", choices=SCOPES, help="출력 범위: vuln(취약·수동점검) / good(성공) / all")
    p.add_argument("--fix-scope", default="required", choices=("required", "all", "groups"),
                   help="조치 범위: required(엑셀 O 항목만, 기본) / all(O+?) / groups(--fix-groups 로 지정)")
    p.add_argument("--fix-groups", default="", help="분류(file,config,service). --fix-scope groups 와 함께 사용")
    p.add_argument("--with-optional", action="store_true", help="--fix-scope groups 에서 ? 항목도 조치")
    p.add_argument("--out", help="리포트 저장 기본 폴더(기본: isms 폴더 옆 isms-report). 안에 yy-mm-dd_hh-mm 폴더가 생깁니다")
    p.add_argument("--list-snapshots", action="store_true")
    p.add_argument("--restore", metavar="SNAPSHOT_ID")
    p.add_argument("--data-dir", default=DEFAULT_DATA)
    p.add_argument("--items", default=None, help="항목 정의 JSON 경로")
    p.add_argument("--lang", default="ko")
    p.add_argument("--os-release", help=argparse.SUPPRESS)       # 개발·테스트 전용
    p.add_argument("--scripts-dir", help=argparse.SUPPRESS)      # 개발·테스트 전용
    return p.parse_args(argv)


def build_engine(args):
    info = os_info.detect_os(os_release=args.os_release)
    if args.os_release:
        info["policy"]["fix"] = False
    items_path = args.items or str(os_info.resource_path("data/items.json"))
    items = load_items(items_path)
    scripts = args.scripts_dir or os_info.resource_path("scripts")
    for it in items:                           # 스크립트가 실제로 있는 항목만 조치 가능으로 표시
        it["script"] = script_path(scripts, it["id"], info).is_file()
    strict = os.environ.get("ISMS_ALLOW_UNTRUSTED") != "1"
    if strict:
        from isms.util import untrusted_scripts
        bad = untrusted_scripts(scripts)
        if bad:
            tool = os.path.dirname(os.path.abspath(str(scripts)))
            print(f"[오류] 스크립트 경로를 신뢰할 수 없어 실행하지 않습니다: {bad[0][0]}\n"
                  f"       이유: {bad[0][1]}  (같은 문제 {len(bad)}건)\n"
                  f"       root 권한으로 실행하는 스크립트라 소유자가 root 이고 그룹·기타 쓰기 권한이 없어야 합니다.\n"
                  f"       해결:  sudo chown -R root:root {tool} && sudo chmod -R go-w {tool}\n"
                  f"       (개발 중에만 ISMS_ALLOW_UNTRUSTED=1 로 검사를 끌 수 있습니다)", file=sys.stderr)
            sys.exit(2)
    if not strict:
        print("[경고] ISMS_ALLOW_UNTRUSTED=1: 스크립트 경로 신뢰 검사를 끕니다(개발용)", file=sys.stderr)
    return info, Engine(scripts, args.data_dir, info, items, strict_trust=strict)


def select_ids(engine, args):
    items = list(engine.items.values())
    ids = set(args.ids.split(",")) if args.ids else None
    sel = filter_items(items, severity=args.severity, categories=args.category, ids=ids)
    if not args.include_heavy and not ids:
        sel = [i for i in sel if not i["heavy"]]
    return [i["id"] for i in sel]


def noninteractive(args, info, engine):
    ids = select_ids(engine, args)
    if not ids:
        print("선택된 항목이 없습니다.", file=sys.stderr)
        return 2
    results = engine.scan(ids)
    engine.save_last(results)
    kind, before = "scan", results
    if args.fix:
        if not args.yes:
            print("--fix 는 --yes 와 함께 써야 합니다.", file=sys.stderr)
            return 2
        targets = engine.select_fixes(results, mode=args.fix_scope, groups=[g for g in args.fix_groups.split(",") if g],
                                      with_optional=args.with_optional)
        risky = RISKY & set(targets)
        if risky and not args.allow_risky:
            print(f"로그인에 영향을 줄 수 있는 항목은 건너뜁니다: {','.join(sorted(risky))} (--allow-risky 로 허용)", file=sys.stderr)
            targets = [i for i in targets if i not in risky]
        if targets:
            after, sid = engine.apply(targets)
            rows = engine.recheck(after, results)        # 조치 후 재점검: 조치를 했으면 항상 실행
            print("\n조치 후 재점검 결과")
            for x in rows:
                print(f"{x['id']:6} {messages.t('st_' + x['before']):8} → {messages.t('st_' + x['after']):8} {x['title']}  [{x['evidence'][:60]}]")
            print(f"재점검 {len(rows)}건: 양호 {sum(1 for x in rows if x['ok'])} · 미해결 {sum(1 for x in rows if not x['ok'])}")
            amap = {r["id"]: r for r in after}
            results = [amap.get(r["id"], r) for r in results]
            engine.save_last(results)
            print(f"스냅샷: {sid}")
            from isms.util import restart_notices
            for iid, msg in restart_notices(after):
                print(f"[주의] {iid}: {msg}", file=sys.stderr)
        kind = "fix"
    rep = build_report(info, results, kind=kind, before=before if kind == "fix" else None)
    for r in rep["results"]:
        st = r.get("fix_state") or r["state"]
        print(f"{r['id']:6} {messages.state_text(r, use_fix=True):14} {r['title']}")
    from isms.util import run_stamp
    stamp = run_stamp()
    fmts = [x for x in (args.format or DEFAULT_FORMATS).split(",") if x]     # --format 을 안 줘도 json+txt 는 항상 저장(스냅샷과 짝이 되는 기록)
    if fmts:
        d, files, note = save_run(rep, fmts, scope=args.scope, base=args.out, stamp=stamp)
        note and print(f"[안내] {note}", file=sys.stderr)
        for p in files:
            print(f"저장됨: {p}")
    gd, gfiles, note = guidefiles.write_guides(results, engine.items, stamp=stamp)
    if gfiles:
        note and print(f"[안내] {note}", file=sys.stderr)
        print(f"가이드 {len(gfiles)}개: {gd}")
    bad = [r for r in results if r["state"] == "VULN" or r.get("fix_state") == "FAILED"]
    return 1 if bad else 0


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    messages.LANG = args.lang if args.lang in messages.MESSAGES else "ko"
    try:
        info, engine = build_engine(args)
    except (os_info.OSDetectError, ItemError, OSError, ValueError) as e:
        print(f"[오류] {e}", file=sys.stderr)
        return 2
    if not info["policy"]["run"]:
        print(f"[중단] {messages.t('need_root')}", file=sys.stderr)
        return 2
    try:
        if args.list_snapshots:
            for s in engine.snaps.list():
                print(f"{s['id']}  {s['created'][:19]}  항목 {len(s['items'])}개  파일 {s['files']}개")
            return 0
        if args.restore:
            if not args.yes:
                print("복구는 --yes 가 필요합니다.", file=sys.stderr)
                return 2
            r = engine.restore(args.restore)
            print(messages.t("restore_done", ok=len(r["ok"]), fail=len(r["fail"])))
            return 1 if r["fail"] else 0
        if args.scan_only or args.fix or args.ids or args.severity or args.format:
            return noninteractive(args, info, engine)
        if not sys.stdin.isatty():
            print("대화형 실행에는 터미널이 필요합니다. --scan-only 등 옵션을 사용하세요.", file=sys.stderr)
            return 2
        from isms import tui
        return tui.main_loop(engine, info)
    except EngineBusy as e:
        print(f"[오류] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n중단했습니다.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
