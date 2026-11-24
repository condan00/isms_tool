"""체크박스형 TUI (questionary + rich). 엔진 기능을 호출만 하고 화면만 담당한다."""
import os
import questionary
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import guide as guidemod
from .engine import EngineBusy
from .items import filter_items
from .messages import t, state_text
from . import guidefiles, history
from .report import REPORTERS, build_report, save_run
from .util import run_stamp, restart_notices

console = Console()
STATE_STYLE = {"GOOD": "green", "VULN": "bold red", "MANUAL": "yellow", "NA": "dim",
               "ERROR": "magenta", "FIXED": "green", "FAILED": "bold red", "SKIP": "dim", "BLOCKED": "yellow"}
RISKY = {"U-01", "U-02", "U-03", "U-06", "U-08"}     # 잘못 적용하면 로그인이 막힐 수 있는 항목


BACK = "__back__"


def _choice(title, value, checked=False):
    return questionary.Choice(title=title, value=value, checked=checked)


def _back(title="← 뒤로 (취소)"):
    return questionary.Choice(title=title, value=BACK)


def show_env(info):
    key = {"supported": "env_ok", "extended": "env_ext", "unsupported": "env_unsupported",
           "unknown": "env_unknown"}[info["support_level"]]
    console.print(f"[bold]{t('title')}[/bold]")
    console.print(f"OS: {info['os_name'] or '알 수 없음'} ({info['os_key']}) · 커널 {info['kernel']} · 호스트 {info['hostname']}")
    console.print(t(key))
    for w in info.get("warnings", []):
        console.print(f"[yellow]! {w}[/yellow]")


def pick_items(engine):
    items = list(engine.items.values())
    preset = questionary.select(t("pick_preset"), choices=[
        _choice(t("preset_all"), "all"),
        _choice(t("preset_cat"), "cat"), _choice(t("preset_custom"), "custom"), _back()]).ask()
    if preset in (None, BACK):
        return None
    if preset == "all":
        sel = items
    elif preset == "cat":
        cats = sorted({i["category"] for i in items})
        pick = questionary.checkbox(t("pick_preset"), choices=[_choice(c, c, True) for c in cats]).ask()
        if pick is None:
            return None
        sel = filter_items(items, categories=pick)
    else:
        pick = questionary.checkbox(t("pick_items"), choices=[
            _choice(f"[{i['severity']}] {i['id']} {i['title']}", i["id"], not i["heavy"]) for i in items]).ask()
        if pick is None:
            return None
        sel = filter_items(items, ids=pick)
    heavy = [i for i in sel if i["heavy"]]
    if heavy and preset != "custom":
        console.print(f"[yellow]{t('heavy_warn')}[/yellow]")
        if not questionary.confirm(f"전체 검색 항목 {len(heavy)}개도 포함할까요?", default=False).ask():
            sel = [i for i in sel if not i["heavy"]]
    return [i["id"] for i in sel]


def run_scan(engine, ids):
    with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("점검 중", total=len(ids))
        results = engine.scan(ids, progress=lambda n, tot, iid: prog.update(task, completed=n - 1, description=f"점검 중 {iid}"))
        prog.update(task, completed=len(ids))
    engine.save_last(results)
    return results


def show_table(results, only_problem=False):   # 기본: 양호 항목도 모두 표시
    tb = Table(show_lines=False)
    for c in ("중요도", "코드", "항목", "판정", "근거"):
        tb.add_column(c, overflow="fold")
    rows = [r for r in results if not only_problem or r["state"] in ("VULN", "MANUAL", "ERROR")]
    for r in rows:
        st = r.get("fix_state") or r["state"]
        tb.add_row(r["severity"], r["id"], r["title"],
                   f"[{STATE_STYLE.get(st, '')}]{state_text(r, use_fix=True)}[/]", (r.get("evidence") or "")[:60])
    console.print(tb)
    counts = {}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    console.print(" · ".join(f"{t('st_' + k)} {v}" for k, v in sorted(counts.items())))


def _code_label(engine, r, opt_ids):
    return f"{r['id']}{'(' + t('mark_opt') + ')' if r['id'] in opt_ids else ''}"


def show_recheck(rows):
    """조치 후 재점검 결과 표(조치 전 → 재점검 결과)."""
    if not rows:
        return
    console.print("\n[bold]조치 후 재점검 결과[/bold]")
    tb = Table(show_lines=False)
    for c in ("코드", "항목", "조치 전", "재점검", "근거"):
        tb.add_column(c, overflow="fold")
    for x in rows:
        st = "GOOD" if x["ok"] else x["after"]
        tb.add_row(x["id"], x["title"], t("st_" + x["before"]),
                   f"[{STATE_STYLE.get(st, '')}]{t('st_' + x['after'])}[/]", (x["evidence"] or "")[:60])
    console.print(tb)
    good = sum(1 for x in rows if x["ok"])
    console.print(f"재점검 {len(rows)}건: 양호 {good} · 미해결 {len(rows) - good}")


def fix_flow(engine, results):
    """점검 결과에 이어 조치한다. 기본은 필수(O) 항목만, 전체는 O+?, 분류별/항목별 선택도 가능."""
    vulns = engine.fixable_vulns(results)
    guides = [r for r in results if r["state"] == "VULN" and not r.get("fixable")]
    if guides:
        console.print(t("guide_note", n=len(guides)))
    if not vulns:
        console.print(t("no_vuln"))
        return None, None
    opt_ids = {r["id"] for r in engine.optional_vulns(results)}
    n_req = len(vulns) - len(opt_ids)
    mode = questionary.select(t("pick_fix_mode"), choices=[
        _choice(t("fix_mode_required", n=n_req), "required"),
        _choice(t("fix_mode_all", n=len(vulns)), "all"),
        _choice(t("fix_mode_group"), "groups"),
        _choice(t("fix_mode_pick"), "ids"), _back()]).ask()
    if mode in (None, BACK):
        return None, None
    groups, with_opt, ids = None, False, None
    if mode == "groups":
        grp = engine.by_group(results)
        choices = []
        for g in engine.GROUP_ORDER:
            fx, gd = grp[g]["fix"], grp[g]["guide"]
            if g == "guide":
                codes = ", ".join(r["id"] for r in gd) or "-"
                choices.append(questionary.Choice(title=f"{t('group_guide')}: {codes}", value=g,
                                                  disabled=t("group_guide_off")))
            elif fx:
                codes = ", ".join(_code_label(engine, r, opt_ids) for r in fx)
                choices.append(_choice(f"{t('group_' + g)}: {codes}", g))
        choices.append(questionary.Separator())
        choices.append(_choice(t("group_opt"), "__opt__"))
        pick = questionary.checkbox(t("pick_group"), choices=choices).ask()
        if not pick:
            return None, None
        with_opt = "__opt__" in pick
        groups = [g for g in pick if g != "__opt__"]
    elif mode == "ids":
        ids = questionary.checkbox(t("pick_fix"), choices=[
            _choice(f"[{r['severity']}] {_code_label(engine, r, opt_ids)} {r['title']} ({t('type_' + r['type'])})", r["id"])
            for r in vulns]).ask()
    pick = engine.select_fixes(results, mode=mode, groups=groups, with_optional=with_opt, ids=ids)
    if not pick:
        console.print(t("no_required"))
        return None, None
    console.print("조치 대상: " + ", ".join(pick))
    if RISKY & set(pick) and os.environ.get("SSH_CONNECTION"):
        console.print(t("warn_ssh_session"))
    if RISKY & set(pick) and not questionary.confirm(t("confirm_ssh"), default=False).ask():
        console.print(t("cancelled"))
        return None, None
    if not questionary.confirm(t("confirm_apply", n=len(pick)), default=False).ask():
        console.print(t("cancelled"))
        return None, None
    try:
        after, sid = engine.apply(pick)
    except EngineBusy as e:
        console.print(f"[red]{e}[/red]")
        return None, None
    if sid:
        console.print(t("snapshot_made", id=sid))
    show_recheck(engine.recheck(after, results))        # 조치 후 재점검: 묻지 않고 항상 실행
    for iid, msg in restart_notices(after):
        console.print(f"[yellow]⚠ {iid}: {msg}[/yellow]")
    return after, sid


def output_flow(engine, rep, results):
    """리포트(선택한 형식)는 isms-report/<시각>/, 스크립트로 처리되지 않은 항목의 가이드는 isms-guid/<시각>/ 에 저장."""
    stamp = run_stamp()
    fmts = questionary.checkbox(t("pick_format"), choices=[
        _choice(v[0], k, k in ("json", "txt")) for k, v in REPORTERS.items()]).ask()
    if fmts:
        scope = questionary.select(t("pick_scope"), choices=[
            _choice(t("scope_vuln"), "vuln"), _choice(t("scope_good"), "good"),
            _choice(t("scope_all"), "all")]).ask() or "all"
        try:
            d, files, note = save_run(rep, fmts, scope=scope, stamp=stamp)
            if note:
                console.print(f"[yellow]{note}[/yellow]")
            console.print(t("saved_dir", path=d))
            for p in files:
                console.print(t("saved", path=p, size=p.stat().st_size))
        except OSError as e:
            console.print(f"[red]저장 실패: {e}[/red]")
    try:
        d, files, note = guidefiles.write_guides(results, engine.items, stamp=stamp)
        if files:
            if note:
                console.print(f"[yellow]{note}[/yellow]")
            console.print(t("guide_saved", n=len(files), path=d))
    except OSError as e:
        console.print(f"[red]가이드 저장 실패: {e}[/red]")


def restore_flow(engine):
    """스냅샷 선택 → 복구할 항목 선택 → 확인. 각 단계에서 '← 뒤로' 로 이전 단계로 돌아간다."""
    while True:
        snaps = engine.snaps.list()
        if not snaps:
            console.print(t("no_snapshot"))
            return
        sid = questionary.select(t("pick_snapshot"), choices=[
            _choice(f"{s['id']}  ({s['created'][:19]}, 항목 {len(s['items'])}개, 파일 {s['files']}개)", s["id"]) for s in snaps]
            + [_back("← 뒤로 (취소)")]).ask()
        if sid in (None, BACK):
            return
        s = next(x for x in snaps if x["id"] == sid)
        while True:
            pick = questionary.checkbox("복구할 항목을 선택하세요 (모두 선택됨. 비우고 엔터 = 뒤로)", choices=[
                _choice(f"{i} {engine.items[i]['title'] if i in engine.items else ''}", i, True) for i in s["items"]]).ask()
            if not pick:
                break                                    # 스냅샷 목록으로 돌아감
            only = None if len(pick) == len(s["items"]) else pick
            if not questionary.confirm(t("confirm_restore", id=sid, n=s["files"]) + ("" if only is None else f" (선택한 항목 {len(pick)}개만)"),
                                       default=False).ask():
                console.print(t("cancelled"))
                continue                                 # 항목 선택으로 돌아감
            try:
                r = engine.restore(sid, only_items=only)
            except EngineBusy as e:
                console.print(f"[red]{e}[/red]")
                return
            console.print(t("restore_done", ok=len(r["ok"]), fail=len(r["fail"])))
            for p, why in r["fail"]:
                console.print(f"[red] - {p}: {why}[/red]")
            return


def history_flow(engine, info):
    """이전 결과 보기: 마지막 점검 결과와 저장된 실행 결과 목록에서 골라 본다. '← 뒤로' 로 나간다."""
    while True:
        last = engine.load_last()
        runs = history.list_runs()
        choices = []
        if last:
            choices.append(_choice(f"마지막 점검 결과 ({last['saved'][:19]})", "__last__"))
        for r in runs:
            choices.append(_choice(f"{r['name']}  ({', '.join(r['files'])})", r["json"]))
        if not choices:
            console.print("저장된 점검 결과가 없습니다.")
            return
        pick = questionary.select("볼 결과를 선택하세요", choices=choices + [_back()]).ask()
        if pick in (None, BACK):
            return
        if pick == "__last__":
            console.print(f"저장 시각: {last['saved']}")
            show_table(last["results"])
            if questionary.confirm("이 결과를 파일로 저장할까요?", default=False).ask():
                output_flow(engine, build_report(info, last["results"], kind="scan"), last["results"])
        else:
            try:
                rep = history.load_report(pick)
            except history.HistoryError as e:
                console.print(f"[red]{e}[/red]")
                continue
            console.print(history.describe(rep))
            show_table(rep["results"])


def main_loop(engine, info):
    show_env(info)
    while True:
        act = questionary.select(t("menu_main"), choices=[
            _choice(t("menu_scan_fix"), "fix"), _choice(t("menu_last"), "last"),
            _choice(t("menu_restore"), "restore"), _choice(t("menu_quit"), "quit")]).ask()
        if act in (None, "quit"):
            return 0
        if act == "fix":
            ids = pick_items(engine)
            if not ids:
                continue
            results = run_scan(engine, ids)
            show_table(results)
            before, kind = results, "scan"
            if any(r["state"] == "VULN" for r in results) and questionary.confirm(t("ask_fix"), default=False).ask():
                after, sid = fix_flow(engine, results)
                if after:
                    amap = {r["id"]: r for r in after}
                    results = [amap.get(r["id"], r) for r in results]
                    engine.save_last(results)
                    show_table(results)
                    kind = "fix"
            output_flow(engine, build_report(info, results, kind=kind, before=before if kind == "fix" else None), results)
        elif act == "last":
            history_flow(engine, info)
        elif act == "restore":
            restore_flow(engine)
