"""클릭형 GUI (tkinter). TUI 와 같은 흐름(점검 → 조치 → 재점검 → 저장, 이전 결과 보기, 스냅샷 복구)을 창으로 보여 준다.

엔진은 그대로 쓰고 화면만 담당한다. 모든 단계에 '← 뒤로' 또는 '취소' 버튼이 있고 Esc 키도 같은 동작을 한다.
오래 걸리는 일(점검·조치·저장·복구)은 별도 스레드에서 하고, 화면 갱신은 항상 메인 스레드(after 폴링)에서만 한다."""
import os
import queue
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from . import guidefiles, history
from .engine import EngineBusy
from .messages import t, state_text
from .report import REPORTERS, build_report, save_run
from .util import restart_notices, run_stamp

RISKY = {"U-01", "U-02", "U-03", "U-06", "U-08"}      # 잘못 적용하면 로그인이 막힐 수 있는 항목 (TUI 와 같음)
FONT_PREFS = ("Noto Sans CJK KR", "Noto Sans KR", "NanumGothic", "Nanum Gothic", "Malgun Gothic", "Noto Sans CJK JP",
              "Noto Sans CJK SC", "Noto Sans", "DejaVu Sans")
ROW_ON, ROW_GROUP = "#fff1a8", "#dbe7fb"          # 체크된 줄(노란색) / 분류 줄(연한 파랑)
C = {"bg": "#f6f7f9", "card": "#ffffff", "line": "#d0d7de", "text": "#1f2328", "muted": "#656d76",
     "accent": "#0969da", "accent_dark": "#0550ae"}
STATE_FG = {"GOOD": "#1a7f37", "VULN": "#cf222e", "MANUAL": "#9a6700", "NA": "#6e7781", "ERROR": "#8250df",
            "FIXED": "#1a7f37", "FAILED": "#cf222e", "SKIP": "#6e7781", "BLOCKED": "#9a6700"}
BOX_ON, BOX_OFF, BOX_MIX = "[ V ]", "[    ]", "[ - ]"       # 글꼴에 상관없이 보이는 일반 문자
# 결과 분류: 취약(필수)=O 항목, 취약(선택)=? 항목, 수동조치=직접 조치가 필요한 항목(수동점검·오류·가이드 전용 취약)
CAT_ORDER = ("REQ", "OPT", "MAN", "GOOD", "NA")
CAT_LABEL = {"REQ": "취약(필수)", "OPT": "취약(선택)", "MAN": "수동조치", "GOOD": "양호", "NA": "해당없음"}
CAT_COLOR = {"REQ": "#cf222e", "OPT": "#bc4c00", "MAN": "#9a6700", "GOOD": "#1a7f37", "NA": "#6e7781"}
GROUP_TITLE = {"file": "파일 소유자·권한", "config": "설정 파일 값", "service": "서비스 비활성화"}


class Cancelled(Exception):
    """사용자가 점검 중단을 눌렀을 때 작업 스레드를 빠져나오기 위한 예외."""


# ---------------------------------------------------------------- 체크박스 목록
class CheckTree(ttk.Frame):
    """분류(부모) 아래 항목(자식)에 체크박스가 있는 목록. 줄을 클릭하거나 스페이스로 켜고 끈다. 분류를 누르면 하위 전체가 바뀐다."""

    def __init__(self, master, columns=(), widths=(), headings=(), height=16, on_change=None, on_open=None):
        super().__init__(master)
        self.on_change, self.on_open = on_change, on_open
        self.checked, self.children_of, self.label, self.parent_of = {}, {}, {}, {}
        self.tree = ttk.Treeview(self, columns=columns, show="tree headings", selectmode="browse", height=height)
        self.tree.heading("#0", text="선택 / 항목")
        self.tree.column("#0", width=430, stretch=True)
        for c, w, h in zip(columns, widths, headings):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, stretch=False, anchor="w")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self._click)
        self.tree.bind("<space>", self._space)
        self.tree.bind("<Double-1>", self._double)
        self.base_tags = {}
        self.tree.tag_configure("group", background=ROW_GROUP)
        self.tree.tag_configure("on", background=ROW_ON)
        self.tree.tag_configure("gon", background="#b9d3f7")

    # 구성
    def add_group(self, gid, label):
        self.checked[gid] = False
        self.children_of[gid] = []
        self.label[gid] = label
        self.base_tags[gid] = ("group",)
        self.tree.insert("", "end", iid=gid, text=f"{BOX_OFF} {label}", open=True, tags=("group",))

    def add_item(self, iid, label, values=(), checked=False, group=None, tags=()):
        self.checked[iid] = checked
        self.label[iid] = label
        self.parent_of[iid] = group
        self.base_tags[iid] = tuple(tags)
        if group:
            self.children_of[group].append(iid)
        self.tree.insert(group or "", "end", iid=iid, text=f"{BOX_ON if checked else BOX_OFF} {label}", values=values,
                         tags=tuple(tags) + (("on",) if checked else ()))

    def _mark(self, iid):
        if iid in self.children_of:
            kids = self.children_of[iid]
            n = sum(1 for k in kids if self.checked[k])
            box = BOX_ON if kids and n == len(kids) else (BOX_OFF if n == 0 else BOX_MIX)
            tags = self.base_tags[iid] + (("gon",) if n else ())
        else:
            box = BOX_ON if self.checked[iid] else BOX_OFF
            tags = self.base_tags.get(iid, ()) + (("on",) if self.checked[iid] else ())
        self.tree.item(iid, text=f"{box} {self.label[iid]}", tags=tags)

    def _refresh_groups(self):
        for g in self.children_of:
            self._mark(g)

    def toggle(self, iid):
        if iid in self.children_of:
            kids = self.children_of[iid]
            new = not (kids and all(self.checked[k] for k in kids))
            for k in kids:
                self.checked[k] = new
                self._mark(k)
        else:
            self.checked[iid] = not self.checked[iid]
            self._mark(iid)
        self._refresh_groups()
        if self.on_change:
            self.on_change()

    def set_where(self, pred):
        for iid in self.checked:
            if iid in self.children_of:
                continue
            self.checked[iid] = bool(pred(iid))
            self._mark(iid)
        self._refresh_groups()
        if self.on_change:
            self.on_change()

    def selected(self):
        return [i for i, v in self.checked.items() if v and i not in self.children_of]

    def total(self):
        return len([i for i in self.checked if i not in self.children_of])

    # 이벤트
    def _click(self, ev):
        iid = self.tree.identify_row(ev.y)
        if iid and self.tree.identify_column(ev.x) == "#0" and self.tree.identify_element(ev.x, ev.y) != "Treeitem.indicator":
            self.tree.selection_set(iid)
            self.toggle(iid)
            return "break"

    def _space(self, _ev):
        sel = self.tree.selection()
        if sel:
            self.toggle(sel[0])
        return "break"

    def _double(self, ev):
        iid = self.tree.identify_row(ev.y)
        if iid and iid not in self.children_of and self.on_open and self.tree.identify_column(ev.x) != "#0":
            self.on_open(iid)


# ---------------------------------------------------------------- 앱
class App:
    def __init__(self, engine, info):
        self.engine, self.info = engine, info
        self.root = tk.Tk()
        self.root.title(t("title"))
        self.root.geometry("1120x720")
        self.root.minsize(900, 600)
        self.root.configure(bg=C["bg"])
        self._style()
        self.header = ttk.Frame(self.root, style="Header.TFrame")
        self.header.pack(fill="x")
        ttk.Label(self.header, text="ISMS 점검·조치 도구", style="HeaderTitle.TLabel").pack(side="left", padx=20, pady=12)
        ttk.Label(self.header, text="주통2026 Unix · " + (info.get("os_name") or "OS 알 수 없음"), style="HeaderSub.TLabel").pack(side="left")
        self.crumb = ttk.Label(self.header, text="", style="HeaderSub.TLabel")
        self.crumb.pack(side="right", padx=20)
        self.body = ttk.Frame(self.root, style="Body.TFrame")
        self.body.pack(fill="both", expand=True)
        self.q = queue.Queue()
        self.stop = threading.Event()
        self.on_escape = None
        self.s = {}                              # 화면 사이에 넘기는 상태
        self.root.bind("<Escape>", lambda _e: self.on_escape() if self.on_escape else None)
        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        self.busy = False
        self.root.after(80, self._poll)

    # ---- 스타일/공통
    def _style(self):
        fams = {f.lower(): f for f in tkfont.families()}
        fam = next((fams[f.lower()] for f in FONT_PREFS if f.lower() in fams), tkfont.nametofont("TkDefaultFont").actual("family"))
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(name).configure(family=fam, size=11)
            except tk.TclError:
                pass
        self.font = (fam, 11)
        self.font_b = (fam, 11, "bold")
        self.font_big = (fam, 16, "bold")
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=C["bg"], foreground=C["text"], font=self.font)
        st.configure("Body.TFrame", background=C["bg"])
        st.configure("Card.TFrame", background=C["card"], relief="solid", borderwidth=1, bordercolor=C["line"])
        st.configure("CardRow.TFrame", background=C["card"])           # 카드 안쪽 줄(테두리 없음)
        st.configure("Header.TFrame", background="#24292f")
        st.configure("HeaderTitle.TLabel", background="#24292f", foreground="#ffffff", font=(fam, 14, "bold"))
        st.configure("HeaderSub.TLabel", background="#24292f", foreground="#c9d1d9")
        st.configure("Title.TLabel", font=self.font_big, background=C["bg"])
        st.configure("Muted.TLabel", foreground=C["muted"], background=C["bg"])
        st.configure("Card.TLabel", background=C["card"])
        st.configure("CardTitle.TLabel", background=C["card"], font=self.font_b)
        st.configure("CardMuted.TLabel", background=C["card"], foreground=C["muted"])
        st.configure("TButton", padding=(14, 7))
        st.configure("Primary.TButton", background=C["accent"], foreground="#ffffff", padding=(16, 8), font=self.font_b)
        st.map("Primary.TButton", background=[("active", C["accent_dark"]), ("disabled", "#94a3b8")])
        st.configure("Danger.TButton", background="#cf222e", foreground="#ffffff", padding=(16, 8), font=self.font_b)
        st.map("Danger.TButton", background=[("active", "#a40e26"), ("disabled", "#94a3b8")])
        st.configure("Cancel.TButton", padding=(6, 1))                  # 작은 취소 버튼(가로는 일반 버튼 정도, 세로는 낮게)
        st.configure("Big.TButton", padding=(18, 14), font=self.font_b)
        st.configure("Treeview", rowheight=28, background=C["card"], fieldbackground=C["card"], font=self.font)
        st.configure("Treeview.Heading", font=self.font_b, padding=(6, 5))
        st.configure("TProgressbar", thickness=14)
        for name, bg in (("TCheckbutton", C["bg"]), ("TRadiobutton", C["bg"]), ("Card.TCheckbutton", C["card"]), ("Card.TRadiobutton", C["card"])):
            # clam 테마가 글자 옆에 그리는 포커스 표시(모서리 선)를 배경색으로 감춘다
            st.configure(name, background=bg, focuscolor=bg, lightcolor=bg, darkcolor=bg)

    def clear(self, crumb="", escape=None):
        for w in self.body.winfo_children():
            w.destroy()
        self.crumb.configure(text=crumb)
        self.on_escape = escape
        page = ttk.Frame(self.body, style="Body.TFrame")
        page.pack(fill="both", expand=True, padx=24, pady=16)
        return page

    def title(self, page, text, sub=""):
        ttk.Label(page, text=text, style="Title.TLabel").pack(anchor="w")
        if sub:
            ttk.Label(page, text=sub, style="Muted.TLabel", wraplength=1040, justify="left").pack(anchor="w", pady=(2, 10))

    def footer(self, page, left=(), right=()):
        """아래 버튼 줄. left/right: (글자, 동작, 종류) — 종류: None / 'primary' / 'danger'."""
        bar = ttk.Frame(page, style="Body.TFrame")
        first = page.pack_slaves()
        # 다른 위젯보다 먼저 자리를 잡아야 창이 작아도 버튼 줄이 잘리지 않는다
        bar.pack(side="bottom", fill="x", pady=(12, 0), before=first[0]) if first else bar.pack(side="bottom", fill="x", pady=(12, 0))
        btns = {}
        for text, cmd, *kind in left:
            b = ttk.Button(bar, text=text, command=cmd, style=self._bstyle(kind), **self._bopts(kind))
            b.pack(side="left", padx=(0, 8))
            btns[text] = b
        for text, cmd, *kind in reversed(list(right)):
            b = ttk.Button(bar, text=text, command=cmd, style=self._bstyle(kind), **self._bopts(kind))
            b.pack(side="right", padx=(8, 0))
            btns[text] = b
        return btns

    @staticmethod
    def _bstyle(kind):
        return {"primary": "Primary.TButton", "danger": "Danger.TButton", "cancel": "Cancel.TButton"}.get(kind[0] if kind else None, "TButton")

    @staticmethod
    def _bopts(kind):
        return {"width": 12} if kind and kind[0] == "cancel" else {}

    def ask(self, title, msg, icon="question"):
        """예/아니오(기본 아니오). 아니오가 곧 취소다."""
        return messagebox.askyesno(title, msg, icon=icon, default="no", parent=self.root)

    def info_box(self, title, msg):
        messagebox.showinfo(title, msg, parent=self.root)

    def error_box(self, title, msg):
        messagebox.showerror(title, msg, parent=self.root)

    # ---- 백그라운드 작업
    def run_bg(self, fn, on_done, on_error=None):
        """fn(progress) 를 스레드로 돌린다. progress(n, total, iid) 는 화면 갱신 요청이며 self.on_progress 로 전달된다."""
        self.stop.clear()
        self.busy = True

        def work():
            try:
                res = fn(lambda n, tot, iid: self._progress_cb(n, tot, iid))
                self.q.put(("done", on_done, res))
            except Cancelled:
                self.q.put(("cancel", on_error, None))
            except Exception as e:           # 화면은 어떤 오류에도 멈추지 않게 한다
                self.q.put(("error", on_error, e))
        threading.Thread(target=work, daemon=True).start()

    def _progress_cb(self, n, tot, iid):
        if self.stop.is_set():
            raise Cancelled()
        self.q.put(("progress", None, (n, tot, iid)))

    on_progress = None

    def _poll(self):
        try:
            while True:
                kind, cb, payload = self.q.get_nowait()
                if kind == "progress":
                    if self.on_progress:
                        self.on_progress(*payload)
                    continue
                self.busy = False
                self.on_progress = None
                if kind == "done":
                    cb(payload)
                elif kind == "cancel":
                    cb and cb(None)
                elif kind == "error":
                    if cb:
                        cb(payload)
                    else:
                        self.error_box("오류", str(payload))
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _quit(self):
        if self.busy and not self.ask("종료", "작업이 진행 중입니다. 지금 종료하면 조치가 중간에 멈출 수 있습니다. 그래도 종료할까요?", "warning"):
            return
        self.root.destroy()

    def run(self):
        self.show_home()
        self.root.mainloop()

    # ---------------------------------------------------------------- 1. 처음 화면
    def show_home(self):
        page = self.clear("처음")
        self.title(page, "무엇을 할까요?")
        key = {"supported": "env_ok", "extended": "env_ext", "unsupported": "env_unsupported", "unknown": "env_unknown"}[self.info["support_level"]]
        env = ttk.Frame(page, style="Card.TFrame")
        env.pack(fill="x", pady=(0, 16))
        ttk.Label(env, text=f"OS: {self.info['os_name'] or '알 수 없음'} ({self.info['os_key']}) · 커널 {self.info['kernel']} · 호스트 {self.info['hostname']}",
                  style="CardTitle.TLabel").pack(anchor="w", padx=14, pady=(10, 0))
        ttk.Label(env, text=t(key), style="CardMuted.TLabel").pack(anchor="w", padx=14, pady=(0, 2))
        for w in self.info.get("warnings", []):
            ttk.Label(env, text="! " + w, style="CardMuted.TLabel", foreground="#9a6700").pack(anchor="w", padx=14)
        ttk.Label(env, text="", style="Card.TLabel").pack(pady=2)
        grid = ttk.Frame(page, style="Body.TFrame")
        grid.pack(fill="x")
        cards = (("1. 점검 및 조치", "항목을 골라 점검하고, 취약한 항목을 선택해 조치합니다. 조치 후에는 자동으로 재점검합니다.", self.show_select),
                 ("2. 이전 점검 결과 보기", "마지막 점검 결과와 저장해 둔 결과를 다시 봅니다.", self.show_history),
                 ("3. 스냅샷으로 복구", "조치 전에 자동 저장한 스냅샷에서 항목별로 되돌립니다.", self.show_restore_list))
        for i, (head, desc, cmd) in enumerate(cards):
            card = ttk.Frame(grid, style="Card.TFrame")
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))
            grid.columnconfigure(i, weight=1, uniform="c")
            ttk.Label(card, text=head, style="CardTitle.TLabel", font=(self.font[0], 13, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
            ttk.Label(card, text=desc, style="CardMuted.TLabel", wraplength=300, justify="left").pack(anchor="w", padx=16)
            ttk.Button(card, text="시작", style="Primary.TButton", command=cmd).pack(anchor="w", padx=16, pady=16)
        self.footer(page, right=[("종료", self._quit)])

    # ---------------------------------------------------------------- 2. 점검 항목 선택
    def show_select(self):
        page = self.clear("점검 및 조치 › 1. 점검 범위", escape=self.show_home)
        self.title(page, "점검할 항목을 고르세요", "분류 이름을 누르면 그 분류 전체가 선택/해제됩니다. 전체 파일 검색 항목은 시간이 오래 걸려 기본으로 빠져 있습니다.")
        items = list(self.engine.items.values())
        bar = ttk.Frame(page, style="Body.TFrame")
        bar.pack(fill="x", pady=(0, 6))
        self.count_lbl = ttk.Label(bar, text="", style="Muted.TLabel")
        tree = CheckTree(page, columns=("sev", "slow"), widths=(70, 110), headings=("중요도", "소요"), height=16,
                         on_change=lambda: self.count_lbl.configure(text=f"선택 {tree.selected().__len__()} / {tree.total()}개"))
        cats = sorted({i["category"] for i in items})
        for c in cats:
            tree.add_group("cat:" + c, c)
        for i in items:
            tree.add_item(i["id"], f"{i['id']}  {i['title']}", values=(i["severity"], "오래 걸림" if i["heavy"] else ""),
                          checked=not i["heavy"], group="cat:" + i["category"])
        tree._refresh_groups()
        ids = {i["id"]: i for i in items}
        for text, fn in (("전체 선택", lambda: tree.set_where(lambda _i: True)),
                         ("전체 해제", lambda: tree.set_where(lambda _i: False)),
                         ("전체 검색 항목 제외", lambda: tree.set_where(lambda i: tree.checked[i] and not ids[i]["heavy"])),
                         ("중요도 '상'만", lambda: tree.set_where(lambda i: ids[i]["severity"] == "상" and not ids[i]["heavy"]))):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=(0, 6))
        self.count_lbl.pack(side="right")
        tree.pack(fill="both", expand=True)
        tree.on_change()

        def go():
            sel = tree.selected()
            if not sel:
                self.info_box("항목 없음", "점검할 항목을 하나 이상 선택하세요.")
                return
            heavy = [i for i in sel if ids[i]["heavy"]]
            if heavy and not self.ask("오래 걸리는 항목 포함", f"전체 파일 검색 항목 {len(heavy)}개({', '.join(heavy)})가 포함되어 있습니다.\n시스템 전체를 검색해 수 분 이상 걸릴 수 있습니다. 계속할까요?", "warning"):
                return
            self.s["select_ids"] = sel
            self.start_scan(sel)
        self.footer(page, left=[("← 이전: 처음 화면", self.show_home)], right=[("다음: 점검 시작 →", go, "primary")])

    # ---------------------------------------------------------------- 3. 점검 진행
    def start_scan(self, ids):
        page = self.clear("점검 및 조치 › 2. 점검 중")
        self.title(page, "점검 중입니다", "항목마다 스크립트를 실행해 현재 상태를 읽습니다. 시스템은 바꾸지 않습니다.")
        bar = ttk.Progressbar(page, maximum=len(ids), mode="determinate")
        bar.pack(fill="x", pady=(8, 6))
        lbl = ttk.Label(page, text="시작하는 중…", style="Muted.TLabel")
        lbl.pack(anchor="w")

        def prog(n, tot, iid):
            bar["value"] = n - 1
            title = self.engine.items[iid]["title"]
            lbl.configure(text=f"{n} / {tot}   {iid}  {title}")
        self.on_progress = prog

        def cancel():
            self.stop.set()
            lbl.configure(text="현재 항목까지만 마치고 중단합니다…")
        self.footer(page, left=[("중단하고 돌아가기 (취소)", cancel)])

        def done(results):
            self.engine.save_last(results)
            self.s.update(results=results, before=results, kind="scan")
            self.show_results()

        def fail(e):
            if e is None:                 # 사용자가 중단
                self.show_select()
            else:
                self.error_box("점검 실패", str(e))
                self.show_select()
        self.run_bg(lambda p: self.engine.scan(ids, progress=p), done, fail)

    # ---------------------------------------------------------------- 4. 결과 표
    def _cat(self, r):
        st = r["state"]
        if st == "GOOD":
            return "GOOD"
        if st == "NA":
            return "NA"
        if st == "VULN" and r.get("fixable"):
            shell = ((self.engine.items.get(r["id"]) or {}).get("excel") or {}).get("shell")
            return "REQ" if shell == "O" else "OPT"
        return "MAN"                       # 수동점검, 오류, 가이드 전용 취약

    def _result_table(self, parent, results, only_problem=False, height=15):
        cols = ("sev", "id", "title", "state", "ev")
        tv = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse", height=height)
        for c, h, w, st in (("sev", "중요도", 70, False), ("id", "코드", 70, False), ("title", "항목", 360, True),
                            ("state", "판정", 150, False), ("ev", "근거", 380, True)):
            tv.heading(c, text=h)
            tv.column(c, width=w, stretch=st, anchor="w")
        for k, col in STATE_FG.items():
            tv.tag_configure(k, foreground=col)
        for k, col in CAT_COLOR.items():
            tv.tag_configure("cat_" + k, foreground=col)
        sb = ttk.Scrollbar(parent, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        rows = [r for r in results if not only_problem or r["state"] in ("VULN", "MANUAL", "ERROR")]
        index = {}
        for r in rows:
            fs = r.get("fix_state")
            if fs in ("FIXED", "FAILED", "BLOCKED", "SKIP"):          # 조치한 항목은 조치 결과를 그대로 보여 준다
                shown, tag = state_text(r, use_fix=True), fs
            else:
                c = self._cat(r)
                shown, tag = CAT_LABEL[c], "cat_" + c
            tv.insert("", "end", iid=r["id"], values=(r["severity"], r["id"], r["title"], shown, (r.get("evidence") or "")[:90]),
                      tags=(tag,))
            index[r["id"]] = r
        tv.bind("<Double-1>", lambda _e: self._detail_of(tv, index))
        tv.bind("<Return>", lambda _e: self._detail_of(tv, index))
        return tv, sb, index

    def _detail_of(self, tv, index):
        sel = tv.selection()
        if sel and sel[0] in index:
            self.show_detail(index[sel[0]])

    def show_detail(self, r):
        win = tk.Toplevel(self.root)
        win.title(f"{r['id']} {r['title']}")
        win.geometry("860x620")
        win.configure(bg=C["bg"])
        win.transient(self.root)
        txt = tk.Text(win, wrap="word", font=(self.font[0], 11), padx=14, pady=10, bg=C["card"], relief="flat")
        sb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        try:
            body = guidefiles.render(r, self.engine.items)
        except (KeyError, TypeError, ValueError):
            body = f"판정: {state_text(r, use_fix=True)}\n근거: {r.get('evidence', '')}\n" + "\n".join(r.get("detail") or [])
        txt.insert("1.0", f"[{r['id']}] {r['title']}\n\n{body}")
        txt.configure(state="disabled")
        bar = ttk.Frame(win)
        bar.pack(side="bottom", fill="x", padx=12, pady=8)
        ttk.Button(bar, text="닫기", command=win.destroy).pack(side="right")
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        win.bind("<Escape>", lambda _e: win.destroy())
        win.focus_set()

    def _summary(self, parent, results):
        counts = {}
        for r in results:
            c = self._cat(r)
            counts[c] = counts.get(c, 0) + 1
        row = ttk.Frame(parent, style="Body.TFrame")
        for k in CAT_ORDER:
            if counts.get(k):
                tk.Label(row, text=f"  {CAT_LABEL[k]} {counts[k]}  ", bg=CAT_COLOR[k], fg="#ffffff", font=self.font_b).pack(side="left", padx=(0, 6))
        return row

    def show_results(self, readonly=False, results=None, back=None, header=""):
        """점검(또는 조치 후) 결과 표. readonly 는 이전 결과 보기용(조치·저장 버튼 없음)."""
        results = results if results is not None else self.s["results"]
        page = self.clear(("이전 결과 › " if readonly else "점검 및 조치 › 3. 결과 ") + header, escape=back or self.show_home)
        self.title(page, "점검 결과", "줄을 두 번 누르면 판정 근거, 걸린 파일 목록, 조치 방법(가이드)이 열립니다.")
        self._summary(page, results).pack(anchor="w", pady=(0, 8))
        top = ttk.Frame(page, style="Body.TFrame")
        top.pack(fill="x")
        only = tk.BooleanVar(value=False)
        holder = ttk.Frame(page, style="Body.TFrame")
        holder.pack(fill="both", expand=True, pady=(6, 0))

        def draw():
            for w in holder.winfo_children():
                w.destroy()
            tv, sb, _ = self._result_table(holder, results, only.get())
            tv.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
        ttk.Checkbutton(top, text="문제 항목만 보기 (취약·수동점검·오류)", variable=only, command=draw).pack(side="left")
        draw()
        if readonly:
            self.footer(page, left=[("← 목록으로 (뒤로)", back or self.show_home)])
            return
        vulns = self.engine.fixable_vulns(results)
        guides = [r for r in results if r["state"] == "VULN" and not r.get("fixable")]
        note = []
        if guides:
            note.append(t("guide_note", n=len(guides)))
        if not vulns:
            note.append(t("no_vuln"))
        if note:
            ttk.Label(page, text="  ".join(note), style="Muted.TLabel", wraplength=1040).pack(anchor="w", pady=(6, 0))
        def fix_only():
            self.s["guide"] = False
            self.show_fix_select()

        def fix_with_guide():
            self.s["guide"] = True
            self.show_fix_select()

        def guide_only():
            self.s["guide"] = True
            self.start_guides()
        if vulns:
            right = [("자동 조치만 실행", fix_only), ("가이드 생성 & 자동 조치", fix_with_guide, "primary")]
        else:
            right = [("결과 저장…", lambda: self.show_save()), ("가이드 생성", guide_only, "primary")]
        self.footer(page, left=[("취소", self.show_home, "cancel")], right=right)

    def start_guides(self):
        """조치 없이 가이드 파일만 만든다."""
        results = self.s["results"]

        def work(_p):
            return guidefiles.write_guides(results, self.engine.items, stamp=run_stamp())

        def done(res):
            d, files, note = res
            self.info_box("가이드 생성", (f"가이드 {len(files)}개를 저장했습니다.\n{d}" + (f"\n{note}" if note else "")) if files else "가이드가 필요한 항목이 없습니다.")
        self.run_bg(work, done, lambda e: self.error_box("가이드 생성 실패", str(e)))

    # ---------------------------------------------------------------- 5. 조치 항목 선택
    def show_fix_select(self):
        results = self.s["results"]
        eng = self.engine
        page = self.clear("점검 및 조치 › 4. 조치 선택", escape=self.show_results)
        self.title(page, "조치할 항목을 고르세요",
                   "취약(필수)와 취약(선택) 항목이 모두 선택되어 있습니다. (?) 표시는 취약(선택) 항목으로, 환경에 따라 달라 확인이 필요한 항목입니다. 원하지 않는 항목은 체크를 풀어 주세요. 조치 전에 스냅샷을 자동으로 만들고, 조치가 끝나면 바로 재점검합니다.")
        vulns = eng.fixable_vulns(results)
        opt = {r["id"] for r in eng.optional_vulns(results)}
        bar = ttk.Frame(page, style="Body.TFrame")
        bar.pack(fill="x", pady=(0, 6))
        cnt = ttk.Label(bar, text="", style="Muted.TLabel")
        tree = CheckTree(page, columns=("sev", "kind"), widths=(70, 130), headings=("중요도", "적용 방식"), height=15,
                         on_change=lambda: cnt.configure(text=f"선택 {len(tree.selected())} / {tree.total()}개"))
        groups = {}
        for r in vulns:
            groups.setdefault(eng.group_of(r["id"]), []).append(r)
        for g in eng.GROUP_ORDER:
            if g not in groups:
                continue
            tree.add_group("grp:" + g, GROUP_TITLE.get(g, g))
            for r in groups[g]:
                mark = "(?) " if r["id"] in opt else ""
                warn = "  ⚠ 로그인 영향" if r["id"] in RISKY else ""
                tree.add_item(r["id"], f"{r['id']}  {mark}{r['title']}{warn}", values=(r["severity"], t("type_" + r["type"])),
                              checked=True, group="grp:" + g)
        tree._refresh_groups()
        for text, fn in (("필수만", lambda: tree.set_where(lambda i: i not in opt)),
                         ("필수 + 선택 전체", lambda: tree.set_where(lambda _i: True)),
                         ("전체 해제", lambda: tree.set_where(lambda _i: False))):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=(0, 6))
        cnt.pack(side="right")
        tree.pack(fill="both", expand=True)
        tree.on_change()
        index = {r["id"]: r for r in results}
        tree.on_open = lambda i: self.show_detail(index[i])

        def go():
            pick = tree.selected()
            if not pick:
                self.info_box("항목 없음", t("no_required"))
                return
            if RISKY & set(pick):
                if os.environ.get("SSH_CONNECTION"):
                    self.info_box("SSH 접속 중", "현재 SSH(원격) 세션입니다. 기존 연결은 유지되지만 새 연결부터 설정이 적용됩니다. 별도 세션을 열어 두고 진행하세요.")
                if not self.ask("로그인에 영향을 줄 수 있는 항목", t("confirm_ssh") + "\n\n포함된 항목: " + ", ".join(sorted(RISKY & set(pick))), "warning"):
                    return                                   # 취소 → 선택 화면 그대로
            if not self.ask("조치 확인", t("confirm_apply", n=len(pick)) + "\n\n" + ", ".join(pick), "question"):
                return                                       # 취소 → 선택 화면 그대로
            self.start_fix(pick)
        self.footer(page, left=[("← 이전: 점검 결과", self.show_results), ("취소 (처음으로)", self.show_home)],
                    right=[("다음: 조치 실행 →", go, "danger")])

    # ---------------------------------------------------------------- 6. 조치 진행 + 재점검
    def start_fix(self, ids):
        results = self.s["results"]
        page = self.clear("점검 및 조치 › 5. 조치 중")
        self.title(page, "조치 중입니다", "중간에 멈추면 시스템이 어중간한 상태가 될 수 있어 중단 버튼이 없습니다. 항목이 실패하면 그 항목은 자동으로 원복됩니다.")
        bar = ttk.Progressbar(page, maximum=len(ids), mode="determinate")
        bar.pack(fill="x", pady=(8, 6))
        lbl = ttk.Label(page, text="스냅샷을 만드는 중…", style="Muted.TLabel")
        lbl.pack(anchor="w")

        def prog(n, tot, iid):
            bar["value"] = n - 1
            lbl.configure(text=f"{n} / {tot}   {iid}  {self.engine.items[iid]['title']}")
        self.on_progress = prog

        def work(progress):
            after, sid = self.engine.apply(ids, progress=progress)
            rows = self.engine.recheck(after, results)                # 조치 후 재점검: 묻지 않고 항상 실행
            return after, sid, rows

        def done(res):
            after, sid, rows = res
            amap = {r["id"]: r for r in after}
            merged = [amap.get(r["id"], r) for r in results]
            self.engine.save_last(merged)
            self.s.update(results=merged, kind="fix", sid=sid, rechecks=rows, after=after)
            self.show_fix_result()

        def fail(e):
            self.error_box("조치 실패", str(e) if isinstance(e, EngineBusy) else f"조치 중 오류가 발생했습니다: {e}")
            self.show_results()
        # 조치 중에는 stop 신호를 무시한다(_progress_cb 가 Cancelled 를 던지지 않게)
        self.stop.clear()
        self.run_bg(work, done, fail)

    def show_fix_result(self):
        rows, sid, after = self.s["rechecks"], self.s.get("sid"), self.s["after"]
        page = self.clear("점검 및 조치 › 6. 조치 후 재점검", escape=None)
        good = sum(1 for x in rows if x["ok"])
        self.title(page, "조치 후 재점검 결과", f"재점검 {len(rows)}건: 양호 {good} · 미해결 {len(rows) - good}" + (f"     스냅샷: {sid}" if sid else ""))
        cols = ("id", "title", "before", "after", "ev")
        tv = ttk.Treeview(page, columns=cols, show="headings", height=12)
        for c, h, w, st in (("id", "코드", 70, False), ("title", "항목", 340, True), ("before", "조치 전", 100, False),
                            ("after", "재점검", 100, False), ("ev", "근거", 420, True)):
            tv.heading(c, text=h)
            tv.column(c, width=w, stretch=st, anchor="w")
        for k, col in STATE_FG.items():
            tv.tag_configure(k, foreground=col)
        for x in rows:
            tv.insert("", "end", iid=x["id"], values=(x["id"], x["title"], t("st_" + x["before"]), t("st_" + x["after"]), (x["evidence"] or "")[:90]),
                      tags=("GOOD" if x["ok"] else x["after"],))
        tv.pack(fill="both", expand=True)
        index = {r["id"]: r for r in after}
        tv.bind("<Double-1>", lambda _e: tv.selection() and self.show_detail(index[tv.selection()[0]]))
        notes = [f"⚠ {iid}: {msg}" for iid, msg in restart_notices(after)]
        notes += [f"· {r['id']}: {r.get('fix_note', '')}" for r in after if r.get("fix_state") in ("FAILED", "BLOCKED")]
        if not rows:
            notes.append("실제로 조치한 항목이 없습니다(이미 취약이 아니거나 조치할 수 없는 항목).")
        if notes:
            tk.Label(page, text="\n".join(notes), bg="#fff8c5", fg="#4d2d00", justify="left", anchor="w", wraplength=1040, padx=10, pady=8,
                     font=self.font).pack(fill="x", pady=(8, 0))
        def make_guides():
            def done(res):
                d, files, note = res
                self.info_box("가이드 생성", (f"가이드 {len(files)}개를 저장했습니다.\n{d}" + (f"\n{note}" if note else "")) if files else "가이드가 필요한 항목이 없습니다.")
                self.show_home()
            self.run_bg(lambda _p: guidefiles.write_guides(self.s["results"], self.engine.items, stamp=run_stamp()), done,
                        lambda e: self.error_box("가이드 생성 실패", str(e)))
        self.footer(page, left=[("가이드 없이 완료", self.show_home)],
                    right=[("전체 결과 보기", lambda: self.show_results()), ("결과 저장…", lambda: self.show_save()),
                           ("가이드 생성", make_guides, "primary")])

    # ---------------------------------------------------------------- 7. 결과 저장
    def show_save(self):
        results, kind = self.s["results"], self.s.get("kind", "scan")
        page = self.clear("점검 및 조치 › 결과 저장", escape=self.show_results)
        self.title(page, "결과를 저장할까요?", "리포트는 isms-report/yy-mm-dd_hh-mm/ 에, 조치가 필요한 항목의 가이드는 항목 코드별 파일로 isms-guid/yy-mm-dd_hh-mm/ 에 저장됩니다. 도구 폴더 옆에 만들어집니다.")
        box = ttk.Frame(page, style="Card.TFrame")
        box.pack(fill="x", pady=(0, 10))
        ttk.Label(box, text="형식", style="CardTitle.TLabel").pack(anchor="w", padx=14, pady=(10, 2))
        fv = {}
        row = ttk.Frame(box, style="CardRow.TFrame")
        row.pack(anchor="w", padx=14, pady=(0, 8))
        for k, v in REPORTERS.items():
            fv[k] = tk.BooleanVar(value=k in ("json", "txt"))
            ttk.Checkbutton(row, text=v[0], variable=fv[k], style="Card.TCheckbutton").pack(side="left", padx=(0, 14))
        ttk.Label(box, text="범위", style="CardTitle.TLabel").pack(anchor="w", padx=14, pady=(4, 2))
        sv = tk.StringVar(value="all")
        row = ttk.Frame(box, style="CardRow.TFrame")
        row.pack(anchor="w", padx=14, pady=(0, 12))
        for key, label in (("vuln", t("scope_vuln")), ("good", t("scope_good")), ("all", t("scope_all"))):
            ttk.Radiobutton(row, text=label, value=key, variable=sv, style="Card.TRadiobutton").pack(side="left", padx=(0, 14))
        gv = tk.BooleanVar(value=False)
        ttk.Checkbutton(box, text="가이드 파일도 저장 (조치가 필요한 항목)", variable=gv, style="Card.TCheckbutton").pack(anchor="w", padx=14, pady=(0, 10))
        out = tk.Text(page, height=9, wrap="word", state="disabled", bg=C["card"], relief="solid", borderwidth=1, font=self.font)
        out.pack(fill="both", expand=True)

        def write(lines):
            out.configure(state="normal")
            out.delete("1.0", "end")
            out.insert("1.0", "\n".join(lines))
            out.configure(state="disabled")

        def save():
            fmts = [k for k, v in fv.items() if v.get()]
            before = self.s.get("before") if kind == "fix" else None
            rep = build_report(self.info, results, kind=kind, before=before)
            stamp = run_stamp()

            def work(_p):
                lines = []
                if fmts:
                    d, files, note = save_run(rep, fmts, scope=sv.get(), stamp=stamp)
                    lines += ([note] if note else []) + [t("saved_dir", path=d)] + [t("saved", path=p, size=p.stat().st_size) for p in files]
                d, files, note = guidefiles.write_guides(results, self.engine.items, stamp=stamp) if gv.get() else (None, [], "")
                if files:
                    lines += ([note] if note else []) + [t("guide_saved", n=len(files), path=d)]
                return lines or ["저장할 내용이 없습니다."]
            self.run_bg(work, lambda lines: (write(lines), btns["저장"].configure(state="normal")),
                        lambda e: (write([f"저장 실패: {e}"]), btns["저장"].configure(state="normal")))
            btns["저장"].configure(state="disabled")
        btns = self.footer(page, left=[("← 뒤로 (취소)", self.show_results), ("처음으로", self.show_home)], right=[("저장", save, "primary")])

    # ---------------------------------------------------------------- 8. 이전 결과 보기
    def show_history(self):
        page = self.clear("이전 점검 결과", escape=self.show_home)
        self.title(page, "이전 점검 결과", "마지막 점검 결과와 isms-report 폴더에 저장해 둔 JSON 리포트를 볼 수 있습니다. 줄을 두 번 누르면 열립니다.")
        entries = []
        last = self.engine.load_last()
        if last:
            entries.append(("마지막 점검 결과", last["saved"][:19].replace("T", " "), "(저장 없이도 볼 수 있음)", ("last", None)))
        for r in history.list_runs():
            entries.append((r["name"], "", ", ".join(r["files"]), ("run", r["json"])))
        tv = ttk.Treeview(page, columns=("name", "when", "files"), show="headings", height=14, selectmode="browse")
        for c, h, w in (("name", "결과", 250), ("when", "저장 시각", 170), ("files", "파일", 600)):
            tv.heading(c, text=h)
            tv.column(c, width=w, anchor="w")
        for n, (name, when, files, _k) in enumerate(entries):
            tv.insert("", "end", iid=str(n), values=(name, when, files))
        tv.pack(fill="both", expand=True)
        if not entries:
            ttk.Label(page, text="저장된 점검 결과가 없습니다.", style="Muted.TLabel").pack(anchor="w", pady=8)

        def open_sel(_e=None):
            sel = tv.selection()
            if not sel:
                self.info_box("선택 없음", "열 결과를 먼저 고르세요.")
                return
            name, _w, _f, (kind, path) = entries[int(sel[0])]
            try:
                if kind == "last":
                    rows, desc = last["results"], f"마지막 점검 ({last['saved'][:19]})"
                else:
                    rep = history.load_report(path)
                    rows, desc = rep["results"], f"{name} · {history.describe(rep)}"
            except history.HistoryError as e:
                self.error_box("열 수 없음", str(e))
                return
            self.show_results(readonly=True, results=rows, back=self.show_history, header=desc)
        tv.bind("<Double-1>", open_sel)
        self.footer(page, left=[("← 처음으로 (취소)", self.show_home)], right=[("열기 →", open_sel, "primary")])

    # ---------------------------------------------------------------- 9. 스냅샷 복구
    def show_restore_list(self):
        page = self.clear("스냅샷 복구 › 1. 스냅샷 선택", escape=self.show_home)
        self.title(page, "복구할 스냅샷을 고르세요", "조치 직전에 자동으로 저장한 시점입니다. 다음 화면에서 되돌릴 항목을 고를 수 있습니다.")
        snaps = self.engine.snaps.list()
        tv = ttk.Treeview(page, columns=("id", "when", "items", "files"), show="headings", height=14, selectmode="browse")
        for c, h, w in (("id", "스냅샷", 200), ("when", "만든 시각", 190), ("items", "항목 수", 90), ("files", "파일 수", 90)):
            tv.heading(c, text=h)
            tv.column(c, width=w, anchor="w")
        for s in snaps:
            tv.insert("", "end", iid=s["id"], values=(s["id"], s["created"][:19].replace("T", " "), len(s["items"]), s["files"]))
        tv.pack(fill="both", expand=True)
        if not snaps:
            ttk.Label(page, text=t("no_snapshot"), style="Muted.TLabel").pack(anchor="w", pady=8)

        def nxt(_e=None):
            sel = tv.selection()
            if not sel:
                self.info_box("선택 없음", "복구할 스냅샷을 먼저 고르세요.")
                return
            self.show_restore_items(next(s for s in snaps if s["id"] == sel[0]))
        tv.bind("<Double-1>", nxt)
        self.footer(page, left=[("← 처음으로 (취소)", self.show_home)], right=[("다음: 항목 선택 →", nxt, "primary")])

    def show_restore_items(self, snap):
        page = self.clear("스냅샷 복구 › 2. 항목 선택", escape=self.show_restore_list)
        self.title(page, f"스냅샷 {snap['id']}", "되돌릴 항목을 고르세요. 선택한 항목이 바꾼 파일과 서비스 상태만 복구합니다(기본은 전체).")
        bar = ttk.Frame(page, style="Body.TFrame")
        bar.pack(fill="x", pady=(0, 6))
        cnt = ttk.Label(bar, text="", style="Muted.TLabel")
        tree = CheckTree(page, height=8, on_change=lambda: cnt.configure(text=f"선택 {len(tree.selected())} / {tree.total()}개"))
        for i in snap["items"]:
            title = self.engine.items[i]["title"] if i in self.engine.items else ""
            tree.add_item(i, f"{i}  {title}", checked=True)
        for text, fn in (("전체 선택", lambda: tree.set_where(lambda _i: True)), ("전체 해제", lambda: tree.set_where(lambda _i: False))):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=(0, 6))
        cnt.pack(side="right")
        tree.pack(fill="both", expand=True)
        tree.on_change()
        out = tk.Text(page, height=5, wrap="word", state="disabled", bg=C["card"], relief="solid", borderwidth=1, font=self.font)

        def go():
            pick = tree.selected()
            if not pick:
                self.info_box("항목 없음", "복구할 항목을 하나 이상 선택하세요.")
                return
            only = None if len(pick) == len(snap["items"]) else pick
            msg = t("confirm_restore", id=snap["id"], n=snap["files"]) + ("" if only is None else f"\n(선택한 항목 {len(pick)}개만 복구)")
            if not self.ask("복구 확인", msg, "warning"):
                return                                   # 취소 → 항목 선택 화면 그대로
            btns["복구 실행"].configure(state="disabled")
            out.pack(side="bottom", fill="x", pady=(8, 0), before=tree)      # 트리보다 먼저 자리를 잡아 결과 글이 잘리지 않게 한다

            def show(lines):
                out.configure(state="normal")
                out.delete("1.0", "end")
                out.insert("1.0", "\n".join(lines))
                out.configure(state="disabled")
                btns["복구 실행"].configure(state="normal")

            def done(r):
                lines = [t("restore_done", ok=len(r["ok"]), fail=len(r["fail"]))] + [f" - {p}: {why}" for p, why in r["fail"]]
                show(lines)
            self.run_bg(lambda _p: self.engine.restore(snap["id"], only_items=only), done,
                        lambda e: show([str(e) if isinstance(e, EngineBusy) else f"복구 실패: {e}"]))
        btns = self.footer(page, left=[("← 스냅샷 목록으로 (뒤로)", self.show_restore_list), ("취소 (처음으로)", self.show_home)],
                           right=[("복구 실행", go, "danger")])
