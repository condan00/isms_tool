import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from isms import history
from isms.history import HistoryError, describe, list_runs, load_report


def row():
    return {k: "x" for k in history.ROW_KEYS}


def write_run(base, name, rep):
    d = base / name
    d.mkdir(parents=True)
    (d / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    return d


def test_list_runs_newest_first(tmp_path):
    write_run(tmp_path, "26-01-01_10-00", {"results": [row()]})
    write_run(tmp_path, "26-02-01_10-00", {"results": [row()]})
    (tmp_path / "26-03-01_10-00").mkdir()          # JSON 없는 폴더는 제외
    names = [r["name"] for r in list_runs([tmp_path])]
    assert names == ["26-02-01_10-00", "26-01-01_10-00"]


def test_list_runs_skips_symlink_dir(tmp_path):
    real = tmp_path / "real"
    write_run(real, "26-01-01_10-00", {"results": [row()]})
    link = tmp_path / "link"
    link.symlink_to(real)
    assert list_runs([link]) == []


def test_load_report_ok_and_invalid(tmp_path):
    d = write_run(tmp_path, "a", {"results": [row()]})
    assert load_report(d / "report.json")["results"][0]["evidence"] == ""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(HistoryError):
        load_report(bad)
    bad.write_text(json.dumps({"results": [{"id": "U-01"}]}))
    with pytest.raises(HistoryError):
        load_report(bad)
    with pytest.raises(HistoryError):
        load_report(tmp_path / "missing.json")


def test_load_report_rejects_symlink_and_big(tmp_path, monkeypatch):
    d = write_run(tmp_path, "a", {"results": [row()]})
    ln = tmp_path / "ln.json"
    ln.symlink_to(d / "report.json")
    with pytest.raises(HistoryError):
        load_report(ln)
    monkeypatch.setattr(history, "MAX_BYTES", 5)
    with pytest.raises(HistoryError):
        load_report(d / "report.json")


def test_describe():
    s = describe({"kind": "fix", "host": {"hostname": "h"}, "summary": {"VULN": 2}, "results": [1, 2, 3]})
    assert "점검+조치" in s and "취약 2" in s and "전체 3" in s


def test_engine_restore_passes_only_items(tmp_path):
    from isms.engine import Engine
    e = Engine.__new__(Engine)
    got = {}

    class S:
        def restore(self, sid, only_items=None):
            got.update(sid=sid, only=only_items)
            return "ok"
    e.snaps = S()
    import contextlib
    e._lock = contextlib.nullcontext
    assert e.restore("s1", only_items=["U-15"]) == "ok"
    assert got == {"sid": "s1", "only": ["U-15"]}
