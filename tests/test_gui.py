"""Window tests. Skipped automatically without tkinter or a display."""

import json
import os
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _open():
    try:
        import tkinter as tk
    except ImportError:
        raise unittest.SkipTest("tkinter is not installed")
    import mikrotik_scanner as M

    work = tempfile.mkdtemp()
    for name, fname in (("APP_DIR", ""), ("DEVICES_FILE", "devices.json"), ("UI_FILE", "ui.json"),
                        ("SETTINGS_FILE", "settings.json"), ("BACKUP_DIR", "Backups")):
        setattr(M, name, os.path.join(work, fname) if fname else work)
    os.makedirs(M.BACKUP_DIR)
    try:
        root = tk.Tk()
    except tk.TclError:
        raise unittest.SkipTest("no display")
    app = M.ScannerApp(root)
    root.geometry("2200x500+0+0")  # wide enough that every column is on screen
    _pump(root)
    return M, tk, root, app


def _pump(root, n=5):
    for _ in range(n):
        root.update()
        time.sleep(0.02)


def _devices():
    from core import Device
    return [Device(ip="10.20.44.209", identity="R1", board_name="RB4011", key="SN1", connect_ip="10.20.30.209"),
            Device(ip="10.20.30.210", identity="R2", license="4", key="SN2")]


def test_gui_builds_with_all_row_actions():
    M, tk, root, app = _open()
    try:
        for method in ("on_winbox", "on_update_one", "toggle_all", "_on_tree_right_click",
                       "on_backup", "on_send", "on_export", "on_import", "_save_ui_state"):
            assert callable(getattr(app, method, None)), f"missing {method}"
        assert app.tree.cget("columns")[-1] == "winbox"
        assert list(M.COLUMNS).index("Last Backup") == list(M.COLUMNS).index("Last seen") + 1
    finally:
        app._on_close()


def test_gui_click_zones_and_check_all():
    M, tk, root, app = _open()
    try:
        for d in _devices():
            app._upsert_device(d)
        _pump(root)
        updates = []
        app.on_update_one = updates.append
        size, gap = app._icon_size, app._icon_gap

        def click(iid, rel_x):
            bx, by, bw, bh = app.tree.bbox(iid, "#0")
            for seq in ("<Button-1>", "<ButtonRelease-1>"):
                app.tree.event_generate(seq, x=bx + rel_x, y=by + bh // 2)
            _pump(root, 2)

        click("SN1", 3 + size // 2)
        assert app.checked == {"SN1"} and not updates
        click("SN1", 3 + size + gap + size // 2)
        assert updates == ["SN1"] and app.checked == {"SN1"}
        click("SN1", app._icon_w + 40)
        assert updates == ["SN1"]
        app.toggle_all()
        assert app.checked == {"SN1", "SN2"}
        app.toggle_all()
        assert app.checked == set()
    finally:
        app._on_close()


def test_gui_last_backup_is_kept_on_rescan_and_cached():
    from core import Device
    M, tk, root, app = _open()
    try:
        d1, _ = _devices()
        app._upsert_device(d1)
        app._ssh_export = lambda dev, cfg: "/export"
        cfg = {"cmdtype": "SSH", "ssh_port": 22, "timeout": 5, "user": "a", "password": "b", "api_ssl_port": 8729}
        app._backup_worker([app.devices["SN1"]], cfg)
        _pump(root, 10)
        stamp = app.tree.set("SN1", "Last Backup")
        assert len(stamp) == 19, stamp
        app._upsert_device(Device(ip="10.20.44.209", key="SN1", identity="R1"))  # what a rescan produces
        assert app.tree.set("SN1", "Last Backup") == stamp
        assert any(r["last_backup"] == stamp for r in json.load(open(M.DEVICES_FILE)))
    finally:
        app._on_close()


def test_gui_column_widths_are_remembered():
    M, tk, root, app = _open()
    try:
        app.tree.column("Identity", width=333)
        app._save_ui_state()
    finally:
        app._on_close()
    ui_file = M.UI_FILE
    assert json.load(open(ui_file))["column_widths"]["Identity"] == 333
    root2 = None
    try:
        root2 = tk.Tk()
        app2 = M.ScannerApp(root2)
        assert int(app2.tree.column("Identity", "width")) == 333
        json.dump({"column_widths": {"IP": "junk", "Status": 10 ** 6, "Nope": 1}}, open(ui_file, "w"))
        app2._load_ui_state()
        assert int(app2.tree.column("Status", "width")) <= 2000
    finally:
        if root2 is not None:
            app2._on_close()


def test_gui_right_click_copies_cell_or_row():
    M, tk, root, app = _open()
    posted = []
    original = tk.Menu.tk_popup
    tk.Menu.tk_popup = lambda self, x, y, entry="": posted.append(self)
    try:
        for d in _devices():
            app._upsert_device(d)
        _pump(root)

        def right_click(iid, col):
            bx, by, bw, bh = app.tree.bbox(iid, col)
            posted.clear()
            app.tree.event_generate("<Button-3>", x=bx + 5, y=by + bh // 2)
            _pump(root, 2)
            return posted[-1]

        menu = right_click("SN1", "Identity")
        menu.invoke(0)
        assert root.clipboard_get() == "R1"
        menu.invoke(1)
        row = root.clipboard_get().split("\t")
        assert len(row) == len(M.COLUMNS) and row[:2] == ["10.20.44.209", "R1"]
        assert right_click("SN1", "#0").index("end") == 0  # icons column: only "copy row"
    finally:
        tk.Menu.tk_popup = original
        app._on_close()


def test_gui_winbox_button_passes_address_and_login():
    if os.name != "posix":
        raise unittest.SkipTest("uses a shell script as a stand-in for winbox.exe")
    M, tk, root, app = _open()
    try:
        app._upsert_device(_devices()[0])
        _pump(root)
        exe = os.path.join(M.APP_DIR, "winbox64.exe")
        open(exe, "w").write('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/args.txt"\n')
        os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
        app.var_user.set("admin")
        app.var_pass.set("p w;&$'\"")
        app.var_winbox_port.set("61291")
        bx, by, bw, bh = app.tree.bbox("SN1", "winbox")
        app.tree.event_generate("<Button-1>", x=bx + bw // 2, y=by + bh // 2)
        for _ in range(50):
            _pump(root, 1)
            if os.path.exists(os.path.join(M.APP_DIR, "args.txt")):
                time.sleep(0.1)
                break
        args = open(os.path.join(M.APP_DIR, "args.txt")).read().split("\n")[:-1]
        assert args == ["10.20.30.209:61291", "admin", "p w;&$'\""], args
    finally:
        app._on_close()


def test_gui_double_click_last_backup_opens_the_newest_file():
    import core
    M, tk, root, app = _open()
    opened, shown = [], []
    real_open, real_info, real_err = core.open_with_default_app, M.messagebox.showinfo, M.messagebox.showerror
    core.open_with_default_app = opened.append
    M.messagebox.showinfo = lambda *a, **k: shown.append(a[1])
    M.messagebox.showerror = lambda *a, **k: shown.append(a[1])
    try:
        for d in _devices():
            app._upsert_device(d)
        _pump(root)

        clock = [1000]

        def fast_double_click(x, y):
            clock[0] += 10000  # well past Tk's double-click interval since the previous one
            for ms in (clock[0], clock[0] + 100):  # 100 ms apart: Tk turns the 2nd into a double click
                app.tree.event_generate("<ButtonPress-1>", x=x, y=y, time=ms)
                app.tree.event_generate("<ButtonRelease-1>", x=x, y=y, time=ms + 10)
            _pump(root, 2)

        def double_click(iid, column):
            bx, by, bw, bh = app.tree.bbox(iid, column)
            fast_double_click(bx + 6, by + bh // 2)

        older = os.path.join(M.BACKUP_DIR, "10.20.44.209_R1_2026-08-01.rsc")
        newer = os.path.join(M.BACKUP_DIR, "10.20.44.209_R1_2026-09-20.rsc")
        for path, age in ((older, 30), (newer, 2)):
            open(path, "w").write("# config")
            t = time.time() - age * 86400
            os.utime(path, (t, t))

        double_click("SN1", "Last Backup")
        assert opened == [newer], opened

        opened.clear()
        double_click("SN2", "Last Backup")              # no backup and nothing recorded: silent
        assert opened == [] and shown == []

        app.devices["SN2"].last_backup = "2026-09-01 10:00:00"   # recorded, but the file is gone
        double_click("SN2", "Last Backup")
        assert opened == [] and len(shown) == 1 and "10.20.30.210" in shown[0]

        shown.clear()
        core.open_with_default_app = lambda path: (_ for _ in ()).throw(OSError("no program"))
        double_click("SN1", "Last Backup")              # the OS can't open it: told, not crashed
        assert len(shown) == 1 and newer in shown[0]

        # a fast 2nd click on any other cell must still act like a normal click:
        # two quick clicks on a checkbox tick it and un-tick it again (not "swallowed")
        opened.clear()
        bx, by, bw, bh = app.tree.bbox("SN1", "#0")
        fast_double_click(bx + 3 + app._icon_size // 2, by + bh // 2)
        assert app.checked == set() and opened == []
        app.tree.event_generate("<ButtonPress-1>", x=bx + 3 + app._icon_size // 2, y=by + bh // 2, time=clock[0] + 10000)
        _pump(root, 2)
        assert app.checked == {"SN1"}
    finally:
        core.open_with_default_app, M.messagebox.showinfo, M.messagebox.showerror = real_open, real_info, real_err
        app._on_close()
