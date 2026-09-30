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
    root.geometry("2200x1100+0+0")  # wide and tall enough that every column and row is on screen
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
        app._start_job("Бэкап", [app.devices["SN1"]], lambda dev: app._backup_one(dev, cfg), 1)
        _wait_job(root, app)            # the cache is written when the operation ends
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


# ----------------------------------------------------------------- operations
def _wait_job(root, app, timeout=15):
    """Pump the window until the running operation has finished and been shown."""
    end = time.time() + timeout
    while time.time() < end:
        _pump(root, 2)
        if app._job and app._job["finished"] and str(app.btn_stop.cget("state")) == "disabled":
            break
    _pump(root, 3)
    app._tick()


def _many(n, **extra):
    from core import Device
    return [Device(ip=f"10.0.0.{i}", identity=f"R{i}", board_name="RB4011" if i % 2 else "hAP",
                   key=f"SN{i}", connect_ip=f"10.20.30.{i}", **extra) for i in range(1, n + 1)]


def test_gui_progress_says_what_runs_how_far_and_when_done():
    M, tk, root, app = _open()
    try:
        gate = __import__("threading").Event()
        seen = []

        def work(item):
            if item >= 3:
                gate.wait(5)
            seen.append(item)
            return item != 1                      # item 1 fails

        app._start_job("Тест", range(6), work, threads=2, ok_label="успешно", bad_label="ошибок")
        end = time.time() + 5
        while app._job["done"] < 3 and time.time() < end:
            _pump(root, 2)
        app._tick()
        text = app.lbl_progress.cget("text")
        assert text.startswith("Тест: 3 / 6 (50%)") and "прошло" in text and "потоков: 2" in text, text
        assert "ошибок: 1" in text and "успешно: 2" in text, text
        assert int(app.progress["value"]) == 3 and int(float(app.progress["maximum"])) == 6
        assert str(app.btn_stop.cget("state")) == "normal" and str(app.btn_pause.cget("state")) == "normal"
        gate.set()
        _wait_job(root, app)
        text = app.lbl_progress.cget("text")
        assert text.startswith("Готово · Тест: 6 / 6") and "за " in text and "ошибок: 1" in text, text
        assert str(app.btn_stop.cget("state")) == "disabled"
        assert sorted(seen) == list(range(6))
    finally:
        app._on_close()


def test_gui_stop_ends_the_job_early_and_pause_freezes_the_clock():
    M, tk, root, app = _open()
    try:
        app._start_job("Тест", range(40), lambda i: time.sleep(0.05) or True, threads=2)
        end = time.time() + 5
        while app._job["done"] < 2 and time.time() < end:
            _pump(root, 2)
        app.on_pause()
        _pump(root, 2)
        frozen_done = app._job["done"]
        e1 = app._job_elapsed(app._job)
        time.sleep(0.4)
        _pump(root, 3)
        assert app._job["done"] <= frozen_done + 2, "workers keep going while paused"
        assert app._job_elapsed(app._job) - e1 < 0.1, "paused time must not count"
        assert app.lbl_progress.cget("text").startswith("Пауза · Тест")
        app.on_pause()                                   # resume
        app.on_stop()
        _wait_job(root, app)
        job = app._job
        assert job["stopped"] and 2 <= job["done"] < 40, job
        assert app.lbl_progress.cget("text").startswith("Остановлено · Тест")
    finally:
        app._on_close()


def test_gui_a_second_operation_is_refused_while_one_runs():
    M, tk, root, app = _open()
    warned = []
    real = M.messagebox.showwarning
    M.messagebox.showwarning = lambda *a, **k: warned.append(a[1])
    try:
        app._start_job("Бэкап", range(30), lambda i: time.sleep(0.05) or True, threads=1)
        assert app._busy() is True and "Бэкап" in warned[0]
        app.on_stop()
        _wait_job(root, app)
        assert app._busy() is False
    finally:
        M.messagebox.showwarning = real
        app._on_close()


def test_gui_backup_and_commands_run_in_parallel_and_errors_turn_red():
    import threading
    M, tk, root, app = _open()
    try:
        for d in _many(12):
            app._upsert_device(d)
        _pump(root)
        app.var_cmdtype.set("SSH")
        app.var_threads.set("30")                       # more than the cap
        lock, running, peak = threading.Lock(), [0], [0]

        def fake_export(dev, cfg):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.15)
            with lock:
                running[0] -= 1
            if dev.key == "SN5":
                raise RuntimeError("Error reading SSH protocol banner")
            return f"# export of {dev.ip}"

        app._ssh_export = fake_export
        app.toggle_all()
        t0 = time.time()
        app.on_backup()
        _wait_job(root, app)
        took = time.time() - t0
        assert 2 <= peak[0] <= M.MAX_OPS_THREADS, peak
        assert took < 12 * 0.15, f"not parallel: {took:.2f}s"
        files = [f for f in os.listdir(M.BACKUP_DIR) if f.endswith(".rsc")]
        assert len(files) == 11, files
        text = app.lbl_progress.cget("text")
        assert text.startswith("Готово · Бэкап: 12 / 12") and "успешно: 11" in text and "ошибок: 1" in text, text
        assert app.devices["SN5"].failed and "error" in app.tree.item("SN5", "tags")
        assert "Backup error" in app.tree.set("SN5", "Status")
        assert not app.devices["SN4"].failed and "error" not in app.tree.item("SN4", "tags")
        assert app.tree.set("SN4", "Last Backup") and not app.tree.set("SN5", "Last Backup")
        assert str(app.tree.tag_configure("error", "background")) == M.ERROR_BG

        # a later success clears the red
        app._ssh_export = lambda dev, cfg: "# ok"
        app.checked.clear()
        app._set_checked("SN5", True)
        app.on_backup()
        _wait_job(root, app)
        assert not app.devices["SN5"].failed and "error" not in app.tree.item("SN5", "tags")

        # commands: same engine, and a failing device is flagged
        app._run_api_commands = lambda dev, command, cfg: (_ for _ in ()).throw(OSError("nope")) if dev.key == "SN2" else "ok"
        app.var_cmdtype.set("API/SSL")
        app.txt_command.insert("1.0", "/system identity print")
        app.toggle_all()
        app.on_send()
        _wait_job(root, app)
        assert app.lbl_progress.cget("text").startswith("Готово · Команды: 12 / 12")
        assert app.devices["SN2"].failed and app.tree.set("SN1", "Status") == "Command OK"
    finally:
        app._on_close()


def test_gui_counts_show_devices_selected_and_errors():
    M, tk, root, app = _open()
    try:
        for d in _many(5):
            app._upsert_device(d)
        app._set_checked("SN1", True)
        app._set_checked("SN2", True)
        app._set_status("SN3", "Error: boom", True)
        app._tick()
        assert app.lbl_counts.cget("text") == "Устройств: 5 · отмечено: 2 · с ошибками: 1", app.lbl_counts.cget("text")
    finally:
        app._on_close()


def test_gui_shift_click_ticks_a_whole_range():
    M, tk, root, app = _open()
    try:
        for d in _many(8):
            app._upsert_device(d)
        _pump(root)
        clock = [1000]

        def click(iid, shift=False):
            clock[0] += 10000
            bx, by, bw, bh = app.tree.bbox(iid, "#0")
            app.tree.event_generate("<ButtonPress-1>", x=bx + 3 + app._icon_size // 2, y=by + bh // 2,
                                    state=1 if shift else 0, time=clock[0])
            app.tree.event_generate("<ButtonRelease-1>", x=bx + 3 + app._icon_size // 2, y=by + bh // 2, time=clock[0] + 10)
            _pump(root, 1)

        click("SN2")
        click("SN6", shift=True)
        assert app.checked == {"SN2", "SN3", "SN4", "SN5", "SN6"}, app.checked
        click("SN4")                                   # a plain click toggles just that one
        assert app.checked == {"SN2", "SN3", "SN5", "SN6"}
        click("SN1", shift=True)                       # range back to the previous click (un-ticked)
        assert app.checked == {"SN5", "SN6"}, app.checked
        app.checked.clear()
        app._anchor = None
        click("SN8", shift=True)                       # nothing clicked before: behaves like a plain click
        assert app.checked == {"SN8"}
        app._tick()
        assert "отмечено: 1" in app.lbl_counts.cget("text")
    finally:
        app._on_close()


def test_gui_model_filter_errors_filter_and_sort():
    M, tk, root, app = _open()
    try:
        devices = _many(6)                              # odd numbers: RB4011, even: hAP
        devices[5].board_name = ""                      # SN6 has no model
        for d in devices:
            app._upsert_device(d)
        app._set_status("SN3", "Error: boom", True)
        app._tick()
        assert list(app.model_combo.cget("values")) == [M.ALL_MODELS, M.EMPTY_MODEL, "hAP", "RB4011"]

        app.var_model.set("RB4011")
        app._on_filter_change()
        assert list(app.tree.get_children("")) == ["SN1", "SN3", "SN5"]
        app._tick()
        assert "показано 3" in app.lbl_counts.cget("text")

        app.toggle_all()                                # header box ticks only what is shown
        assert app.checked == {"SN1", "SN3", "SN5"} and "SN2" not in app.checked
        assert [d.key for d in app.selected_devices()] == ["SN1", "SN3", "SN5"]

        app.var_model.set("hAP")                        # rows that get hidden lose their tick
        app._on_filter_change()
        assert list(app.tree.get_children("")) == ["SN2", "SN4"] and app.checked == set()

        app.var_model.set(M.EMPTY_MODEL)
        app._on_filter_change()
        assert list(app.tree.get_children("")) == ["SN6"]

        app.var_model.set(M.ALL_MODELS)
        app.var_errors_only.set(True)
        app._on_filter_change()
        assert list(app.tree.get_children("")) == ["SN3"]
        app.toggle_all()
        assert app.checked == {"SN3"}

        # an error that appears while the filter is on shows up at once; a fixed one disappears
        app._set_status("SN4", "Backup error: x", True)
        assert list(app.tree.get_children("")) == ["SN3", "SN4"] or set(app.tree.get_children("")) == {"SN3", "SN4"}
        app._set_status("SN3", "OK", False)
        assert set(app.tree.get_children("")) == {"SN4"} and "SN3" not in app.checked

        app.var_errors_only.set(False)
        app._on_filter_change()
        assert len(app.tree.get_children("")) == 6

        # sort: numeric for IPs, and it survives filtering
        app.devices["SN1"].ip = "10.0.0.10"
        app.devices["SN2"].ip = "10.0.0.9"
        app.sort_by("IP")
        order = [app.devices[i].ip for i in app.tree.get_children("")]
        assert order.index("10.0.0.9") < order.index("10.0.0.10"), order
        app.var_model.set("RB4011")
        app._on_filter_change()
        shown = [app.devices[i].ip for i in app.tree.get_children("")]
        assert shown == sorted(shown, key=lambda ip: tuple(int(x) for x in ip.split("."))), shown
    finally:
        app._on_close()


def test_gui_delete_asks_first_and_removes_only_ticked_rows():
    M, tk, root, app = _open()
    asked, told = [], []
    real_ask, real_info = M.messagebox.askyesno, M.messagebox.showinfo
    M.messagebox.showinfo = lambda *a, **k: told.append(a[1])
    try:
        for d in _many(5):
            app._upsert_device(d)
        app._tick()
        app.on_delete()                                 # nothing ticked
        assert told and "Отметьте" in told[0] and len(app.devices) == 5

        app._set_checked("SN2", True)
        app._set_checked("SN4", True)
        M.messagebox.askyesno = lambda *a, **k: asked.append(a) or False
        app.on_delete()                                 # answered "no"
        assert len(asked) == 1 and "2" in asked[0][1] and len(app.devices) == 5 and app.checked == {"SN2", "SN4"}

        M.messagebox.askyesno = lambda *a, **k: True
        app.on_delete()
        assert set(app.devices) == {"SN1", "SN3", "SN5"} and list(app.tree.get_children("")) == ["SN1", "SN3", "SN5"]
        assert app.checked == set()
        app._tick()
        assert app.lbl_counts.cget("text").startswith("Устройств: 3")
        assert sorted(r["key"] for r in json.load(open(M.DEVICES_FILE))) == ["SN1", "SN3", "SN5"]
    finally:
        M.messagebox.askyesno, M.messagebox.showinfo = real_ask, real_info
        app._on_close()


def test_gui_old_cache_without_the_error_flag_is_recognised():
    M, tk, root, app = _open()
    try:
        json.dump([{"ip": "10.0.0.1", "key": "A", "status": "Backup error: timed out"},
                   {"ip": "10.0.0.2", "key": "B", "status": "OK (API-SSL:8729)"},
                   {"ip": "10.0.0.3", "key": "C", "status": "Backup: 10.0.0.3_x_error.rsc"}], open(M.DEVICES_FILE, "w"))
        app.devices.clear()
        for iid in app.tree.get_children(""):
            app.tree.delete(iid)
        app._load_devices()
        assert [app.devices[k].failed for k in ("A", "B", "C")] == [True, False, False]
        assert "error" in app.tree.item("A", "tags") and "error" not in app.tree.item("C", "tags")
    finally:
        app._on_close()


def test_gui_scan_and_update_use_the_job_engine_and_mark_lost_devices_red():
    import core
    from core import Device
    M, tk, root, app = _open()
    real_scan, real_ask = core.scan_host, M.messagebox.askyesno
    alive = {"10.9.9.1": ("SNA", "RB4011"), "10.9.9.2": ("SNB", "hAP")}

    def fake_scan(ip, user, password, port, plain_port=8728, timeout=10, retries=2, logger=None):
        if ip not in alive:
            raise TimeoutError("timed out")
        key, board = alive[ip]
        return Device(ip=ip, identity=f"id-{key}", board_name=board, key=key, connect_ip=ip,
                      status="OK (API-SSL:8729)")

    core.scan_host = fake_scan
    M.messagebox.askyesno = lambda *a, **k: True
    try:
        app.var_network.set("10.9.9.1-4")
        app.on_scan()
        _wait_job(root, app)
        assert app.lbl_progress.cget("text").startswith("Готово · Сканирование: 4 / 4"), app.lbl_progress.cget("text")
        assert "найдено: 2" in app.lbl_progress.cget("text")
        assert sorted(app.devices) == ["SNA", "SNB"]              # silent addresses leave no rows
        assert not any(d.failed for d in app.devices.values())

        alive.pop("10.9.9.2")                                      # SNB stops answering
        app.var_model.set("hAP")
        app.var_errors_only.set(True)
        app._on_filter_change()
        assert list(app.tree.get_children("")) == []               # nothing has failed yet
        app.on_update()                                            # rescans the table + the subnet
        _wait_job(root, app)
        assert app.lbl_progress.cget("text").startswith("Готово · Обновление: 4 / 4")
        assert app.devices["SNB"].failed and "error" in app.tree.item("SNB", "tags")
        assert not app.devices["SNA"].failed
        assert list(app.tree.get_children("")) == ["SNB"]          # shown by the filters that were set
        assert "Error: TimeoutError" in app.tree.set("SNB", "Status")

        alive["10.9.9.3"] = ("SNC", "RB4011")                      # a new scan starts from a clean slate
        app.on_scan()
        _wait_job(root, app)
        assert app.var_model.get() == M.ALL_MODELS and app.var_errors_only.get() is False
        assert sorted(app.devices) == ["SNA", "SNC"] and len(app.tree.get_children("")) == 2
    finally:
        core.scan_host, M.messagebox.askyesno = real_scan, real_ask
        app._on_close()
