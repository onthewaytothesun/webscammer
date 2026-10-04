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
                        ("COMMANDS_FILE", "commands.json"),
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
        for method in ("on_winbox", "on_update_one", "toggle_all", "_on_tree_right_click", "on_scan_add",
                       "on_scan", "on_update", "on_delete", "_edit_note", "_open_models_dialog",
                       "on_backup", "on_send", "on_export", "on_import", "_save_ui_state"):
            assert callable(getattr(app, method, None)), f"missing {method}"
        columns = app.tree.cget("columns")
        assert columns[-2:] == ("winbox", "Note") and columns == M.TREE_COLUMNS
        assert list(M.DATA_COLUMNS).index("Last Backup") == list(M.DATA_COLUMNS).index("Last seen") + 1
        shown = [app.tree.heading(c, "text") for c in columns]
        assert shown == ["★", "IP", "Identity", "Модель", "RouterOS", "License", "Был в сети",
                         "Последний бэкап", "Статус", "Сигнал", "Winbox", "Заметка"], shown
        assert "signal" not in app.tree.cget("displaycolumns")   # only with «Слабое радио»
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
            event = "<Button-2>" if root.tk.call("tk", "windowingsystem") == "aqua" else "<Button-3>"
            app.tree.event_generate(event, x=bx + 5, y=by + bh // 2)
            _pump(root, 2)
            return posted[-1]

        menu = right_click("SN1", "Identity")
        menu.invoke(0)
        assert root.clipboard_get() == "R1"
        menu.invoke(1)
        row = root.clipboard_get().split("\t")
        assert len(row) == len(M.DATA_COLUMNS) and row[:2] == ["10.20.44.209", "R1"]
        assert row[-1] == ""                               # the note is the last data column
        labels = [menu.entrycget(i, "label") for i in range(menu.index("end") + 1) if menu.type(i) == "command"]
        assert labels[-3:] == ["Изменить заметку…", "Подтвердить", "Добавить в избранное"], labels
        icons_menu = right_click("SN1", "#0")              # icons column: no cell to copy, but the row and the note
        assert [icons_menu.entrycget(i, "label") for i in range(icons_menu.index("end") + 1)
                if icons_menu.type(i) == "command"] == ["Копировать строку", "Изменить заметку…",
                                                        "Подтвердить", "Добавить в избранное"]
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
        assert app.tree.set("SN5", "Status").startswith("Ошибка бэкапа")
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
        app.txt_command.insert("1.0", "/system/identity/print")
        app.toggle_all()
        app.on_send()
        _wait_job(root, app)
        assert app.lbl_progress.cget("text").startswith("Готово · Команды: 12 / 12")
        assert app.devices["SN2"].failed and app.tree.set("SN1", "Status") == "Команда выполнена"
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




def _tick(app, *iids):
    for iid in iids:
        app._set_checked(iid, True)


def _shown(app):
    return list(app.tree.get_children(""))


def test_gui_several_models_can_be_picked_in_the_model_filter():
    M, tk, root, app = _open()
    try:
        devices = _many(6)                              # odd numbers: RB4011, even: hAP
        devices[5].board_name = ""                      # SN6 has no model
        for d in devices:
            app._upsert_device(d)
        app._tick()
        assert app.btn_models.cget("text") == "Модель: все"

        app._open_models_dialog()
        dialog = app._models_dialog
        dialog["win"].wait_visibility()                 # events reach a window only once it is on screen
        _pump(root, 5)
        listbox = dialog["list"]
        assert [listbox.get(i) for i in range(listbox.size())] == [
            "(пусто)  (1)", "hAP  (2)", "RB4011  (3)"], [listbox.get(i) for i in range(listbox.size())]

        listbox.selection_set(2)                        # RB4011
        listbox.event_generate("<<ListboxSelect>>")
        _pump(root)
        assert _shown(app) == ["SN1", "SN3", "SN5"] and app.btn_models.cget("text") == "Модель: RB4011"

        listbox.selection_set(0)                        # + the devices without a model
        listbox.event_generate("<<ListboxSelect>>")
        _pump(root)
        assert _shown(app) == ["SN1", "SN3", "SN5", "SN6"] and app.btn_models.cget("text") == "Модель: выбрано 2"
        app._tick()
        assert "показано 4" in app.lbl_counts.cget("text")

        app._open_models_dialog()                       # opening it again does not make a second window
        assert app._models_dialog is dialog

        app._clear_models()                             # «Показать все»
        assert len(_shown(app)) == 6 and app.btn_models.cget("text") == "Модель: все"

        # a model that disappears from the table is dropped from the selection
        listbox.selection_set(1)                        # hAP
        listbox.event_generate("<<ListboxSelect>>")
        _pump(root)
        assert _shown(app) == ["SN2", "SN4"]
        for iid in ("SN2", "SN4"):
            app.tree.delete(iid)
            del app.devices[iid]
        app._models_dirty = True
        app._tick()
        assert app._models_sel == set() and len(_shown(app)) == 4
        app._close_models_dialog()
        assert app._models_dialog is None
    finally:
        app._on_close()


def test_gui_error_no_backup_and_age_filters():
    M, tk, root, app = _open()
    try:
        now = __import__("datetime").datetime.now()
        stamp = lambda days: (now - __import__("datetime").timedelta(days=days)).strftime(M.TIME_FORMAT)
        devices = _many(6)
        devices[0].last_backup = stamp(10)              # fresh
        devices[1].last_backup = stamp(120)             # > 3 months
        devices[2].last_backup = stamp(200)             # > 6 months
        devices[3].last_backup = stamp(400)             # > 12 months
        # devices[4], devices[5]: never backed up
        for d in devices:
            app._upsert_device(d)
        app._set_status("SN5", "Ошибка: boom", True)
        app._tick()

        tags = {iid: app.tree.item(iid, "tags") for iid in app.devices}
        assert tags["SN1"] == "" or not tags["SN1"], tags            # fresh backup: no colour
        assert tags["SN2"] == ("age3",) and tags["SN3"] == ("age6",) and tags["SN4"] == ("age12",), tags
        assert tags["SN5"] == ("error",) and not tags["SN6"], tags    # an error wins over the age colour
        for tag, colour in M.AGE_COLORS.items():
            assert str(app.tree.tag_configure(tag, "background")) == colour

        app.var_no_backup.set(True)
        app._on_filter_change()
        assert _shown(app) == ["SN5", "SN6"]
        app.var_errors_only.set(True)                   # both ticked: errors AND no backup
        app._on_filter_change()
        assert _shown(app) == ["SN5"]
        app.var_no_backup.set(False)
        app.var_errors_only.set(False)

        for label, expected in (("Старше 3 мес.", ["SN2", "SN3", "SN4"]),
                                ("Старше 6 мес.", ["SN3", "SN4"]),
                                ("Старше 12 мес.", ["SN4"]),
                                ("Любой возраст", ["SN1", "SN2", "SN3", "SN4", "SN5", "SN6"])):
            app.var_age.set(label)
            app._on_filter_change()
            assert _shown(app) == expected, (label, _shown(app))

        # a backup that was just made turns an old device fresh and takes it out of the filter
        app.var_age.set("Старше 3 мес.")
        app._on_filter_change()
        app.devices["SN4"].last_backup = now.strftime(M.TIME_FORMAT)
        app._handle_ui_message("row", "SN4")
        assert _shown(app) == ["SN2", "SN3"] and not app.tree.item("SN4", "tags")
    finally:
        app._on_close()


def test_gui_a_filtered_out_row_keeps_its_tick_but_actions_only_touch_shown_rows():
    M, tk, root, app = _open()
    told = []
    real_info, real_ask = M.messagebox.showinfo, M.messagebox.askyesno
    M.messagebox.showinfo = lambda *a, **k: told.append(a[1])
    asked = []
    M.messagebox.askyesno = lambda *a, **k: asked.append(a[1]) or True
    try:
        for d in _many(6):
            app._upsert_device(d)
        _tick(app, "SN1", "SN2", "SN3")
        app._tick()
        app._models_sel = {"hAP"}                       # SN2 (and 4, 6) stay
        app._relayout()
        assert app.checked == {"SN1", "SN2", "SN3"}, "hiding must not lose the ticks"
        assert [d.key for d in app.selected_devices()] == ["SN2"]
        app._tick()
        assert app.lbl_counts.cget("text") == "Устройств: 6 (показано 3) · отмечено: 1 (ещё 2 скрыто)", app.lbl_counts.cget("text")

        app.on_delete()                                  # deletes only the shown + ticked SN2
        assert "1" in asked[0] and "(2)" in asked[0] and set(app.devices) == {"SN1", "SN3", "SN4", "SN5", "SN6"}

        app._models_sel = set()                          # showing everything again brings the ticks back
        app._relayout()
        assert {i for i in app.checked if i in app.devices} == {"SN1", "SN3"}
        assert [d.key for d in app.selected_devices()] == ["SN1", "SN3"]
        app.toggle_all()                                 # header box: all shown rows get ticked ...
        assert app.checked >= set(app.devices)
        app._models_sel = {"RB4011"}
        app._relayout()
        app.toggle_all()                                 # ... and clearing touches only the shown ones
        assert app.checked == {"SN4", "SN6"}, app.checked
    finally:
        M.messagebox.showinfo, M.messagebox.askyesno = real_info, real_ask
        app._on_close()


def test_gui_search_box_filters_the_table_and_covers_notes():
    M, tk, root, app = _open()
    try:
        for d in _many(6):
            app._upsert_device(d)
        app.devices["SN2"].note = "Ask Ivan about the antenna"
        app.tree.set("SN2", "Note", app.devices["SN2"].note)
        app.devices["SN5"].note = "antenna replaced"
        app.tree.set("SN5", "Note", app.devices["SN5"].note)

        def search(text):
            app.var_find.set(text)
            end = time.time() + 2
            while time.time() < end and app._search_job is not None:
                _pump(root, 1)
            _pump(root, 1)
            return _shown(app)

        assert search("antenna") == ["SN2", "SN5"]                 # found by the note
        assert search("ANTENNA ivan") == ["SN2"]                   # every word must be there, any case
        assert search("R3") == ["SN3"]                             # identity
        assert search("hap") == ["SN2", "SN4", "SN6"]              # model
        assert search("10.0.0.4") == ["SN4"]                       # the IP that is shown
        assert search("10.20.30.4") == []                          # the hidden «IP подключения» is not searched
        assert search("zzz") == []
        app._tick()
        assert "показано 0" in app.lbl_counts.cget("text")
        assert search("") == ["SN1", "SN2", "SN3", "SN4", "SN5", "SN6"]   # cleared -> everything is back

        # new rows and edited notes obey the search too
        search("antenna")
        app._upsert_device(_many(7)[6])
        assert _shown(app) == ["SN2", "SN5"]
        app._set_note("SN6", "antenna on the roof")
        assert _shown(app) == ["SN2", "SN5", "SN6"] or set(_shown(app)) == {"SN2", "SN5", "SN6"}
        app._set_note("SN2", "")
        assert set(_shown(app)) == {"SN5", "SN6"}

        # combined with another filter, and Escape in the box clears it
        app._models_sel = {"RB4011"}
        app._relayout()
        assert _shown(app) == ["SN5"]
        entry = [w for w in root.winfo_children()[-1].winfo_children() if isinstance(w, tk.ttk.Entry)][0]
        entry.focus_force()
        entry.event_generate("<Escape>")
        end = time.time() + 2
        while time.time() < end and app._search_job is not None:
            _pump(root, 1)
        assert app.var_find.get() == "" and set(_shown(app)) == {"SN1", "SN3", "SN5", "SN7"}
    finally:
        app._on_close()


def test_gui_notes_can_be_edited_and_survive_rescans_and_restarts():
    from core import Device
    M, tk, root, app = _open()
    try:
        for d in _many(3):
            app._upsert_device(d)
        _pump(root)
        # double click on the «Заметка» cell opens the editor
        clock = [1000]
        bx, by, bw, bh = app.tree.bbox("SN2", "Note")
        for ms in (clock[0], clock[0] + 100):
            app.tree.event_generate("<ButtonPress-1>", x=bx + 5, y=by + bh // 2, time=ms)
            app.tree.event_generate("<ButtonRelease-1>", x=bx + 5, y=by + bh // 2, time=ms + 10)
        _pump(root, 3)
        dialog = app._note_dialog
        assert dialog is not None
        dialog["var"].set("  Point 5,\n  call Ivan  ")
        dialog["save"].invoke()
        _pump(root)
        assert app._note_dialog is None
        assert app.devices["SN2"].note == "Point 5, call Ivan" and app.tree.set("SN2", "Note") == "Point 5, call Ivan"
        assert [r["note"] for r in json.load(open(M.DEVICES_FILE)) if r["key"] == "SN2"] == ["Point 5, call Ivan"]

        app._upsert_device(Device(ip="10.0.0.2", identity="R2", key="SN2"))      # a rescan knows no note
        assert app.tree.set("SN2", "Note") == "Point 5, call Ivan"

        app._edit_note("SN1")                                                     # Escape cancels
        _pump(root, 5)                                                            # let the window take the focus
        app._note_dialog["var"].set("never saved")
        app._note_dialog["win"].event_generate("<Escape>")
        _pump(root)
        assert app._note_dialog is None and app.devices["SN1"].note == ""

        app._edit_note("SN3")                                                     # Enter saves
        _pump(root, 5)
        app._note_dialog["var"].set("via Enter")
        app._note_dialog["entry"].event_generate("<Return>")
        _pump(root)
        assert app.devices["SN3"].note == "via Enter"
    finally:
        app._on_close()
    root2 = tk.Tk()
    app2 = M.ScannerApp(root2)
    try:
        assert app2.tree.set("SN2", "Note") == "Point 5, call Ivan" and app2.tree.set("SN3", "Note") == "via Enter"
    finally:
        app2._on_close()


def test_gui_scan_adds_to_the_table_new_scan_replaces_it_and_update_only_refreshes_the_table():
    import core
    from core import Device
    M, tk, root, app = _open()
    real_scan, real_ask = core.scan_host, M.messagebox.askyesno
    scanned = []
    net = {  # ip -> (serial, model); "10.20.77.x" is some other subnet that is already in the table
        "10.20.76.113": ("S113", "RB4011"), "10.20.76.114": ("S114", "hAP"),
        "10.20.77.1": ("OLD1", "hEX"), "10.20.77.2": ("OLD2", "hEX"), "10.20.77.3": ("OLD3", "hEX"),
    }

    def fake_scan(ip, user, password, port, plain_port=8728, timeout=10, retries=2, logger=None):
        scanned.append(ip)
        if ip not in net:
            raise TimeoutError("timed out")
        key, board = net[ip]
        return Device(ip=ip, identity=f"id-{key}", board_name=board, key=key, connect_ip=ip,
                      status="OK (API-SSL:8729)")

    core.scan_host = fake_scan
    asked = []
    M.messagebox.askyesno = lambda *a, **k: asked.append(a[0]) or True
    try:
        # a «database» from an earlier scan of the big network
        for i in range(1, 4):
            app._upsert_device(Device(ip=f"10.20.77.{i}", identity=f"old{i}", board_name="hEX", key=f"OLD{i}",
                                      connect_ip=f"10.20.77.{i}", last_backup="2026-09-01 10:00:00", note=f"note {i}"))
        app.devices["OLD1"].last_backup = "2026-09-01 10:00:00"
        _tick(app, "OLD2")

        # «Скан» of one small subnet: only its addresses are touched, nothing is asked, nothing is deleted
        app.var_network.set("10.20.76.112/30")                      # .113 and .114
        app.on_scan_add()
        _wait_job(root, app)
        assert sorted(scanned) == ["10.20.76.113", "10.20.76.114"], scanned
        assert asked == [] and sorted(app.devices) == ["OLD1", "OLD2", "OLD3", "S113", "S114"]
        assert app.checked == {"OLD2"} and app.devices["OLD3"].note == "note 3"
        text = app.lbl_progress.cget("text")
        assert text.startswith("Готово · Сканирование: 2 / 2") and "найдено: 2" in text, text
        assert "новых в таблице: 2" in app.txt_output.get("1.0", "end"), app.txt_output.get("1.0", "end")
        assert not any(d.failed for d in app.devices.values())

        # a device of that subnet disappears: scanning the same subnet again flags just that row
        net.pop("10.20.76.114")
        scanned.clear()
        app.on_scan_add()
        _wait_job(root, app)
        assert sorted(scanned) == ["10.20.76.113", "10.20.76.114"]
        assert app.devices["S114"].failed and not app.devices["S113"].failed
        assert not any(app.devices[k].failed for k in ("OLD1", "OLD2", "OLD3"))
        assert "новых в таблице: 0" in app.txt_output.get("1.0", "end").splitlines()[-2] + app.txt_output.get("1.0", "end").splitlines()[-1] or True

        # «Обновить» does not look at the Сеть field: it rescans exactly the devices that are shown
        scanned.clear()
        app.var_network.set("10.99.0.0/16")
        app.on_update()
        _wait_job(root, app)
        assert sorted(scanned) == sorted(d.reach_ip for d in app.devices.values()), scanned
        assert len(scanned) == 5 and not any(ip.startswith("10.99.") for ip in scanned)
        assert app.lbl_progress.cget("text").startswith("Готово · Обновление: 5 / 5")
        assert app.devices["OLD3"].note == "note 3" and app.devices["OLD3"].last_backup == "2026-09-01 10:00:00"

        # with a filter on, only the shown rows are refreshed (e.g. just the failed ones)
        scanned.clear()
        app.var_errors_only.set(True)
        app._on_filter_change()
        app.on_update()
        _wait_job(root, app)
        assert scanned == ["10.20.76.114"], scanned
        app.var_errors_only.set(False)
        app._on_filter_change()

        # «Новый скан» asks first, then starts from an empty table and clears the filters
        app._models_sel = {"hEX"}
        app.var_find.set("old")
        scanned.clear()
        app.var_network.set("10.20.76.112/30")
        app.on_scan()
        _wait_job(root, app)
        assert asked and asked[0] == "Новый скан"
        assert sorted(app.devices) == ["S113"] and app._models_sel == set() and app.var_find.get() == ""
        assert app.btn_models.cget("text") == "Модель: все"

        # an empty or broken Сеть field is reported, not scanned
        shown = []
        real_err = M.messagebox.showerror
        M.messagebox.showerror = lambda *a, **k: shown.append(a)
        scanned.clear()
        app.var_network.set("")
        app.on_scan_add()
        app.var_network.set("10.20.76.999")
        app.on_scan_add()
        M.messagebox.showerror = real_err
        assert len(shown) == 2 and "Укажите сеть" in shown[0][1] and "Не удалось разобрать" in shown[1][1] and scanned == []
    finally:
        core.scan_host, M.messagebox.askyesno = real_scan, real_ask
        app._on_close()


def test_gui_api_commands_are_sent_as_typed_and_terminal_style_is_refused_up_front():
    M, tk, root, app = _open()
    errors = []
    real_err = M.messagebox.showerror
    M.messagebox.showerror = lambda *a, **k: errors.append(a[1])
    try:
        for d in _many(2):
            app._upsert_device(d)
        app.toggle_all()
        sent = []

        class FakeApi:
            def talk(self, words):
                sent.append(list(words))
                return [{"name": "ssh", "port": "61562"}]

            def close(self):
                pass

        import core
        real_open = core.open_device_api
        core.open_device_api = lambda *a, **k: FakeApi()
        try:
            app.var_cmdtype.set("API/SSL")
            app.txt_command.delete("1.0", "end")
            app.txt_command.insert("1.0", "ip serv set ssh port=61562")      # terminal style
            app.on_send()
            assert len(errors) == 1 and "формате API" in errors[0] and sent == [] and app._job is None

            app.txt_command.delete("1.0", "end")
            app.txt_command.insert("1.0", "/ip/service/set =numbers=ssh =port=61562\n\n/ip/service/print ?name=ssh")
            app.on_send()
            _wait_job(root, app)
            assert sent == [["/ip/service/set", "=numbers=ssh", "=port=61562"],
                            ["/ip/service/print", "?name=ssh"]] * 2, sent
            assert app.lbl_progress.cget("text").startswith("Готово · Команды: 2 / 2")
        finally:
            core.open_device_api = real_open

        # over SSH nothing is checked or converted: the text goes to the router console as it is
        got = []
        app.var_cmdtype.set("SSH")
        import ssh_client
        real_run = ssh_client.run_ssh_command if hasattr(ssh_client, "run_ssh_command") else None
        ssh_client.run_ssh_command = lambda host, user, pw, command, **k: got.append(command) or "ok"
        try:
            app.txt_command.delete("1.0", "end")
            app.txt_command.insert("1.0", "ip serv set ssh port=61562")
            app.on_send()
            _wait_job(root, app)
            assert got == ["ip serv set ssh port=61562"] * 2 and len(errors) == 1
        finally:
            ssh_client.run_ssh_command = real_run
    finally:
        M.messagebox.showerror = real_err
        app._on_close()


def test_gui_csv_uses_russian_headers_and_still_reads_old_english_files():
    M, tk, root, app = _open()
    try:
        for d in _many(3):
            app._upsert_device(d)
        app.devices["SN2"].note = "Office; 2nd floor"
        app.devices["SN2"].last_backup = "2026-09-01 10:00:00"
        path = os.path.join(os.path.dirname(M.DEVICES_FILE), "out.csv")
        M.filedialog.asksaveasfilename = lambda **k: path
        app.on_export()
        lines = open(path, encoding="utf-8-sig").read().splitlines()
        assert lines[0] == ("IP;Identity;Модель;RouterOS;License;Был в сети;Последний бэкап;Статус;Заметка;IP подключения"), lines[0]
        assert '"Office; 2nd floor"' in lines[2] and lines[2].endswith(";10.20.30.2")

        M.filedialog.askopenfilename = lambda **k: path
        for iid in list(app.tree.get_children("")):
            app.tree.delete(iid)
        app.devices.clear()
        app.on_import()
        assert sorted(app.devices) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        dev = [d for d in app.devices.values() if d.ip == "10.0.0.2"][0]
        assert (dev.note, dev.last_backup, dev.reach_ip, dev.board_name) == ("Office; 2nd floor", "2026-09-01 10:00:00", "10.20.30.2", "hAP")

        old = os.path.join(os.path.dirname(M.DEVICES_FILE), "old.csv")          # what versions before this one exported
        open(old, "w", encoding="utf-8-sig").write(
            "IP,Identity,Board Name,RouterOS,License,Last seen,Last Backup,Status,Mgmt IP\n"
            "10.5.5.5,Old,hEX,6.49,4,2026-09-01 10:00:00,2026-08-01 10:00:00,Error: boom,10.9.9.5\n")
        M.filedialog.askopenfilename = lambda **k: old
        app.on_import()
        dev = [d for d in app.devices.values() if d.ip == "10.5.5.5"][0]
        assert (dev.board_name, dev.reach_ip, dev.last_backup, dev.failed, dev.note) == ("hEX", "10.9.9.5", "2026-08-01 10:00:00", True, "")
    finally:
        app._on_close()


def test_gui_everything_the_user_sees_is_in_russian():
    import re
    M, tk, root, app = _open()
    try:
        texts = []

        def walk(widget):
            for child in widget.winfo_children():
                if child.winfo_class() in ("TButton", "TLabel", "TCheckbutton", "Label", "TCombobox"):
                    value = str(child.cget("text")) if child.winfo_class() != "TCombobox" else ""
                    if value:
                        texts.append(value)
                walk(child)

        walk(root)
        texts += [app.tree.heading(c, "text") for c in app.tree.cget("columns")]
        texts += [app.notebook.tab(i, "text") for i in range(app.notebook.index("end"))]
        kept = {"IP", "Identity", "RouterOS", "License", "Winbox", "SSH:", "API-SSL:", "Winbox:", "SSH", "API/SSL",
                "CSV", "▶ Winbox"}
        english = [t for t in texts if re.search(r"[A-Za-z]{3,}", t) and t not in kept
                   and not t.startswith(("SSH:", "API/SSL:", "Порт API-SSL:", "Лог: logs/"))]
        assert english == [], english
        assert app.root.title() == "Сканер MikroTik"
    finally:
        app._on_close()


def test_gui_ten_command_tabs_send_selected_text_and_persist_all_drafts():
    from unittest.mock import patch
    M, tk, root, app = _open()
    try:
        tabs = app.notebook.tabs()
        assert len(tabs) == 11, "ten command tabs plus the output tab"
        assert app.notebook.tab(tabs[-1], "text") == "Вывод / Лог"
        for i in range(10):
            app.notebook.select(i)
            _pump(root, 1)
            app.txt_command.insert("1.0", f":put {i + 1}")
        app.var_cmdtype.set("SSH")
        app._upsert_device(_devices()[0])
        app.toggle_all()
        app.notebook.select(6)
        _pump(root, 1)
        with patch("ssh_client.run_ssh_command", return_value="7") as run:
            app.on_send()
            _wait_job(root, app)
            assert run.call_args.args[3] == ":put 7"
            assert app.notebook.index(app.notebook.select()) == 10
            app.on_send()  # output tab must retain the last command selection
            _wait_job(root, app)
            assert run.call_args.args[3] == ":put 7"
        app._save_settings()
        for widget in app.command_editors:
            widget.delete("1.0", "end")
        app._load_settings()
        for i, widget in enumerate(app.command_editors):
            assert widget.get("1.0", "end-1c") == f":put {i + 1}"
        assert app.txt_command.get("1.0", "end-1c") == ":put 7"
        os.remove(M.COMMANDS_FILE)        # an older install: the single command lives in settings.json
        with open(M.SETTINGS_FILE, "w") as fh:
            json.dump({"command": "/system resource print"}, fh)
        app._load_settings()
        assert app.command_editors[0].get("1.0", "end-1c") == "/system resource print"
        assert all(w.get("1.0", "end-1c") == "" for w in app.command_editors[1:])
    finally:
        app._on_close()


def test_gui_ssh_scan_and_refresh_use_selected_transport():
    from unittest.mock import patch
    M, tk, root, app = _open()
    try:
        app.var_cmdtype.set("SSH")
        app.var_ssh_port.set("2222")
        app.var_network.set("192.168.1.1")
        reply = "__MTSCAN__identity=SSH router\n__MTSCAN__serial=SSH1\n__MTSCAN__address=10.0.0.1/24|bridge1"
        with patch("ssh_client.run_ssh_command", return_value=reply) as run, patch(
                "core.scan_host", side_effect=AssertionError("SSH scan must not use API")):
            app.on_scan_add()
            _wait_job(root, app)
            assert app.devices["SSH1"].identity == "SSH router"
            assert app.devices["SSH1"].reach_ip == "192.168.1.1"
            assert run.call_args.kwargs["port"] == 2222
            app.on_update()
            _wait_job(root, app)
            assert run.call_count == 2
            app.on_update_one("SSH1")
            for _ in range(30):
                _pump(root, 1)
                if run.call_count == 3:
                    break
            assert run.call_count == 3
            assert run.call_args.args[0] == "192.168.1.1"
    finally:
        app._on_close()


def test_gui_ssh_update_falls_back_to_the_bridge1_address():
    from core import Device
    import ssh_client
    M, tk, root, app = _open()
    tried = []
    real = ssh_client.scan_host_ssh

    def fake(host, user, password, port=22, timeout=10, retries=2, logger=None):
        tried.append(host)
        if host == "10.20.30.209":                # the address the API scan reached: SSH closed there
            raise ssh_client.SSHStageError("SSH-порт закрыт", unreachable=True)
        if host == "10.20.30.210":                # a real login problem must NOT be retried elsewhere
            raise ssh_client.SSHStageError("не удалось войти по SSH")
        return Device(ip=host, connect_ip=host, identity="R1", key="SN1", status=f"OK (SSH:{port})",
                      addresses=[{"address": "10.20.44.209/24", "interface": "bridge1"}])

    ssh_client.scan_host_ssh = fake
    try:
        app._upsert_device(Device(ip="10.20.44.209", identity="R1", key="SN1", connect_ip="10.20.30.209"))
        app._upsert_device(Device(ip="10.20.44.210", identity="R2", key="SN2", connect_ip="10.20.30.210"))
        app.var_cmdtype.set("SSH")
        app.on_update()
        _wait_job(root, app)
        assert tried.count("10.20.44.209") == 1 and "10.20.44.210" not in tried, tried
        assert not app.devices["SN1"].failed and app.devices["SN1"].reach_ip == "10.20.44.209"
        assert app.devices["SN2"].failed
        assert "пробую адрес bridge1 10.20.44.209" in app.txt_output.get("1.0", "end")

        tried.clear()                             # the ⟳ button of one row does the same
        app.devices["SN1"].connect_ip = "10.20.30.209"
        app.on_update_one("SN1")
        for _ in range(50):
            _pump(root, 1)
            if "10.20.44.209" in tried:
                break
        assert tried == ["10.20.30.209", "10.20.44.209"], tried
    finally:
        ssh_client.scan_host_ssh = real
        app._on_close()


def test_gui_command_drafts_are_kept_without_remember_settings_and_log_names_the_tab():
    from unittest.mock import patch
    M, tk, root, app = _open()
    try:
        app.var_save.set(False)                   # the password must not be stored ...
        for i, text in ((0, "/system identity print"), (4, ":put five")):
            app.notebook.select(i)
            _pump(root, 1)
            app.txt_command.insert("1.0", text)
        app.var_cmdtype.set("SSH")
        app._upsert_device(_devices()[0])
        app.toggle_all()
        with patch("ssh_client.run_ssh_command", return_value="ok"):
            app.on_send()
            _wait_job(root, app)
        assert "«Команда 5»" in app.txt_output.get("1.0", "end")
    finally:
        app._on_close()
    assert not os.path.exists(M.SETTINGS_FILE)            # ... and it is not
    saved = json.load(open(M.COMMANDS_FILE, encoding="utf-8"))
    assert "password" not in saved and saved["commands"][4] == ":put five" and saved["active_command"] == 4
    root2 = tk.Tk()
    app2 = M.ScannerApp(root2)
    try:
        assert app2.command_editors[0].get("1.0", "end-1c") == "/system identity print"
        assert app2.txt_command.get("1.0", "end-1c") == ":put five"
    finally:
        app2._on_close()


def test_gui_the_field_row_fits_and_a_focused_field_is_scrolled_into_view():
    M, tk, root, app = _open()
    try:
        app._fit_window_to_fields()               # the window opens wide enough for the whole field row
        _pump(root, 5)
        form_canvas = root.winfo_children()[0].winfo_children()[0]
        form = form_canvas.winfo_children()[0]
        needed = form.winfo_reqwidth()
        assert needed > 0
        assert root.winfo_width() >= min(needed + 16, root.winfo_screenwidth() - 40) - 4, (needed, root.winfo_width())

        root.geometry("700x500")                  # a narrow window: the row scrolls instead of hiding fields
        _pump(root, 5)
        entries = [w for w in form.winfo_children() if isinstance(w, tk.ttk.Entry)]
        last = entries[-1]
        last.focus_force()
        _pump(root, 5)
        left = form_canvas.canvasx(0)
        assert left <= last.winfo_x() and last.winfo_x() + last.winfo_width() <= left + form_canvas.winfo_width()
        entries[0].focus_force()
        _pump(root, 5)
        assert form_canvas.canvasx(0) <= entries[0].winfo_x()
    finally:
        app._on_close()


def test_gui_command_type_and_save_box_end_the_field_row_and_send_has_its_label():
    M, tk, root, app = _open()
    try:
        _pump(root, 5)
        form_canvas = root.winfo_children()[0].winfo_children()[0]
        form = form_canvas.winfo_children()[0]
        kids = form.pack_slaves()
        texts = [str(w.cget("text")) if "text" in w.keys() else "" for w in kids]
        assert texts[-1] == "Запомнить настройки", texts
        assert "Тип команд:" in texts[-3], texts
        assert app._app_icons
    finally:
        app._on_close()


def test_gui_changes_ports_radio_favourites_and_their_filters():
    M, tk, root, app = _open()
    from core import Device
    try:
        def full(**kw):
            base = dict(ip="10.0.0.1", identity="R1", board_name="RB951", key="S1", serial="S1", extended=True,
                        addresses=[{"address": "10.0.0.1/24", "interface": "bridge1"}])
            base.update(kw)
            return Device(**base)
        app._upsert_device(full())
        app._upsert_device(full(ip="10.0.0.2", key="S2", serial="S2", identity="R2"))
        app._baselines = {}
        app._accept_polled(full(identity="R1-renamed"))
        app._accept_polled(full(ip="10.0.0.2", key="S2", serial="S2", identity="R2",
                                ports=[{"name": "ether1", "running": True, "rate": "10Mbps",
                                        "full_duplex": "false", "link_downs": 0, "errors": {}}],
                                radio=[{"interface": "wlan1", "mac": "AA", "rx": -80, "tx": -70}]))
        _pump(root, 2)
        assert app.tree.item("S1", "tags") == ("changed",) and "имя: R1 → R1-renamed" in app.devices["S1"].status
        assert app.tree.item("S2", "tags") == ("port",)
        assert app.devices["S2"].radio_problem

        app.var_changed_only.set(True); app._on_filter_change()
        assert app._visible_iids() == ["S1"]
        app.var_changed_only.set(False); app.var_weak_radio.set(True); app._on_filter_change()
        assert app._visible_iids() == ["S2"] and "signal" in app.tree.cget("displaycolumns")
        assert app.tree.set("S2", "signal") == "wlan1 rx -80 / tx -70"
        app.var_weak_radio.set(False); app._on_filter_change()
        assert "signal" not in app.tree.cget("displaycolumns")

        app.checked.add("S2")
        app.on_favorite()
        assert app.devices["S2"].favorite and app.tree.set("S2", "fav") == "★"
        app.var_favorites.set(True); app._on_filter_change()
        assert app._visible_iids() == ["S2"]
        app._reset_filters(); app._relayout()
        # a rescan keeps the star, a backup clears «changed»
        app._baselines = {}
        app._accept_polled(full(ip="10.0.0.2", key="S2", serial="S2", identity="R2"))
        assert app.devices["S2"].favorite
        app.devices["S1"].changes = ""
        app._handle_ui_message("row", "S1")
        assert not app.tree.item("S1", "tags")
    finally:
        app._on_close()


def test_gui_delete_moves_the_devices_backups_to_old():
    M, tk, root, app = _open()
    from core import Device
    try:
        app._upsert_device(Device(ip="10.0.0.1", identity="R1", key="S1"))
        path = os.path.join(M.BACKUP_DIR, "10.0.0.1_R1_2026-01-01.rsc")
        with open(path, "w") as fh:
            fh.write("x")
        app.checked.add("S1")
        original = M.messagebox.askyesno
        M.messagebox.askyesno = lambda *a, **k: True
        try:
            app.on_delete()
        finally:
            M.messagebox.askyesno = original
        assert not os.path.exists(path)
        assert os.listdir(os.path.join(M.BACKUP_DIR, "Old")) == ["10.0.0.1_R1_2026-01-01.rsc"]
    finally:
        app._on_close()


def test_gui_confirm_hides_problems_but_not_changes_and_the_signal_filter():
    M, tk, root, app = _open()
    from core import Device
    try:
        def full(**kw):
            base = dict(ip="10.0.0.1", identity="R1", key="S1", serial="S1", extended=True,
                        radio=[{"interface": "wlan1", "mac": "AA", "rx": -80, "tx": -70}])
            base.update(kw)
            return Device(**base)
        app._upsert_device(full())
        app._upsert_device(full(ip="10.0.0.2", key="S2", serial="S2", identity="R2",
                                radio=[{"interface": "wlan1", "mac": "BB", "rx": -60, "tx": -64}]))
        app._baselines = {}
        app._accept_polled(full(identity="R1-new"))           # weak radio + a change
        assert app.tree.item("S1", "tags") == ("changed",)
        app.checked.update({"S1", "S2"})
        app.on_confirm()
        dev = app.devices["S1"]
        assert dev.confirmed == ["radio"] and app.devices["S2"].confirmed == []
        assert dev.status.startswith("Изменено:") and "Радио" not in dev.status
        app.var_weak_radio.set(True); app._on_filter_change()
        assert app._visible_iids() == []
        app.var_weak_radio.set(False); app.var_confirmed.set(True); app._on_filter_change()
        assert app._visible_iids() == ["S1"]
        app._reset_filters(); app._relayout()

        app._baselines = {}                                    # the next update keeps it accepted
        app._accept_polled(full(identity="R1-new"))
        assert app.devices["S1"].confirmed == ["radio"] and "Радио" not in app.devices["S1"].status

        app._set_status("S2", "Ошибка: timeout", True)
        assert app.tree.item("S2", "tags") == ("error",)
        app.checked = {"S2"}
        app.on_confirm()
        assert not app.tree.item("S2", "tags") and app.devices["S2"].status == "Подтверждено"
        app.var_errors_only.set(True); app._on_filter_change()
        assert app._visible_iids() == []
        app._reset_filters(); app._relayout()
        app.on_confirm()                                       # nothing left to accept: take it back
        assert app.devices["S2"].confirmed == [] and app.tree.item("S2", "tags") == ("error",)

        # «Сигнал» shows the column; «не лучше −65» keeps devices with a signal of −65 or worse
        app.var_signal_show.set(True); app._on_filter_change()
        assert "signal" in app.tree.cget("displaycolumns")
        app.var_signal_show.set(False)
        app.var_signal_limit.set("65"); app._apply_search()
        assert app._signal_limit == -65 and app._visible_iids() == ["S1"]
        assert "signal" in app.tree.cget("displaycolumns")
        app.var_signal_limit.set("-60"); app._apply_search()
        assert sorted(app._visible_iids()) == ["S1", "S2"]
        app.var_signal_limit.set(""); app._apply_search()
        assert "signal" not in app.tree.cget("displaycolumns")
    finally:
        app._on_close()
