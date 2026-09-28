#!/usr/bin/env python3
"""
MikroTik subnet scanner & manager.

A Tkinter desktop tool that scans a subnet for MikroTik / RouterOS devices,
authenticates with operator-supplied credentials over the RouterOS API
(API-SSL, with plain API as a fallback), inventories them, runs commands on selected
devices, and saves textual (.rsc) backups.

Run:  python3 mikrotik_scanner.py
"""

from __future__ import annotations

import base64
import csv
import dataclasses
import json
import os
import queue
import subprocess
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    HORIZONTAL,
    StringVar,
    BooleanVar,
    Tk,
    X,
    Y,
    filedialog,
    messagebox,
)
from tkinter import font as tkfont
from tkinter import ttk

import core
from applog import setup_logging
from core import Device, backup_filename, dedupe_devices, expand_targets, parse_cli_to_api

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
DEVICES_FILE = os.path.join(APP_DIR, "devices.json")  # cached scan results
BACKUP_DIR = os.path.join(APP_DIR, "Backups")
CSV_DELIMITER = ";"  # Excel-friendly in RU locale; "Mgmt IP" is the reach address

COLUMNS = ("IP", "Identity", "Board Name", "RouterOS", "License", "Last seen", "Status")
CHECK_ON = "☑"
CHECK_OFF = "☐"
UPDATE_GLYPH = "⟳"  # per-row refresh button
WINBOX_LABEL = "▶ Winbox"  # per-row launcher, last column


class ScannerApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("MikroTik Scanner")
        self.root.geometry("1280x820")

        # file logging for observability (logs/scanner-*.log next to program)
        self.logger, self.log_path = setup_logging(APP_DIR)

        # runtime state
        self.ui_queue: "queue.Queue[tuple]" = queue.Queue()
        self.devices: dict[str, Device] = {}       # keyed by table iid
        self.checked: set[str] = set()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.sort_state: dict[str, bool] = {}

        # form variables
        self.var_user = StringVar()
        self.var_pass = StringVar()
        self.var_network = StringVar()
        self.var_api_port = StringVar(value="8729")
        self.var_ssh_port = StringVar(value="22")
        self.var_winbox_port = StringVar(value="8291")
        self.var_threads = StringVar(value="30")
        self.var_timeout = StringVar(value="10")
        self.var_retries = StringVar(value="2")
        self.var_cmdtype = StringVar(value="API/SSL")
        self.var_save = BooleanVar(value=False)
        self.var_find = StringVar()

        self._build_ui()
        self._load_settings()
        self._load_devices()
        self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        # bigger table rows so the check / update glyphs are easy to hit
        style = ttk.Style(self.root)
        base = tkfont.nametofont("TkDefaultFont")
        self._tree_font = base.copy()  # keep a reference or Tk drops it
        self._tree_font.configure(size=abs(base.cget("size")) + 2)
        style.configure("Treeview", font=self._tree_font,
                        rowheight=int(self._tree_font.metrics("linespace") * 1.8))
        # copy/paste for entries and log, independent of keyboard layout
        self._install_clipboard_bindings()

        form = ttk.Frame(self.root, padding=6)
        form.pack(fill=X)

        def field(parent, label, var, width, show=None):
            ttk.Label(parent, text=label).pack(side=LEFT, padx=(4, 2))
            e = ttk.Entry(parent, textvariable=var, width=width, show=show)
            e.pack(side=LEFT)
            self._attach_context_menu(e)
            return e

        field(form, "Username:", self.var_user, 12)
        field(form, "Password:", self.var_pass, 12, show="*")
        field(form, "Network:", self.var_network, 18)
        field(form, "API-SSL:", self.var_api_port, 6)
        field(form, "SSH:", self.var_ssh_port, 6)
        field(form, "Winbox:", self.var_winbox_port, 6)
        field(form, "Threads:", self.var_threads, 5)
        field(form, "Timeout:", self.var_timeout, 4)
        field(form, "Retries:", self.var_retries, 3)
        # how SEND and Backup talk to the router; the scan always uses the API
        ttk.Label(form, text="Command Type:").pack(side=LEFT, padx=(6, 2))
        ttk.Combobox(
            form, textvariable=self.var_cmdtype, values=["API/SSL", "SSH"],
            width=8, state="readonly",
        ).pack(side=LEFT)
        ttk.Checkbutton(form, text="Save", variable=self.var_save).pack(side=LEFT, padx=(8, 2))

        # buttons row
        actions = ttk.Frame(self.root, padding=(6, 0))
        actions.pack(fill=X)
        self.btn_scan = ttk.Button(actions, text="New Scan", command=self.on_scan)
        self.btn_scan.pack(side=LEFT, padx=2)
        self.btn_pause = ttk.Button(actions, text="Pause", command=self.on_pause, state="disabled")
        self.btn_pause.pack(side=LEFT, padx=2)
        self.btn_stop = ttk.Button(actions, text="Stop", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Update", command=self.on_update).pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Backup", command=self.on_backup).pack(side=LEFT, padx=2)
        ttk.Label(actions, text="Command:").pack(side=RIGHT, padx=(2, 4))
        ttk.Button(actions, text="SEND", command=self.on_send).pack(side=RIGHT, padx=2)

        # command / output notebook (single big box, two tabs)
        nb = ttk.Notebook(self.root)
        nb.pack(fill=BOTH, expand=False, padx=6, pady=4)
        from tkinter.scrolledtext import ScrolledText

        cmd_frame = ttk.Frame(nb)
        self.txt_command = ScrolledText(cmd_frame, height=8, wrap="word")
        self.txt_command.pack(fill=BOTH, expand=True)
        self._attach_context_menu(self.txt_command)
        nb.add(cmd_frame, text="Command")

        out_frame = ttk.Frame(nb)
        self.txt_output = ScrolledText(out_frame, height=8, wrap="word")
        self.txt_output.pack(fill=BOTH, expand=True)
        self._make_readonly(self.txt_output)  # selectable & copyable, not editable
        nb.add(out_frame, text="Output / Log")
        self.notebook = nb

        # progress bar
        self.progress = ttk.Progressbar(self.root, orient=HORIZONTAL, mode="determinate")
        self.progress.pack(fill=X, padx=6, pady=2)

        # table
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=BOTH, expand=True, padx=6, pady=2)
        cols = ("check", "upd") + COLUMNS + ("winbox",)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="none")
        self.tree.heading("check", text=CHECK_OFF, command=self.toggle_all)
        self.tree.column("check", width=46, anchor="center", stretch=False)
        self.tree.heading("upd", text=UPDATE_GLYPH)
        self.tree.column("upd", width=40, anchor="center", stretch=False)
        for col in COLUMNS:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=150, anchor="w")
        self.tree.heading("winbox", text="Winbox")
        self.tree.column("winbox", width=90, anchor="center", stretch=False)
        self.tree.column("IP", width=120)
        self.tree.column("Status", width=220)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=RIGHT, fill=Y)
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.bind("<Button-1>", self._on_tree_click)

        # bottom bar
        bottom = ttk.Frame(self.root, padding=6)
        bottom.pack(fill=X)
        find_entry = ttk.Entry(bottom, textvariable=self.var_find, width=30)
        find_entry.pack(side=LEFT)
        self._attach_context_menu(find_entry)
        find_entry.bind("<Return>", lambda e: self.on_find())
        ttk.Button(bottom, text="Find", command=self.on_find).pack(side=LEFT, padx=4)
        ttk.Button(bottom, text="Save Log", command=self.on_save_log).pack(side=LEFT, padx=8)
        ttk.Label(bottom, text=f"Log: logs/{os.path.basename(self.log_path)}",
                  foreground="#666").pack(side=LEFT)
        ttk.Button(bottom, text="Export", command=self.on_export).pack(side=RIGHT, padx=2)
        ttk.Button(bottom, text="Import", command=self.on_import).pack(side=RIGHT, padx=2)

    # ---------------------------------------------------- clipboard helpers
    # Physical key codes of C / V / X / A. Tk binds only the Latin keysyms, so on
    # a Cyrillic layout Ctrl+С etc. do nothing unless we dispatch by key code.
    # The codes differ per windowing system (Windows VK codes vs X11 keycodes).
    _CLIP_CODES = {
        "win32": {67: "<<Copy>>", 86: "<<Paste>>", 88: "<<Cut>>", 65: "all"},
        "x11": {54: "<<Copy>>", 55: "<<Paste>>", 53: "<<Cut>>", 38: "all"},
    }

    def _install_clipboard_bindings(self) -> None:
        self._clip_codes = self._CLIP_CODES.get(self.root.tk.call("tk", "windowingsystem"), {})
        if not self._clip_codes:
            return  # macOS: Tk already maps Command+C/V/X/A for the active layout

        def dispatch(event):
            action = self._clip_codes.get(event.keycode)
            if not action:
                return None
            if action == "all":
                self._select_all(event.widget)
                return "break"
            if (event.keysym or "").lower() in ("c", "v", "x"):
                # Latin layout: Tk's own class binding has already done it, and
                # doing it again would e.g. paste twice.
                return None
            self._safe_event(event.widget, action)
            return "break"

        self.root.bind_all("<Control-KeyPress>", dispatch)

    @staticmethod
    def _safe_event(widget, virtual: str) -> None:
        try:
            widget.event_generate(virtual)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _select_all(widget) -> None:
        try:
            if isinstance(widget, (tk.Text,)):
                widget.tag_add("sel", "1.0", "end-1c")
            else:
                widget.select_range(0, END)
                widget.icursor(END)
        except Exception:  # noqa: BLE001
            pass

    def _attach_context_menu(self, widget, readonly: bool = False) -> None:
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Копировать", command=lambda: self._safe_event(widget, "<<Copy>>"))
        if not readonly:
            menu.add_command(label="Вставить", command=lambda: self._safe_event(widget, "<<Paste>>"))
            menu.add_command(label="Вырезать", command=lambda: self._safe_event(widget, "<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="Выделить всё", command=lambda: self._select_all(widget))

        def popup(event):
            widget.focus_set()
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", popup)

    def _make_readonly(self, text) -> None:
        """Let the user select and copy from a Text but not change it."""
        nav = {"Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next",
               "Shift_L", "Shift_R", "Control_L", "Control_R"}

        def block(event):
            if event.keysym in nav:
                return None
            if event.state & 0x4:  # Ctrl held: only copy / select-all may pass
                code = getattr(self, "_clip_codes", {}).get(event.keycode)
                if event.keysym.lower() in ("c", "a", "insert") or code in ("<<Copy>>", "all"):
                    return None
            return "break"

        text.bind("<Key>", block)
        # paste / cut / middle-click paste come in as virtual events
        for virtual in ("<<Paste>>", "<<Cut>>", "<<PasteSelection>>", "<<Clear>>"):
            text.bind(virtual, lambda e: "break")
        self._attach_context_menu(text, readonly=True)

    # ------------------------------------------------------------- helpers
    def log(self, message: str) -> None:
        # mirror every human-facing line into the log file too
        try:
            self.logger.info(message)
        except Exception:  # noqa: BLE001
            pass
        self.ui_queue.put(("log", message))

    def _write_log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        at_bottom = self.txt_output.yview()[1] >= 0.999  # follow the log only if already at the end
        self.txt_output.insert(END, f"[{stamp}] {message}\n")
        if at_bottom:
            self.txt_output.see(END)

    def _drain_queue(self) -> None:
        try:
            while True:
                try:
                    kind, payload = self.ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle_ui_message(kind, payload)
                except Exception:  # noqa: BLE001 - keep the UI loop alive
                    self.logger.exception("UI message %r failed", kind)
        finally:
            self.root.after(100, self._drain_queue)

    def _handle_ui_message(self, kind: str, payload) -> None:
        if kind == "log":
            self._write_log(payload)
        elif kind == "device":
            self._upsert_device(payload)
        elif kind == "progress":
            done, total = payload
            self.progress["maximum"] = max(total, 1)
            self.progress["value"] = done
        elif kind == "status":
            iid, text = payload
            if self.tree.exists(iid):
                self.tree.set(iid, "Status", text)
                self.devices[iid].status = text
        elif kind == "status_ip":
            ip, text = payload
            for iid, dev in self.devices.items():
                if ip in (dev.ip, dev.reach_ip) and self.tree.exists(iid):
                    dev.status = text
                    self.tree.set(iid, "Status", text)
        elif kind == "save_devices":
            self._save_devices()
        elif kind == "done":
            self._scan_finished(payload)

    def _upsert_device(self, dev: Device) -> None:
        iid = dev.key or dev.ip
        # A row for this IP may exist under another id (imported rows are
        # keyed by IP, scanned ones by serial): replace it, keep its checkbox.
        for other in [i for i, d in self.devices.items() if d.ip == dev.ip and i != iid]:
            if other in self.checked:
                self.checked.discard(other)
                self.checked.add(iid)
            if self.tree.exists(other):
                self.tree.delete(other)
            del self.devices[other]
        values = (CHECK_ON if iid in self.checked else CHECK_OFF, UPDATE_GLYPH) + tuple(
            dev.as_row()[c] for c in COLUMNS
        ) + (WINBOX_LABEL,)
        if self.tree.exists(iid):
            self.tree.item(iid, values=values)
        else:
            self.tree.insert("", END, iid=iid, values=values)
        self.devices[iid] = dev

    # --------------------------------------------------------- table logic
    def _on_tree_click(self, event) -> None:
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if col == "#1":  # checkbox column
            if iid in self.checked:
                self.checked.discard(iid)
                self.tree.set(iid, "check", CHECK_OFF)
            else:
                self.checked.add(iid)
                self.tree.set(iid, "check", CHECK_ON)
        elif col == "#2":  # per-row update button
            self.on_update_one(iid)
        elif col == "#%d" % (len(COLUMNS) + 3):  # last column: Winbox launcher
            self.on_winbox(iid)

    def _find_winbox(self):
        """winbox.exe (any winbox*.exe) sitting next to the program."""
        try:
            names = sorted(os.listdir(APP_DIR))
        except OSError:
            return None
        for name in names:
            low = name.lower()
            if low.startswith("winbox") and low.endswith(".exe"):
                return os.path.join(APP_DIR, name)
        return None

    def on_winbox(self, iid: str) -> None:
        """Open WinBox for one device with the username/password from the form."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        exe = self._find_winbox()
        if exe is None:
            messagebox.showerror(
                "Winbox", f"winbox.exe не найден.\nПоложите его в папку с программой:\n{APP_DIR}")
            return
        cfg = self._read_config()
        if not cfg["user"]:
            messagebox.showwarning("Winbox", "Введите Username (и Password) в верхней панели.")
            return
        # the address the scan reached (the bridge1 one shown in the table may
        # be unreachable from this PC) plus the Winbox port
        address = f"{dev.reach_ip}:{cfg['winbox_port']}"
        try:
            # argument list, no shell: nothing in the password is interpreted
            subprocess.Popen([exe, address, cfg["user"], cfg["password"]], cwd=APP_DIR)
        except OSError as exc:
            self.log(f"{dev.ip}: could not start Winbox: {exc}")
            messagebox.showerror("Winbox", f"Не удалось запустить Winbox:\n{exc}")
            return
        self.log(f"Winbox started for {address} (user {cfg['user']})")  # never log the password

    def on_update_one(self, iid: str) -> None:
        """Reconnect to one device and refresh its row."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Update", "A scan is already running.")
            return
        cfg = self._read_config()
        self.tree.set(iid, "Status", "Updating…")

        def work():
            ip = dev.reach_ip
            try:
                fresh = core.scan_host(
                    ip, cfg["user"], cfg["password"],
                    cfg["api_ssl_port"], plain_port=8728,
                    timeout=cfg["timeout"], retries=cfg["retries"], logger=self.logger,
                )
                fresh = dedupe_devices([fresh])[0]  # keep bridge1 as the shown IP
                fresh.last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log(f"{ip}: updated {fresh.identity or fresh.board_name} [{fresh.status}]")
                self.ui_queue.put(("device", fresh))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{ip}: update failed: {type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Error: {type(exc).__name__}: {exc}")))
            self.ui_queue.put(("save_devices", None))

        threading.Thread(target=work, daemon=True).start()

    def toggle_all(self) -> None:
        all_iids = self.tree.get_children("")
        if self.checked >= set(all_iids) and all_iids:
            self.checked.clear()
            new = CHECK_OFF
            self.tree.heading("check", text=CHECK_OFF)
        else:
            self.checked = set(all_iids)
            new = CHECK_ON
            self.tree.heading("check", text=CHECK_ON)
        for iid in all_iids:
            self.tree.set(iid, "check", new)

    def sort_by(self, column: str) -> None:
        reverse = self.sort_state.get(column, False)
        items = [(self.tree.set(i, column), i) for i in self.tree.get_children("")]

        def key(pair):
            val = pair[0]
            parts = val.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return tuple(int(p) for p in parts)
            return val.lower()

        items.sort(key=key, reverse=reverse)
        for index, (_, iid) in enumerate(items):
            self.tree.move(iid, "", index)
        self.sort_state[column] = not reverse

    def on_find(self) -> None:
        needle = self.var_find.get().strip().lower()
        if not needle:
            return
        rows = list(self.tree.get_children(""))
        # continue after the current match so repeated Find walks all hits
        current = self.tree.selection()
        start = rows.index(current[0]) + 1 if current and current[0] in rows else 0
        for iid in rows[start:] + rows[:start]:
            row = " ".join(self.tree.set(iid, c) for c in COLUMNS).lower()
            if needle in row:
                self.tree.selection_set(iid)
                self.tree.see(iid)
                return
        messagebox.showinfo("Find", "No match found.")

    def selected_devices(self) -> list[Device]:
        if self.checked:
            return [self.devices[i] for i in self.checked if i in self.devices]
        return []

    # -------------------------------------------------------------- config
    def _read_config(self):
        try:
            threads = max(1, int(self.var_threads.get()))
        except ValueError:
            threads = 20
        try:
            api_ssl_port = int(self.var_api_port.get())
        except ValueError:
            api_ssl_port = 8729
        try:
            ssh_port = int(self.var_ssh_port.get() or 22)
        except ValueError:
            ssh_port = 22
        try:
            winbox_port = int(self.var_winbox_port.get() or 8291)
        except ValueError:
            winbox_port = 8291
        try:
            timeout = max(1.0, float(self.var_timeout.get()))
        except ValueError:
            timeout = 10.0
        try:
            retries = max(0, int(self.var_retries.get()))
        except ValueError:
            retries = 2
        return {
            "user": self.var_user.get(),
            "password": self.var_pass.get(),
            "api_ssl_port": api_ssl_port,
            "threads": threads,
            "ssh_port": ssh_port,
            "winbox_port": winbox_port,
            "cmdtype": self.var_cmdtype.get(),
            "timeout": timeout,
            "retries": retries,
        }

    # ---------------------------------------------------------------- scan
    def on_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Scan", "A scan is already running.")
            return
        if self.devices and not messagebox.askyesno(
            "New Scan",
            "Текущие результаты будут удалены, а таблица очищена.\n\n"
            "Чтобы дополнить/обновить существующие результаты без потери, "
            "используйте кнопку Update.\n\nВсё равно начать новый скан?",
            icon="warning", default="no",
        ):
            return
        targets = self._targets_or_warn()
        if targets is None:
            return
        if not targets:
            messagebox.showerror("Scan", "Enter a network, e.g. 192.168.0.0/24")
            return
        # fresh scan clears the table
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)
        self.devices.clear()
        self.checked.clear()
        self.tree.heading("check", text=CHECK_OFF)
        self._start_scan(targets, "New scan")

    def on_update(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Update", "A scan is already running.")
            return
        # rescan known devices plus any other host in the subnet
        subnet = self._targets_or_warn()
        if subnet is None:
            return
        targets = set(dev.reach_ip for dev in self.devices.values())
        targets.update(subnet)
        if not targets:
            messagebox.showinfo("Update", "Nothing to update yet — run a scan first.")
            return
        self._start_scan(sorted(targets), "Update")

    def _targets_or_warn(self):
        """Expand the Network field; None (after a message) if it's invalid."""
        try:
            return expand_targets(self.var_network.get())
        except ValueError as exc:
            messagebox.showerror("Network", f"Can't parse network: {exc}")
            return None

    def _start_scan(self, targets: list[str], label: str) -> None:
        self.stop_event.clear()
        self.pause_event.clear()
        self._maybe_save_settings()
        cfg = self._read_config()
        self.btn_pause.configure(state="normal", text="Pause")
        self.btn_stop.configure(state="normal")
        self.log(f"{label}: {len(targets)} target(s), {cfg['threads']} threads, "
                 f"timeout {cfg['timeout']}s, {cfg['retries']} retries, "
                 f"API-SSL port {cfg['api_ssl_port']} (plain API 8728 only if that port is refused).")
        self.worker = threading.Thread(
            target=self._scan_worker, args=(targets, cfg), daemon=True
        )
        self.worker.start()

    def _scan_worker(self, targets: list[str], cfg: dict) -> None:
        total = len(targets)
        done = 0
        found: list[Device] = []
        lock = threading.Lock()

        def work(ip: str):
            nonlocal done
            while self.pause_event.is_set() and not self.stop_event.is_set():
                threading.Event().wait(0.2)
            if self.stop_event.is_set():
                return None
            try:
                dev = core.scan_host(
                    ip, cfg["user"], cfg["password"],
                    cfg["api_ssl_port"], plain_port=8728,
                    timeout=cfg["timeout"], retries=cfg["retries"],
                    logger=self.logger,
                )
                dev.last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log(f"{ip}: found {dev.identity or dev.board_name or 'RouterOS'} "
                         f"[{dev.status}]")
                self.ui_queue.put(("device", dev))  # show it right away
            except Exception as exc:  # noqa: BLE001 - report every failure
                dev = None
                self.log(f"{ip}: {type(exc).__name__}: {exc}")
                # a device already in the table must not keep a stale "OK"
                self.ui_queue.put(("status_ip", (ip, f"Error: {type(exc).__name__}: {exc}")))
            finally:
                with lock:
                    done += 1
                    self.ui_queue.put(("progress", (done, total)))
            return dev

        with ThreadPoolExecutor(max_workers=cfg["threads"]) as pool:
            for dev in pool.map(work, targets):
                if dev is not None:
                    found.append(dev)

        deduped = dedupe_devices(found)
        self.ui_queue.put(("done", deduped))

    def _scan_finished(self, deduped: list[Device]) -> None:
        for dev in deduped:
            self._upsert_device(dev)
        self.btn_pause.configure(state="disabled", text="Pause")
        self.btn_stop.configure(state="disabled")
        self._write_log(f"Scan complete: {len(deduped)} unique device(s).")
        self._save_devices()  # cache results so a restart doesn't require rescanning

    def on_pause(self) -> None:
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.configure(text="Pause")
            self.log("Resumed.")
        else:
            self.pause_event.set()
            self.btn_pause.configure(text="Resume")
            self.log("Paused.")

    def on_stop(self) -> None:
        self.stop_event.set()
        self.pause_event.clear()
        self.log("Stopping…")

    # -------------------------------------------------------------- send
    def on_send(self) -> None:
        devices = self.selected_devices()
        if not devices:
            messagebox.showinfo("Send", "Tick one or more devices in the table first.")
            return
        command = self.txt_command.get("1.0", END).strip()
        if not command:
            messagebox.showinfo("Send", "Type a command in the Command tab.")
            return
        cfg = self._read_config()
        self.notebook.select(1)  # show output tab
        threading.Thread(
            target=self._send_worker, args=(devices, command, cfg), daemon=True
        ).start()

    def _send_worker(self, devices, command, cfg) -> None:
        for dev in devices:
            iid = dev.key or dev.ip
            try:
                if cfg["cmdtype"] == "SSH":
                    from ssh_client import run_ssh_command
                    out = self._ssh_try_addresses(dev, cfg, lambda host: run_ssh_command(
                        host, cfg["user"], cfg["password"], command,
                        port=cfg["ssh_port"], timeout=cfg["timeout"],
                    ))
                else:
                    out = self._run_api_commands(dev, command, cfg)
                self.log(f"--- {dev.ip} ({dev.identity}) via {self._via(dev, cfg)} ---\n{out}")
                self.ui_queue.put(("status", (iid, "Command OK")))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{dev.ip} (via {self._via(dev, cfg)}): command failed: "
                         f"{type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Command error: {exc}")))

    @staticmethod
    def _via(dev: Device, cfg: dict) -> str:
        if cfg["cmdtype"] == "SSH":
            return f"SSH {dev.reach_ip}:{cfg['ssh_port']}"
        return f"API {dev.reach_ip}:{dev.api_port or cfg['api_ssl_port']}"

    def _run_api_commands(self, dev: Device, command: str, cfg: dict) -> str:
        api = core.open_device_api(
            dev, cfg["user"], cfg["password"], cfg["api_ssl_port"],
            timeout=cfg["timeout"], logger=self.logger,
        )
        chunks = []
        try:
            for line in command.splitlines():
                if not line.strip():
                    continue
                sentence = parse_cli_to_api(line)
                if not sentence:
                    continue
                rows = api.talk(sentence)
                chunks.append(f"$ {line}")
                for row in rows:
                    chunks.append("  " + ", ".join(f"{k}={v}" for k, v in row.items()))
        finally:
            api.close()
        return "\n".join(chunks) if chunks else "(no output)"

    # ------------------------------------------------------------- backup
    def on_backup(self) -> None:
        devices = self.selected_devices()
        if not devices:
            messagebox.showinfo("Backup", "Tick one or more devices to back up.")
            return
        cfg = self._read_config()
        os.makedirs(BACKUP_DIR, exist_ok=True)
        threading.Thread(
            target=self._backup_worker, args=(devices, cfg), daemon=True
        ).start()

    def _backup_worker(self, devices, cfg) -> None:
        for dev in devices:
            iid = dev.key or dev.ip
            try:
                if cfg["cmdtype"] == "SSH":
                    text = self._ssh_export(dev, cfg)
                else:
                    try:
                        api = core.open_device_api(
                            dev, cfg["user"], cfg["password"], cfg["api_ssl_port"],
                            timeout=cfg["timeout"], logger=self.logger,
                        )
                        try:
                            text = core.fetch_export(api, logger=self.logger)
                        finally:
                            api.close()
                    except core.ExportTooLarge as exc:
                        # old RouterOS can't hand big configs over the API
                        self.log(f"{dev.ip}: {exc}; trying SSH port {cfg['ssh_port']}")
                        text = self._ssh_export(dev, cfg)
                fname = backup_filename(dev.ip, dev.identity)
                path = os.path.join(BACKUP_DIR, fname)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                self.log(f"{dev.ip}: backup saved -> Backups/{fname}")
                self.ui_queue.put(("status", (iid, f"Backup: {fname}")))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{dev.ip} (via {self._via(dev, cfg)}): backup failed: "
                         f"{type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Backup error: {exc}")))

    def _ssh_try_addresses(self, dev: Device, cfg: dict, action):
        """Run action(host) over SSH on the scanned address, then on the
        bridge1 address if the first one's SSH port does not answer at all
        (SSH is often allowed only on the management/bridge network)."""
        from ssh_client import SSHStageError
        hosts = [dev.reach_ip] + ([dev.ip] if dev.ip and dev.ip != dev.reach_ip else [])
        for i, host in enumerate(hosts):
            try:
                return action(host)
            except SSHStageError as exc:
                unreachable = "did not answer" in str(exc) or "refused" in str(exc)
                if unreachable and i + 1 < len(hosts):
                    self.log(f"{dev.ip}: {exc}; trying bridge1 address {hosts[i + 1]}")
                    continue
                raise

    def _ssh_export(self, dev: Device, cfg: dict) -> str:
        from ssh_client import export_config
        return self._ssh_try_addresses(dev, cfg, lambda host: export_config(
            host, cfg["user"], cfg["password"],
            port=cfg["ssh_port"], timeout=max(cfg["timeout"], 20.0),
        ))

    # ---------------------------------------------------------- import/exp
    def on_export(self) -> None:
        if not self.devices:
            messagebox.showinfo("Export", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")], title="Export results"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            # "Mgmt IP" = the address the router actually answered on during the
            # scan, so imported rows can still be backed up / sent commands
            # (the IP column shows the bridge1 address, which may be unroutable).
            writer = csv.DictWriter(
                fh, fieldnames=COLUMNS + ("Mgmt IP",), delimiter=CSV_DELIMITER
            )
            writer.writeheader()
            for dev in self.devices.values():
                writer.writerow({**dev.as_row(), "Mgmt IP": dev.reach_ip})
        self.log(f"Exported {len(self.devices)} row(s) -> {path}")

    def on_import(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("CSV", "*.csv")], title="Import results"
        )
        if not path:
            return
        with open(path, newline="", encoding="utf-8-sig") as fh:
            header = fh.readline()
            fh.seek(0)
            counts = {d: header.count(d) for d in (";", ",", "\t")}
            delim = max(counts, key=counts.get) if any(counts.values()) else CSV_DELIMITER
            reader = csv.DictReader(fh, delimiter=delim)
            count = 0
            for row in reader:
                dev = Device(
                    ip=row.get("IP", ""),
                    identity=row.get("Identity", ""),
                    board_name=row.get("Board Name", ""),
                    routeros=row.get("RouterOS", ""),
                    license=row.get("License", ""),
                    last_seen=row.get("Last seen", ""),
                    status=row.get("Status", ""),
                    key=row.get("IP", ""),
                    connect_ip=row.get("Mgmt IP", "") or "",
                )
                self._upsert_device(dev)
                count += 1
        self._save_devices()
        self.log(f"Imported {count} row(s) from {path}")

    # ------------------------------------------------- cached scan results
    def _save_devices(self) -> None:
        try:
            rows = [dataclasses.asdict(d) for d in self.devices.values()]
            tmp = DEVICES_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=1)
            os.replace(tmp, DEVICES_FILE)  # a crash mid-write must not destroy the cache
        except (OSError, TypeError) as exc:
            self.log(f"Could not save results cache: {exc}")

    def _load_devices(self) -> None:
        if not os.path.exists(DEVICES_FILE):
            return
        try:
            with open(DEVICES_FILE, encoding="utf-8") as fh:
                rows = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self._write_log(f"devices.json is unreadable ({exc}); starting with an empty table.")
            return
        allowed = {f.name for f in dataclasses.fields(Device)}
        loaded = 0
        for row in rows if isinstance(rows, list) else []:
            try:
                self._upsert_device(Device(**{k: v for k, v in row.items() if k in allowed}))
                loaded += 1
            except (TypeError, AttributeError):
                continue  # skip a malformed entry, keep the rest
        if loaded:
            self._write_log(f"Loaded {loaded} cached device(s) from last session. "
                            f"Use Update to refresh, New Scan to start over.")

    def on_save_log(self) -> None:
        import shutil
        for handler in self.logger.handlers:
            handler.flush()
        dest = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=os.path.basename(self.log_path),
            filetypes=[("Log", "*.log"), ("All files", "*.*")],
            title="Save log for debugging",
        )
        if not dest:
            return
        try:
            shutil.copyfile(self.log_path, dest)
            messagebox.showinfo("Log", f"Лог сохранён:\n{dest}\n\nМожешь прислать этот файл для дебага.")
        except OSError as exc:
            messagebox.showerror("Log", f"Не удалось сохранить лог: {exc}")

    # ------------------------------------------------------------ settings
    def _maybe_save_settings(self) -> None:
        if self.var_save.get():
            self._save_settings()
        elif os.path.exists(SETTINGS_FILE):
            # Save was unticked: forget the stored settings (incl. password)
            try:
                os.remove(SETTINGS_FILE)
            except OSError as exc:
                self.log(f"Could not remove saved settings: {exc}")

    def _save_settings(self) -> None:
        data = {}
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
        data.update({
            "user": self.var_user.get(),
            "network": self.var_network.get(),
            "api_port": self.var_api_port.get(),
            "threads": self.var_threads.get(),
            "ssh_port": self.var_ssh_port.get(),
            "winbox_port": self.var_winbox_port.get(),
            "cmdtype": self.var_cmdtype.get(),
            "timeout": self.var_timeout.get(),
            "retries": self.var_retries.get(),
            "command": self.txt_command.get("1.0", END).rstrip(),
            "save": True,
        })
        # Password is stored only when Save is ticked; base64 is obfuscation,
        # not encryption — the file is local to the operator's machine.
        data["password"] = base64.b64encode(self.var_pass.get().encode()).decode()
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            self.log(f"Could not save settings: {exc}")

    def _load_settings(self) -> None:
        if not os.path.exists(SETTINGS_FILE):
            return
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return
        self.var_user.set(data.get("user", ""))
        self.var_network.set(data.get("network", ""))
        self.var_api_port.set(data.get("api_port", "8729"))
        self.var_threads.set(data.get("threads", "30"))
        self.var_ssh_port.set(data.get("ssh_port", "22"))
        self.var_winbox_port.set(data.get("winbox_port", "8291"))
        self.var_cmdtype.set(data.get("cmdtype", "API/SSL"))
        self.var_timeout.set(data.get("timeout", "10"))
        self.var_retries.set(data.get("retries", "2"))
        self.var_save.set(data.get("save", False))
        if data.get("password"):
            try:
                self.var_pass.set(base64.b64decode(data["password"]).decode())
            except Exception:  # noqa: BLE001
                pass
        if data.get("command"):
            self.txt_command.insert("1.0", data["command"])

    def _on_close(self) -> None:
        self.stop_event.set()
        self._maybe_save_settings()
        self._save_devices()  # persist statuses (backups/commands) too
        self.root.destroy()


def main() -> None:
    root = Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
