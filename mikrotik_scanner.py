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
import time
import tkinter as tk
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
import icons
from applog import setup_logging
from core import Device, backup_filename, dedupe_devices, expand_targets, parse_cli_to_api

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
DEVICES_FILE = os.path.join(APP_DIR, "devices.json")  # cached scan results
UI_FILE = os.path.join(APP_DIR, "ui.json")  # user-set column widths
BACKUP_DIR = os.path.join(APP_DIR, "Backups")
CSV_DELIMITER = ";"  # Excel-friendly in RU locale; "Mgmt IP" is the reach address

COLUMNS = ("IP", "Identity", "Board Name", "RouterOS", "License", "Last seen", "Last Backup", "Status")
# default column widths, in characters of the current font (so they fit any font/DPI)
DEFAULT_CHARS = {"IP": 14, "Identity": 20, "Board Name": 13, "RouterOS": 11, "License": 7,
                 "Last seen": 19, "Last Backup": 19, "Status": 20, "winbox": 8}
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
WINBOX_LABEL = "▶ Winbox"  # per-row launcher, last column
MAX_OPS_THREADS = 10  # Backup / SEND run this many devices at once at most
ALL_MODELS = "Все модели"  # the "no filter" entry of the Board Name filter
EMPTY_MODEL = "(пусто)"  # devices whose Board Name could not be read
IDLE_TEXT = "Нет активных операций"
ERROR_BG, ERROR_FG = "#ffd6d6", "#7a0000"  # rows of devices whose last operation failed


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
        self._sort: tuple[str, bool] | None = None   # (column, reverse) currently applied
        self._resizing_columns = False
        self._job: dict | None = None                # the running (or last finished) operation
        self._progress_text = ""
        self._hidden: set[str] = set()               # rows filtered out of the view
        self._anchor: tuple[str, bool] | None = None  # last clicked checkbox, for Shift-click ranges
        self._counts_dirty = True
        self._models_dirty = True
        self._last_cache_save = time.monotonic()

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
        self.var_model = StringVar(value=ALL_MODELS)
        self.var_errors_only = BooleanVar(value=False)

        self._build_ui()
        self._load_settings()
        self._load_devices()
        self._after_id = self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        # The table text keeps the default font. A ttk table can't size one cell's
        # font, so the checkbox and the update button are drawn as images, a bit
        # larger than the text.
        style = ttk.Style(self.root)
        linespace = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        self._icon_size = max(16, round(linespace * 1.25))
        self._icon_gap, self._icon_w, self._refresh_x = icons.layout(self._icon_size)
        self._icons = {}  # PhotoImages must stay referenced or Tk drops them
        for checked in (False, True):
            self._icons[("row", checked)] = tk.PhotoImage(
                data=icons.row_icon(self._icon_size, checked)[2])
            self._icons[("head", checked)] = tk.PhotoImage(
                data=icons.header_icon(self._icon_size, checked)[2])
        try:
            base_height = int(style.lookup("Treeview", "rowheight") or 0)
        except ValueError:
            base_height = 0
        style.configure("Treeview", rowheight=max(base_height, linespace + 4, self._icon_size + 6))
        try:
            # no expand/collapse indicator space: the icons start at the cell edge
            style.layout("Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
                ("Treeitem.image", {"side": "left", "sticky": ""}),
                ("Treeitem.focus", {"side": "left", "sticky": "", "children": [
                    ("Treeitem.text", {"side": "left", "sticky": ""})]}),
            ]})])
            # ttk puts a heading's image on the right by default; keep it on the left
            style.layout("Treeview.Heading", [
                ("Treeheading.cell", {"sticky": "nswe"}),
                ("Treeheading.border", {"sticky": "nswe", "children": [
                    ("Treeheading.padding", {"sticky": "nswe", "children": [
                        ("Treeheading.image", {"side": "left", "sticky": ""}),
                        ("Treeheading.text", {"sticky": "we"}),
                    ]})]}),
            ])
        except tk.TclError:
            pass

        # Tk 8.6.9 (bundled with some Pythons) ignores Treeview tag colours
        # unless the style map is filtered like this
        def fixed_map(option):
            return [e for e in style.map("Treeview", query_opt=option)
                    if e[:2] != ("!disabled", "!selected")]

        style.map("Treeview", foreground=fixed_map("foreground"), background=fixed_map("background"))
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
        ttk.Button(actions, text="Delete", command=self.on_delete).pack(side=LEFT, padx=2)
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

        # progress: bar, then what is running / how far / how long is left
        self.progress = ttk.Progressbar(self.root, orient=HORIZONTAL, mode="determinate")
        self.progress.pack(fill=X, padx=6, pady=(2, 0))
        self.lbl_progress = ttk.Label(self.root, text=IDLE_TEXT, anchor="w")
        self.lbl_progress.pack(fill=X, padx=8)

        # filters on the left, how many devices / how many ticked on the right
        filters = ttk.Frame(self.root)
        filters.pack(fill=X, padx=6, pady=(4, 0))
        ttk.Label(filters, text="Модель (Board Name):").pack(side=LEFT, padx=(2, 4))
        self.model_combo = ttk.Combobox(filters, textvariable=self.var_model, state="readonly",
                                        width=28, values=[ALL_MODELS])
        self.model_combo.pack(side=LEFT)
        self.model_combo.bind("<<ComboboxSelected>>", lambda e: self._on_filter_change())
        ttk.Checkbutton(filters, text="Только с ошибками", variable=self.var_errors_only,
                        command=self._on_filter_change).pack(side=LEFT, padx=12)
        self.lbl_counts = ttk.Label(filters, anchor="e")
        self.lbl_counts.pack(side=RIGHT, padx=4)

        # table
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=BOTH, expand=True, padx=6, pady=2)
        cols = COLUMNS + ("winbox",)
        self._winbox_col = "#%d" % (len(COLUMNS) + 1)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="tree headings", selectmode="none")
        # column #0 holds the checkbox + update button images
        self.tree.heading("#0", image=self._icons[("head", False)], anchor="w",
                          command=self.toggle_all)
        self.tree.column("#0", width=self._icon_w + 14, minwidth=self._icon_w + 6,
                         anchor="w", stretch=False)
        for col in COLUMNS:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=self._default_width(col), anchor="w", stretch=False)
        self.tree.heading("winbox", text="Winbox")
        self.tree.column("winbox", width=self._default_width("winbox"), anchor="center", stretch=False)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=RIGHT, fill=Y)
        hsb.pack(side="bottom", fill=X)
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.tag_configure("error", background=ERROR_BG, foreground=ERROR_FG)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-Button-1>", self._on_tree_double_click)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_release)
        for seq in self._right_click_sequences():
            self.tree.bind(seq, self._on_tree_right_click)
        self._load_ui_state()

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

    def _right_click_sequences(self) -> tuple:
        if self.root.tk.call("tk", "windowingsystem") == "aqua":
            return ("<Button-2>", "<Control-Button-1>")
        return ("<Button-3>",)

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

        for seq in self._right_click_sequences():
            widget.bind(seq, popup)

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
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self.logger.exception("UI refresh failed")
        finally:
            self._after_id = self.root.after(100, self._drain_queue)

    def _tick(self) -> None:
        """Every 100 ms: progress text/bar, model list, counters."""
        self._render_progress()
        if self._models_dirty:
            self._refresh_model_choices()
        if self._counts_dirty:
            self._update_counts()

    def _handle_ui_message(self, kind: str, payload) -> None:
        if kind == "log":
            self._write_log(payload)
        elif kind == "device":
            self._upsert_device(payload)
        elif kind == "status":
            iid, text, failed = payload
            self._set_status(iid, text, failed)
        elif kind == "status_ip":
            ip, text, failed = payload
            for iid, dev in list(self.devices.items()):
                if ip in (dev.ip, dev.reach_ip):
                    self._set_status(iid, text, failed)
        elif kind == "row":
            dev = self.devices.get(payload)
            if dev is not None and self.tree.exists(payload):
                self.tree.item(payload, values=self._row_values(dev))
        elif kind == "save_devices":
            self._save_devices()
        elif kind == "done":
            self._scan_finished(payload)
        elif kind == "job_done":
            self._finish_job(payload)

    def _set_status(self, iid: str, text: str, failed: bool) -> None:
        dev = self.devices.get(iid)
        if dev is None:
            return
        dev.status, dev.failed = text, failed
        if self.tree.exists(iid):
            self.tree.set(iid, "Status", text)
            self.tree.item(iid, tags=self._row_tags(dev))
        self._apply_visibility(iid)
        self._counts_dirty = True

    def _default_width(self, column: str) -> int:
        font = tkfont.nametofont("TkDefaultFont")
        return font.measure("0" * DEFAULT_CHARS[column]) + 22

    def _row_values(self, dev: Device) -> tuple:
        row = dev.as_row()
        return tuple(row[c] for c in COLUMNS) + (WINBOX_LABEL,)

    def _row_image(self, iid: str):
        return self._icons[("row", iid in self.checked)]

    def _row_tags(self, dev: Device) -> tuple:
        return ("error",) if dev.failed else ()

    def _sync_header(self) -> None:
        """Header box is ticked only while every visible row is."""
        visible = [i for i in self.devices if i not in self._hidden]
        every = bool(visible) and all(i in self.checked for i in visible)
        self.tree.heading("#0", image=self._icons[("head", every)])

    # ---- filters: model (Board Name) and "errors only"
    @staticmethod
    def _model_key(dev: Device) -> str:
        return dev.board_name or EMPTY_MODEL

    def _matches_filter(self, dev: Device) -> bool:
        model = self.var_model.get()
        if model != ALL_MODELS and self._model_key(dev) != model:
            return False
        return dev.failed or not self.var_errors_only.get()

    def _apply_visibility(self, iid: str) -> None:
        """Show or hide one row after its data changed. A hidden row is never ticked."""
        dev = self.devices.get(iid)
        if dev is None or not self.tree.exists(iid):
            return
        show = self._matches_filter(dev)
        if show and iid in self._hidden:
            self._hidden.discard(iid)
            self.tree.move(iid, "", "end")
        elif not show and iid not in self._hidden:
            self._hidden.add(iid)
            self.tree.detach(iid)
            if iid in self.checked:
                self.checked.discard(iid)
                self.tree.item(iid, image=self._row_image(iid))
            if self._anchor and self._anchor[0] == iid:
                self._anchor = None

    def _sort_key(self, value: str):
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return (0, tuple(int(p) for p in parts))   # IP addresses sort numerically
        return (1, value.lower())

    def _ordered_iids(self) -> list:
        iids = list(self.devices)
        if self._sort:
            column, reverse = self._sort
            iids.sort(key=lambda i: self._sort_key(self.devices[i].as_row()[column]), reverse=reverse)
        return iids

    def _relayout(self) -> None:
        """Re-apply the filters and the sort order to the whole table."""
        iids = self._ordered_iids()
        visible = [i for i in iids if self._matches_filter(self.devices[i])]
        shown = set(visible)
        hidden_now = {i for i in iids if i not in shown}
        for iid in hidden_now - self._hidden:
            self.tree.detach(iid)
        for iid in hidden_now & self.checked:      # a hidden row is never ticked
            self.checked.discard(iid)
            self.tree.item(iid, image=self._row_image(iid))
        for index, iid in enumerate(visible):      # move() also re-attaches hidden rows
            self.tree.move(iid, "", index)
        self._hidden = hidden_now
        if self._anchor and self._anchor[0] not in shown:
            self._anchor = None
        self._sync_header()
        self._counts_dirty = True

    def _on_filter_change(self) -> None:
        self._relayout()

    def _refresh_model_choices(self) -> None:
        self._models_dirty = False
        models = sorted({self._model_key(d) for d in self.devices.values()}, key=str.lower)
        values = [ALL_MODELS] + models
        if list(self.model_combo.cget("values")) != values:
            self.model_combo.configure(values=values)
        if self.var_model.get() not in values:     # that model is gone (deleted / rescanned)
            self.var_model.set(ALL_MODELS)
            self._relayout()

    def _update_counts(self) -> None:
        self._counts_dirty = False
        total = len(self.devices)
        ticked = len(self.checked & self.devices.keys())
        failed = sum(1 for d in self.devices.values() if d.failed)
        text = f"Устройств: {total}"
        if self._hidden:
            text += f" (показано {total - len(self._hidden)})"
        text += f" · отмечено: {ticked}"
        if failed:
            text += f" · с ошибками: {failed}"
        self.lbl_counts.configure(text=text)

    def _upsert_device(self, dev: Device) -> None:
        iid = dev.key or dev.ip
        # A row for this IP may exist under another id (imported rows are
        # keyed by IP, scanned ones by serial): replace it, keep its checkbox.
        stale = [i for i, d in self.devices.items() if d.ip == dev.ip and i != iid]
        if not dev.last_backup:
            # a rescan builds a fresh Device that knows nothing about backups
            previous = [self.devices.get(iid)] + [self.devices[i] for i in stale]
            dev.last_backup = next((p.last_backup for p in previous if p and p.last_backup), "")
        for other in stale:
            if other in self.checked:
                self.checked.discard(other)
                self.checked.add(iid)
            if self.tree.exists(other):
                self.tree.delete(other)
            self._hidden.discard(other)
            del self.devices[other]
        values = self._row_values(dev)
        if self.tree.exists(iid):
            self.tree.item(iid, values=values, image=self._row_image(iid), tags=self._row_tags(dev))
        else:
            self.tree.insert("", END, iid=iid, values=values, image=self._row_image(iid),
                             tags=self._row_tags(dev))
        self.devices[iid] = dev
        self._apply_visibility(iid)
        self._counts_dirty = self._models_dirty = True

    # --------------------------------------------------------- table logic
    def _on_tree_click(self, event) -> None:
        # remember a column-border drag so its new width is saved on release
        self._resizing_columns = self.tree.identify_region(event.x, event.y) == "separator"
        if event.state & 0x4:  # Ctrl-click is the right click on macOS
            return
        if self.tree.identify_region(event.x, event.y) not in ("tree", "cell"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        col = self.tree.identify_column(event.x)
        if col == "#0":
            box = self.tree.bbox(iid, "#0")
            if not box:
                return
            rel = event.x - box[0]  # x inside the cell; image = checkbox, gap, update button
            if rel < self._icon_size + self._icon_gap // 2 + 3:
                self._toggle_check(iid, shift=bool(event.state & 0x1))
            elif rel < self._icon_w + 10:
                self.on_update_one(iid)
        elif col == self._winbox_col:
            self.on_winbox(iid)

    def _set_checked(self, iid: str, state: bool) -> None:
        if state:
            self.checked.add(iid)
        else:
            self.checked.discard(iid)
        self.tree.item(iid, image=self._row_image(iid))

    def _toggle_check(self, iid: str, shift: bool = False) -> None:
        """Click on a row's checkbox. With Shift: every visible row from the
        previously clicked checkbox to this one gets the state that one got."""
        if shift and self._anchor:
            visible = list(self.tree.get_children(""))
            if self._anchor[0] in visible and iid in visible:
                first, last = sorted((visible.index(self._anchor[0]), visible.index(iid)))
                state = self._anchor[1]
                for other in visible[first:last + 1]:
                    self._set_checked(other, state)
                self._anchor = (iid, state)
                self._sync_header()
                self._counts_dirty = True
                return
        state = iid not in self.checked
        self._set_checked(iid, state)
        self._anchor = (iid, state)
        self._sync_header()
        self._counts_dirty = True

    def _column_name(self, column_id: str):
        """Data column name for a '#N' id from identify_column, else None."""
        if column_id == "#0":
            return None
        names = self.tree.cget("columns")
        index = int(column_id[1:]) - 1
        return names[index] if 0 <= index < len(COLUMNS) else None

    def _on_tree_double_click(self, event) -> None:
        # Tk delivers the 2nd click of a fast pair ONLY to this binding, not to
        # the single-click one, so everything except the Last Backup cell must
        # behave as an ordinary click (else a quick 2nd click on a checkbox,
        # update or Winbox button would be swallowed).
        if self.tree.identify_region(event.x, event.y) == "cell":
            iid = self.tree.identify_row(event.y)
            if iid and self._column_name(self.tree.identify_column(event.x)) == "Last Backup":
                self.open_last_backup(iid)
                return
        self._on_tree_click(event)

    def open_last_backup(self, iid: str) -> None:
        """Open the device's newest backup in the default program for .rsc."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        path = core.latest_backup_file(BACKUP_DIR, dev.ip)
        if path is None:
            if dev.last_backup:  # the table says there was one, but the file is gone
                messagebox.showinfo(
                    "Backup", f"Файл бэкапа для {dev.ip} не найден в папке:\n{BACKUP_DIR}")
            return
        try:
            core.open_with_default_app(path)
        except OSError as exc:
            self.log(f"{dev.ip}: could not open {os.path.basename(path)}: {exc}")
            messagebox.showerror(
                "Backup", f"Не удалось открыть файл:\n{path}\n\n{exc}\n\n"
                          "Возможно, для файлов .rsc не назначена программа по умолчанию.")
            return
        self.log(f"{dev.ip}: opened {os.path.basename(path)}")

    def _on_tree_release(self, _event) -> None:
        if self._resizing_columns:
            self._resizing_columns = False
            self._save_ui_state()

    # ------------------------------------------ copy from the table (right click)
    def _copy_text(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _on_tree_right_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) not in ("tree", "cell"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        name = self._column_name(self.tree.identify_column(event.x))  # data cells only
        row_text = "\t".join(self.tree.set(iid, c) for c in COLUMNS)  # tabs paste into Excel columns
        menu = tk.Menu(self.tree, tearoff=0)
        if name:
            value = self.tree.set(iid, name)
            shown = value if len(value) <= 32 else value[:31] + "…"
            menu.add_command(label=f"Копировать ячейку: {shown}" if value else "Копировать ячейку (пусто)",
                             state="normal" if value else "disabled",
                             command=lambda: self._copy_text(value))
        menu.add_command(label="Копировать строку", command=lambda: self._copy_text(row_text))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ------------------------------------------------ remembered column widths
    def _save_ui_state(self) -> None:
        widths = {name: int(self.tree.column(name, "width"))
                  for name in ("#0",) + tuple(self.tree.cget("columns"))}
        try:
            tmp = UI_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"column_widths": widths}, fh, indent=1)
            os.replace(tmp, UI_FILE)
        except OSError as exc:
            self.logger.warning("could not save column widths: %s", exc)

    def _load_ui_state(self) -> None:
        try:
            with open(UI_FILE, encoding="utf-8") as fh:
                widths = json.load(fh).get("column_widths", {})
        except (OSError, ValueError, AttributeError):
            return
        known = ("#0",) + tuple(self.tree.cget("columns"))
        for name, width in (widths.items() if isinstance(widths, dict) else []):
            try:
                width = int(width)
            except (TypeError, ValueError):
                continue
            if name in known:
                minimum = int(self.tree.column(name, "minwidth"))
                self.tree.column(name, width=max(minimum, min(width, 2000)))

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
        if self._busy():
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
                self.ui_queue.put(("status", (iid, f"Error: {type(exc).__name__}: {exc}", True)))
            self.ui_queue.put(("save_devices", None))

        threading.Thread(target=work, daemon=True).start()

    def toggle_all(self) -> None:
        """Header checkbox: tick every visible row, or clear them if all are ticked."""
        visible = list(self.tree.get_children(""))
        select = not (visible and all(i in self.checked for i in visible))
        for iid in visible:
            self._set_checked(iid, select)
        self._anchor = None
        self._sync_header()
        self._counts_dirty = True

    def sort_by(self, column: str) -> None:
        reverse = self.sort_state.get(column, False)
        self._sort = (column, reverse)
        self.sort_state[column] = not reverse
        self._relayout()

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

    def selected_iids(self) -> list:
        """Ticked devices (table row ids), in the order they are shown."""
        return [i for i in self.tree.get_children("") if i in self.checked and i in self.devices]

    def selected_devices(self) -> list[Device]:
        return [self.devices[i] for i in self.selected_iids()]

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

    # ------------------------------------------------------ operations (jobs)
    def _busy(self) -> bool:
        """True, after telling the user, while an operation is still running."""
        job = self._job
        if job is not None and not job["finished"]:
            messagebox.showwarning(
                "Операция выполняется",
                f"Сейчас выполняется: {job['title']}.\nДождитесь окончания или нажмите Stop.")
            return True
        return False

    def _job_elapsed(self, job: dict) -> float:
        """Seconds the job has been working (time spent paused is not counted)."""
        if job["finished"]:
            return job["elapsed"]
        now = time.monotonic()
        paused = job["paused_total"]
        if job["pause_started"] is not None:
            paused += now - job["pause_started"]
        return max(0.0, now - job["t0"] - paused)

    def _job_text(self, job: dict) -> str:
        return core.progress_text(
            job["title"], job["done"], job["total"], self._job_elapsed(job),
            ok=job["ok"], bad=job["bad"], ok_label=job["ok_label"], bad_label=job["bad_label"],
            paused=self.pause_event.is_set() and not job["finished"],
            finished=job["finished"], stopped=job["stopped"], threads=job["threads"],
        )

    def _render_progress(self) -> None:
        job = self._job
        if job is None:
            return
        self.progress["maximum"] = max(job["total"], 1)
        self.progress["value"] = job["done"]
        text = self._job_text(job)
        if text != self._progress_text:
            self._progress_text = text
            self.lbl_progress.configure(text=text)
        if not job["finished"] and time.monotonic() - self._last_cache_save > 30:
            self._save_devices()   # a long job must not lose its results if the app dies

    def _start_job(self, title: str, items, func, threads: int, ok_label: str = "",
                   bad_label: str = "", on_finish=None) -> None:
        """Run func(item) -> bool for every item in `threads` worker threads,
        with progress, time left, Pause and Stop. func returns True on success."""
        items = list(items)
        job = {
            "title": title, "total": len(items), "done": 0, "ok": 0, "bad": 0,
            "threads": max(1, min(threads, len(items))), "ok_label": ok_label,
            "bad_label": bad_label, "t0": time.monotonic(), "paused_total": 0.0,
            "pause_started": None, "finished": False, "stopped": False, "elapsed": 0.0,
        }
        self._job = job
        self._last_cache_save = time.monotonic()
        self.stop_event.clear()
        self.pause_event.clear()
        self.btn_pause.configure(state="normal", text="Pause")
        self.btn_stop.configure(state="normal")
        self._progress_text = ""
        self._render_progress()
        self.worker = threading.Thread(
            target=self._run_job, args=(job, items, func, on_finish), daemon=True)
        self.worker.start()

    def _run_job(self, job: dict, items: list, func, on_finish) -> None:
        feed = iter(items)
        lock = threading.Lock()
        end = object()

        def next_item():
            with lock:
                return next(feed, end)

        def loop() -> None:
            while True:
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)
                if self.stop_event.is_set():
                    return
                item = next_item()
                if item is end:
                    return
                try:
                    ok = bool(func(item))
                except Exception:  # noqa: BLE001 - one bad device must not stop the job
                    self.logger.exception("%s: item failed", job["title"])
                    ok = False
                with lock:
                    job["done"] += 1
                    job["ok" if ok else "bad"] += 1

        workers = [threading.Thread(target=loop, daemon=True) for _ in range(job["threads"])]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        if on_finish is not None:
            try:
                on_finish(job)
            except Exception:  # noqa: BLE001
                self.logger.exception("%s: finishing step failed", job["title"])
        job["elapsed"] = self._job_elapsed(job)
        job["stopped"] = self.stop_event.is_set() and job["done"] < job["total"]
        job["finished"] = True
        self.ui_queue.put(("job_done", job))

    def _finish_job(self, job: dict) -> None:
        self.pause_event.clear()
        self.btn_pause.configure(state="disabled", text="Pause")
        self.btn_stop.configure(state="disabled")
        self._render_progress()
        self.log(self._progress_text)
        self._save_devices()

    def on_pause(self) -> None:
        job = self._job
        if self.pause_event.is_set():
            self.pause_event.clear()
            if job is not None and job["pause_started"] is not None:
                job["paused_total"] += time.monotonic() - job["pause_started"]
                job["pause_started"] = None
            self.btn_pause.configure(text="Pause")
            self.log("Resumed.")
        else:
            self.pause_event.set()
            if job is not None and not job["finished"]:
                job["pause_started"] = time.monotonic()
            self.btn_pause.configure(text="Resume")
            self.log("Paused.")

    def on_stop(self) -> None:
        job = self._job
        if job is not None and job["pause_started"] is not None:
            job["paused_total"] += time.monotonic() - job["pause_started"]
            job["pause_started"] = None
        self.stop_event.set()
        self.pause_event.clear()
        self.log("Stopping… (devices already in progress will finish)")

    # ---------------------------------------------------------------- scan
    def on_scan(self) -> None:
        if self._busy():
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
        # fresh scan clears the table (filters too: new rows must not start hidden)
        for iid in list(self.devices):
            if self.tree.exists(iid):
                self.tree.delete(iid)
        self.devices.clear()
        self.checked.clear()
        self._hidden.clear()
        self._anchor = None
        self.var_model.set(ALL_MODELS)
        self.var_errors_only.set(False)
        self._sync_header()
        self._counts_dirty = self._models_dirty = True
        self._start_scan(targets, "New scan")

    def on_update(self) -> None:
        if self._busy():
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
        self._maybe_save_settings()
        cfg = self._read_config()
        found: list[Device] = []
        # only addresses of devices already in the table need a red status when they fail
        known = {a for d in self.devices.values() for a in (d.ip, d.reach_ip)}

        def scan_one(ip: str) -> bool:
            try:
                dev = core.scan_host(
                    ip, cfg["user"], cfg["password"],
                    cfg["api_ssl_port"], plain_port=8728,
                    timeout=cfg["timeout"], retries=cfg["retries"],
                    logger=self.logger,
                )
                dev.last_seen = datetime.now().strftime(TIME_FORMAT)
                self.log(f"{ip}: found {dev.identity or dev.board_name or 'RouterOS'} "
                         f"[{dev.status}]")
                self.ui_queue.put(("device", dev))  # show it right away
                found.append(dev)
                return True
            except Exception as exc:  # noqa: BLE001 - report every failure
                self.log(f"{ip}: {type(exc).__name__}: {exc}")
                if ip in known:   # a device already in the table must not keep a stale "OK"
                    self.ui_queue.put(("status_ip", (ip, f"Error: {type(exc).__name__}: {exc}", True)))
                return False

        def finish(_job: dict) -> None:
            self.ui_queue.put(("done", dedupe_devices(found)))

        self.log(f"{label}: {len(targets)} target(s), {cfg['threads']} threads, "
                 f"timeout {cfg['timeout']}s, {cfg['retries']} retries, "
                 f"API-SSL port {cfg['api_ssl_port']} (plain API 8728 only if that port is refused).")
        self._start_job("Сканирование" if label == "New scan" else "Обновление", targets,
                        scan_one, cfg["threads"], ok_label="найдено", on_finish=finish)

    def _scan_finished(self, deduped: list[Device]) -> None:
        for dev in deduped:
            self._upsert_device(dev)
        self._write_log(f"Scan complete: {len(deduped)} unique device(s).")
        self._seed_last_backup()
        self._relayout()   # sort order / filters for the rows added during the scan
        self._save_devices()  # cache results so a restart doesn't require rescanning

    # -------------------------------------------------------------- send
    @staticmethod
    def _ops_threads(cfg: dict) -> int:
        """Backup / SEND run several devices at once, but never more than MAX_OPS_THREADS."""
        return max(1, min(cfg["threads"], MAX_OPS_THREADS))

    def on_send(self) -> None:
        if self._busy():
            return
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
        self.log(f"Send ({cfg['cmdtype']}): {len(devices)} device(s), {self._ops_threads(cfg)} at a time")
        self._start_job("Команды", devices, lambda dev: self._send_one(dev, command, cfg),
                        self._ops_threads(cfg), ok_label="успешно", bad_label="ошибок")

    def _send_one(self, dev: Device, command: str, cfg: dict) -> bool:
        iid = dev.key or dev.ip
        try:
            if cfg["cmdtype"] == "SSH":
                from ssh_client import run_ssh_command
                out = self._ssh_try_addresses(dev, cfg, lambda host: run_ssh_command(
                    host, cfg["user"], cfg["password"], command,
                    port=cfg["ssh_port"], timeout=cfg["timeout"], retries=cfg["retries"],
                ))
            else:
                out = self._run_api_commands(dev, command, cfg)
            self.log(f"--- {dev.ip} ({dev.identity}) via {self._via(dev, cfg)} ---\n{out}")
            self.ui_queue.put(("status", (iid, "Command OK", False)))
            return True
        except Exception as exc:  # noqa: BLE001
            self.log(f"{dev.ip} (via {self._via(dev, cfg)}): command failed: "
                     f"{type(exc).__name__}: {exc}")
            self.ui_queue.put(("status", (iid, f"Command error: {exc}", True)))
            return False

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
        if self._busy():
            return
        devices = self.selected_devices()
        if not devices:
            messagebox.showinfo("Backup", "Tick one or more devices to back up.")
            return
        cfg = self._read_config()
        os.makedirs(BACKUP_DIR, exist_ok=True)
        self.log(f"Backup ({cfg['cmdtype']}): {len(devices)} device(s), {self._ops_threads(cfg)} at a time")
        self._start_job("Бэкап", devices, lambda dev: self._backup_one(dev, cfg),
                        self._ops_threads(cfg), ok_label="успешно", bad_label="ошибок")

    def _backup_one(self, dev: Device, cfg: dict) -> bool:
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
            dev.last_backup = datetime.now().strftime(TIME_FORMAT)
            self.log(f"{dev.ip}: backup saved -> Backups/{fname}")
            self.ui_queue.put(("status", (iid, f"Backup: {fname}", False)))
            self.ui_queue.put(("row", iid))  # shows the new Last Backup time
            return True
        except Exception as exc:  # noqa: BLE001
            self.log(f"{dev.ip} (via {self._via(dev, cfg)}): backup failed: "
                     f"{type(exc).__name__}: {exc}")
            self.ui_queue.put(("status", (iid, f"Backup error: {exc}", True)))
            return False

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
            port=cfg["ssh_port"], timeout=max(cfg["timeout"], 20.0), retries=cfg["retries"],
        ))

    # ------------------------------------------------------------- delete
    def on_delete(self) -> None:
        """Remove the ticked devices from the table (not from the network)."""
        if self._busy():
            return
        iids = self.selected_iids()
        if not iids:
            messagebox.showinfo("Delete", "Отметьте галочками устройства, которые нужно удалить из таблицы.")
            return
        if not messagebox.askyesno(
            "Delete",
            f"Удалить из таблицы отмеченные устройства: {len(iids)}?\n\n"
            "Удаляются только строки таблицы и их запись в сохранённом списке. "
            "Сами устройства и файлы бэкапов не затрагиваются.\n"
            "Вернуть строки можно новым сканом или импортом CSV.",
            icon="warning", default="no",
        ):
            return
        for iid in iids:
            if self.tree.exists(iid):
                self.tree.delete(iid)
            self.devices.pop(iid, None)
            self.checked.discard(iid)
            self._hidden.discard(iid)
        self._anchor = None
        self._sync_header()
        self._counts_dirty = self._models_dirty = True
        self._save_devices()
        self.log(f"Deleted {len(iids)} device(s) from the table.")

    # ---------------------------------------------------------- import/exp
    def on_export(self) -> None:
        if not self.devices or len(self._hidden) == len(self.devices):
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
            rows = [self.devices[i] for i in self.tree.get_children("") if i in self.devices]
            for dev in rows:
                writer.writerow({**dev.as_row(), "Mgmt IP": dev.reach_ip})
        note = f" (filter active: {len(self.devices)} in total)" if self._hidden else ""
        self.log(f"Exported {len(rows)} row(s){note} -> {path}")

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
                    last_backup=row.get("Last Backup", "") or "",
                    status=row.get("Status", ""),
                    failed=core.looks_like_error(row.get("Status", "")),
                    key=row.get("IP", ""),
                    connect_ip=row.get("Mgmt IP", "") or "",
                )
                self._upsert_device(dev)
                count += 1
        self._seed_last_backup()
        self._sync_header()
        self._save_devices()
        self.log(f"Imported {count} row(s) from {path}")

    # ------------------------------------------------- cached scan results
    def _seed_last_backup(self) -> None:
        """Backups made before this column existed carry no timestamp; take it
        from the newest matching file in Backups/."""
        missing = [(i, d) for i, d in self.devices.items() if not d.last_backup]
        if not missing:
            return
        index = core.backup_index(BACKUP_DIR)
        for iid, dev in missing:
            stamp = index.get(dev.ip)
            if stamp:
                dev.last_backup = stamp
                self.tree.set(iid, "Last Backup", stamp)

    def _save_devices(self) -> None:
        try:
            rows = [dataclasses.asdict(d) for d in self.devices.values()]
            tmp = DEVICES_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=1)
            os.replace(tmp, DEVICES_FILE)  # a crash mid-write must not destroy the cache
            self._last_cache_save = time.monotonic()
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
                dev = Device(**{k: v for k, v in row.items() if k in allowed})
                if "failed" not in row:   # cache from before errors were tracked
                    dev.failed = core.looks_like_error(dev.status)
                self._upsert_device(dev)
                loaded += 1
            except (TypeError, AttributeError):
                continue  # skip a malformed entry, keep the rest
        self._seed_last_backup()
        self._sync_header()
        self._counts_dirty = self._models_dirty = True
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
        try:
            self.root.after_cancel(self._after_id)
        except (tk.TclError, AttributeError):
            pass
        self._maybe_save_settings()
        self._save_devices()  # persist statuses (backups/commands) too
        self._save_ui_state()
        self.root.destroy()


def main() -> None:
    root = Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
