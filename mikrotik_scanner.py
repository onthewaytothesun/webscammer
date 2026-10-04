#!/usr/bin/env python3
"""
MikroTik subnet scanner & manager.

A Tkinter desktop tool that scans a subnet for MikroTik / RouterOS devices,
authenticates with operator-supplied credentials over SSH or the RouterOS API
(API-SSL, with plain API as a fallback), inventories them, runs commands on selected
devices, and saves textual (.rsc) backups. The interface is in Russian.

Run:  python3 mikrotik_scanner.py
"""

from __future__ import annotations

import base64
import copy
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
import health
import icons
from applog import setup_logging
from core import Device, backup_filename, dedupe_devices, expand_targets, split_api_line

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
COMMANDS_FILE = os.path.join(APP_DIR, "commands.json")  # the 10 command drafts, kept always
DEVICES_FILE = os.path.join(APP_DIR, "devices.json")  # cached scan results
UI_FILE = os.path.join(APP_DIR, "ui.json")  # user-set column widths
BACKUP_DIR = os.path.join(APP_DIR, "Backups")
CSV_DELIMITER = ";"  # Excel-friendly in RU locale

# Data columns: what is copied, searched, sorted and exported. The keys are internal;
# HEADINGS are the names shown in the table (IP, Identity, RouterOS, License and
# Winbox deliberately stay as they are).
DATA_COLUMNS = ("IP", "Identity", "Board Name", "RouterOS", "License", "Last seen",
                "Last Backup", "Status", "Note")
# left to right in the table: the favourite star, the data, the signal levels (shown
# only while the «Слабое радио» filter is on), the Winbox button and the note
TREE_COLUMNS = ("fav",) + DATA_COLUMNS[:-1] + ("signal", "ping", "router_id", "winbox", "Note")
EXTRA_COLUMNS = ("fav", "signal", "ping", "router_id", "winbox")   # not data: not sorted or exported
OPTIONAL_COLUMNS = ("signal", "ping", "router_id")   # shown only when their checkbox is ticked
HEADINGS = {
    "IP": "IP", "Identity": "Identity", "Board Name": "Модель", "RouterOS": "RouterOS",
    "License": "License", "Last seen": "Был в сети", "Last Backup": "Последний бэкап",
    "Status": "Статус", "winbox": "Winbox", "Note": "Заметка", "fav": "★", "signal": "Сигнал",
    "ping": "Ping", "router_id": "Router-ID",
}
HEALTH_FIELDS = ("serial", "ports", "wireless", "radio", "extended",
                 "port_problem", "radio_problem", "changes")
MGMT_HEADING = "IP подключения"  # the address the scan reached (CSV only)
# CSV headers accepted on import: the current names, the key names and the older English ones
CSV_ALIASES = {**{v: k for k, v in HEADINGS.items()}, **{k: k for k in DATA_COLUMNS},
               "Mgmt IP": "Mgmt IP", MGMT_HEADING: "Mgmt IP"}
# default column widths, in characters of the current font (so they fit any font/DPI)
DEFAULT_CHARS = {"IP": 14, "Identity": 18, "Board Name": 13, "RouterOS": 10, "License": 7,
                 "Last seen": 19, "Last Backup": 19, "Status": 18, "winbox": 8, "Note": 26,
                 "fav": 1, "signal": 24, "ping": 9, "router_id": 14}
TIME_FORMAT = core.TIME_FORMAT
WINBOX_LABEL = "▶ Winbox"  # per-row launcher
MAX_OPS_THREADS = 10  # Backup / SEND run this many devices at once at most
EMPTY_MODEL = "(пусто)"  # devices whose model (Board Name) could not be read
IDLE_TEXT = "Нет активных операций"
ERROR_BG, ERROR_FG = "#ffd6d6", "#7a0000"  # rows of devices whose last operation failed
# rows whose last backup is older than 3 / 6 / 12 months (also the legend chips)
AGE_COLORS = {"age3": "#fff1a0", "age6": "#ffc27d", "age12": "#ff8f8f"}
# changed since the previous update (until a backup saves it) / port problems / weak radio
STATE_COLORS = {"changed": "#d9b8f5", "port": "#8db4f0", "radio": "#c4ecff"}
FAV_MARK = "★"
ROW_FRAME_COLOR = "#1a4fd6"   # the frame around the row last worked with
AGE_CHOICES = (("Любой возраст", 0), ("Старше 3 мес.", 3), ("Старше 6 мес.", 6), ("Старше 12 мес.", 12))
COMMAND_HINTS = {
    "SSH": "SSH: команды как в терминале RouterOS, например /ip service set ssh port=22",
    "API/SSL": "API/SSL: команды в формате API, одна на строку, без конвертации: "
               "/ip/service/set =numbers=ssh =port=22",
}


class ScannerApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Сканер MikroTik")
        self.root.geometry("1320x820")

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
        self._hidden: set[str] = set()               # rows filtered out of the view (they keep their tick)
        self._models_sel: set[str] = set()           # models shown; empty = all
        self._models_dialog: dict | None = None
        self._search_words: list[str] = []
        self._search_job = None
        self._note_dialog: dict | None = None
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
        self.var_errors_only = BooleanVar(value=False)
        self.var_no_backup = BooleanVar(value=False)
        self.var_age = StringVar(value=AGE_CHOICES[0][0])
        self.var_port_issue = BooleanVar(value=False)
        self.var_weak_radio = BooleanVar(value=False)
        self.var_changed_only = BooleanVar(value=False)
        self.var_favorites = BooleanVar(value=False)
        self.var_confirmed = BooleanVar(value=False)
        self.var_signal_show = BooleanVar(value=False)
        self.var_signal_limit = StringVar()
        self.var_ping_show = BooleanVar(value=False)
        self.var_router_id_show = BooleanVar(value=False)
        self._column_order = list(TREE_COLUMNS)   # the operator can drag columns around
        self._drag_column = None
        self._current_row = None                  # the row last clicked: drawn with a frame
        self._row_frame_box = None
        self._search_nets: list = []   # subnets typed in the search box (10.20.30.0/24)
        self._signal_limit = None   # the parsed «не лучше» value, dBm
        self._baselines: dict = {}   # iid -> the device as it was before the running scan / update

        self._build_ui()
        self._fit_window_to_fields()
        self._set_app_icon()
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

        # Keep all input fields in one row. On narrow windows the row scrolls
        # horizontally instead of wrapping or hiding the rightmost inputs.
        form_host = ttk.Frame(self.root)
        form_host.pack(fill=X)
        form_canvas = tk.Canvas(form_host, height=36, highlightthickness=0)
        form_canvas.pack(fill=X)
        form_scroll = ttk.Scrollbar(form_host, orient="horizontal", command=form_canvas.xview)
        form_canvas.configure(xscrollcommand=form_scroll.set)
        form = ttk.Frame(form_canvas, padding=(3, 4))
        form_canvas.create_window((0, 0), window=form, anchor="nw")
        self._field_row = form

        def resize_form(_event=None):
            form_canvas.configure(scrollregion=form_canvas.bbox("all"), height=form.winfo_reqheight())
            if form.winfo_reqwidth() > form_canvas.winfo_width():
                form_scroll.pack(fill=X)
            else:
                form_scroll.pack_forget()
                form_canvas.xview_moveto(0)

        form.bind("<Configure>", resize_form)
        form_canvas.bind("<Configure>", resize_form)

        def show_widget(widget):
            """Scroll the field row so that a focused field is fully visible."""
            total = form.winfo_reqwidth()
            view = form_canvas.winfo_width()
            if total <= view:
                return
            left = widget.winfo_x()
            right = left + widget.winfo_width()
            first = form_canvas.canvasx(0)
            if left < first:
                form_canvas.xview_moveto(max(0, left - 8) / total)
            elif right > first + view:
                form_canvas.xview_moveto(min(total - view, right + 8 - view) / total)

        def wheel(event):
            if form.winfo_reqwidth() <= form_canvas.winfo_width():
                return None
            step = -1 if (getattr(event, "delta", 0) > 0 or event.num == 4) else 1
            form_canvas.xview_scroll(step * 3, "units")
            return "break"

        def watch(widget):
            widget.bind("<FocusIn>", lambda e: show_widget(e.widget), add="+")

        # the mouse wheel over the field row moves it sideways (when it does not fit)
        for target in (form_canvas, form):
            for seq in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>"):
                target.bind(seq, wheel)

        def field(parent, label, var, width, show=None):
            ttk.Label(parent, text=label).pack(side=LEFT, padx=(5, 1))
            e = ttk.Entry(parent, textvariable=var, width=width, show=show)
            e.pack(side=LEFT)
            self._attach_context_menu(e)
            watch(e)
            return e

        # compact widths so the whole row fits the window
        field(form, "Логин:", self.var_user, 9)
        field(form, "Пароль:", self.var_pass, 9, show="*")
        field(form, "Сеть:", self.var_network, 15)
        field(form, "API-SSL:", self.var_api_port, 5)
        field(form, "SSH:", self.var_ssh_port, 5)
        field(form, "Winbox:", self.var_winbox_port, 5)
        field(form, "Потоки:", self.var_threads, 3)
        field(form, "Таймаут:", self.var_timeout, 3)
        field(form, "Повторы:", self.var_retries, 2)
        # on the right: the transport for scanning, refreshing, SEND and Backup,
        # then «Запомнить настройки»
        ttk.Label(form, text="Тип команд:").pack(side=LEFT, padx=(10, 1))
        cmdtype_box = ttk.Combobox(
            form, textvariable=self.var_cmdtype, values=["API/SSL", "SSH"],
            width=7, state="readonly",
        )
        cmdtype_box.pack(side=LEFT)
        watch(cmdtype_box)
        save_box = ttk.Checkbutton(form, text="Запомнить настройки", variable=self.var_save)
        save_box.pack(side=LEFT, padx=(10, 2))
        watch(save_box)

        # buttons row
        actions = ttk.Frame(self.root, padding=(6, 0))
        actions.pack(fill=X)
        self.btn_add_scan = ttk.Button(actions, text="Скан", command=self.on_scan_add)
        self.btn_add_scan.pack(side=LEFT, padx=2)
        self.btn_scan = ttk.Button(actions, text="Новый скан", command=self.on_scan)
        self.btn_scan.pack(side=LEFT, padx=2)
        self.btn_pause = ttk.Button(actions, text="Пауза", command=self.on_pause, state="disabled")
        self.btn_pause.pack(side=LEFT, padx=2)
        self.btn_stop = ttk.Button(actions, text="Стоп", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Обновить", command=self.on_update).pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Удалить", command=self.on_delete).pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Бэкап", command=self.on_backup).pack(side=LEFT, padx=2)
        ttk.Button(actions, text="Подтвердить", command=self.on_confirm).pack(side=LEFT, padx=(10, 2))
        ttk.Button(actions, text="★ Избранное", command=self.on_favorite).pack(side=LEFT, padx=2)
        ttk.Label(actions, text="Команда:").pack(side=RIGHT, padx=(2, 4))
        ttk.Button(actions, text="Отправить", command=self.on_send).pack(side=RIGHT, padx=2)

        # Ten independent command drafts, followed by the output tab on the right.
        nb = ttk.Notebook(self.root)
        nb.pack(fill=BOTH, expand=False, padx=6, pady=4)
        from tkinter.scrolledtext import ScrolledText

        self.command_editors = []
        self.command_hints = []
        self.active_command = 0
        for i in range(10):
            cmd_frame = ttk.Frame(nb)
            hint = ttk.Label(cmd_frame, anchor="w", foreground="#555555")
            hint.pack(fill=X, padx=2)
            editor = ScrolledText(cmd_frame, height=8, wrap="word")
            editor.pack(fill=BOTH, expand=True)
            self._attach_context_menu(editor)
            self.command_editors.append(editor)
            self.command_hints.append(hint)
            nb.add(cmd_frame, text=f"Команда {i + 1}")
        self.var_cmdtype.trace_add("write", lambda *_: self._update_command_hint())
        self._update_command_hint()

        out_frame = ttk.Frame(nb)
        self.txt_output = ScrolledText(out_frame, height=8, wrap="word")
        self.txt_output.pack(fill=BOTH, expand=True)
        self._make_readonly(self.txt_output)  # selectable & copyable, not editable
        nb.add(out_frame, text="Вывод / Лог")
        self.notebook = nb
        nb.bind("<<NotebookTabChanged>>", self._command_tab_changed)

        # progress: bar, then what is running / how far / how long is left,
        # and on the right what the row colours mean
        self.progress = ttk.Progressbar(self.root, orient=HORIZONTAL, mode="determinate")
        self.progress.pack(fill=X, padx=6, pady=(2, 0))
        info = ttk.Frame(self.root)
        info.pack(fill=X, padx=8)
        legend = ttk.Frame(info)
        legend.pack(side=RIGHT)
        ttk.Label(legend, text="Последний бэкап старше:").pack(side=LEFT)
        for tag, text in (("age3", "3 мес."), ("age6", "6 мес."), ("age12", "12 мес.")):
            tk.Label(legend, width=2, bg=AGE_COLORS[tag], bd=1, relief="solid").pack(side=LEFT, padx=(6, 2))
            ttk.Label(legend, text=text).pack(side=LEFT)
        tk.Label(legend, width=2, bg=ERROR_BG, bd=1, relief="solid").pack(side=LEFT, padx=(10, 2))
        ttk.Label(legend, text="ошибка").pack(side=LEFT)
        for tag, text in (("changed", "изменения"), ("port", "порт"), ("radio", "радио")):
            tk.Label(legend, width=2, bg=STATE_COLORS[tag], bd=1, relief="solid").pack(side=LEFT, padx=(6, 2))
            ttk.Label(legend, text=text).pack(side=LEFT)
        self.lbl_progress = ttk.Label(info, text=IDLE_TEXT, anchor="w")
        self.lbl_progress.pack(side=LEFT, fill=X, expand=True)

        # filters (the device counts are in the bottom bar)
        filters = ttk.Frame(self.root)
        filters.pack(fill=X, padx=6, pady=(4, 0))
        self.btn_models = ttk.Button(filters, width=26, command=self._open_models_dialog)
        self.btn_models.pack(side=LEFT, padx=(2, 8))
        ttk.Label(filters, text="Бэкап:").pack(side=LEFT, padx=(0, 4))
        self.age_combo = ttk.Combobox(filters, textvariable=self.var_age, state="readonly",
                                      width=16, values=[name for name, _ in AGE_CHOICES])
        self.age_combo.pack(side=LEFT)
        self.age_combo.bind("<<ComboboxSelected>>", lambda e: self._on_filter_change())
        ttk.Checkbutton(filters, text="Только с ошибками", variable=self.var_errors_only,
                        command=self._on_filter_change).pack(side=LEFT, padx=(12, 0))
        ttk.Checkbutton(filters, text="Только без бэкапов", variable=self.var_no_backup,
                        command=self._on_filter_change).pack(side=LEFT, padx=(12, 0))
        for text, var in (("Только с изменениями", self.var_changed_only),
                          ("Избранное", self.var_favorites)):
            ttk.Checkbutton(filters, text=text, variable=var,
                            command=self._on_filter_change).pack(side=LEFT, padx=(12, 0))
        self._update_models_button()

        # second filter row: device health
        health_row = ttk.Frame(self.root)
        health_row.pack(fill=X, padx=6, pady=(2, 0))
        for i, (text, var) in enumerate((("Проблемы с портом", self.var_port_issue),
                                         ("Слабое радио", self.var_weak_radio),
                                         ("Подтверждённые", self.var_confirmed))):
            ttk.Checkbutton(health_row, text=text, variable=var,
                            command=self._on_filter_change).pack(side=LEFT, padx=(4 if i == 0 else 12, 0))
        ttk.Checkbutton(health_row, text="Сигнал", variable=self.var_signal_show,
                        command=self._on_filter_change).pack(side=LEFT, padx=(24, 0))
        ttk.Label(health_row, text="не лучше").pack(side=LEFT, padx=(8, 4))
        signal_entry = ttk.Entry(health_row, textvariable=self.var_signal_limit, width=6)
        signal_entry.pack(side=LEFT)
        self._attach_context_menu(signal_entry)
        signal_entry.bind("<Escape>", lambda e: self.var_signal_limit.set(""))
        ttk.Label(health_row, text="дБм (например −65: показать сигналы −65 и хуже)",
                  foreground="#666").pack(side=LEFT, padx=(4, 0))
        ttk.Checkbutton(health_row, text="Ping", variable=self.var_ping_show,
                        command=self._on_filter_change).pack(side=LEFT, padx=(24, 0))
        ttk.Checkbutton(health_row, text="Router-ID", variable=self.var_router_id_show,
                        command=self._on_filter_change).pack(side=LEFT, padx=(12, 0))
        self.var_signal_limit.trace_add("write", lambda *_: self._on_search_changed())

        # table
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=BOTH, expand=True, padx=6, pady=2)
        self.tree = ttk.Treeview(table_frame, columns=TREE_COLUMNS, show="tree headings", selectmode="none")
        # column #0 holds the checkbox + update button images
        self.tree.heading("#0", image=self._icons[("head", False)], anchor="w",
                          command=self.toggle_all)
        self.tree.column("#0", width=self._icon_w + 14, minwidth=self._icon_w + 6,
                         anchor="w", stretch=False)
        for col in TREE_COLUMNS:
            if col in EXTRA_COLUMNS:
                self.tree.heading(col, text=HEADINGS[col])
            else:
                self.tree.heading(col, text=HEADINGS[col], command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=self._default_width(col), stretch=False,
                             anchor="center" if col in ("winbox", "fav") else "w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=RIGHT, fill=Y)
        hsb.pack(side="bottom", fill=X)
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.tag_configure("error", background=ERROR_BG, foreground=ERROR_FG)
        for tag, color in list(AGE_COLORS.items()) + list(STATE_COLORS.items()):
            self.tree.tag_configure(tag, background=color, foreground="#000000")
        self._show_signal_column(False)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-Button-1>", self._on_tree_double_click)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_release)
        self.tree.bind("<B1-Motion>", self._on_tree_drag)
        self._row_frame = [tk.Frame(self.tree, bg=ROW_FRAME_COLOR, bd=0, highlightthickness=0)
                           for _ in range(4)]
        for seq in self._right_click_sequences():
            self.tree.bind(seq, self._on_tree_right_click)
        self._load_ui_state()

        # bottom bar: the search box filters the table while it is not empty
        bottom = ttk.Frame(self.root, padding=6)
        bottom.pack(fill=X)
        ttk.Label(bottom, text="Поиск:").pack(side=LEFT, padx=(0, 4))
        find_entry = ttk.Entry(bottom, textvariable=self.var_find, width=30)
        find_entry.pack(side=LEFT)
        self._attach_context_menu(find_entry)
        find_entry.bind("<Escape>", lambda e: self.var_find.set(""))
        self.var_find.trace_add("write", lambda *_: self._on_search_changed())
        ttk.Button(bottom, text="Очистить", command=lambda: self.var_find.set("")).pack(side=LEFT, padx=4)
        ttk.Button(bottom, text="Сохранить лог", command=self.on_save_log).pack(side=LEFT, padx=8)
        ttk.Label(bottom, text=f"Лог: logs/{os.path.basename(self.log_path)}",
                  foreground="#666").pack(side=LEFT)
        ttk.Button(bottom, text="Экспорт", command=self.on_export).pack(side=RIGHT, padx=2)
        ttk.Button(bottom, text="Импорт", command=self.on_import).pack(side=RIGHT, padx=2)
        # how many devices / how many ticked (the filter row above is full)
        self.lbl_counts = ttk.Label(bottom, anchor="e")
        self.lbl_counts.pack(side=RIGHT, padx=(4, 12))

    def _fit_window_to_fields(self) -> None:
        """Open the window wide enough for the whole field row when the screen
        allows it; on a narrower screen the row scrolls instead."""
        self.root.update_idletasks()
        needed = self._field_row.winfo_reqwidth() + 16
        screen = self.root.winfo_screenwidth()
        width = max(1320, min(needed, screen - 40))
        self.root.geometry(f"{width}x820")

    def _set_app_icon(self) -> None:
        """Window / taskbar icon: a white «M» on a router-blue tile, drawn in code."""
        try:
            self._app_icons = [tk.PhotoImage(data=icons.app_icon(size)[2]) for size in (64, 32, 16)]
            self.root.iconphoto(True, *self._app_icons)
        except tk.TclError:
            pass   # an icon is cosmetic: never let it stop the program

    def _update_command_hint(self) -> None:
        for hint in self.command_hints:
            hint.configure(text=COMMAND_HINTS.get(self.var_cmdtype.get(), ""))

    def _command_tab_changed(self, _event=None) -> None:
        index = self.notebook.index(self.notebook.select())
        if index < len(self.command_editors):
            self.active_command = index

    @property
    def txt_command(self):
        # Read selection synchronously too: the tab event may still be queued.
        self._command_tab_changed()
        return self.command_editors[self.active_command]

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
        self._place_row_frame()

    # ---- the row last worked with is drawn with a frame until another row is clicked
    def _set_current_row(self, iid: str) -> None:
        self._current_row = iid
        self._place_row_frame()

    def _place_row_frame(self) -> None:
        iid = self._current_row
        box = self.tree.bbox(iid) if iid and self.tree.exists(iid) else ""
        if box == self._row_frame_box:
            return
        self._row_frame_box = box
        if not box:
            for line in self._row_frame:
                line.place_forget()
            return
        x, y, w, h = box
        t = 2
        for line, (lx, ly, lw, lh) in zip(self._row_frame, ((x, y, w, t), (x, y + h - t, w, t),
                                                            (x, y, t, h), (x + w - t, y, t, h))):
            line.place(x=lx, y=ly, width=lw, height=lh)
            line.lift()

    def _handle_ui_message(self, kind: str, payload) -> None:
        if kind == "log":
            self._write_log(payload)
        elif kind == "device":
            self._accept_polled(payload)
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
                self.tree.item(payload, values=self._row_values(dev), tags=self._row_tags(dev))
                self._apply_visibility(payload)
                self._counts_dirty = True
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
        if column == "fav":
            return font.measure(FAV_MARK) + 20
        return max(font.measure("0" * DEFAULT_CHARS[column]), font.measure(HEADINGS[column]) + 30) + 22

    def _row_values(self, dev: Device) -> tuple:
        row = dev.as_row()
        row.update(winbox=WINBOX_LABEL, fav=FAV_MARK if dev.favorite else "",
                   signal=health.signal_text(dev.radio), ping=dev.ping, router_id=dev.router_id)
        return tuple(row[c] for c in TREE_COLUMNS)

    def _row_image(self, iid: str):
        return self._icons[("row", iid in self.checked)]

    def _row_tags(self, dev: Device) -> tuple:
        """One colour tag per row: red for a failed device, purple for unsaved changes,
        blue for port problems, light blue for weak radio, else by age of the last backup."""
        if health.open_problem(dev, "error"):
            return ("error",)
        for tag, flag in (("changed", dev.changes), ("port", health.open_problem(dev, "port")),
                          ("radio", health.open_problem(dev, "radio"))):
            if flag:
                return (tag,)
        tag = core.backup_age_tag(dev.last_backup)
        return (tag,) if tag else ()

    def _visible_iids(self) -> list:
        return list(self.tree.get_children(""))

    def _sync_header(self) -> None:
        """Header box is ticked only while every visible row is."""
        visible = [i for i in self.devices if i not in self._hidden]
        every = bool(visible) and all(i in self.checked for i in visible)
        self.tree.heading("#0", image=self._icons[("head", every)])

    # ---- filters: model, errors, no backup, backup age, and the search box.
    # A hidden row keeps its tick, but Backup / SEND / Delete / Export only ever act
    # on the rows that are shown.
    @staticmethod
    def _model_key(dev: Device) -> str:
        return dev.board_name or EMPTY_MODEL

    def _age_months(self) -> int:
        return dict(AGE_CHOICES).get(self.var_age.get(), 0)

    @staticmethod
    def _search_text(dev: Device) -> str:
        """What the search box looks in: the columns, and every IP of the device
        (also the ones not shown: other interfaces, client addresses)."""
        row = dev.as_row()
        return " ".join([row[c] for c in DATA_COLUMNS] + core.all_ips(dev) + [dev.router_id]).lower()

    def _matches_filter(self, dev: Device) -> bool:
        if self._models_sel and self._model_key(dev) not in self._models_sel:
            return False
        if self.var_errors_only.get() and not health.open_problem(dev, "error"):
            return False
        if self.var_no_backup.get() and dev.last_backup:
            return False
        if self.var_changed_only.get() and not dev.changes:
            return False
        if self.var_port_issue.get() and not health.open_problem(dev, "port"):
            return False
        if self.var_weak_radio.get() and not health.open_problem(dev, "radio"):
            return False
        if self.var_confirmed.get() and not dev.confirmed:
            return False
        if self._signal_limit is not None:
            worst = health.worst_signal(dev.radio)
            if worst is None or worst > self._signal_limit:
                return False
        if self.var_favorites.get() and not dev.favorite:
            return False
        months = self._age_months()
        if months and not core.backup_older_than(dev.last_backup, months):
            return False
        for net in self._search_nets:
            if not any(core.ip_in_subnet(ip, net) for ip in core.all_ips(dev)):
                return False
        if self._search_words:
            text = self._search_text(dev)
            if not all(word in text for word in self._search_words):
                return False
        return True

    def _apply_visibility(self, iid: str) -> None:
        """Show or hide one row after its data changed."""
        dev = self.devices.get(iid)
        if dev is None or not self.tree.exists(iid):
            return
        show = self._matches_filter(dev)
        if show and iid in self._hidden:
            self._relayout()   # puts the row back at its place in the current sort order
        elif not show and iid not in self._hidden:
            self._hidden.add(iid)
            self.tree.detach(iid)
            if self._anchor and self._anchor[0] == iid:
                self._anchor = None
            self._sync_header()
            self._counts_dirty = True

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
        for index, iid in enumerate(visible):      # move() also re-attaches hidden rows
            self.tree.move(iid, "", index)
        self._hidden = hidden_now
        if self._anchor and self._anchor[0] not in shown:
            self._anchor = None
        self._sync_header()
        self._counts_dirty = True

    def _on_filter_change(self) -> None:
        self._show_signal_column(self.var_weak_radio.get() or self.var_signal_show.get()
                                 or self._signal_limit is not None)
        self._relayout()

    @staticmethod
    def _parse_signal_limit(text: str):
        """'-65', '65', '−65' -> -65 (signals are negative); '' or junk -> None."""
        text = text.strip().replace("−", "-").replace(",", ".")
        try:
            value = int(float(text))
        except ValueError:
            return None
        return -abs(value)

    def _show_signal_column(self, show: bool) -> None:
        """The «Сигнал» column is there only with «Сигнал», «Слабое радио» or a «не лучше» value;
        «Ping» only with its checkbox."""
        self._signal_shown = show
        wanted = {"signal": show, "ping": self.var_ping_show.get(), "router_id": self.var_router_id_show.get()}
        self.tree.configure(displaycolumns=[c for c in self._column_order
                                            if c not in OPTIONAL_COLUMNS or wanted[c]])

    def _on_search_changed(self) -> None:
        """Typing in the search box filters the table (after a short pause)."""
        if self._search_job is not None:
            self.root.after_cancel(self._search_job)
        self._search_job = self.root.after(150, self._apply_search)

    def _apply_search(self) -> None:
        if self._search_job is not None:   # called directly while a delayed run is pending
            try:
                self.root.after_cancel(self._search_job)
            except tk.TclError:
                pass
        self._search_job = None
        words = self.var_find.get().lower().split()
        nets = [core.parse_subnet(w) for w in words]
        words = [w for w, net in zip(words, nets) if net is None]   # a subnet matches addresses in it
        nets = [net for net in nets if net is not None]
        limit = self._parse_signal_limit(self.var_signal_limit.get())
        if words != self._search_words or nets != self._search_nets or limit != self._signal_limit:
            self._search_words = words
            self._search_nets = nets
            self._signal_limit = limit
            self._on_filter_change()

    def _reset_filters(self) -> None:
        self._models_sel.clear()
        self.var_errors_only.set(False)
        self.var_no_backup.set(False)
        for var in (self.var_changed_only, self.var_port_issue, self.var_weak_radio, self.var_favorites,
                    self.var_confirmed, self.var_signal_show):
            var.set(False)
        self.var_signal_limit.set("")
        self._signal_limit = None
        self._show_signal_column(False)
        self.var_age.set(AGE_CHOICES[0][0])
        self.var_find.set("")
        self._search_words = []
        self._search_nets = []
        if self._search_job is not None:
            self.root.after_cancel(self._search_job)
            self._search_job = None
        self._update_models_button()

    # ---- the model filter: a small window with a list where several models can be ticked
    def _model_counts(self) -> dict:
        counts: dict = {}
        for dev in self.devices.values():
            key = self._model_key(dev)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _update_models_button(self) -> None:
        chosen = self._models_sel
        if not chosen:
            text = "Модель: все"
        elif len(chosen) == 1:
            name = next(iter(chosen))
            text = "Модель: " + (name if len(name) <= 16 else name[:15] + "…")
        else:
            text = f"Модель: выбрано {len(chosen)}"
        self.btn_models.configure(text=text)

    def _open_models_dialog(self) -> None:
        if self._models_dialog is not None:
            self._models_dialog["win"].lift()
            return
        win = tk.Toplevel(self.root)
        win.title("Фильтр по моделям")
        win.transient(self.root)
        win.geometry("+%d+%d" % (self.btn_models.winfo_rootx(),
                                 self.btn_models.winfo_rooty() + self.btn_models.winfo_height()))
        ttk.Label(win, text="Отметьте модели, которые нужно показать\n(клик по строке добавляет или убирает её):",
                  justify="left").pack(anchor="w", padx=8, pady=(8, 4))
        body = ttk.Frame(win)
        body.pack(fill=BOTH, expand=True, padx=8)
        listbox = tk.Listbox(body, selectmode="multiple", exportselection=False, width=38,
                             height=min(max(len(self._model_counts()), 5), 18), activestyle="none")
        scroll = ttk.Scrollbar(body, orient="vertical", command=listbox.yview)
        listbox.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        listbox.pack(side=LEFT, fill=BOTH, expand=True)
        buttons = ttk.Frame(win)
        buttons.pack(fill=X, padx=8, pady=8)
        ttk.Button(buttons, text="Показать все", command=self._clear_models).pack(side=LEFT)
        ttk.Button(buttons, text="Закрыть", command=self._close_models_dialog).pack(side=RIGHT)
        listbox.bind("<<ListboxSelect>>", lambda e: self._on_models_selected())
        win.bind("<Escape>", lambda e: self._close_models_dialog())
        win.protocol("WM_DELETE_WINDOW", self._close_models_dialog)
        self._models_dialog = {"win": win, "list": listbox, "keys": [], "snapshot": None}
        self._fill_models_list()

    def _close_models_dialog(self) -> None:
        if self._models_dialog is not None:
            self._models_dialog["win"].destroy()
            self._models_dialog = None

    def _fill_models_list(self) -> None:
        dialog = self._models_dialog
        if dialog is None:
            return
        counts = self._model_counts()
        keys = sorted(counts, key=str.lower)
        snapshot = [(k, counts[k]) for k in keys]
        if snapshot == dialog["snapshot"]:
            return
        dialog["snapshot"], dialog["keys"] = snapshot, keys
        listbox = dialog["list"]
        listbox.delete(0, END)
        for index, key in enumerate(keys):
            listbox.insert(END, f"{key}  ({counts[key]})")
            if key in self._models_sel:
                listbox.selection_set(index)

    def _on_models_selected(self) -> None:
        dialog = self._models_dialog
        if dialog is None:
            return
        keys = dialog["keys"]
        self._models_sel = {keys[i] for i in dialog["list"].curselection()}
        self._update_models_button()
        self._relayout()

    def _clear_models(self) -> None:
        self._models_sel.clear()
        if self._models_dialog is not None:
            self._models_dialog["list"].selection_clear(0, END)
        self._update_models_button()
        self._relayout()

    def _refresh_model_choices(self) -> None:
        self._models_dirty = False
        gone = self._models_sel - {self._model_key(d) for d in self.devices.values()}
        if gone:   # that model is no longer in the table (deleted / rescanned)
            self._models_sel -= gone
            self._update_models_button()
            self._relayout()
        self._fill_models_list()

    def _update_counts(self) -> None:
        self._counts_dirty = False
        total = len(self.devices)
        ticked_shown = sum(1 for i in self.checked if i in self.devices and i not in self._hidden)
        ticked_hidden = sum(1 for i in self.checked if i in self.devices and i in self._hidden)
        failed = sum(1 for d in self.devices.values() if health.open_problem(d, "error"))
        text = f"Устройств: {total}"
        if self._hidden:
            text += f" (показано {total - len(self._hidden)})"
        text += f" · отмечено: {ticked_shown}"
        if ticked_hidden:
            text += f" (ещё {ticked_hidden} скрыто)"
        if failed:
            text += f" · с ошибками: {failed}"
        self.lbl_counts.configure(text=text)

    def _upsert_device(self, dev: Device) -> None:
        iid = dev.key or dev.ip
        # A row for this IP may exist under another id (imported rows are
        # keyed by IP, scanned ones by serial): replace it, keep its checkbox.
        stale = [i for i, d in self.devices.items() if d.ip == dev.ip and i != iid]
        # a rescan builds a fresh Device that knows nothing about backups or notes
        previous = [p for p in [self.devices.get(iid)] + [self.devices[i] for i in stale] if p]
        for attr in ("last_backup", "note", "favorite", "confirmed", "main_ip", "ping"):
            if not getattr(dev, attr):
                setattr(dev, attr, next((getattr(p, attr) for p in previous if getattr(p, attr)),
                                        getattr(dev, attr)))
        if previous and not dev.extended:
            # a CSV row knows nothing about ports, radio or changes: keep what the table had
            for attr in HEALTH_FIELDS:
                setattr(dev, attr, copy.deepcopy(getattr(previous[0], attr)))
        if dev.main_ip and dev.ip != dev.main_ip:
            if not dev.connect_ip:
                dev.connect_ip = dev.ip
            dev.ip = dev.main_ip   # the address the operator chose is the one shown
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

    def _accept_polled(self, dev: Device) -> None:
        """A device just read by a scan / update: compare it with how it was before
        this scan (ports, radio, changes — see health.analyse), then show it.
        A router reached through several addresses arrives several times; each
        arrival is compared with the same state from before the scan."""
        iid = dev.key or dev.ip
        if iid not in self._baselines:
            before = self.devices.get(iid) or next(
                (d for d in self.devices.values() if dev.ip in (d.ip, d.reach_ip)), None)
            self._baselines[iid] = copy.deepcopy(before)
        base = self._baselines[iid]
        if base is not None:
            dev.confirmed = list(base.confirmed)   # accepted problems stay accepted
        health.analyse(dev, base)
        if health.status_parts(dev):
            self._write_log(f"{dev.ip} ({dev.identity}): {dev.status}")   # the full text; the cell may be cut
        self._upsert_device(dev)

    # --------------------------------------------------------- table logic
    def _on_tree_click(self, event) -> None:
        # remember a column-border drag so its new width is saved on release
        region = self.tree.identify_region(event.x, event.y)
        self._resizing_columns = region == "separator"
        # a heading can be dragged onto another one to move the column
        self._drag_column = self._shown_column(self.tree.identify_column(event.x)) if region == "heading" else None
        if event.state & 0x4:  # Ctrl-click is the right click on macOS
            return
        if region not in ("tree", "cell"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self._set_current_row(iid)
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
        elif self._shown_column(col) == "winbox":
            self.on_winbox(iid)
        elif self._shown_column(col) == "ping":
            self.on_ping(iid)
        elif self._shown_column(col) == "fav":
            self._set_favorite([iid], not self.devices[iid].favorite)

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
        """Data column key for a '#N' id from identify_column; None for the
        checkbox / update column and for the Winbox button."""
        name = self._shown_column(column_id)
        return name if name not in ("fav", "winbox") else None

    def _shown_column(self, column_id: str):
        """Column key for a '#N' id (counted among the columns shown; «Сигнал» may be hidden)."""
        if not column_id.startswith("#") or column_id == "#0":
            return None
        index = int(column_id[1:]) - 1
        columns = self.tree.cget("displaycolumns")
        columns = TREE_COLUMNS if columns in ("#all", ("#all",)) else tuple(columns)
        return columns[index] if 0 <= index < len(columns) else None

    def _on_tree_double_click(self, event) -> None:
        # Tk delivers the 2nd click of a fast pair ONLY to this binding, not to
        # the single-click one, so everything except the two cells below must
        # behave as an ordinary click (else a quick 2nd click on a checkbox,
        # update or Winbox button would be swallowed).
        if self.tree.identify_region(event.x, event.y) == "cell":
            iid = self.tree.identify_row(event.y)
            if iid:
                self._set_current_row(iid)
            name = self._column_name(self.tree.identify_column(event.x)) if iid else None
            if name == "Last Backup":
                self.open_last_backup(iid)
                return
            if name == "Note":
                self._edit_note(iid)
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
                    "Бэкап", f"Файл бэкапа для {dev.ip} не найден в папке:\n{BACKUP_DIR}")
            return
        try:
            core.open_with_default_app(path)
        except OSError as exc:
            self.log(f"{dev.ip}: не удалось открыть {os.path.basename(path)}: {exc}")
            messagebox.showerror(
                "Бэкап", f"Не удалось открыть файл:\n{path}\n\n{exc}\n\n"
                         "Возможно, для файлов .rsc не назначена программа по умолчанию.")
            return
        self.log(f"{dev.ip}: открыт {os.path.basename(path)}")

    # ---- the note of a device
    def _edit_note(self, iid: str) -> None:
        dev = self.devices.get(iid)
        if dev is None:
            return
        if self._note_dialog is not None:
            self._note_dialog["win"].destroy()
            self._note_dialog = None
        win = tk.Toplevel(self.root)
        win.title("Заметка")
        win.transient(self.root)
        ttk.Label(win, text=f"{dev.ip} · {dev.identity or dev.board_name or ''}").pack(
            anchor="w", padx=10, pady=(10, 4))
        var = StringVar(value=dev.note)
        entry = ttk.Entry(win, textvariable=var, width=72)
        entry.pack(fill=X, padx=10)
        self._attach_context_menu(entry)

        def close() -> None:
            win.destroy()
            self._note_dialog = None

        def save() -> None:
            self._set_note(iid, var.get())
            close()

        buttons = ttk.Frame(win)
        buttons.pack(fill=X, padx=10, pady=10)
        save_button = ttk.Button(buttons, text="Сохранить", command=save)
        save_button.pack(side=RIGHT)
        ttk.Button(buttons, text="Отмена", command=close).pack(side=RIGHT, padx=6)
        entry.bind("<Return>", lambda e: save())
        win.bind("<Escape>", lambda e: close())
        win.protocol("WM_DELETE_WINDOW", close)
        win.geometry("+%d+%d" % (self.root.winfo_rootx() + 120, self.root.winfo_rooty() + 120))
        self._note_dialog = {"win": win, "entry": entry, "var": var, "save": save_button}
        entry.select_range(0, END)
        try:
            win.wait_visibility()
            win.grab_set()
        except tk.TclError:
            pass
        entry.focus_force()

    def _set_note(self, iid: str, text: str) -> None:
        dev = self.devices.get(iid)
        if dev is None:
            return
        dev.note = " ".join(text.split())   # one line
        if self.tree.exists(iid):
            self.tree.set(iid, "Note", dev.note)
        self._apply_visibility(iid)   # the search covers notes, so the row may drop out or appear
        self._counts_dirty = True
        self._save_devices()

    def _on_tree_release(self, event) -> None:
        if self._resizing_columns:
            self._resizing_columns = False
            self._save_ui_state()
        dragged, self._drag_column = self._drag_column, None
        if dragged is None:
            return
        self.tree.configure(cursor="")
        if self.tree.identify_region(event.x, event.y) not in ("heading", "separator"):
            return
        target = self._shown_column(self.tree.identify_column(event.x))
        if target and target != dragged:
            self._move_column(dragged, target)

    def _on_tree_drag(self, event) -> None:
        if self._drag_column is not None:
            over = self._shown_column(self.tree.identify_column(event.x))
            self.tree.configure(cursor="sb_h_double_arrow" if over and over != self._drag_column else "")

    def _move_column(self, column: str, target: str) -> None:
        """Put `column` where `target` is (after it when moving right, before it when moving left)."""
        order = self._column_order
        moving_right = order.index(column) < order.index(target)
        order.remove(column)
        order.insert(order.index(target) + (1 if moving_right else 0), column)
        self._show_signal_column(self._signal_shown)
        self._row_frame_box = None
        self._save_ui_state()

    def _reset_column_order(self) -> None:
        self._column_order = list(TREE_COLUMNS)
        self._show_signal_column(self._signal_shown)
        self._row_frame_box = None
        self._save_ui_state()

    # ------------------------------------------ copy from the table (right click)
    def _copy_text(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _on_tree_right_click(self, event) -> None:
        region = self.tree.identify_region(event.x, event.y)
        if region in ("heading", "separator"):
            menu = tk.Menu(self.tree, tearoff=0)
            menu.add_command(label="Порядок столбцов по умолчанию", command=self._reset_column_order,
                             state="normal" if self._column_order != list(TREE_COLUMNS) else "disabled")
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return
        if region not in ("tree", "cell"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self._set_current_row(iid)
        name = self._column_name(self.tree.identify_column(event.x))  # data cells only
        row_text = "\t".join(self.tree.set(iid, c) for c in DATA_COLUMNS)  # tabs paste into Excel columns
        menu = tk.Menu(self.tree, tearoff=0)
        if name:
            value = self.tree.set(iid, name)
            shown = value if len(value) <= 32 else value[:31] + "…"
            menu.add_command(label=f"Копировать ячейку: {shown}" if value else "Копировать ячейку (пусто)",
                             state="normal" if value else "disabled",
                             command=lambda: self._copy_text(value))
        menu.add_command(label="Копировать строку", command=lambda: self._copy_text(row_text))
        if name == "IP":
            menu.add_command(label="Показать все IP…", command=lambda: self._show_all_ips(iid))
        menu.add_separator()
        menu.add_command(label="Изменить заметку…", command=lambda: self._edit_note(iid))
        confirmed = bool(self.devices[iid].confirmed) and not self._unconfirmed(self.devices[iid])
        menu.add_command(label="Снять подтверждение" if confirmed else "Подтвердить",
                         state="normal" if confirmed or self._unconfirmed(self.devices[iid]) else "disabled",
                         command=lambda: self._set_confirmed([iid], not confirmed))
        favorite = self.devices[iid].favorite
        menu.add_command(label="Убрать из избранного" if favorite else "Добавить в избранное",
                         command=lambda: self._set_favorite([iid], not favorite))
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
                json.dump({"column_widths": widths, "column_order": self._column_order}, fh, indent=1)
            os.replace(tmp, UI_FILE)
        except OSError as exc:
            self.logger.warning("could not save column widths: %s", exc)

    def _load_ui_state(self) -> None:
        try:
            with open(UI_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
            widths = data.get("column_widths", {})
            saved_order = data.get("column_order", [])
        except (OSError, ValueError, AttributeError):
            return
        if isinstance(saved_order, list):
            order = [c for c in dict.fromkeys(saved_order) if c in TREE_COLUMNS]
            for index, column in enumerate(TREE_COLUMNS):   # columns added in a newer version
                if column not in order:
                    order.insert(min(index, len(order)), column)
            self._column_order = order
            self._show_signal_column(False)
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
            messagebox.showwarning("Winbox", "Введите логин (и пароль) в верхней панели.")
            return
        # the address the scan reached (the bridge1 one shown in the table may
        # be unreachable from this PC) plus the Winbox port
        address = f"{dev.reach_ip}:{cfg['winbox_port']}"
        try:
            # argument list, no shell: nothing in the password is interpreted
            subprocess.Popen([exe, address, cfg["user"], cfg["password"]], cwd=APP_DIR)
        except OSError as exc:
            self.log(f"{dev.ip}: не удалось запустить Winbox: {exc}")
            messagebox.showerror("Winbox", f"Не удалось запустить Winbox:\n{exc}")
            return
        self.log(f"Winbox запущен для {address} (пользователь {cfg['user']})")  # never log the password

    def on_update_one(self, iid: str) -> None:
        """Reconnect to one device and refresh its row."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        if self._busy():
            return
        cfg = self._read_config()
        self.tree.set(iid, "Status", "Обновление…")
        self._baselines = {}

        def work():
            hosts = core.connect_candidates(dev) or [dev.ip]
            ip = hosts[0]
            try:
                fresh = self._poll_host(ip, cfg, hosts[1:])
                fresh = dedupe_devices([fresh])[0]  # keep bridge1 as the shown IP
                self._ping_device(fresh)
                fresh.last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log(f"{ip}: обновлено {fresh.identity or fresh.board_name} [{fresh.status}]")
                self.ui_queue.put(("device", fresh))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{ip}: не удалось обновить: {type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Ошибка: {type(exc).__name__}: {exc}", True)))
            self.ui_queue.put(("save_devices", None))

        threading.Thread(target=work, daemon=True).start()

    # ---- every IP of a device, and the choice of the main one
    @staticmethod
    def _ip_rows(dev: Device) -> list:
        """(ip, interface, what it is, can be the main IP) for the «Все IP» window."""
        rows, seen = [], set()
        for entry in core.address_entries(dev.addresses):
            kind = {"own": "свой", "dynamic": "динамический (в изменениях не учитывается)",
                    "client": f"клиент: network на {entry['address']}, не подключаемся"}[entry["kind"]]
            if entry["disabled"]:
                kind += ", выключен"
            if entry["ip"] == dev.router_id and entry["kind"] != "client":
                kind += ", Router-ID OSPF"
            rows.append((entry["ip"], entry["interface"], kind, entry["kind"] != "client"))
            seen.add(entry["ip"])
        for ip, what in ((dev.connect_ip, "адрес, по которому устройство найдено"), (dev.ip, "адрес в таблице")):
            if ip and ip not in seen:
                rows.insert(0, (ip, "", what, True))
                seen.add(ip)
        return rows

    def _show_all_ips(self, iid: str) -> None:
        dev = self.devices.get(iid)
        if dev is None:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Все IP — {dev.identity or dev.ip}")
        win.transient(self.root)
        win.minsize(560, 200)
        info = ttk.Label(win, justify="left")
        info.pack(anchor="w", padx=8, pady=(8, 4))
        body = ttk.Frame(win)
        body.pack(fill=BOTH, expand=True, padx=8)
        rows = self._ip_rows(dev)
        tv = ttk.Treeview(body, columns=("ip", "iface", "kind"), show="headings", selectmode="extended",
                          height=min(max(len(rows), 4), 16))
        for col, text, width in (("ip", "IP", 130), ("iface", "Интерфейс", 120), ("kind", "Что это", 460)):
            tv.heading(col, text=text)
            tv.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(body, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=scroll.set)
        scroll.pack(side=RIGHT, fill=Y)
        tv.pack(side=LEFT, fill=BOTH, expand=True)

        def fill():
            tv.delete(*tv.get_children())
            for i, (ip, iface, kind, _ok) in enumerate(self._ip_rows(dev)):
                mark = "★ основной · " if ip == dev.ip else ""
                tv.insert("", END, iid=str(i), values=(ip, iface, mark + kind))
            info.configure(text=f"Основной IP: {dev.ip}" + (" (выбран вручную)" if dev.main_ip else
                                                              " (автоматически: Router-ID OSPF или адрес на bridge1)")
                           + "\nПодключение — через основной, если он не отвечает — через другие свои адреса.")

        def chosen():
            sel = tv.selection()
            return self._ip_rows(dev)[int(sel[0])] if sel else None

        def copy(what: str) -> None:
            rows = self._ip_rows(dev)
            picked = [rows[int(i)] for i in tv.selection()] or (rows if what == "all" else [])
            if what == "ips":
                self._copy_text("\n".join(r[0] for r in picked))
            else:
                self._copy_text("\n".join(f"{r[0]}\t{r[1]}\t{r[2]}" for r in picked))

        def popup(event):
            row = tv.identify_row(event.y)
            if row and row not in tv.selection():
                tv.selection_set(row)
            menu = tk.Menu(tv, tearoff=0)
            menu.add_command(label="Копировать IP", command=lambda: copy("ips"))
            menu.add_command(label="Копировать строки", command=lambda: copy("rows"))
            menu.add_command(label="Копировать все", command=lambda: copy("all"))
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        def make_main():
            row = chosen()
            if row is None:
                return
            if not row[3]:
                messagebox.showinfo("Основной IP", "Это адрес клиента (network), он не может быть основным.",
                                    parent=win)
                return
            self._set_main_ip(iid, row[0])
            fill()

        def automatic():
            self._set_main_ip(iid, "")
            fill()

        buttons = ttk.Frame(win)
        buttons.pack(fill=X, padx=8, pady=8)
        ttk.Button(buttons, text="Сделать основным", command=make_main).pack(side=LEFT)
        ttk.Button(buttons, text="Автоматически", command=automatic).pack(side=LEFT, padx=4)
        ttk.Button(buttons, text="Копировать IP", command=lambda: copy("ips")).pack(side=LEFT, padx=4)
        ttk.Button(buttons, text="Копировать все", command=lambda: copy("all")).pack(side=LEFT, padx=4)
        ttk.Button(buttons, text="Закрыть", command=win.destroy).pack(side=RIGHT)
        tv.bind("<Double-Button-1>", lambda e: make_main())
        for seq in self._right_click_sequences():
            tv.bind(seq, popup)
        for seq in ("<Control-c>", "<Control-C>", "<Command-c>"):
            try:
                tv.bind(seq, lambda e: copy("ips"))
            except tk.TclError:   # <Command-…> exists only on macOS
                pass
        ttk.Label(win, text="Выделите строки (Ctrl/Shift+клик) и скопируйте: Ctrl+C — только IP, "
                            "правый клик — меню.", foreground="#666").pack(anchor="w", padx=8, pady=(0, 6))
        win.bind("<Escape>", lambda e: win.destroy())
        fill()
        self._ips_dialog = win   # for tests

    def _set_main_ip(self, iid: str, ip: str) -> None:
        """Choose the IP shown in the table and tried first ('' = automatic: bridge1)."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        if not dev.connect_ip:
            dev.connect_ip = dev.ip
        dev.main_ip = ip
        dev.ip = ip or core.auto_ip(dev) or dev.connect_ip or dev.ip
        if self.tree.exists(iid):
            self.tree.item(iid, values=self._row_values(dev))
        self._apply_visibility(iid)
        self._save_devices()
        self.log(f"{dev.identity or dev.ip}: основной IP — {ip or 'автоматически'} ({dev.ip})")

    def _ping_device(self, dev: Device) -> None:
        """Ping the address the device was last reached at (worker threads)."""
        host = dev.connect_ip or dev.ip
        if host:
            dev.ping = core.ping_text(core.ping(host))

    def on_ping(self, iid: str) -> None:
        """Click on a «Ping» cell: ping that device again."""
        dev = self.devices.get(iid)
        if dev is None:
            return
        self.tree.set(iid, "ping", "…")

        def work():
            self._ping_device(dev)
            self.log(f"{dev.ip}: ping {dev.connect_ip or dev.ip} — {dev.ping}")
            self.ui_queue.put(("row", iid))
            self.ui_queue.put(("save_devices", None))
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _unconfirmed(dev: Device) -> list:
        return [k for k in health.problem_kinds(dev) if k not in dev.confirmed]

    def on_confirm(self) -> None:
        """«Подтвердить»: accept the current problems of the ticked rows that are shown
        (connection error, port, weak radio — not changes): the row is no longer
        coloured and leaves those filters. If nothing is left to accept, it takes
        the confirmation back."""
        iids = self.selected_iids()
        if not iids:
            messagebox.showinfo("Подтвердить", "Отметьте галочками устройства, проблемы которых "
                                               "нужно подтвердить (или снять подтверждение).")
            return
        devices = [self.devices[i] for i in iids]
        if any(self._unconfirmed(d) for d in devices):
            self._set_confirmed(iids, True)
        elif any(d.confirmed for d in devices):
            self._set_confirmed(iids, False)
        else:
            messagebox.showinfo("Подтвердить", "У отмеченных устройств нет ошибок, проблем с портом "
                                               "или слабого радио — подтверждать нечего.")

    def _set_confirmed(self, iids: list, state: bool) -> None:
        count = 0
        for iid in iids:
            dev = self.devices.get(iid)
            if dev is None:
                continue
            if state:
                fresh = self._unconfirmed(dev)
                if not fresh:
                    continue
                dev.confirmed = sorted(set(dev.confirmed) | set(fresh))
                dev.status = " | ".join(health.status_parts(dev)) or "Подтверждено"
            else:
                if not dev.confirmed:
                    continue
                dev.confirmed = []
                dev.status = " | ".join(health.status_parts(dev)) or (
                    "Ошибка (подробности в логе; «Обновить» — проверить снова)" if dev.failed else "OK")
            count += 1
            if self.tree.exists(iid):
                self.tree.item(iid, values=self._row_values(dev), tags=self._row_tags(dev))
            self._apply_visibility(iid)
        self._counts_dirty = True
        self._save_devices()
        self.log(f"{'Подтверждено' if state else 'Снято подтверждение'}: {count}")

    def on_favorite(self) -> None:
        """«★ Избранное»: add the ticked rows that are shown to the favourites,
        or take them out if they all are favourites already."""
        iids = self.selected_iids()
        if not iids:
            messagebox.showinfo("Избранное", "Отметьте галочками устройства, которые нужно добавить "
                                             "в избранное (или убрать из него).")
            return
        self._set_favorite(iids, not all(self.devices[i].favorite for i in iids))

    def _set_favorite(self, iids: list, state: bool) -> None:
        for iid in iids:
            dev = self.devices.get(iid)
            if dev is None:
                continue
            dev.favorite = state
            if self.tree.exists(iid):
                self.tree.set(iid, "fav", FAV_MARK if state else "")
            self._apply_visibility(iid)
        self._save_devices()
        self.log(f"{'Добавлено в избранное' if state else 'Убрано из избранного'}: {len(iids)}")

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
                f"Сейчас выполняется: {job['title']}.\nДождитесь окончания или нажмите «Стоп».")
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
                   bad_label: str = "", on_finish=None, extra: dict | None = None) -> None:
        """Run func(item) -> bool for every item in `threads` worker threads,
        with progress, time left, Pause and Stop. func returns True on success."""
        items = list(items)
        job = {
            "title": title, "total": len(items), "done": 0, "ok": 0, "bad": 0,
            "threads": max(1, min(threads, len(items))), "ok_label": ok_label,
            "bad_label": bad_label, "t0": time.monotonic(), "paused_total": 0.0,
            "pause_started": None, "finished": False, "stopped": False, "elapsed": 0.0,
            **(extra or {}),
        }
        self._job = job
        self._last_cache_save = time.monotonic()
        self.stop_event.clear()
        self.pause_event.clear()
        self.btn_pause.configure(state="normal", text="Пауза")
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
        self.btn_pause.configure(state="disabled", text="Пауза")
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
            self.btn_pause.configure(text="Пауза")
            self.log("Продолжено.")
        else:
            self.pause_event.set()
            if job is not None and not job["finished"]:
                job["pause_started"] = time.monotonic()
            self.btn_pause.configure(text="Продолжить")
            self.log("Пауза.")

    def on_stop(self) -> None:
        job = self._job
        if job is not None and job["pause_started"] is not None:
            job["paused_total"] += time.monotonic() - job["pause_started"]
            job["pause_started"] = None
        self.stop_event.set()
        self.pause_event.clear()
        self.log("Остановка… (устройства, которые уже в работе, будут доделаны)")

    # ---------------------------------------------------------------- scan
    def _clear_table(self) -> None:
        for iid in list(self.devices):
            if self.tree.exists(iid):
                self.tree.delete(iid)
        self.devices.clear()
        self.checked.clear()
        self._hidden.clear()
        self._anchor = None
        self._reset_filters()   # new rows must not start hidden
        self._sync_header()
        self._counts_dirty = self._models_dirty = True

    def _network_targets(self):
        """Addresses from the «Сеть» field; None (after a message) when it is empty or invalid."""
        targets = self._targets_or_warn()
        if targets is None:
            return None
        if not targets:
            messagebox.showerror(
                "Скан", "Укажите сеть в поле «Сеть», например 192.168.0.0/24 или 10.20.76.112/28.")
            return None
        return targets

    def on_scan_add(self) -> None:
        """Скан: scan only the network in the field and ADD its devices to the table
        (or refresh the ones already there). Everything else in the table is left alone."""
        if self._busy():
            return
        targets = self._network_targets()
        if targets is None:
            return
        self._start_scan(targets, "Скан")

    def on_scan(self) -> None:
        """Новый скан: empty the table first."""
        if self._busy():
            return
        if self.devices and not messagebox.askyesno(
            "Новый скан",
            "Текущие результаты будут удалены, а таблица очищена.\n\n"
            "Чтобы добавить устройства из сети к существующим результатам, используйте кнопку «Скан», "
            "чтобы обновить уже найденные — «Обновить».\n\nВсё равно начать новый скан?",
            icon="warning", default="no",
        ):
            return
        targets = self._network_targets()
        if targets is None:
            return
        self._clear_table()
        self._start_scan(targets, "Новый скан")

    def on_update(self) -> None:
        """Обновить: reconnect to the devices that are shown in the table (all of them
        unless a filter is on); the «Сеть» field is not used."""
        if self._busy():
            return
        targets, alternatives = [], {}
        for iid in self._visible_iids():
            dev = self.devices[iid]
            hosts = core.connect_candidates(dev) or [dev.reach_ip]
            if hosts[0] and hosts[0] not in targets:
                targets.append(hosts[0])
                alternatives[hosts[0]] = hosts[1:]   # tried when the first one does not answer
        if not targets:
            messagebox.showinfo("Обновить", "В таблице нет устройств для обновления. Сначала выполните «Скан».")
            return
        self._start_scan(targets, "Обновление", alternatives)

    def _targets_or_warn(self):
        """Expand the «Сеть» field; None (after a message) if it's invalid."""
        try:
            return expand_targets(self.var_network.get())
        except ValueError as exc:
            messagebox.showerror(
                "Сеть", f"Не удалось разобрать поле «Сеть»: {exc}\n\n"
                        "Примеры: 192.168.0.0/24, 10.20.76.112/28, 192.168.0.10-20, 192.168.0.5")
            return None

    def _poll_host(self, ip: str, cfg: dict, alternates=()) -> Device:
        """Poll one device with the selected transport. When nothing answers on `ip`,
        the device's other own addresses (`alternates`, see core.connect_candidates:
        never client addresses) are tried in turn."""
        if cfg["cmdtype"] == "SSH":
            from ssh_client import scan_host_ssh

            def poll(host: str) -> Device:
                return scan_host_ssh(host, cfg["user"], cfg["password"], port=cfg["ssh_port"],
                                     timeout=cfg["timeout"], retries=cfg["retries"],
                                     logger=self.logger)
        else:
            def poll(host: str) -> Device:
                return core.scan_host(host, cfg["user"], cfg["password"], cfg["api_ssl_port"],
                                      plain_port=8728, timeout=cfg["timeout"], retries=cfg["retries"],
                                      logger=self.logger)
        hosts = [ip] + [h for h in alternates if h != ip]
        for i, host in enumerate(hosts):
            try:
                return poll(host)
            except Exception as exc:  # noqa: BLE001
                if i + 1 < len(hosts) and core.is_unreachable(exc):
                    self.log(f"{host}: не отвечает ({exc}); пробую другой адрес устройства {hosts[i + 1]}")
                    continue
                raise
        raise RuntimeError("нет адресов для подключения")

    def _start_scan(self, targets: list[str], kind: str, alternatives: dict | None = None) -> None:
        alternatives = alternatives or {}
        self._maybe_save_settings()
        cfg = self._read_config()
        self._baselines = {}
        found: list[Device] = []
        # only addresses of devices already in the table need a red status when they fail
        known = {a for d in self.devices.values() for a in (d.ip, d.reach_ip)}
        known_keys = set(self.devices)                  # to tell new devices from refreshed ones
        known_ips = {d.ip for d in self.devices.values()}
        new_keys: set = set()

        def scan_one(ip: str) -> bool:
            try:
                dev = self._poll_host(ip, cfg, alternatives.get(ip, ()))
                dev.last_seen = datetime.now().strftime(TIME_FORMAT)
                self._ping_device(dev)
                self.log(f"{ip}: найдено {dev.identity or dev.board_name or 'RouterOS'} "
                         f"[{dev.status}]")
                self.ui_queue.put(("device", dev))  # show it right away
                found.append(dev)
                key = dev.key or dev.ip
                if key not in known_keys and dev.ip not in known_ips:
                    new_keys.add(key)
                return True
            except Exception as exc:  # noqa: BLE001 - report every failure
                self.log(f"{ip}: {type(exc).__name__}: {exc}")
                if ip in known:   # a device already in the table must not keep a stale "OK"
                    self.ui_queue.put(("status_ip", (ip, f"Ошибка: {type(exc).__name__}: {exc}", True)))
                return False

        def finish(job: dict) -> None:
            job["new"] = len(new_keys)
            self.ui_queue.put(("done", dedupe_devices(found)))

        scanning = kind != "Обновление"
        transport = (f"SSH {cfg['ssh_port']}" if cfg["cmdtype"] == "SSH" else
                     f"API-SSL {cfg['api_ssl_port']} (обычный API 8728 — если порт закрыт)")
        self.log(f"{kind}: адресов {len(targets)}, потоков {cfg['threads']}, "
                 f"таймаут {cfg['timeout']:g} с, повторов {cfg['retries']}, {transport}.")
        self._start_job("Сканирование" if scanning else "Обновление", targets, scan_one, cfg["threads"],
                        ok_label="найдено", on_finish=finish,
                        extra={"new": 0} if scanning else None)

    def _scan_finished(self, deduped: list[Device]) -> None:
        for dev in deduped:
            self._upsert_device(dev)
        job = self._job
        text = f"Готово: найдено устройств — {len(deduped)}"
        if job is not None and "new" in job:
            text += f", из них новых в таблице: {job['new']}"
        self._write_log(text + ".")
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
            messagebox.showinfo("Отправить", "Отметьте галочками одно или несколько устройств в таблице.")
            return
        command = self.txt_command.get("1.0", END).strip()
        if not command:
            messagebox.showinfo("Отправить", "Введите команду на одной из вкладок «Команда 1–10».")
            return
        cfg = self._read_config()
        if cfg["cmdtype"] != "SSH":
            # nothing is converted: every line must already be an API command. Check it
            # before connecting anywhere, so a typo does not hit all the devices.
            try:
                for line in command.splitlines():
                    split_api_line(line)
            except ValueError as exc:
                messagebox.showerror("Отправить", str(exc))
                return
        self.notebook.select(len(self.command_editors))  # show output tab
        self.log(f"Отправка ({cfg['cmdtype']}, «Команда {self.active_command + 1}»): устройств {len(devices)}, "
                 f"одновременно {self._ops_threads(cfg)}")
        self._save_commands()
        self._start_job("Команды", devices, lambda dev: self._send_one(dev, command, cfg),
                        self._ops_threads(cfg), ok_label="успешно", bad_label="ошибок")

    def _send_one(self, dev: Device, command: str, cfg: dict) -> bool:
        iid = dev.key or dev.ip
        try:
            if cfg["cmdtype"] == "SSH":
                from ssh_client import run_ssh_command
                out = self._try_addresses(dev, lambda host: run_ssh_command(
                    host, cfg["user"], cfg["password"], command,
                    port=cfg["ssh_port"], timeout=cfg["timeout"], retries=cfg["retries"],
                ))
            else:
                out = self._run_api_commands(dev, command, cfg)
            self.log(f"--- {dev.ip} ({dev.identity}) через {self._via(dev, cfg)} ---\n{out}")
            self._ping_device(dev)
            self.ui_queue.put(("status", (iid, "Команда выполнена", False)))
            self.ui_queue.put(("row", iid))
            return True
        except Exception as exc:  # noqa: BLE001
            self.log(f"{dev.ip} (через {self._via(dev, cfg)}): ошибка команды: "
                     f"{type(exc).__name__}: {exc}")
            self.ui_queue.put(("status", (iid, f"Ошибка команды: {exc}", True)))
            return False

    @staticmethod
    def _via(dev: Device, cfg: dict) -> str:
        if cfg["cmdtype"] == "SSH":
            return f"SSH {dev.reach_ip}:{cfg['ssh_port']}"
        return f"API {dev.reach_ip}:{dev.api_port or cfg['api_ssl_port']}"

    def _run_api_commands(self, dev: Device, command: str, cfg: dict) -> str:
        """Each line is one API sentence, sent exactly as typed (no conversion)."""
        sentences = [(line.strip(), split_api_line(line)) for line in command.splitlines() if line.strip()]
        api = self._open_api(dev, cfg)
        chunks = []
        try:
            for line, words in sentences:
                rows = api.talk(words)
                chunks.append(f"$ {line}")
                for row in rows:
                    chunks.append("  " + ", ".join(f"{k}={v}" for k, v in row.items()))
        finally:
            api.close()
        return "\n".join(chunks) if chunks else "(нет вывода)"

    # ------------------------------------------------------------- backup
    def on_backup(self) -> None:
        if self._busy():
            return
        devices = self.selected_devices()
        if not devices:
            messagebox.showinfo("Бэкап", "Отметьте галочками одно или несколько устройств для бэкапа.")
            return
        cfg = self._read_config()
        os.makedirs(BACKUP_DIR, exist_ok=True)
        self.log(f"Бэкап ({cfg['cmdtype']}): устройств {len(devices)}, одновременно {self._ops_threads(cfg)}")
        self._start_job("Бэкап", devices, lambda dev: self._backup_one(dev, cfg),
                        self._ops_threads(cfg), ok_label="успешно", bad_label="ошибок")

    def _backup_one(self, dev: Device, cfg: dict) -> bool:
        iid = dev.key or dev.ip
        try:
            if cfg["cmdtype"] == "SSH":
                text = self._ssh_export(dev, cfg)
            else:
                try:
                    api = self._open_api(dev, cfg)
                    try:
                        text = core.fetch_export(api, logger=self.logger)
                    finally:
                        api.close()
                except core.ExportTooLarge as exc:
                    # old RouterOS can't hand big configs over the API
                    self.log(f"{dev.ip}: {exc}; пробую по SSH (порт {cfg['ssh_port']})")
                    text = self._ssh_export(dev, cfg)
            fname = backup_filename(dev.ip, dev.identity)
            path = os.path.join(BACKUP_DIR, fname)
            moved = core.archive_backups(BACKUP_DIR, dev.ip)   # the previous ones go to Backups/Old
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            dev.last_backup = datetime.now().strftime(TIME_FORMAT)
            dev.changes = ""   # the backup has saved them: the device is no longer «changed»
            self._ping_device(dev)
            self.log(f"{dev.ip}: бэкап сохранён -> Backups/{fname}"
                     + (f"; прежних бэкапов перенесено в Backups/Old: {len(moved)}" if moved else ""))
            self.ui_queue.put(("status", (iid, f"Бэкап: {fname}", False)))
            self.ui_queue.put(("row", iid))  # shows the new Last Backup time
            return True
        except Exception as exc:  # noqa: BLE001
            self.log(f"{dev.ip} (через {self._via(dev, cfg)}): не удалось сделать бэкап: "
                     f"{type(exc).__name__}: {exc}")
            self.ui_queue.put(("status", (iid, f"Ошибка бэкапа: {exc}", True)))
            return False

    def _try_addresses(self, dev: Device, action):
        """Run action(host) on the device's main / connection address, then on its
        other own addresses while nothing answers (never on client addresses).
        Remembers the address that worked as the connection address."""
        hosts = core.connect_candidates(dev) or [dev.reach_ip]
        for i, host in enumerate(hosts):
            try:
                result = action(host)
                dev.connect_ip = host
                return result
            except Exception as exc:  # noqa: BLE001
                if i + 1 < len(hosts) and core.is_unreachable(exc):
                    self.log(f"{dev.ip}: {host} не отвечает ({exc}); пробую {hosts[i + 1]}")
                    continue
                raise

    def _open_api(self, dev: Device, cfg: dict):
        def connect(host: str):
            return core.open_device_api(dataclasses.replace(dev, connect_ip=host), cfg["user"],
                                        cfg["password"], cfg["api_ssl_port"],
                                        timeout=cfg["timeout"], logger=self.logger)
        return self._try_addresses(dev, connect)

    def _ssh_export(self, dev: Device, cfg: dict) -> str:
        from ssh_client import export_config
        return self._try_addresses(dev, lambda host: export_config(
            host, cfg["user"], cfg["password"],
            port=cfg["ssh_port"], timeout=max(cfg["timeout"], 20.0), retries=cfg["retries"],
        ))

    # ------------------------------------------------------------- delete
    def on_delete(self) -> None:
        """Remove the ticked devices that are shown from the table (not from the network)."""
        if self._busy():
            return
        iids = self.selected_iids()
        if not iids:
            messagebox.showinfo("Удалить", "Отметьте галочками устройства, которые нужно удалить из таблицы.")
            return
        hidden_ticked = sum(1 for i in self.checked if i in self._hidden and i in self.devices)
        text = (f"Удалить из таблицы отмеченные устройства: {len(iids)}?\n\n"
                "Удаляются строки таблицы и их запись в сохранённом списке, "
                "а бэкапы этих устройств переносятся в папку Backups/Old. "
                "Сами устройства не затрагиваются.\n"
                "Вернуть строки можно новым сканом или импортом CSV.")
        if hidden_ticked:
            text += f"\n\nОтмеченные, но скрытые фильтром устройства ({hidden_ticked}) не затрагиваются."
        if not messagebox.askyesno("Удалить", text, icon="warning", default="no"):
            return
        archived = 0
        for iid in iids:
            if self.tree.exists(iid):
                self.tree.delete(iid)
            dev = self.devices.pop(iid, None)
            if dev is not None and dev.ip:
                try:
                    archived += len(core.archive_backups(BACKUP_DIR, dev.ip))
                except OSError as exc:
                    self.log(f"{dev.ip}: не удалось перенести бэкапы в Backups/Old: {exc}")
            self.checked.discard(iid)
            self._hidden.discard(iid)
        self._anchor = None
        self._sync_header()
        self._counts_dirty = self._models_dirty = True
        self._save_devices()
        self.log(f"Удалено из таблицы устройств: {len(iids)}."
                 + (f" Бэкапов перенесено в Backups/Old: {archived}." if archived else ""))

    # ---------------------------------------------------------- import/exp
    def on_export(self) -> None:
        if not self.devices or len(self._hidden) == len(self.devices):
            messagebox.showinfo("Экспорт", "Нечего экспортировать.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")], title="Экспорт результатов"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            # "IP подключения" = the address the router actually answered on during the
            # scan, so imported rows can still be backed up / sent commands
            # (the IP column shows the bridge1 address, which may be unroutable).
            writer = csv.DictWriter(
                fh, fieldnames=[HEADINGS[c] for c in DATA_COLUMNS] + [MGMT_HEADING],
                delimiter=CSV_DELIMITER,
            )
            writer.writeheader()
            rows = [self.devices[i] for i in self.tree.get_children("") if i in self.devices]
            for dev in rows:
                values = dev.as_row()
                writer.writerow({**{HEADINGS[c]: values[c] for c in DATA_COLUMNS},
                                 MGMT_HEADING: dev.reach_ip})
        note = f" (включён фильтр, всего в таблице {len(self.devices)})" if self._hidden else ""
        self.log(f"Экспортировано строк: {len(rows)}{note} -> {path}")

    def on_import(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("CSV", "*.csv")], title="Импорт результатов"
        )
        if not path:
            return
        with open(path, newline="", encoding="utf-8-sig") as fh:
            header = fh.readline()
            fh.seek(0)
            counts = {d: header.count(d) for d in (";", ",", "\t")}
            delim = max(counts, key=counts.get) if any(counts.values()) else CSV_DELIMITER
            reader = csv.DictReader(fh, delimiter=delim)
            # the current Russian headers, the key names and the older English ones all work
            columns = {name: CSV_ALIASES.get((name or "").strip()) for name in (reader.fieldnames or [])}
            count = 0
            for row in reader:
                values = {key: (row.get(name) or "").strip() for name, key in columns.items() if key}
                status = values.get("Status", "")
                dev = Device(
                    ip=values.get("IP", ""),
                    identity=values.get("Identity", ""),
                    board_name=values.get("Board Name", ""),
                    routeros=values.get("RouterOS", ""),
                    license=values.get("License", ""),
                    last_seen=values.get("Last seen", ""),
                    last_backup=values.get("Last Backup", ""),
                    status=status,
                    failed=core.looks_like_error(status),
                    note=values.get("Note", ""),
                    key=values.get("IP", ""),
                    connect_ip=values.get("Mgmt IP", ""),
                )
                if not dev.ip:
                    continue
                self._upsert_device(dev)
                count += 1
        self._seed_last_backup()
        self._relayout()
        self._save_devices()
        self.log(f"Импортировано строк: {count} из {path}")

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
                self.tree.item(iid, tags=self._row_tags(dev))
                self._apply_visibility(iid)

    def _save_devices(self) -> None:
        try:
            rows = [dataclasses.asdict(d) for d in self.devices.values()]
            tmp = DEVICES_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=1)
            os.replace(tmp, DEVICES_FILE)  # a crash mid-write must not destroy the cache
            self._last_cache_save = time.monotonic()
        except (OSError, TypeError) as exc:
            self.log(f"Не удалось сохранить список устройств: {exc}")

    def _load_devices(self) -> None:
        if not os.path.exists(DEVICES_FILE):
            return
        try:
            with open(DEVICES_FILE, encoding="utf-8") as fh:
                rows = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self._write_log(f"Не удалось прочитать devices.json ({exc}); таблица пуста.")
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
            self._write_log(f"Загружено устройств с прошлого раза: {loaded}. "
                            f"«Обновить» — обновить данные, «Новый скан» — начать заново.")

    def on_save_log(self) -> None:
        import shutil
        for handler in self.logger.handlers:
            handler.flush()
        dest = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=os.path.basename(self.log_path),
            filetypes=[("Лог", "*.log"), ("Все файлы", "*.*")],
            title="Сохранить лог для отладки",
        )
        if not dest:
            return
        try:
            shutil.copyfile(self.log_path, dest)
            messagebox.showinfo("Лог", f"Лог сохранён:\n{dest}\n\nЭтот файл можно прислать для разбора проблемы.")
        except OSError as exc:
            messagebox.showerror("Лог", f"Не удалось сохранить лог: {exc}")

    # ------------------------------------------------------------ settings
    def _maybe_save_settings(self) -> None:
        if self.var_save.get():
            self._save_settings()
        elif os.path.exists(SETTINGS_FILE):
            # Save was unticked: forget the stored settings (incl. password)
            try:
                os.remove(SETTINGS_FILE)
            except OSError as exc:
                self.log(f"Не удалось удалить сохранённые настройки: {exc}")

    def _save_settings(self) -> None:
        self._command_tab_changed()
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
            "save": True,
        })
        # the command drafts live in commands.json now (kept even without «Запомнить настройки»)
        for key in ("command", "commands", "active_command"):
            data.pop(key, None)
        self._save_commands()
        # Password is stored only when Save is ticked; base64 is obfuscation,
        # not encryption — the file is local to the operator's machine.
        data["password"] = base64.b64encode(self.var_pass.get().encode()).decode()
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            self.log(f"Не удалось сохранить настройки: {exc}")

    def _load_settings(self) -> None:
        data = {}
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
        if not isinstance(data, dict):
            data = {}
        self._load_commands(data)
        if not data:
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

    # ---- the 10 command drafts: commands.json, saved always (no password in it)
    def _save_commands(self) -> None:
        self._command_tab_changed()
        data = {"commands": [editor.get("1.0", "end-1c") for editor in self.command_editors],
                "active_command": self.active_command}
        try:
            tmp = COMMANDS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, COMMANDS_FILE)
        except OSError as exc:
            self.log(f"Не удалось сохранить тексты команд: {exc}")

    def _load_commands(self, legacy: dict | None = None) -> None:
        """Drafts from commands.json; without it, from an older settings.json
        (its ten "commands", or the single "command" of earlier versions)."""
        data = None
        try:
            with open(COMMANDS_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
        if not isinstance(data, dict):
            data = legacy or {}
            if not isinstance(data.get("commands"), list) and not data.get("command"):
                return   # nothing saved anywhere: keep the tabs as they are
        commands = data.get("commands")
        if not isinstance(commands, list):
            commands = [data.get("command", "")]
        for i, editor in enumerate(self.command_editors):
            editor.delete("1.0", END)
            if i < len(commands) and isinstance(commands[i], str):
                editor.insert("1.0", commands[i])
        active = data.get("active_command", 0)
        self.active_command = (active if isinstance(active, int) and not isinstance(active, bool)
                               and 0 <= active < len(self.command_editors) else 0)
        self.notebook.select(self.active_command)

    def _on_close(self) -> None:
        self.stop_event.set()
        for job in (self._after_id, self._search_job):
            try:
                if job is not None:
                    self.root.after_cancel(job)
            except (tk.TclError, AttributeError):
                pass
        self._maybe_save_settings()
        self._save_commands()
        self._save_devices()  # persist statuses (backups/commands) too
        self._save_ui_state()
        self.root.destroy()


def main() -> None:
    root = Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
