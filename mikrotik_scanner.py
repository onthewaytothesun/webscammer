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
import json
import os
import queue
import threading
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
from tkinter import ttk

import core
from applog import setup_logging
from core import Device, backup_filename, dedupe_devices, expand_targets, parse_cli_to_api

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
BACKUP_DIR = os.path.join(APP_DIR, "Backups")

COLUMNS = ("IP", "Identity", "Board Name", "RouterOS", "License", "Last seen", "Status")
CHECK_ON = "☑"   # ☑
CHECK_OFF = "☐"  # ☐


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
        self.var_threads = StringVar(value="30")
        self.var_timeout = StringVar(value="10")
        self.var_retries = StringVar(value="2")
        self.var_cmdtype = StringVar(value="API/SSL")
        self.var_save = BooleanVar(value=False)
        self.var_find = StringVar()

        self._build_ui()
        self._load_settings()
        self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        form = ttk.Frame(self.root, padding=6)
        form.pack(fill=X)

        def field(parent, label, var, width, show=None):
            ttk.Label(parent, text=label).pack(side=LEFT, padx=(4, 2))
            e = ttk.Entry(parent, textvariable=var, width=width, show=show)
            e.pack(side=LEFT)
            return e

        field(form, "Username:", self.var_user, 12)
        field(form, "Password:", self.var_pass, 12, show="*")
        field(form, "Network:", self.var_network, 18)
        field(form, "API-SSL:", self.var_api_port, 6)
        field(form, "SSH:", self.var_ssh_port, 6)
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
        nb.add(cmd_frame, text="Command")

        out_frame = ttk.Frame(nb)
        self.txt_output = ScrolledText(out_frame, height=8, wrap="word", state="disabled")
        self.txt_output.pack(fill=BOTH, expand=True)
        nb.add(out_frame, text="Output / Log")
        self.notebook = nb

        # progress bar
        self.progress = ttk.Progressbar(self.root, orient=HORIZONTAL, mode="determinate")
        self.progress.pack(fill=X, padx=6, pady=2)

        # table
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=BOTH, expand=True, padx=6, pady=2)
        cols = ("check",) + COLUMNS
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="none")
        self.tree.heading("check", text=CHECK_OFF, command=self.toggle_all)
        self.tree.column("check", width=34, anchor="center", stretch=False)
        for col in COLUMNS:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=150, anchor="w")
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
        ttk.Entry(bottom, textvariable=self.var_find, width=30).pack(side=LEFT)
        ttk.Button(bottom, text="Find", command=self.on_find).pack(side=LEFT, padx=4)
        ttk.Button(bottom, text="Save Log", command=self.on_save_log).pack(side=LEFT, padx=8)
        ttk.Label(bottom, text=f"Log: logs/{os.path.basename(self.log_path)}",
                  foreground="#666").pack(side=LEFT)
        ttk.Button(bottom, text="Export", command=self.on_export).pack(side=RIGHT, padx=2)
        ttk.Button(bottom, text="Import", command=self.on_import).pack(side=RIGHT, padx=2)

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
        self.txt_output.configure(state="normal")
        self.txt_output.insert(END, f"[{stamp}] {message}\n")
        self.txt_output.see(END)
        self.txt_output.configure(state="disabled")

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
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
                elif kind == "done":
                    self._scan_finished(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

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
        values = (CHECK_ON if iid in self.checked else CHECK_OFF,) + tuple(
            dev.as_row()[c] for c in COLUMNS
        )
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
        if col != "#1":  # checkbox column
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid in self.checked:
            self.checked.discard(iid)
            self.tree.set(iid, "check", CHECK_OFF)
        else:
            self.checked.add(iid)
            self.tree.set(iid, "check", CHECK_ON)

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
            "cmdtype": self.var_cmdtype.get(),
            "timeout": timeout,
            "retries": retries,
        }

    # ---------------------------------------------------------------- scan
    def on_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Scan", "A scan is already running.")
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
                    out = run_ssh_command(
                        dev.reach_ip, cfg["user"], cfg["password"], command,
                        port=cfg["ssh_port"], timeout=cfg["timeout"],
                    )
                else:
                    out = self._run_api_commands(dev, command, cfg)
                self.log(f"--- {dev.ip} ({dev.identity}) via {cfg['cmdtype']} "
                         f"{dev.reach_ip} ---\n{out}")
                self.ui_queue.put(("status", (iid, "Command OK")))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{dev.ip} (via {cfg['cmdtype']} {dev.reach_ip}): command failed: "
                         f"{type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Command error: {exc}")))

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
                    from ssh_client import export_config
                    text = export_config(
                        dev.reach_ip, cfg["user"], cfg["password"],
                        port=cfg["ssh_port"], timeout=max(cfg["timeout"], 20.0),
                    )
                else:
                    api = core.open_device_api(
                        dev, cfg["user"], cfg["password"], cfg["api_ssl_port"],
                        timeout=cfg["timeout"], logger=self.logger,
                    )
                    try:
                        text = core.fetch_export(api, logger=self.logger)
                    finally:
                        api.close()
                fname = backup_filename(dev.ip, dev.identity)
                path = os.path.join(BACKUP_DIR, fname)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                self.log(f"{dev.ip}: backup saved -> Backups/{fname}")
                self.ui_queue.put(("status", (iid, f"Backup: {fname}")))
            except Exception as exc:  # noqa: BLE001
                self.log(f"{dev.ip} (via {cfg['cmdtype']} {dev.reach_ip}): backup failed: "
                         f"{type(exc).__name__}: {exc}")
                self.ui_queue.put(("status", (iid, f"Backup error: {exc}")))

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
        with open(path, "w", newline="", encoding="utf-8") as fh:
            # "Mgmt IP" = the address the router actually answers on, so an
            # imported list can still be backed up / sent commands
            writer = csv.DictWriter(fh, fieldnames=COLUMNS + ("Mgmt IP",))
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
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
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
        self.log(f"Imported {count} row(s) from {path}")

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
        data = {
            "user": self.var_user.get(),
            "network": self.var_network.get(),
            "api_port": self.var_api_port.get(),
            "threads": self.var_threads.get(),
            "ssh_port": self.var_ssh_port.get(),
            "cmdtype": self.var_cmdtype.get(),
            "timeout": self.var_timeout.get(),
            "retries": self.var_retries.get(),
            "command": self.txt_command.get("1.0", END).rstrip(),
            "save": True,
        }
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
        self.root.destroy()


def main() -> None:
    root = Tk()
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
