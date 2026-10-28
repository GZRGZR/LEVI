"""PC Slow Watch: local-only Windows performance logger with privacy-preserving exports."""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import time
import zipfile
from collections import Counter, deque
from pathlib import Path
from typing import Any
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import psutil
except ImportError:
    psutil = None

APP_NAME = "PC Slow Watch"
APP_VERSION = "0.2.0"
SAMPLE_INTERVAL_DEFAULT = 5
RETENTION_DAYS = 30
EXPORT_DAYS = 7
ALERT_COOLDOWN_SECONDS = 60
HISTORY_POINTS = 90

CATEGORIES = (
    "browser", "security", "sync_backup", "search_indexing",
    "development", "communication", "windows_system", "other",
)
CATEGORY_LABELS = {
    "browser": "דפדפנים",
    "security": "אבטחה",
    "sync_backup": "סנכרון/גיבוי",
    "search_indexing": "חיפוש/אינדוקס",
    "development": "פיתוח",
    "communication": "תקשורת",
    "windows_system": "רכיבי Windows",
    "other": "תוכנות אחרות",
}

METRIC_FIELDS = [
    "timestamp", "cpu_pct", "ram_pct", "ram_used_mb", "ram_available_mb",
    "swap_pct", "disk_read_mb_s", "disk_write_mb_s", "disk_busy_pct_est",
    "disk_read_latency_ms", "disk_write_latency_ms", "network_recv_mb_s",
    "network_sent_mb_s", "system_drive_free_pct", "uptime_hours",
    "top_cpu_category", "top_ram_category",
] + [f"proc_{cat}_{metric}" for cat in CATEGORIES for metric in ("cpu_pct", "ram_mb")]
EVENT_FIELDS = [
    "timestamp", "kind", "details", "cpu_pct", "ram_pct", "disk_busy_pct_est",
    "disk_read_latency_ms", "disk_write_latency_ms", "network_recv_mb_s",
    "network_sent_mb_s", "top_cpu_category", "top_ram_category",
]
PROCESS_FIELDS = ["timestamp", "program", "category", "cpu_pct", "ram_mb", "read_mb_s", "write_mb_s", "threads", "instances"]
BROWSER_FIELDS = ["sample_id", "timestamp", "tab_ref", "site_label", "site_category", "mail_thread_id", "visible", "resource_count", "transfer_kb", "long_task_count", "long_task_ms", "js_heap_mb", "dom_nodes", "load_ms"]
BROWSER_CATEGORIES = {"banking", "email", "shopping", "video", "social", "news", "development", "search", "other"}


def data_dir() -> Path:
    """Return a private per-user local data directory, never exported as metadata."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "PCSlowWatch"
    return Path.home() / ".pcslowwatch"


def today_key(value: dt.datetime | None = None) -> str:
    return (value or dt.datetime.now()).strftime("%Y-%m-%d")


def safe_category(process_name: str | None) -> str:
    """Map a process name to a broad category; raw names are never persisted or displayed."""
    name = (process_name or "").lower()
    groups = {
        "browser": ("chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "browser"),
        "security": ("msmpeng", "antimalware", "defender", "avast", "avg", "kaspersky", "eset", "bitdefender", "sentinel"),
        "sync_backup": ("onedrive", "dropbox", "googledrive", "drivefs", "syncthing", "backup", "sync"),
        "search_indexing": ("searchindexer", "searchhost", "everything", "indexer"),
        "development": ("code.exe", "devenv", "pycharm", "idea64", "node.exe", "python", "java.exe", "dotnet", "git.exe"),
        "communication": ("teams", "zoom", "slack", "discord", "telegram", "whatsapp", "outlook"),
        "windows_system": ("system", "registry", "svchost", "dwm.exe", "explorer.exe", "csrss", "services.exe", "lsass", "wininit", "winlogon", "fontdrvhost", "smss", "spoolsv", "runtimebroker", "sihost"),
    }
    for category, needles in groups.items():
        if any(needle in name for needle in needles):
            return category
    return "other"


def safe_program_name(value: str | None) -> str:
    """Keep an executable basename only; never persist paths, PID, or command line."""
    raw = (value or "").replace("\\", "/").split("/")[-1].strip()
    raw = re.sub(r"[^A-Za-z0-9._() -]", "", raw)[:80]
    return raw or "unknown-program"


def sanitize_browser_sample(sample: Any) -> dict[str, Any] | None:
    if not isinstance(sample, dict):
        return None
    timestamp = sample.get("timestamp")
    if not isinstance(timestamp, str) or len(timestamp) > 45:
        return None
    try:
        parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if not parsed.tzinfo:
        parsed = parsed.astimezone()
    if parsed > dt.datetime.now().astimezone() + dt.timedelta(days=1):
        return None
    site = sample.get("site_label", "")
    if not isinstance(site, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,100}", site):
        return None
    category = sample.get("site_category", "other")
    if not isinstance(category, str) or category not in BROWSER_CATEGORIES:
        category = "other"
    sample_id = sample.get("sample_id", "")
    if not isinstance(sample_id, str) or not re.fullmatch(r"[A-Fa-f0-9-]{8,64}", sample_id):
        sample_id = ""
    tab_ref = sample.get("tab_ref", "")
    if not isinstance(tab_ref, str) or not re.fullmatch(r"[A-Fa-f0-9-]{8,64}", tab_ref):
        tab_ref = ""
    thread_id = sample.get("mail_thread_id", "")
    if category != "email" or not isinstance(thread_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", thread_id):
        thread_id = ""
    def num(key: str, integer: bool = False, maximum: float = 1_000_000) -> int | float:
        try:
            val = float(sample.get(key, 0))
            if not (val >= 0 and val <= maximum):
                val = 0
        except (TypeError, ValueError):
            val = 0
        return int(val) if integer else round(val, 2)
    return {
        "sample_id": sample_id,
        "timestamp": parsed.astimezone().isoformat(timespec="seconds"),
        "tab_ref": tab_ref, "site_label": site.lower(), "site_category": category,
        "mail_thread_id": thread_id, "visible": sample.get("visible", False) is True,
        "resource_count": num("resource_count", True, 100_000),
        "transfer_kb": num("transfer_kb", False, 10_000_000),
        "long_task_count": num("long_task_count", True, 100_000),
        "long_task_ms": num("long_task_ms", False, 86_400_000),
        "js_heap_mb": num("js_heap_mb", False, 100_000),
        "dom_nodes": num("dom_nodes", True, 10_000_000),
        "load_ms": num("load_ms", False, 86_400_000),
    }


def pct(value: Any) -> float:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return 0.0


def read_csv_rows(paths: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(paths):
        try:
            with path.open("r", newline="", encoding="utf-8-sig") as f:
                rows.extend(dict(row) for row in csv.DictReader(f))
        except (OSError, csv.Error):
            continue
    return rows


class Collector:
    """Sample system and aggregate executable performance without storing PIDs."""
    def __init__(self) -> None:
        if psutil is None:
            raise RuntimeError("חסרה ספריית psutil. התקן לפי README.md")
        self.cpu_count = psutil.cpu_count(logical=True) or 1
        self.previous_disk: Any = psutil.disk_io_counters()
        self.previous_net: Any = psutil.net_io_counters()
        self.previous_time = time.monotonic()
        self.boot_time = psutil.boot_time()
        self.previous_proc = self._capture_process_baseline()
        self.last_process_rows: list[dict[str, Any]] = []
        psutil.cpu_percent(interval=None)
        self.previous_time = time.monotonic()

    def _capture_process_baseline(self) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_times", "io_counters"]):
            try:
                info = proc.info
                times = info.get("cpu_times")
                if times is None:
                    continue
                io = info.get("io_counters")
                result[int(info["pid"])] = {
                    "cpu_s": float(times.user + times.system),
                    "read_bytes": int(getattr(io, "read_bytes", 0) or 0),
                    "write_bytes": int(getattr(io, "write_bytes", 0) or 0),
                }
            except (psutil.Error, AttributeError, TypeError, ValueError, KeyError):
                continue
        return result

    def _process_usage(self, elapsed: float) -> dict[str, tuple[float, float]]:
        cat_cpu: dict[str, float] = {c: 0.0 for c in CATEGORIES}
        cat_ram: dict[str, float] = {c: 0.0 for c in CATEGORIES}
        current: dict[int, dict[str, Any]] = {}
        grouped: dict[str, dict[str, Any]] = {}
        divisor = max(0.25, elapsed) * self.cpu_count
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_times", "memory_info", "io_counters", "num_threads"]):
            try:
                info = proc.info
                pid = int(info["pid"])
                program = safe_program_name(info.get("name"))
                category = safe_category(program)
                times, io, mem = info.get("cpu_times"), info.get("io_counters"), info.get("memory_info")
                cpu_s = float(times.user + times.system) if times is not None else 0.0
                read_bytes = int(getattr(io, "read_bytes", 0) or 0)
                write_bytes = int(getattr(io, "write_bytes", 0) or 0)
                old = self.previous_proc.get(pid)
                cpu_pct = read_mb_s = write_mb_s = 0.0
                if old:
                    cpu_pct = max(0.0, cpu_s - old["cpu_s"]) / divisor * 100
                    read_mb_s = max(0, read_bytes - old["read_bytes"]) / max(0.25, elapsed) / (1024 * 1024)
                    write_mb_s = max(0, write_bytes - old["write_bytes"]) / max(0.25, elapsed) / (1024 * 1024)
                ram_mb = float(mem.rss) / (1024 * 1024) if mem else 0.0
                current[pid] = {"cpu_s": cpu_s, "read_bytes": read_bytes, "write_bytes": write_bytes}
                cat_cpu[category] += cpu_pct
                cat_ram[category] += ram_mb
                row = grouped.setdefault(program, {"program": program, "category": category, "cpu_pct": 0.0, "ram_mb": 0.0, "read_mb_s": 0.0, "write_mb_s": 0.0, "threads": 0, "instances": 0})
                row["cpu_pct"] += cpu_pct
                row["ram_mb"] += ram_mb
                row["read_mb_s"] += read_mb_s
                row["write_mb_s"] += write_mb_s
                row["threads"] += int(info.get("num_threads") or 0)
                row["instances"] += 1
            except (psutil.Error, AttributeError, TypeError, ValueError, KeyError):
                continue
        self.previous_proc = current
        names: set[str] = set()
        rows = list(grouped.values())
        for metric in ("cpu_pct", "ram_mb", "read_mb_s", "write_mb_s"):
            names.update(r["program"] for r in sorted(rows, key=lambda x: x[metric], reverse=True)[:12])
        names.update(r["program"] for r in rows if r["cpu_pct"] >= 0.5 or r["ram_mb"] >= 75 or r["read_mb_s"] >= 0.25 or r["write_mb_s"] >= 0.25)
        rows = [r for r in rows if r["program"] in names]
        rows.sort(key=lambda r: max(r["cpu_pct"], r["ram_mb"] / 16, r["read_mb_s"] * 10, r["write_mb_s"] * 10), reverse=True)
        self.last_process_rows = [
            {"program": r["program"], "category": r["category"], "cpu_pct": round(r["cpu_pct"], 2),
             "ram_mb": round(r["ram_mb"], 1), "read_mb_s": round(r["read_mb_s"], 3),
             "write_mb_s": round(r["write_mb_s"], 3), "threads": r["threads"], "instances": r["instances"]}
            for r in rows[:50]
        ]
        return {c: (round(cat_cpu[c], 1), round(cat_ram[c], 1)) for c in CATEGORIES}

    @staticmethod
    def _disk_usage_pct() -> float:
        drive = os.environ.get("SystemDrive", "C:")
        try:
            usage = psutil.disk_usage(drive + "\\" if not drive.endswith("\\") else drive)
            return round(100.0 - usage.percent, 1)
        except (OSError, AttributeError):
            return 0.0

    def sample(self) -> dict[str, Any]:
        now = time.monotonic()
        elapsed = max(0.25, now - self.previous_time)
        self.previous_time = now
        cpu, vm, swap = pct(psutil.cpu_percent(interval=None)), psutil.virtual_memory(), psutil.swap_memory()
        disk, net = psutil.disk_io_counters(), psutil.net_io_counters()
        read_mb_s = write_mb_s = busy_pct = read_latency = write_latency = 0.0
        if disk is not None and self.previous_disk is not None:
            read_mb_s = max(0.0, disk.read_bytes - self.previous_disk.read_bytes) / elapsed / (1024 * 1024)
            write_mb_s = max(0.0, disk.write_bytes - self.previous_disk.write_bytes) / elapsed / (1024 * 1024)
            r_ops = max(0, disk.read_count - self.previous_disk.read_count)
            w_ops = max(0, disk.write_count - self.previous_disk.write_count)
            r_ms = max(0, getattr(disk, "read_time", 0) - getattr(self.previous_disk, "read_time", 0))
            w_ms = max(0, getattr(disk, "write_time", 0) - getattr(self.previous_disk, "write_time", 0))
            if r_ops: read_latency = r_ms / r_ops
            if w_ops: write_latency = w_ms / w_ops
            busy_pct = min(100.0, (r_ms + w_ms) / (elapsed * 1000) * 100)
        self.previous_disk = disk
        recv_mb_s = sent_mb_s = 0.0
        if net is not None and self.previous_net is not None:
            recv_mb_s = max(0.0, net.bytes_recv - self.previous_net.bytes_recv) / elapsed / (1024 * 1024)
            sent_mb_s = max(0.0, net.bytes_sent - self.previous_net.bytes_sent) / elapsed / (1024 * 1024)
        self.previous_net = net
        cats = self._process_usage(elapsed)
        top_cpu = max(cats, key=lambda k: cats[k][0])
        top_ram = max(cats, key=lambda k: cats[k][1])
        result: dict[str, Any] = {
            "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "cpu_pct": round(cpu, 1), "ram_pct": round(vm.percent, 1),
            "ram_used_mb": round(vm.used / (1024 * 1024), 1), "ram_available_mb": round(vm.available / (1024 * 1024), 1),
            "swap_pct": round(swap.percent, 1), "disk_read_mb_s": round(read_mb_s, 3), "disk_write_mb_s": round(write_mb_s, 3),
            "disk_busy_pct_est": round(busy_pct, 1), "disk_read_latency_ms": round(read_latency, 1), "disk_write_latency_ms": round(write_latency, 1),
            "network_recv_mb_s": round(recv_mb_s, 3), "network_sent_mb_s": round(sent_mb_s, 3),
            "system_drive_free_pct": self._disk_usage_pct(), "uptime_hours": round(max(0.0, time.time() - self.boot_time) / 3600, 1),
            "top_cpu_category": top_cpu, "top_ram_category": top_ram,
        }
        for cat in CATEGORIES:
            result[f"proc_{cat}_cpu_pct"] = cats[cat][0]
            result[f"proc_{cat}_ram_mb"] = cats[cat][1]
        return result


class SlowWatchApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_NAME} — אבחון איטיות מחשב")
        self.root.geometry("1050x790")
        self.root.minsize(920, 680)
        self.root.configure(bg="#f3f5f8")
        self.base_dir = data_dir()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.collector: Collector | None = None
        self.running = False
        self.after_id: str | None = None
        self.last_alert: dict[str, float] = {}
        self.current: dict[str, Any] = {}
        self.history: deque[dict[str, Any]] = deque(maxlen=HISTORY_POINTS)
        self.recent_events: deque[str] = deque(maxlen=9)
        self.sample_interval = tk.IntVar(value=SAMPLE_INTERVAL_DEFAULT)
        self._build_ui()
        self._cleanup_old_data()
        self._set_status("מוכן. האיסוף יתחיל רק לאחר לחיצה על 'התחל איסוף'.")
        if psutil is None:
            self.start_button.configure(state="disabled")
            self._set_status("חסרה ספריית psutil. התקן אותה לפי ההוראות ב-README.md.")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg="#f3f5f8", padx=18, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="PC Slow Watch", font=("Segoe UI", 20, "bold"), bg="#f3f5f8", fg="#162238").pack(anchor="w")
        tk.Label(header, text="אבחון מקומי של עומס ואיטיות • ללא שליחת מידע לרשת • ללא תוכן אישי",
                 font=("Segoe UI", 10), bg="#f3f5f8", fg="#4b5b73").pack(anchor="w", pady=(3, 0))

        controls = tk.Frame(self.root, bg="#ffffff", padx=12, pady=10, highlightbackground="#dbe1ea", highlightthickness=1)
        controls.pack(fill="x", padx=18, pady=(0, 12))
        self.start_button = ttk.Button(controls, text="התחל איסוף", command=self.start)
        self.start_button.pack(side="left", padx=(0, 7))
        self.stop_button = ttk.Button(controls, text="עצור", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=7)
        ttk.Button(controls, text="סמן שהמחשב איטי עכשיו", command=self.mark_slow).pack(side="left", padx=7)
        ttk.Button(controls, text="הכן דוח ל-AI", command=self.export_report).pack(side="left", padx=7)
        ttk.Button(controls, text="פתח תיקיית נתונים", command=self.open_data_folder).pack(side="left", padx=7)
        ttk.Button(controls, text="מחק נתונים מקומיים", command=self.delete_data).pack(side="left", padx=7)
        tk.Label(controls, text="דגימה:", bg="#ffffff", fg="#334155", font=("Segoe UI", 9)).pack(side="right", padx=(10, 4))
        self.interval_box = ttk.Combobox(controls, width=5, state="readonly", values=(2, 5, 10), textvariable=self.sample_interval)
        self.interval_box.pack(side="right")

        self.status_var = tk.StringVar()
        tk.Label(self.root, textvariable=self.status_var, bg="#eaf0f7", fg="#2c3e55", anchor="w", padx=12, pady=8,
                 font=("Segoe UI", 9)).pack(fill="x", padx=18, pady=(0, 12))

        cards = tk.Frame(self.root, bg="#f3f5f8")
        cards.pack(fill="x", padx=18)
        self.card_vars: dict[str, tk.StringVar] = {}
        card_info = [("cpu_pct", "עומס מעבד"), ("ram_pct", "זיכרון RAM"),
                     ("disk_busy_pct_est", "פעילות דיסק משוערת"), ("network", "תעבורת רשת")]
        for idx, (key, title) in enumerate(card_info):
            card = tk.Frame(cards, bg="#ffffff", padx=14, pady=12, highlightbackground="#dbe1ea", highlightthickness=1)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 5, 0 if idx == 3 else 5))
            cards.grid_columnconfigure(idx, weight=1)
            tk.Label(card, text=title, bg="#ffffff", fg="#59677c", font=("Segoe UI", 10)).pack(anchor="w")
            var = tk.StringVar(value="—")
            self.card_vars[key] = var
            tk.Label(card, textvariable=var, bg="#ffffff", fg="#152238", font=("Segoe UI", 19, "bold")).pack(anchor="w", pady=(5, 0))

        chartbox = tk.Frame(self.root, bg="#ffffff", padx=10, pady=10, highlightbackground="#dbe1ea", highlightthickness=1)
        chartbox.pack(fill="both", expand=True, padx=18, pady=12)
        tk.Label(chartbox, text="מגמת עומסים — הדגימות האחרונות", bg="#ffffff", fg="#25334a",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
        self.chart = tk.Canvas(chartbox, height=245, bg="#fbfcfe", highlightthickness=0)
        self.chart.pack(fill="both", expand=True)
        self.chart.bind("<Configure>", lambda _e: self._draw_chart())

        lower = tk.Frame(self.root, bg="#f3f5f8")
        lower.pack(fill="both", padx=18, pady=(0, 15))
        info = tk.Frame(lower, bg="#ffffff", padx=12, pady=10, highlightbackground="#dbe1ea", highlightthickness=1)
        info.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(info, text="מה נראה כרגע", bg="#ffffff", fg="#25334a", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.diagnosis_var = tk.StringVar(value="לא נאספו עדיין נתונים.")
        tk.Label(info, textvariable=self.diagnosis_var, bg="#ffffff", fg="#526177", justify="left", anchor="nw",
                 wraplength=440, font=("Segoe UI", 9)).pack(fill="both", expand=True, anchor="w", pady=(7, 0))
        events_frame = tk.Frame(lower, bg="#ffffff", padx=12, pady=10, highlightbackground="#dbe1ea", highlightthickness=1)
        events_frame.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(events_frame, text="אירועים אחרונים", bg="#ffffff", fg="#25334a", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.events_text = tk.Text(events_frame, height=7, wrap="word", bg="#ffffff", fg="#526177", relief="flat",
                                   font=("Consolas", 9), state="disabled")
        self.events_text.pack(fill="both", expand=True, pady=(5, 0))

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _path(self, prefix: str, date_key: str | None = None) -> Path:
        return self.base_dir / f"{prefix}_{date_key or today_key()}.csv"

    def _append_row(self, path: Path, fields: list[str], row: dict[str, Any]) -> None:
        exists = path.exists()
        try:
            with path.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                if not exists:
                    writer.writeheader()
                writer.writerow({field: row.get(field, "") for field in fields})
        except OSError as exc:
            self._set_status(f"שגיאה בשמירה המקומית: {type(exc).__name__}. בדוק הרשאות ותיקיית נתונים.")

    def _append_event(self, kind: str, details: str, metrics: dict[str, Any] | None = None) -> None:
        metrics = metrics or self.current
        row = {
            "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "kind": kind, "details": details,
            "cpu_pct": metrics.get("cpu_pct", ""), "ram_pct": metrics.get("ram_pct", ""),
            "disk_busy_pct_est": metrics.get("disk_busy_pct_est", ""),
            "disk_read_latency_ms": metrics.get("disk_read_latency_ms", ""),
            "disk_write_latency_ms": metrics.get("disk_write_latency_ms", ""),
            "network_recv_mb_s": metrics.get("network_recv_mb_s", ""),
            "network_sent_mb_s": metrics.get("network_sent_mb_s", ""),
            "top_cpu_category": metrics.get("top_cpu_category", ""),
            "top_ram_category": metrics.get("top_ram_category", ""),
        }
        self._append_row(self._path("events"), EVENT_FIELDS, row)
        self.recent_events.appendleft(f"{row['timestamp'][11:19]}  {kind}: {details}")
        self._refresh_events()

    def _refresh_events(self) -> None:
        self.events_text.configure(state="normal")
        self.events_text.delete("1.0", "end")
        self.events_text.insert("1.0", "\n".join(self.recent_events) or "אין אירועים עדיין.")
        self.events_text.configure(state="disabled")

    def start(self) -> None:
        if self.running:
            return
        try:
            self.collector = Collector()
        except Exception as exc:
            messagebox.showerror("לא ניתן להתחיל", f"לא ניתן להתחיל איסוף.\n{exc}")
            return
        self.running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.interval_box.configure(state="disabled")
        self._set_status("האיסוף פעיל ונשמר רק במחשב זה. לחץ על 'סמן שהמחשב איטי עכשיו' ברגע שהתקלה מורגשת.")
        self._tick()

    def stop(self) -> None:
        self.running = False
        if self.after_id:
            try:
                self.root.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None
        self.start_button.configure(state="normal" if psutil is not None else "disabled")
        self.stop_button.configure(state="disabled")
        self.interval_box.configure(state="readonly")
        self._set_status("האיסוף נעצר. הנתונים שנאספו עד עכשיו נשארו מקומית.")

    def _tick(self) -> None:
        if not self.running or self.collector is None:
            return
        try:
            row = self.collector.sample()
            self.current = row
            self._append_row(self._path("metrics"), METRIC_FIELDS, row)
            self.history.append(row)
            self._update_cards(row)
            self._update_diagnosis(row)
            self._draw_chart()
            self._check_alerts(row)
            self._set_status(f"איסוף פעיל • דגימה אחרונה: {row['timestamp']} • שמירה מקומית בלבד")
        except Exception as exc:
            self._set_status(f"הדגימה נכשלה ({type(exc).__name__}); האיסוף ינסה שוב.")
        self.after_id = self.root.after(int(self.sample_interval.get() * 1000), self._tick)

    def _update_cards(self, row: dict[str, Any]) -> None:
        self.card_vars["cpu_pct"].set(f"{row['cpu_pct']:.0f}%")
        self.card_vars["ram_pct"].set(f"{row['ram_pct']:.0f}%")
        self.card_vars["disk_busy_pct_est"].set(f"{row['disk_busy_pct_est']:.0f}%")
        self.card_vars["network"].set(f"↓ {row['network_recv_mb_s']:.2f} / ↑ {row['network_sent_mb_s']:.2f} MB/s")

    def _update_diagnosis(self, row: dict[str, Any]) -> None:
        likely: list[str] = []
        if row["cpu_pct"] >= 85:
            likely.append("המעבד עמוס מאוד")
        if row["ram_pct"] >= 90:
            likely.append("הזיכרון כמעט מלא")
        if row["disk_busy_pct_est"] >= 85:
            likely.append("פעילות הדיסק גבוהה (מדד משוער)")
        if row["disk_read_latency_ms"] >= 80 or row["disk_write_latency_ms"] >= 80:
            likely.append("זמן תגובה של הדיסק גבוה")
        if row["swap_pct"] >= 70:
            likely.append("שימוש רב בזיכרון וירטואלי")
        cpu_cat = CATEGORY_LABELS.get(row.get("top_cpu_category", ""), "לא ידוע")
        ram_cat = CATEGORY_LABELS.get(row.get("top_ram_category", ""), "לא ידוע")
        if likely:
            headline = "סימני עומס: " + ", ".join(likely) + "."
        else:
            headline = "לא זוהה כרגע צוואר בקבוק ברור במדדים שנאספים. אם המחשב איטי, סמן זאת בזמן אמת כדי להשוות לנתונים."
        self.diagnosis_var.set(
            f"{headline}\n\nקטגוריה עם שימוש המעבד הגבוה ביותר: {cpu_cat}.\n"
            f"קטגוריה עם שימוש הזיכרון הגבוה ביותר: {ram_cat}.\n"
            f"זיכרון פנוי: {row['ram_available_mb'] / 1024:.1f} GB • פנוי בכונן המערכת: {row['system_drive_free_pct']:.0f}%\n"
            "הקטגוריות מצטברות בלבד: שמות תוכנות ותהליכים לא נשמרים."
        )

    def _draw_chart(self) -> None:
        if not hasattr(self, "chart"):
            return
        canvas = self.chart
        canvas.delete("all")
        width = max(200, canvas.winfo_width())
        height = max(100, canvas.winfo_height())
        left, right, top, bottom = 42, width - 16, 14, height - 28
        plot_h = bottom - top
        for value in (0, 25, 50, 75, 100):
            y = bottom - (value / 100.0) * plot_h
            canvas.create_line(left, y, right, y, fill="#e5eaf1")
            canvas.create_text(left - 8, y, text=str(value), anchor="e", fill="#65758c", font=("Segoe UI", 8))
        canvas.create_text(left, 2, text="%", anchor="nw", fill="#65758c", font=("Segoe UI", 8))
        values = list(self.history)
        if len(values) < 2:
            canvas.create_text(width / 2, height / 2, text="הגרף יופיע לאחר מספר דגימות", fill="#738197",
                               font=("Segoe UI", 10))
            return
        series = [
            ("cpu_pct", "מעבד", "#2670c9"),
            ("ram_pct", "RAM", "#17966b"),
            ("disk_busy_pct_est", "דיסק (משוער)", "#d17a20"),
        ]
        for key, _label, color in series:
            points: list[float] = []
            for index, row in enumerate(values):
                x = left + index * (right - left) / max(1, len(values) - 1)
                y = bottom - min(100.0, max(0.0, float(row.get(key, 0)))) / 100.0 * plot_h
                points.extend((x, y))
            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=2, smooth=True)
        legend_x = right - 235
        for idx, (_key, label, color) in enumerate(series):
            x = legend_x + idx * 80
            canvas.create_line(x, height - 10, x + 15, height - 10, fill=color, width=3)
            canvas.create_text(x + 19, height - 10, text=label, anchor="w", fill="#526177", font=("Segoe UI", 8))

    def _check_alerts(self, row: dict[str, Any]) -> None:
        now = time.monotonic()
        candidates = []
        if row["cpu_pct"] >= 85:
            candidates.append(("CPU_HIGH", f"עומס מעבד גבוה ({row['cpu_pct']:.0f}%)"))
        if row["ram_pct"] >= 90:
            candidates.append(("RAM_HIGH", f"שימוש גבוה ב-RAM ({row['ram_pct']:.0f}%)"))
        if row["disk_busy_pct_est"] >= 85:
            candidates.append(("DISK_BUSY", f"פעילות דיסק משוערת גבוהה ({row['disk_busy_pct_est']:.0f}%)"))
        if max(row["disk_read_latency_ms"], row["disk_write_latency_ms"]) >= 80:
            candidates.append(("DISK_LATENCY", "זמן תגובה ממוצע של הדיסק גבוה (80ms ומעלה)"))
        if row["swap_pct"] >= 70:
            candidates.append(("SWAP_HIGH", f"שימוש גבוה בזיכרון וירטואלי ({row['swap_pct']:.0f}%)"))
        for kind, detail in candidates:
            if now - self.last_alert.get(kind, -1e9) >= ALERT_COOLDOWN_SECONDS:
                self.last_alert[kind] = now
                self._append_event(kind, detail, row)

    def mark_slow(self) -> None:
        if not self.current:
            self._append_event("USER_MARKED_SLOW", "המשתמש סימן שהמחשב איטי; עדיין לא נאספה דגימה.", {})
            self._set_status("נשמר סימון ידני. התחל איסוף כדי לצרף אליו מדדים.")
        else:
            self._append_event("USER_MARKED_SLOW", "המשתמש סימן שהמחשב איטי עכשיו.", self.current)
            self._set_status("נשמר סימון של רגע האיטיות לצד המדדים שנמדדו.")

    def _cleanup_old_data(self) -> None:
        cutoff = dt.date.today() - dt.timedelta(days=RETENTION_DAYS)
        for prefix in ("metrics", "events"):
            for path in self.base_dir.glob(f"{prefix}_????-??-??.csv"):
                try:
                    key = path.stem.split("_", 1)[1]
                    if dt.date.fromisoformat(key) < cutoff:
                        path.unlink(missing_ok=True)
                except (ValueError, OSError):
                    continue

    def _paths_for_days(self, prefix: str, days: int) -> list[Path]:
        start = dt.date.today() - dt.timedelta(days=max(0, days - 1))
        paths = []
        for path in self.base_dir.glob(f"{prefix}_????-??-??.csv"):
            try:
                key = dt.date.fromisoformat(path.stem.split("_", 1)[1])
                if start <= key <= dt.date.today():
                    paths.append(path)
            except ValueError:
                continue
        return sorted(paths)

    def _system_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "application": APP_NAME,
            "application_version": APP_VERSION,
            "os_family": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "logical_cpu_count": psutil.cpu_count(logical=True) if psutil else None,
            "physical_cpu_count": psutil.cpu_count(logical=False) if psutil else None,
            "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2) if psutil else None,
            "processor_model": platform.processor() or "not reported",
            "collection_interval_seconds": self.sample_interval.get(),
            "report_period_days": EXPORT_DAYS,
            "privacy_note": "No hostname, username, IP/MAC address, process name/PID, paths, window titles, browser history, keystrokes, or file contents are included.",
        }
        try:
            drive = os.environ.get("SystemDrive", "C:")
            usage = psutil.disk_usage(drive + "\\" if not drive.endswith("\\") else drive)
            info["system_drive_total_gb"] = round(usage.total / (1024 ** 3), 2)
            info["system_drive_free_percent"] = round(100.0 - usage.percent, 1)
        except Exception:
            info["system_drive_total_gb"] = None
            info["system_drive_free_percent"] = None
        return info

    def _build_ai_report(self, metrics: list[dict[str, str]], events: list[dict[str, str]]) -> str:
        def numbers(field: str) -> list[float]:
            out = []
            for row in metrics:
                try:
                    out.append(float(row.get(field, "")))
                except (TypeError, ValueError):
                    pass
            return out

        def stats(field: str, unit: str = "%") -> str:
            vals = numbers(field)
            if not vals:
                return "אין נתונים"
            return f"ממוצע {sum(vals) / len(vals):.1f}{unit}, מינימום {min(vals):.1f}{unit}, מקסימום {max(vals):.1f}{unit}"

        counts = Counter(row.get("kind", "unknown") for row in events)
        from_ts = metrics[0].get("timestamp", "לא ידוע") if metrics else "לא נאספו דגימות"
        to_ts = metrics[-1].get("timestamp", "לא ידוע") if metrics else "לא נאספו דגימות"
        lines = [
            "דוח אבחון איטיות מחשב — PC Slow Watch",
            "=" * 48,
            f"נוצר בתאריך: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
            f"טווח הדגימות: {from_ts} עד {to_ts}",
            f"מספר דגימות: {len(metrics)} | מספר אירועים: {len(events)}",
            "",
            "סיכום מדדים:",
            f"מעבד: {stats('cpu_pct')}",
            f"RAM: {stats('ram_pct')}",
            f"פעילות דיסק משוערת: {stats('disk_busy_pct_est')}",
            f"זמן תגובה לקריאה מהדיסק: {stats('disk_read_latency_ms', 'ms')}",
            f"זמן תגובה לכתיבה בדיסק: {stats('disk_write_latency_ms', 'ms')}",
            f"קצב קריאה מהדיסק: {stats('disk_read_mb_s', ' MB/s')}",
            f"קצב כתיבה לדיסק: {stats('disk_write_mb_s', ' MB/s')}",
            f"תעבורת רשת נכנסת: {stats('network_recv_mb_s', ' MB/s')}",
            f"תעבורת רשת יוצאת: {stats('network_sent_mb_s', ' MB/s')}",
            "",
            "אירועים לפי סוג:",
        ]
        if counts:
            lines.extend(f"- {kind}: {count}" for kind, count in counts.most_common())
        else:
            lines.append("לא נרשמו אירועים.")
        lines += ["", "אירועים בולטים (עד 30 אחרונים):"]
        if events:
            for row in events[-30:]:
                lines.append(
                    f"- {row.get('timestamp','')} | {row.get('kind','')}: {row.get('details','')} "
                    f"(CPU={row.get('cpu_pct','')}%, RAM={row.get('ram_pct','')}%, "
                    f"disk-est={row.get('disk_busy_pct_est','')}%)"
                )
        else:
            lines.append("לא נרשמו אירועים.")
        lines += [
            "",
            "קטגוריות תהליכים:",
            "בקובץ המדדים מופיעים רק סכומים לפי קטגוריות כלליות (למשל דפדפנים או אבטחה). שמות תוכנות, מזהי תהליך ונתיבי קבצים אינם נשמרים.",
            "",
            "איך לפרש:",
            "1. השווה את השעות שסומנו USER_MARKED_SLOW עם המדדים באותה שעה.",
            "2. עומס CPU גבוה וממושך עשוי להעיד על חישוב כבד ברקע.",
            "3. RAM גבוה יחד עם swap גבוה עשוי להעיד על מחסור בזיכרון.",
            "4. פעילות דיסק וזמני תגובה גבוהים עשויים להעיד על אחסון עמוס/איטי.",
            "5. פעילות דיסק היא הערכה על בסיס מוני זמן מצטברים, לא מדידה ישירה של אחוז Active Time.",
            "6. זו מדידה לצורך אבחון, לא הוכחה לסיבה יחידה; בדוק גם עדכונים, דרייברים וטמפרטורות באמצעות כלים ייעודיים אם נדרש.",
            "",
            "פרטיות: הדוח נוצר לבקשת המשתמש. התוכנה אינה שולחת אותו ל-AI או לרשת; יש לצרף אותו ידנית לשירות AI לפי בחירתך.",
        ]
        return "\n".join(lines)

    def export_report(self) -> None:
        path_str = filedialog.asksaveasfilename(
            title="שמירת חבילת נתונים לניתוח AI",
            defaultextension=".zip",
            initialfile=f"PCSlowWatch_AI_Report_{dt.datetime.now().strftime('%Y%m%d_%H%M')}.zip",
            filetypes=(("ZIP", "*.zip"),),
        )
        if not path_str:
            return
        metric_paths = self._paths_for_days("metrics", EXPORT_DAYS)
        event_paths = self._paths_for_days("events", EXPORT_DAYS)
        metric_rows = read_csv_rows(metric_paths)
        event_rows = read_csv_rows(event_paths)
        metric_rows.sort(key=lambda r: r.get("timestamp", ""))
        event_rows.sort(key=lambda r: r.get("timestamp", ""))
        system_info = self._system_info()
        report = self._build_ai_report(metric_rows, event_rows)
        privacy = (
            "חבילת ייצוא פרטיות — PC Slow Watch\n\n"
            "מה כלול: מדדי ביצועים מצטברים, אירועי עומס וסיכום חומרה/מערכת כללי.\n"
            "מה לא כלול: שם משתמש, שם מחשב, כתובת IP/MAC, שמות תהליכים ותוכנות ספציפיים, מזהי תהליך, שורת פקודה, נתיבי קבצים, תוכן קבצים, כותרות חלונות, הקלדות, היסטוריית גלישה או צילומי מסך.\n"
            "הקטגוריה של שימוש בתהליכים מחושבת בזיכרון ונשמרת רק כסכום קטגוריה.\n"
            "לא מתבצעת שליחה אוטומטית. ה-ZIP נוצר רק לאחר לחיצה על 'הכן דוח ל-AI'.\n"
            "בדוק את תוכן החבילה לפני העלאה לשירות חיצוני.\n"
        )
        try:
            with zipfile.ZipFile(path_str, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("AI_REPORT_HE.txt", report)
                archive.writestr("PRIVACY_HE.txt", privacy)
                archive.writestr("system_info.json", json.dumps(system_info, ensure_ascii=False, indent=2))
                archive.writestr("metrics.csv", self._csv_text(METRIC_FIELDS, metric_rows))
                archive.writestr("events.csv", self._csv_text(EVENT_FIELDS, event_rows))
            messagebox.showinfo("הדוח מוכן", f"נוצרה חבילת ניתוח מקומית:\n{path_str}\n\nדגימות: {len(metric_rows)} | אירועים: {len(event_rows)}\n\nלא נשלח מידע אוטומטית.")
        except (OSError, zipfile.BadZipFile) as exc:
            messagebox.showerror("שגיאה בייצוא", f"לא ניתן ליצור את הדוח ({type(exc).__name__}).")

    @staticmethod
    def _csv_text(fields: list[str], rows: list[dict[str, str]]) -> str:
        from io import StringIO
        stream = StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
        return stream.getvalue()

    def open_data_folder(self) -> None:
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                os.startfile(str(self.base_dir))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(self.base_dir)])
            else:
                subprocess.Popen(["xdg-open", str(self.base_dir)])
        except Exception as exc:
            messagebox.showerror("פתיחת תיקייה נכשלה", f"לא ניתן לפתוח את תיקיית הנתונים ({type(exc).__name__}).\n{self.base_dir}")

    def delete_data(self) -> None:
        confirmed = messagebox.askyesno(
            "מחיקת נתונים",
            "למחוק את כל קובצי המדדים והאירועים שנשמרו במחשב הזה?\n\nהפעולה לא ניתנת לביטול ולא תמחק דוחות ZIP ששמרת במקום אחר.",
        )
        if not confirmed:
            return
        if self.running:
            self.stop()
        removed = 0
        for path in self.base_dir.glob("*.csv"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        self.history.clear()
        self.recent_events.clear()
        self._refresh_events()
        self._draw_chart()
        messagebox.showinfo("המחיקה הושלמה", f"נמחקו {removed} קובצי CSV מתיקיית הנתונים המקומית.")

    def _on_close(self) -> None:
        if self.running:
            self.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = SlowWatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
