import csv
import datetime as dt
import tempfile
import importlib.util
import sys
import unittest
from unittest import mock
from types import SimpleNamespace
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app.py"
spec = importlib.util.spec_from_file_location("pcslowwatch_app", APP)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PrivacyCategoryTests(unittest.TestCase):
    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_process_enumeration_runtime_error_does_not_escape(self):
        with mock.patch.object(module.psutil, "process_iter", side_effect=RuntimeError("enumeration failed")):
            self.assertEqual(list(module.safe_process_iter(["pid"])), [])

    def test_diagnostic_error_message_redacts_local_paths(self):
        message = module.safe_error_message(RuntimeError(r"C:\Users\OWNER\Private\app.py failed"))
        self.assertNotIn("OWNER", message)
        self.assertNotIn("Private", message)
        self.assertIn("[נתיב מקומי]", message)

    def test_categories_are_broad_and_generic(self):
        self.assertEqual(module.safe_category("msedge.exe"), "browser")
        self.assertEqual(module.safe_category("MsMpEng.exe"), "security")
        self.assertEqual(module.safe_category("OneDrive.exe"), "sync_backup")
        self.assertEqual(module.safe_category("unrecognized-app.exe"), "other")

    def test_process_names_do_not_enter_metric_field_names(self):
        self.assertFalse(any("chrome" in field.lower() for field in module.METRIC_FIELDS))
        self.assertFalse(any("edge" in field.lower() for field in module.METRIC_FIELDS))
        self.assertFalse(any("pid" in field.lower() for field in module.METRIC_FIELDS))

    def test_pct_is_resilient(self):
        self.assertEqual(module.pct("12.34"), 12.3)
        self.assertEqual(module.pct(None), 0.0)

    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_swap_usage_uses_psutil_counter_when_available(self):
        with mock.patch.object(module.psutil, "swap_memory", return_value=SimpleNamespace(percent=27.4)):
            self.assertEqual(module.swap_usage_percent(), (27.4, False))

    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_swap_usage_falls_back_when_windows_pdh_counter_is_disabled(self):
        error = RuntimeError("PdhAddEnglishCounterW failed. Performance counters may be disabled.")
        with (
            mock.patch.object(module.platform, "system", return_value="Windows"),
            mock.patch.object(module.psutil, "swap_memory", side_effect=error),
            mock.patch.object(module, "windows_commit_usage_percent", return_value=63.2),
        ):
            self.assertEqual(module.swap_usage_percent(), (63.2, True))

    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_unrelated_swap_errors_are_not_hidden(self):
        error = RuntimeError("unexpected swap failure")
        with mock.patch.object(module.psutil, "swap_memory", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "unexpected swap failure"):
                module.swap_usage_percent()

    def test_program_name_drops_directories_and_path(self):
        self.assertEqual(module.safe_program_name(r"C:\Users\PrivateName\App\chrome.exe"), "chrome.exe")
        self.assertNotIn("PrivateName", module.safe_program_name(r"C:\Users\PrivateName\App\chrome.exe"))

    def test_browser_import_keeps_allowlisted_metadata_only(self):
        now = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        raw = {
            "sample_id": "a" * 32,
            "timestamp": now,
            "tab_ref": "b" * 32,
            "site_label": "gmail",
            "site_category": "email",
            "mail_thread_id": "FMfcgzQXabc123456",
            "visible": True,
            "resource_count": 50,
            "transfer_kb": 1234,
            "long_task_count": 4,
            "long_task_ms": 100.5,
            "js_heap_mb": 20.2,
            "dom_nodes": 1000,
            "load_ms": 2500,
            "page_title": "Private email subject",
            "url": "https://mail.google.com/mail/u/0/#inbox/secret",
            "message_body": "secret body",
            "username": "not-to-save",
        }
        clean = module.sanitize_browser_sample(raw)
        self.assertIsNotNone(clean)
        self.assertEqual(clean["site_label"], "gmail")
        self.assertEqual(clean["mail_thread_id"], "FMfcgzQXabc123456")
        self.assertNotIn("page_title", clean)
        self.assertNotIn("url", clean)
        self.assertNotIn("message_body", clean)
        self.assertNotIn("username", clean)
        self.assertEqual(set(clean), set(module.BROWSER_FIELDS))

    def test_only_gmail_thread_ids_are_preserved(self):
        raw = {
            "timestamp": dt.datetime.now().astimezone().isoformat(),
            "site_label": "outlook",
            "site_category": "email",
            "mail_thread_id": "opaque-thread-key-1234",
        }
        self.assertEqual(module.sanitize_browser_sample(raw)["mail_thread_id"], "")

    def test_browser_import_rejects_full_urls_as_site_label(self):
        raw = {"timestamp": dt.datetime.now().astimezone().isoformat(), "site_label": "mybank.com/account/123", "site_category": "banking"}
        self.assertIsNone(module.sanitize_browser_sample(raw))

    def test_browser_import_handles_unhashable_category_safely(self):
        raw = {"timestamp": dt.datetime.now().astimezone().isoformat(), "site_label": "example.com", "site_category": ["email"]}
        self.assertEqual(module.sanitize_browser_sample(raw)["site_category"], "other")



class PersistenceAndSamplingTests(unittest.TestCase):
    def test_process_logging_limits_are_bounded(self):
        self.assertEqual(module.MAX_PROCESS_ROWS, 15)
        self.assertGreater(module.PROCESS_LOG_INTERVAL_SECONDS, module.SAMPLE_INTERVAL_DEFAULT)
        self.assertLess(module.HIGH_LOAD_PROCESS_LOG_INTERVAL_SECONDS, module.PROCESS_LOG_INTERVAL_SECONDS)


    def test_transient_cpu_and_ram_peaks_survive_until_snapshot(self):
        collector = object.__new__(module.Collector)
        collector.pending_process_peaks = {}
        collector._accumulate_process_peaks({
            "short_task.exe": {
                "program": "short_task.exe", "category": "other",
                "cpu_pct": 91.0, "ram_mb": 180.0, "instances": 1
            }
        })
        collector._accumulate_process_peaks({
            "short_task.exe": {
                "program": "short_task.exe", "category": "other",
                "cpu_pct": 2.0, "ram_mb": 60.0, "instances": 1
            }
        })
        peak = collector.pending_process_peaks["short_task.exe"]
        self.assertEqual(peak["cpu_pct"], 91.0)
        self.assertEqual(peak["ram_mb"], 180.0)

    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_fast_process_scan_does_not_request_io_or_threads(self):
        collector = object.__new__(module.Collector)
        collector.cpu_count = 4
        collector.previous_proc = {12: {"cpu_s": 1.0}}
        collector.pending_process_peaks = {}
        collector.last_detailed_mode = True
        process = SimpleNamespace(info={
            "pid": 12,
            "name": "short_task.exe",
            "cpu_times": SimpleNamespace(user=2.0, system=0.0),
            "memory_info": SimpleNamespace(rss=40 * 1024 * 1024),
        })
        with mock.patch.object(module.psutil, "process_iter", return_value=[process]) as mocked:
            collector._process_usage(5.0, include_details=True)
        self.assertEqual(
            mocked.call_args.kwargs["attrs"],
            ["pid", "name", "cpu_times", "memory_info"]
        )
        self.assertNotIn("io_counters", mocked.call_args.kwargs["attrs"])
        self.assertNotIn("num_threads", mocked.call_args.kwargs["attrs"])

    @unittest.skipIf(module.psutil is None, "psutil dependency unavailable")
    def test_detailed_snapshot_merges_accumulated_peak_and_queries_io_once(self):
        collector = object.__new__(module.Collector)
        collector.pending_process_peaks = {
            "short_task.exe": {
                "program": "short_task.exe", "category": "other",
                "cpu_pct": 91.0, "ram_mb": 100.0, "read_mb_s": 0.0,
                "write_mb_s": 0.0, "threads": 0, "instances": 1,
            }
        }
        collector.previous_detailed_io = {}
        collector.previous_detailed_at = None
        collector.last_process_rows = []
        process = SimpleNamespace(info={
            "pid": 12, "name": "short_task.exe",
            "io_counters": SimpleNamespace(read_bytes=4096, write_bytes=2048),
            "num_threads": 3,
            "memory_info": SimpleNamespace(rss=80 * 1024 * 1024),
        })
        with mock.patch.object(module.psutil, "process_iter", return_value=[process]) as mocked:
            rows = collector.capture_process_snapshot()
        self.assertEqual(
            mocked.call_args.kwargs["attrs"],
            ["pid", "name", "io_counters", "num_threads", "memory_info"]
        )
        self.assertEqual(rows[0]["program"], "short_task.exe")
        self.assertEqual(rows[0]["cpu_pct"], 91.0)
        self.assertEqual(rows[0]["ram_mb"], 100.0)
        self.assertEqual(rows[0]["threads"], 3)
        self.assertEqual(collector.pending_process_peaks, {})

    def test_append_rows_writes_one_header_and_appends_batches(self):
        app = object.__new__(module.SlowWatchApp)
        fields = ["timestamp", "program"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "processes.csv"
            app._append_rows(path, fields, [
                {"timestamp": "2026-10-28T10:00:00+02:00", "program": "chrome.exe"},
                {"timestamp": "2026-10-28T10:00:30+02:00", "program": "render.exe"},
            ])
            app._append_rows(path, fields, [
                {"timestamp": "2026-10-28T10:01:00+02:00", "program": "chrome.exe"},
            ])
            with path.open("r", newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], fields)
            self.assertEqual(len(rows), 4)
            self.assertEqual([row[1] for row in rows[1:]], ["chrome.exe", "render.exe", "chrome.exe"])

if __name__ == "__main__":
    unittest.main()
