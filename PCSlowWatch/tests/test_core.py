import csv
import datetime as dt
import tempfile
import importlib.util
import sys
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app.py"
spec = importlib.util.spec_from_file_location("pcslowwatch_app", APP)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PrivacyCategoryTests(unittest.TestCase):
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
