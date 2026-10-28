import datetime as dt
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

    def test_browser_import_rejects_full_urls_as_site_label(self):
        raw = {"timestamp": dt.datetime.now().astimezone().isoformat(), "site_label": "mybank.com/account/123", "site_category": "banking"}
        self.assertIsNone(module.sanitize_browser_sample(raw))

    def test_browser_import_handles_unhashable_category_safely(self):
        raw = {"timestamp": dt.datetime.now().astimezone().isoformat(), "site_label": "example.com", "site_category": ["email"]}
        self.assertEqual(module.sanitize_browser_sample(raw)["site_category"], "other")


if __name__ == "__main__":
    unittest.main()
