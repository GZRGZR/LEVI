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


if __name__ == "__main__":
    unittest.main()
