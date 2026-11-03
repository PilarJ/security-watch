"""Tests for the per-repo `exclude_paths` option. Run: python3 -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "watcher"))

import watch  # noqa: E402


class IsExcludedTest(unittest.TestCase):
    def test_file_inside_excluded_dir(self):
        self.assertTrue(watch.is_excluded("old-eshop/i/tovar.php", ["old-eshop"]))

    def test_trailing_slash_and_dot_prefix_are_ignored(self):
        self.assertTrue(watch.is_excluded("./old-eshop/a.php", ["old-eshop/"]))

    def test_sibling_with_same_prefix_is_not_excluded(self):
        self.assertFalse(watch.is_excluded("old-eshop-sk/i/tovar.php", ["old-eshop"]))

    def test_nested_dir_with_same_name_is_not_excluded(self):
        self.assertFalse(watch.is_excluded("modules/old-eshop/a.php", ["old-eshop"]))

    def test_exact_file(self):
        self.assertTrue(watch.is_excluded("legacy.php", ["legacy.php"]))

    def test_no_path_or_no_excludes(self):
        self.assertFalse(watch.is_excluded("", ["old-eshop"]))
        self.assertFalse(watch.is_excluded("old-eshop/a.php", []))


class FilterExcludedTest(unittest.TestCase):
    def test_filters_code_and_dependency_findings_but_keeps_pathless(self):
        findings = [
            {"tool": "semgrep", "path": "old-eshop-sk/i/tovar.php"},
            {"tool": "semgrep", "path": "modules/watermark/watermark.php"},
            {"tool": "osv", "lockfile": "old-eshop/admin/PHPMailer/composer.lock"},
            {"tool": "osv", "lockfile": "composer.lock"},
            {"tool": "trivyimg"},
        ]
        kept = watch.filter_excluded(findings, ["old-eshop", "old-eshop-sk"])
        self.assertEqual(
            kept,
            [
                {"tool": "semgrep", "path": "modules/watermark/watermark.php"},
                {"tool": "osv", "lockfile": "composer.lock"},
                {"tool": "trivyimg"},
            ],
        )

    def test_default_is_empty(self):
        self.assertEqual(watch.DEFAULTS["exclude_paths"], [])


if __name__ == "__main__":
    unittest.main()
