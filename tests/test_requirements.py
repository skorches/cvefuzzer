import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cvefuzz.adapters.requirements import requirements_issues
from cvefuzz.cli import main


class RequirementsTests(unittest.TestCase):
    def test_plain_pins_comments_bom_and_exact_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text("\ufeff# fixture\nExample_pkg == 1.2.3rc1  # pinned\nother==1!2.0+local.1\n", encoding="utf-8")
            self.assertEqual(requirements_issues(path), [])

    def test_unsupported_forms_skip_scanner_and_cannot_exit_clean(self):
        forms = ["-r ../outside.txt", "--requirement=https://example.invalid/requirements.txt",
                 "-c constraints.txt", "-e .", "pkg>=1", "pkg==1.*", "pkg===arbitrary",
                 "pkg @ https://example.invalid/pkg.whl", "git+https://example.invalid/repo",
                 "./local.whl", "pkg[extra]==1", 'pkg==1; python_version < "3.12"',
                 "pkg==${VERSION}", "--index-url https://example.invalid", "pkg==1 --hash=sha256:abc",
                 "pkg==1 \\\n --hash=sha256:abc", "# no dependencies\n"]
        for form in forms:
            with self.subTest(form=form), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "requirements.txt").write_text(form, encoding="utf-8")
                with patch("cvefuzz.adapters.osv.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "2.7.0", "")) as runner, contextlib.redirect_stderr(io.StringIO()):
                    code = main(["scan", str(root), "--database", str(root / ".cvefuzz/scans.db"),
                                 "--output", str(root / ".cvefuzz/report.json"), "--fail-on", "never"])
                self.assertEqual(code, 2)
                self.assertEqual(runner.call_count, 1)  # Version check only; unsupported file never sent.
                report = json.loads((root / ".cvefuzz/report.json").read_text())
                self.assertEqual(report["status"], "scan-incomplete")

    def test_mixed_supported_and_unsupported_lines_reject_whole_input(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text("good==1.0\n-r other.txt\n")
            issues = requirements_issues(path)
            self.assertEqual(len(issues), 1)
            self.assertIn("line 2", issues[0])
