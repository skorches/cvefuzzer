import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cvefuzz.adapters.npm import dependency_paths
from cvefuzz.adapters.osv import scan_dependencies
from cvefuzz.inventory import discover


class NpmTests(unittest.TestCase):
    def lock(self):
        return {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"a": "1", "@scope/b": "1"}},
            "node_modules/a": {"version": "1", "dependencies": {"shared": "1", "nested": "2"}},
            "node_modules/@scope/b": {"version": "1", "dependencies": {"shared": "1"}},
            "node_modules/shared": {"version": "1", "dependencies": {"a": "1"}},
            "node_modules/a/node_modules/nested": {"version": "2"},
            "node_modules/a/node_modules/shared": {"version": "2"},
        }}

    def test_hoisted_nested_scoped_cycles_and_versions(self):
        for version in (2, 3):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "package-lock.json"
                data = self.lock()
                data["lockfileVersion"] = version
                path.write_text(json.dumps(data))
                paths, issues = dependency_paths(path)
                self.assertEqual(issues, [])
                self.assertEqual(paths[("nested", "2")], ["a@1", "nested@2"])
                self.assertEqual(paths[("shared", "1")], ["@scope/b@1", "shared@1"])
                self.assertEqual(paths[("a", "1")], ["a@1"])
                self.assertEqual(paths[("shared", "2")], ["a@1", "shared@2"])

    def test_missing_required_optional_links_and_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "package-lock.json"
            data = self.lock()
            data["packages"][""]["dependencies"].update({"missing": "1", "alias": "npm:actual@1", "workspace": "*"})
            data["packages"][""]["optionalDependencies"] = {"absent": "1"}
            data["packages"]["node_modules/alias"] = {"version": "1"}
            data["packages"]["node_modules/workspace"] = {"link": True, "resolved": "packages/workspace"}
            path.write_text(json.dumps(data))
            paths, issues = dependency_paths(path)
            self.assertEqual(len(issues), 3)
            self.assertNotIn(("alias", "1"), paths)
            self.assertFalse(any("absent" in issue for issue in issues))

    def test_scan_serializes_path_and_retains_unmatched_findings(self):
        for name, expected in (("nested", "completed"), ("unknown", "incomplete")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / "package-lock.json").write_text(json.dumps(self.lock()))
                payload = {"results": [{"packages": [{"package": {"name": name, "version": "2", "ecosystem": "npm"},
                            "vulnerabilities": [{"id": "TEST-1"}]}]}]}
                def run(command, **kwargs):
                    return subprocess.CompletedProcess(command, 0 if command[-1] == "--version" else 1,
                                                       "2.7.0" if command[-1] == "--version" else json.dumps(payload), "")
                with patch("cvefuzz.adapters.osv.subprocess.run", side_effect=run):
                    result = scan_dependencies(root, discover(root), "scanner", root / "artifacts", "now")
                self.assertEqual(result.status, expected)
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(result.findings[0].component.dependency_path,
                                 ["a@1", "nested@2"] if name == "nested" else [])

    def test_old_and_malformed_formats_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "package-lock.json"
            for data in ({"lockfileVersion": 1}, {"lockfileVersion": 3}, {"lockfileVersion": 3, "packages": {}}):
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    dependency_paths(path)
