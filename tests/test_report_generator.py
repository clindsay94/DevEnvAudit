import unittest
import os
import tempfile
import shutil
import json
from datetime import datetime

from report_generator import ReportGenerator
from scan_logic import DetectedComponent, EnvironmentVariableInfo, ScanIssue

class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

        self.comp1 = DetectedComponent(
            id="python_3.9_fake",
            name="Python",
            category="Language",
            version="3.9.7",
            path="/fake/path/python3.9",
            executable_path="/fake/bin/python3.9",
            details={"Arch": "x64"},
            issues=[ScanIssue(description="Path warning", severity="Warning", component_id="python_3.9_fake")],
            update_info={"latest_version": "3.9.10", "package_manager_name": "fakepm",
                         "update_command": "fakepm update python", "is_update_available": True}
        )
        self.comp2 = DetectedComponent(
            id="git_2.30_fake",
            name="Git",
            category="VCS",
            version="2.30.0",
            path="/fake/path/git",
            executable_path="/fake/bin/git",
            details={"user.name": "Test User"}
        )
        self.env1 = EnvironmentVariableInfo(
            name="PATH",
            value="/usr/bin:/bin",
            scope="active_session",
            issues=[ScanIssue(description="Duplicate entry /bin", severity="Info", related_path="/bin")]
        )
        self.env2 = EnvironmentVariableInfo(name="API_KEY", value="****SENSITIVE_VALUE****", scope="active_session")

        self.issue1 = ScanIssue(description="Critical system problem", severity="Critical", category="System")
        self.issue2 = ScanIssue(description="Config warning for Git", severity="Warning", component_id="git_2.30_fake", category="Configuration")

        self.detected_components = [self.comp1, self.comp2]
        self.environment_variables = [self.env1, self.env2]
        self.issues = [self.issue1, self.issue2]

        self.reporter = ReportGenerator(
            self.detected_components, self.environment_variables, self.issues
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_generate_report_data_for_gui(self):
        data = self.reporter.generate_report_data_for_gui()
        self.assertIn("report_time", data)
        self.assertEqual(len(data["detected_components"]), 2)
        self.assertEqual(data["detected_components"][0]["name"], "Python")
        self.assertEqual(data["detected_components"][1]["name"], "Git")
        self.assertEqual(len(data["environment_variables"]), 2)
        self.assertEqual(data["environment_variables"][0]["name"], "API_KEY")
        self.assertEqual(data["environment_variables"][1]["name"], "PATH")
        self.assertEqual(len(data["issues"]), 2)
        self.assertEqual(data["issues"][0]["severity"], "Critical")
        self.assertEqual(data["issues"][1]["severity"], "Warning")

    def test_export_to_txt(self):
        filepath = os.path.join(self.test_dir, "report.txt")
        success = self.reporter.export_to_txt(filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("Developer Environment Audit Report", content)
            self.assertIn("Tool: Python (3.9.7)", content)
            self.assertIn("Update Status: Update Available: Installed 3.9.7 -> Latest 3.9.10 (via fakepm)", content)
            self.assertIn("Update Command: `fakepm update python`", content)
            self.assertIn("PATH (active_session): /usr/bin:/bin", content)
            self.assertIn("- Critical (System): Critical system problem", content)
            self.assertIn("API_KEY (active_session): ****SENSITIVE_VALUE****", content)

    def test_export_to_markdown(self):
        filepath = os.path.join(self.test_dir, "report.md")
        success = self.reporter.export_to_markdown(filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("# Developer Environment Audit Report", content)
            self.assertIn("### Python (3.9.7)", content)
            self.assertIn("- **Update Status:** Update Available: Installed 3.9.7 -> Latest 3.9.10 (via fakepm)", content)
            self.assertIn("  - Update Command: `fakepm update python`", content)
            self.assertIn("- **`PATH`** (`active_session`): `/usr/bin:/bin`", content)
            self.assertIn("- **Critical (System):** Critical system problem", content)

    def test_export_to_json(self):
        filepath = os.path.join(self.test_dir, "report.json")
        success = self.reporter.export_to_json(filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("report_time", data)
        self.assertEqual(len(data["detected_components"]), 2)
        self.assertEqual(data["detected_components"][0]["name"], "Python")
        self.assertEqual(data["detected_components"][0]["update_info"]["latest_version"], "3.9.10")
        self.assertEqual(len(data["environment_variables"]), 2)
        self.assertEqual(data["environment_variables"][0]["name"], "API_KEY")
        self.assertEqual(len(data["issues"]), 2)
        self.assertEqual(data["issues"][0]["severity"], "Critical")

    def test_export_to_html(self):
        filepath = os.path.join(self.test_dir, "report.html")
        success = self.reporter.export_to_html(filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("<title>Developer Environment Audit Report</title>", content)
            self.assertIn("<h3>Python (3.9.7)</h3>", content)
            self.assertIn("Update Status: Update Available: Installed 3.9.7 -&gt; Latest 3.9.10 (via fakepm)", content)
            self.assertIn("<code>PATH</code>", content)
            self.assertIn("<div class='issue Critical'>", content)
            self.assertIn("<b>Critical (System):</b> Critical system problem", content)

    def test_empty_data_export(self):
        empty_reporter = ReportGenerator([], [], [])
        filepath_txt = os.path.join(self.test_dir, "empty_report.txt")
        empty_reporter.export_to_txt(filepath_txt)
        with open(filepath_txt, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("No components detected.", content)
            self.assertIn("No environment variables collected or to display.", content)
            self.assertIn("No issues identified.", content)

        filepath_json = os.path.join(self.test_dir, "empty_report.json")
        empty_reporter.export_to_json(filepath_json)
        with open(filepath_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertEqual(len(data["detected_components"]), 0)
            self.assertEqual(len(data["environment_variables"]), 0)
            self.assertEqual(len(data["issues"]), 0)

if __name__ == '__main__':
    unittest.main()