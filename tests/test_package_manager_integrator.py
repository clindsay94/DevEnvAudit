import unittest
from unittest.mock import patch, MagicMock
import platform

import package_manager_integrator as pmi

class TestPackageManagerIntegrator(unittest.TestCase):

    def setUp(self):
        # Mock the detected package managers to control which ones are "found"
        self.patch_shutil_which = patch('shutil.which')
        self.mock_shutil_which = self.patch_shutil_which.start()

        self.patch_run_pm_command = patch('package_manager_integrator._run_pm_command')
        self.mock_run_pm_command = self.patch_run_pm_command.start()

    def tearDown(self):
        self.patch_shutil_which.stop()
        self.patch_run_pm_command.stop()

    def test_detect_package_managers_windows(self):
        if platform.system() == "Windows":
            self.mock_shutil_which.side_effect = lambda exe: f"C:\\path\\to\\{exe}.exe" if exe in ["winget", "choco"] else None
            detected = pmi.detect_package_managers()
            self.assertIn("winget", detected)
            self.assertIn("choco", detected)
            self.assertNotIn("scoop", detected)
            self.assertNotIn("brew", detected)
            self.assertEqual(detected["winget"]["path"], "C:\\path\\to\\winget.exe")
        else:
            self.skipTest("Skipping Windows specific PM detection test on non-Windows OS.")

    def test_detect_package_managers_macos(self):
        if platform.system() == "Darwin":
            self.mock_shutil_which.side_effect = lambda exe: f"/usr/local/bin/{exe}" if exe == "brew" else None
            detected = pmi.detect_package_managers()
            self.assertIn("brew", detected)
            self.assertNotIn("apt", detected)
        else:
            self.skipTest("Skipping macOS specific PM detection test on non-macOS OS.")

    def test_detect_package_managers_linux(self):
        if platform.system() == "Linux":
            self.mock_shutil_which.side_effect = lambda exe: f"/usr/bin/{exe}" if exe in ["apt-get", "snap"] else None
            detected = pmi.detect_package_managers()
            self.assertIn("apt", detected) # Note: 'apt' detection uses 'apt-get'
            self.assertIn("snap", detected)
            self.assertNotIn("brew", detected) # Unless Linuxbrew is specifically mocked
        else:
            self.skipTest("Skipping Linux specific PM detection test on non-Linux OS.")

    def test_get_pm_package_name(self):
        self.assertEqual(pmi.get_pm_package_name("python", "apt"), "python3")
        self.assertEqual(pmi.get_pm_package_name("vscode", "snap"), "code")
        self.assertIsNone(pmi.get_pm_package_name("unknown_tool", "apt"))
        self.assertIsNone(pmi.get_pm_package_name("python", "unknown_pm"))

    def test_parse_version_from_output_apt(self):
        output_candidate = "Package: python3\nVersion: 3.9.2-1ubuntu1\nCandidate: 3.9.7-1~20.04\n"
        self.assertEqual(pmi.parse_version_from_output(output_candidate, "apt", "python3"), "3.9.7-1~20.04")
        # Test with apt show output format (often just Version:)
        output_show = """Package: python3
Status: install ok installed
Priority: important
Section: python
Installed-Size: 424
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: python3-defaults (3.8.2-0ubuntu2)
Version: 3.8.2-0ubuntu2
Provides: python3-dev (= 3.8.2-0ubuntu2)
Depends: python3.8 (>= 3.8.2-1~)
Suggests: python3-setuptools, python3-pip
Conflicts: python3-dev (<< 3.8.2-0ubuntu2)
Breaks: python-virtualenv (<< 1.7.1.2-2~)
Replaces: python3-dev (<< 3.8.2-0ubuntu2)
Description: interactive high-level object-oriented language (default python3 version)
 Python, the high-level, interactive object oriented language, includes an
 extensive class library with lots of goodies for network programming, GUI
 development, regular expressions, etc.
 .
 This package is a dependency package, which depends on Debian's default
 Python 3 version (currently v3.8).
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
""" # End of triple-quoted string
        self.assertEqual(pmi.parse_version_from_output(output_show, "apt", "python3"), "3.8.2-0ubuntu2")

    def test_parse_version_from_output_brew(self):
        output = "git: stable 2.30.1 (bottled), HEAD\n"
        self.assertEqual(pmi.parse_version_from_output(output, "brew", "git"), "2.30.1")
        output_simple = "python@3.9: 3.9.12\n"
        self.assertEqual(pmi.parse_version_from_output(output_simple, "brew", "python@3.9"), "3.9.12")

    def test_parse_version_from_output_winget(self):
        output = """
Name        Id                 Version   Matched By
----------------------------------------------------
Python 3.11  Python.Python.3.11  3.11.4   Moniker
Python 3.10  Python.Python.3.10  3.10.11  Moniker
Git          Git.Git             2.40.0   Moniker
"""
        self.assertEqual(pmi.parse_version_from_output(output, "winget", "Python.Python.3.10"), "3.10.11")
        self.assertEqual(pmi.parse_version_from_output(output, "winget", "Git.Git"), "2.40.0")
        self.assertIsNone(pmi.parse_version_from_output(output, "winget", "NonExistent.Package"))

    @patch('package_manager_integrator.detect_package_managers')
    def test_get_latest_version_and_update_command_success(self, mock_detect_pms):
        mock_detect_pms.return_value = {"brew": {"name": "Homebrew", "path": "/usr/local/bin/brew"}}
        self.mock_run_pm_command.return_value = ("git: stable 2.40.0 (bottled), HEAD\n", "")

        tool_id = "git"
        tool_name = "Git"
        installed_version = "2.39.0"
        preferred_pms = ["brew"]

        result = pmi.get_latest_version_and_update_command(tool_id, tool_name, installed_version, preferred_pms)

        self.assertIsNotNone(result)
        self.assertEqual(result["latest_version"], "2.40.0")
        self.assertEqual(result["package_manager_id"], "brew")
        self.assertEqual(result["package_manager_name"], "Homebrew")
        self.assertEqual(result["package_name_in_pm"], "git")
        self.assertTrue("brew upgrade git" in result["update_command"])
        self.assertTrue(result["is_update_available"])

        installed_version_latest = "2.40.0"
        result_latest = pmi.get_latest_version_and_update_command(tool_id, tool_name, installed_version_latest, preferred_pms)
        self.assertFalse(result_latest["is_update_available"])

    @patch('package_manager_integrator.detect_package_managers')
    def test_get_latest_version_no_mapping(self, mock_detect_pms):
        mock_detect_pms.return_value = {"apt": {"name": "APT", "path":"/usr/bin/apt-get"}}
        result = pmi.get_latest_version_and_update_command("unknown_tool_id", "UnknownTool", "1.0", ["apt"])
        self.assertIsNone(result)

    @patch('package_manager_integrator.detect_package_managers')
    def test_get_latest_version_pm_command_fails(self, mock_detect_pms):
        mock_detect_pms.return_value = {"brew": {"name": "Homebrew", "path":"/usr/local/bin/brew"}}
        self.mock_run_pm_command.return_value = (None, "Error occurred")
        result = pmi.get_latest_version_and_update_command("git", "Git", "1.0", ["brew"])
        self.assertIsNone(result)

    @patch('package_manager_integrator.detect_package_managers')
    def test_get_latest_version_version_parse_fails(self, mock_detect_pms):
        mock_detect_pms.return_value = {"brew": {"name": "Homebrew", "path":"/usr/local/bin/brew"}}
        self.mock_run_pm_command.return_value = ("Some unexpected output", "")
        result = pmi.get_latest_version_and_update_command("git", "Git", "1.0", ["brew"])
        self.assertIsNone(result)

    @patch('package_manager_integrator.detect_package_managers')
    def test_version_comparison_logic(self, mock_detect_pms):
        mock_detect_pms.return_value = {"brew": {"name": "Homebrew", "path": "/usr/local/bin/brew"}}

        # Mock a tool that exists in TOOL_TO_PM_PACKAGE_MAP for brew
        original_tool_map = pmi.TOOL_TO_PM_PACKAGE_MAP.get("mytool_id_version_test")
        pmi.TOOL_TO_PM_PACKAGE_MAP["mytool_id_version_test"] = {"brew": "mytool-package"}
        self.mock_run_pm_command.return_value = ("mytool-package: stable 1.0.10\n", "")

        # Case 1: packaging library works (default behavior, no need to patch parse_version itself here unless testing its absence)
        result = pmi.get_latest_version_and_update_command("mytool_id_version_test", "MyToolVersionTest", "1.0.2", ["brew"])
        self.assertIsNotNone(result)
        self.assertTrue(result["is_update_available"]) # 1.0.10 > 1.0.2

        result_no_update = pmi.get_latest_version_and_update_command("mytool_id_version_test", "MyToolVersionTest", "1.0.10", ["brew"])
        self.assertIsNotNone(result_no_update)
        self.assertFalse(result_no_update["is_update_available"])

        # Case 2: packaging library import fails (fallback to string comparison)
        # For this, we need to simulate the ImportError for 'packaging.version' inside the function
        with patch.dict('sys.modules', {'packaging.version': None, 'packaging': None}): # Simulate packaging module not being available
            pmi.TOOL_TO_PM_PACKAGE_MAP['mytool_lexical'] = {'brew': 'mytool-lex'}
            self.mock_run_pm_command.return_value = ("mytool-lex: stable 1.2\n", "")
            result_lex = pmi.get_latest_version_and_update_command("mytool_lexical", "MyToolLex", "1.11", ["brew"]) # "1.2" > "1.11" lexicographically
            self.assertIsNotNone(result_lex)
            self.assertTrue(result_lex["is_update_available"])

            self.mock_run_pm_command.return_value = ("mytool-lex: stable 2.0\n", "")
            result_lex_major = pmi.get_latest_version_and_update_command("mytool_lexical", "MyToolLex", "1.9.9", ["brew"])
            self.assertIsNotNone(result_lex_major)
            self.assertTrue(result_lex_major["is_update_available"]) # "2.0" > "1.9.9"

            del pmi.TOOL_TO_PM_PACKAGE_MAP['mytool_lexical']

        # Restore original map if it existed, otherwise remove the test key
        if original_tool_map is not None:
            pmi.TOOL_TO_PM_PACKAGE_MAP["mytool_id_version_test"] = original_tool_map
        else:
            del pmi.TOOL_TO_PM_PACKAGE_MAP["mytool_id_version_test"]

if __name__ == '__main__':
    unittest.main()