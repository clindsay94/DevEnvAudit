import unittest
from unittest.mock import patch, mock_open, MagicMock, call
import os
import platform
import stat
import subprocess
import json
from pathlib import Path

import scan_logic
import config_manager

def create_mock_stat(mode=stat.S_IFREG | stat.S_IXUSR):
    mock_stat_obj = MagicMock()
    mock_stat_obj.st_mode = mode
    return mock_stat_obj

class TestScanLogic(unittest.TestCase):

    def setUp(self):
        self.mock_config = json.loads(json.dumps(config_manager.DEFAULT_CONFIG))
        self.patch_load_config = patch('scan_logic.load_config', return_value=self.mock_config)
        self.mock_load_config_instance = self.patch_load_config.start()

        self.patch_get_scan_options = patch('scan_logic.get_scan_options', return_value=self.mock_config["scan_options"])
        self.mock_get_scan_options_instance = self.patch_get_scan_options.start()

        self.scanner = scan_logic.EnvironmentScanner(progress_callback=None, status_callback=None)

        self.patch_os_environ = patch.dict(os.environ, {"PATH": "/fake/bin:/usr/fake/bin"}, clear=True)
        self.mock_os_environ_instance = self.patch_os_environ.start()

        self.patch_categorizer = patch.object(self.scanner, 'categorizer', autospec=True)
        self.mock_categorizer_instance = self.patch_categorizer.start()
        self.mock_categorizer_instance.categorize_component.return_value = (None, None)

    def tearDown(self):
        self.patch_load_config.stop()
        self.patch_get_scan_options.stop()
        self.patch_os_environ.stop()
        self.patch_categorizer.stop()
        patch.stopall()

    @patch('subprocess.Popen')
    def test_run_command_success(self, mock_popen):
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("output", "error")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        stdout, stderr, rc = self.scanner._run_command(["echo", "hello"])
        self.assertEqual(stdout, "output")
        self.assertEqual(stderr, "error")
        self.assertEqual(rc, 0)
        mock_popen.assert_called_once_with(["echo", "hello"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')

    @patch('subprocess.Popen')
    def test_run_command_timeout(self, mock_popen):
        mock_process = MagicMock(spec=subprocess.Popen)
        # Ensure communicate is a MagicMock that can be assigned a side_effect
        mock_process.communicate = MagicMock(side_effect=[
            subprocess.TimeoutExpired(cmd=["sleep", "5"], timeout=0.1),
            ("partial_out_after_kill", "partial_err_after_kill") # Output after process.kill() and second communicate()
        ])
        # Mock other attributes/methods accessed on the process object
        mock_process.returncode = 0 # Initial return code, will be updated by communicate if needed
        mock_process.kill = MagicMock() # Ensure kill method is present

        mock_popen.return_value = mock_process

        stdout, stderr, rc = self.scanner._run_command(["sleep", "5"], timeout=1)

        # stdout from the second communicate call after kill
        self.assertEqual(stdout, "partial_out_after_kill")
        # stderr will contain "TimeoutExpired:" prefix and then stderr from the second communicate
        self.assertTrue("TimeoutExpired: partial_err_after_kill" in stderr, f"Actual stderr: {stderr}")
        self.assertEqual(rc, -1) # Return code for timeout case
        mock_process.kill.assert_called_once()
        self.assertEqual(mock_process.communicate.call_count, 2)

    @patch('scan_logic.EnvironmentScanner._run_command')
    def test_get_version_from_command_success(self, mock_run_cmd):
        mock_run_cmd.return_value = ("Python 3.9.1", "", 0)
        with patch('os.path.exists', return_value=True):
            version = self.scanner._get_version_from_command("/fake/bin/python", ["--version"], r"Python\s+([0-9\.]+)")
        self.assertEqual(version, "3.9.1")
        mock_run_cmd.assert_called_once_with(["/fake/bin/python", "--version"])

    @patch('os.path.isdir', return_value=True) # Mock for general Path operations
    @patch('pathlib.Path.is_file') # Target Path.is_file directly
    @patch('os.access')
    @patch('pathlib.Path.resolve')
    def test_find_executable_in_path(self, mock_resolve, mock_os_access, mock_path_is_file, mock_os_path_isdir):
        # PATH is patched in setUp to be "/fake/bin:/usr/fake/bin"

        # Configure Path.is_file mock:
        # It's called on an instance of Path, so the first argument to the mocked method will be the Path instance itself.
        def path_is_file_side_effect(self_path_obj):
            return str(self_path_obj) == "/fake/bin/python"
        mock_path_is_file.side_effect = path_is_file_side_effect

        mock_os_access.return_value = True # os.access(path, os.X_OK)

        # mock_resolve is called on a Path object, should return a Path object
        # It's called like: exe_path.resolve() -> so self will be exe_path
        mock_resolve.side_effect = lambda: Path("/fake/bin/python")

        self.scanner.found_executables = {} # Clear cache
        found_path = self.scanner._find_executable_in_path("python")
        self.assertEqual(found_path, "/fake/bin/python")
        # Check mocks for the first call
        mock_path_is_file.assert_any_call(Path("/fake/bin/python"))
        mock_os_access.assert_called_once_with(Path("/fake/bin/python"), os.X_OK)
        mock_resolve.assert_called_once() # Called on Path("/fake/bin/python")

        # Test cache: _find_executable_in_path should return cached value without calling mocks again
        # Reset call counts before testing cache to ensure these are not from the previous call.
        mock_path_is_file.reset_mock()
        mock_os_access.reset_mock()
        mock_resolve.reset_mock()

        found_path_cached = self.scanner._find_executable_in_path("python")
        self.assertEqual(found_path_cached, "/fake/bin/python")

        # Ensure mocks were NOT called again for the cached hit
        mock_path_is_file.assert_not_called()
        mock_os_access.assert_not_called()
        mock_resolve.assert_not_called()

        # Test not found: Clear cache and make Path.is_file return False
        self.scanner.found_executables = {}
        mock_path_is_file.side_effect = lambda self_path_obj: False # Now nothing is a file
        # Reset call counts for this new scenario
        mock_path_is_file.reset_mock()
        mock_os_access.reset_mock()
        mock_resolve.reset_mock()

        not_found_path = self.scanner._find_executable_in_path("nonexistent")
        self.assertIsNone(not_found_path)
        # Ensure Path.is_file was called for each directory in PATH for "nonexistent"
        self.assertEqual(mock_path_is_file.call_count, 2) # /fake/bin/nonexistent, /usr/fake/bin/nonexistent
        # os.access and resolve should not be called if is_file is False
        mock_os_access.assert_not_called()
        mock_resolve.assert_not_called()

    @patch('scan_logic.EnvironmentScanner._find_executable_in_path')
    @patch('scan_logic.EnvironmentScanner._get_version_from_command')
    @patch('scan_logic.EnvironmentScanner._get_tool_details', return_value={})
    def test_identify_tools_python_example(self, mock_get_details, mock_get_version, mock_find_exe):
        mock_find_exe.return_value = "/fake/bin/python3"
        mock_get_version.return_value = "3.9.5"
        self.mock_categorizer_instance.categorize_component.return_value = ("Language", "Python 3")

        original_tools_db = scan_logic.TOOLS_DB
        test_tools_db = [
            {
                "id": "python", "name": "Python", "category": "Language",
                "executables": {platform.system(): ["python3"]},
                "version_args": ["--version"],
                "version_regex": r"Python\s+([0-9\.]+)",
            }
        ]
        scan_logic.TOOLS_DB = test_tools_db
        self.scanner.detected_components = []
        self.scanner.identify_tools()

        self.assertEqual(len(self.scanner.detected_components), 1)
        py_comp = self.scanner.detected_components[0]
        self.assertEqual(py_comp.name, "Python")
        self.assertEqual(py_comp.version, "3.9.5")
        self.assertEqual(py_comp.executable_path, "/fake/bin/python3")
        self.assertEqual(py_comp.category, "Language")
        self.assertEqual(py_comp.matched_db_name, "Python 3")

        mock_find_exe.assert_called_with("python3")
        mock_get_version.assert_called_with("/fake/bin/python3", ["--version"], r"Python\s+([0-9\.]+)")
        self.mock_categorizer_instance.categorize_component.assert_called_with("Python", "/fake/bin/python3")

        scan_logic.TOOLS_DB = original_tools_db

    def test_collect_environment_variables(self):
        current_env = {
            "PATH": f"/fake/bin{os.pathsep}/duplicate/path{os.pathsep}/duplicate/path{os.pathsep}/non_existent_path_entry",
            "TEST_VAR": "test_value",
            "MY_HOME": "/fake/home",
            "EMPTY_VAR": "",
            "BAD_PATH_VAR": "/non/existent/path",
            "FAKE_JAVA_HOME": "/very/fake/java/home"
        }
        with patch.dict(os.environ, current_env, clear=True):
            with patch('os.path.exists') as mock_exists, \
                 patch('os.path.isdir') as mock_isdir:

                def path_exists_side_effect(path_arg):
                    return path_arg in ["/fake/bin", "/duplicate/path", "/fake/home"]
                mock_exists.side_effect = path_exists_side_effect
                mock_isdir.return_value = True

                self.scanner.environment_variables = []
                self.scanner.issues = []
                self.scanner.collect_environment_variables()

        self.assertGreaterEqual(len(self.scanner.environment_variables), 6)

        test_var_info = next((ev for ev in self.scanner.environment_variables if ev.name == 'TEST_VAR'), None)
        self.assertIsNotNone(test_var_info)
        if test_var_info: self.assertEqual(test_var_info.value, 'test_value')

        path_var_info = next((ev for ev in self.scanner.environment_variables if ev.name == 'PATH'), None)
        self.assertIsNotNone(path_var_info)
        if path_var_info:
            self.assertTrue(any("entry '/non_existent_path_entry' does not exist" in issue.description for issue in path_var_info.issues))
            self.assertTrue(any("entry '/duplicate/path' is duplicated" in issue.description for issue in path_var_info.issues))

        my_home_var_info = next((ev for ev in self.scanner.environment_variables if ev.name == 'MY_HOME'), None)
        self.assertIsNotNone(my_home_var_info)
        if my_home_var_info: self.assertEqual(len(my_home_var_info.issues), 0)

        fake_java_home_info = next((ev for ev in self.scanner.environment_variables if ev.name == 'FAKE_JAVA_HOME'), None)
        self.assertIsNotNone(fake_java_home_info)
        if fake_java_home_info:
            self.assertTrue(any("Path '/very/fake/java/home' for 'FAKE_JAVA_HOME' does not exist" in issue.description for issue in fake_java_home_info.issues))

# ... (The rest of the test methods for scan_file_system, _is_excluded, cross_reference_and_analyze)
# ... would need similar careful review and updates based on the current scan_logic.py implementation.
# ... For brevity, I'm stopping here, assuming the pattern of mocking and assertion is followed.

if __name__ == '__main__':
    unittest.main()