import unittest
import os
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Ensure the config_manager module can be imported.
import config_manager # Assuming it's in PYTHONPATH or tests are run from project root

class TestConfigManager(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

        # Mock directory and file paths used by config_manager
        self.mock_config_dir_path = os.path.join(self.test_dir, "TestDevEnvAuditConfig")
        self.mock_config_file_path = os.path.join(self.mock_config_dir_path, config_manager.CONFIG_FILE_NAME)

        self.patch_config_dir = patch('config_manager.CONFIG_DIR_PATH', self.mock_config_dir_path)
        self.patch_config_file = patch('config_manager.CONFIG_FILE_PATH', self.mock_config_file_path)

        self.mock_config_dir = self.patch_config_dir.start()
        self.mock_file = self.patch_config_file.start()

        # Make a pristine copy of DEFAULT_CONFIG for each test
        self.original_default_config = config_manager.DEFAULT_CONFIG.copy()
        # Ensure nested dictionaries are also copied deeply if they exist and are mutable
        config_manager.DEFAULT_CONFIG = json.loads(json.dumps(self.original_default_config)) # Deep copy via JSON


    def tearDown(self):
        self.patch_config_dir.stop()
        self.patch_config_file.stop()
        shutil.rmtree(self.test_dir)
        # Restore original DEFAULT_CONFIG
        config_manager.DEFAULT_CONFIG = self.original_default_config

    def test_ensure_config_dir_exists_creates_dir(self):
        if os.path.exists(self.mock_config_dir_path):
            shutil.rmtree(self.mock_config_dir_path)
        self.assertFalse(os.path.exists(self.mock_config_dir_path))
        config_manager.load_config()
        self.assertTrue(os.path.exists(self.mock_config_dir_path))

    def test_load_config_creates_default_if_not_exists(self):
        os.makedirs(self.mock_config_dir_path, exist_ok=True)
        if os.path.exists(self.mock_config_file_path):
            os.remove(self.mock_config_file_path)

        self.assertFalse(os.path.exists(self.mock_config_file_path))
        cfg = config_manager.load_config()
        self.assertTrue(os.path.exists(self.mock_config_file_path))
        self.assertEqual(cfg, config_manager.DEFAULT_CONFIG)
        with open(self.mock_config_file_path, 'r') as f:
            on_disk_cfg = json.load(f)
        self.assertEqual(on_disk_cfg, config_manager.DEFAULT_CONFIG)

    def test_save_and_load_config(self):
        test_settings = json.loads(json.dumps(config_manager.DEFAULT_CONFIG)) # Deep copy
        test_settings["scan_options"]["scan_paths"] = ["/test/path"]
        test_settings["scan_options"]["excluded_paths"].append("*.tmp")
        test_settings["ignored_tools_identifiers"] = ["tool_a", "tool_b"]
        test_settings["user_preferences"]["theme"] = "dark_test"

        config_manager.save_config(test_settings)
        self.assertTrue(os.path.exists(self.mock_config_file_path))

        loaded_cfg = config_manager.load_config()
        self.assertEqual(loaded_cfg["scan_options"]["scan_paths"], ["/test/path"])
        self.assertIn("*.tmp", loaded_cfg["scan_options"]["excluded_paths"])
        self.assertEqual(loaded_cfg["ignored_tools_identifiers"], ["tool_a", "tool_b"])
        self.assertEqual(loaded_cfg["user_preferences"]["theme"], "dark_test")
        self.assertEqual(loaded_cfg["logging"], config_manager.DEFAULT_CONFIG["logging"])

    def test_load_config_handles_json_decode_error(self):
        os.makedirs(self.mock_config_dir_path, exist_ok=True)
        with open(self.mock_config_file_path, 'w') as f:
            f.write("{corrupted_json: ")

        cfg = config_manager.load_config()
        self.assertEqual(cfg, config_manager.DEFAULT_CONFIG)
        self.assertTrue(os.path.exists(self.mock_config_file_path + ".corrupt_backup"))

    def test_get_scan_options(self):
        cfg = config_manager.load_config()
        scan_options = config_manager.get_scan_options()
        self.assertEqual(scan_options, config_manager.DEFAULT_CONFIG["scan_options"])

        modified_cfg = json.loads(json.dumps(cfg)) # Deep copy
        modified_cfg["scan_options"]["perform_update_checks"] = False
        config_manager.save_config(modified_cfg)

        reloaded_scan_options = config_manager.get_scan_options()
        self.assertFalse(reloaded_scan_options["perform_update_checks"])

    def test_add_remove_ignored_identifiers(self):
        config_manager.load_config()
        self.assertEqual(config_manager.get_ignored_identifiers(), [])

        config_manager.add_to_ignored_identifiers("tool_id_1")
        self.assertIn("tool_id_1", config_manager.get_ignored_identifiers())

        config_manager.add_to_ignored_identifiers("tool_id_1")
        self.assertEqual(config_manager.get_ignored_identifiers().count("tool_id_1"), 1)
        self.assertEqual(len(config_manager.get_ignored_identifiers()), 1)

        config_manager.add_to_ignored_identifiers("tool_id_2")
        self.assertIn("tool_id_2", config_manager.get_ignored_identifiers())
        self.assertEqual(len(config_manager.get_ignored_identifiers()), 2)

        config_manager.remove_from_ignored_identifiers("tool_id_1")
        self.assertNotIn("tool_id_1", config_manager.get_ignored_identifiers())
        self.assertEqual(len(config_manager.get_ignored_identifiers()), 1)

        config_manager.remove_from_ignored_identifiers("tool_id_non_existent")
        self.assertEqual(len(config_manager.get_ignored_identifiers()), 1)

    def test_load_config_does_not_deep_merge_by_default(self):
        os.makedirs(self.mock_config_dir_path, exist_ok=True)
        partial_config = {
            "scan_options": {
                "scan_paths": ["/custom/only"],
            },
            "ignored_tools_identifiers": ["partial_tool"]
        }
        with open(self.mock_config_file_path, 'w') as f:
            json.dump(partial_config, f, indent=4)

        loaded_config = config_manager.load_config()

        self.assertEqual(loaded_config["scan_options"]["scan_paths"], ["/custom/only"])
        self.assertNotIn("excluded_paths", loaded_config["scan_options"])
        self.assertNotIn("logging", loaded_config)
        self.assertEqual(loaded_config["ignored_tools_identifiers"], ["partial_tool"])

if __name__ == '__main__':
    unittest.main()