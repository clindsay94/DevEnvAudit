"""
Manages loading from and saving to 'devenvaudit_config.json'.
Handles user-defined scan paths, inclusion/exclusion patterns,
the persistent ignore list, and user preferences for package managers.
"""
import json
import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Define the name for the configuration file
CONFIG_FILE_NAME = "devenvaudit_config.json"

# Determine the path for the configuration file (e.g., in user's home directory)
# This makes it persistent and user-specific.
APP_DATA_DIR_NAME = "DevEnvAudit" # Name of the folder in user's app data

def get_config_dir_path() -> str:
    """Gets the path to the directory where the config file should be stored."""
    if os.name == 'nt': # Windows
        base_path = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
    else: # macOS, Linux
        base_path = os.environ.get('XDG_CONFIG_HOME', os.path.join(os.path.expanduser('~'), '.config'))

    config_dir = os.path.join(base_path, APP_DATA_DIR_NAME)
    return config_dir

CONFIG_DIR_PATH = get_config_dir_path()
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, CONFIG_FILE_NAME)


DEFAULT_CONFIG: Dict[str, Any] = {
    "scan_options": {
        "scan_paths": ["~"],  # Default to user's home directory
        "excluded_paths": [
            "~/Library", "/System", "/private", "/var/log", "/tmp",
            "C:\\Windows", "C:\\Program Files (x86)\\Common Files", "C:\\ProgramData\\Package Cache" # Common noisy/system paths
        ],
        "scan_env_vars": True,
        "cross_reference_tools": True, # e.g., check if JAVA_HOME points to a detected Java
        "perform_update_checks": True, # Check for updates using package managers
        "preferred_package_managers_windows": ["winget", "choco", "scoop"],
        "preferred_package_managers_linux": ["apt", "dnf", "yum", "pacman", "snap", "flatpak"],
        "preferred_package_managers_darwin": ["brew"],
        "executable_extensions": ['.exe', '.bat', '.cmd', '.sh', '.py', '.jar', '.msi', '.dmg', '.pkg'] # Added more
    },
    "logging": {
        "level": "INFO", # DEBUG, INFO, WARNING, ERROR, CRITICAL
        "file": "devenvaudit.log" # Log file name (will be placed in CONFIG_DIR_PATH)
    },
    "ignored_tools_identifiers": [], # List of component IDs to ignore in reports
    "user_preferences": {
        "theme": "default",
        "always_show_details": False
    }
}

def _ensure_config_dir_exists():
    """Ensures the configuration directory exists. Creates it if not."""
    if not os.path.exists(CONFIG_DIR_PATH):
        try:
            os.makedirs(CONFIG_DIR_PATH)
            logger.info(f"Created configuration directory: {CONFIG_DIR_PATH}")
        except OSError as e:
            logger.error(f"Could not create configuration directory {CONFIG_DIR_PATH}: {e}")
            # Fallback or raise? For now, we'll log and continue; load_config will use defaults.


def load_config() -> Dict[str, Any]:
    """
    Reads 'devenvaudit_config.json', returns a dictionary of settings.
    Handles file not found by returning defaults and creating the file.
    Handles JSON decode errors by returning defaults and attempting to backup/overwrite.
    """
    _ensure_config_dir_exists() # Make sure directory exists before trying to read/write file

    if not os.path.exists(CONFIG_FILE_PATH):
        logger.warning(f"Configuration file not found at {CONFIG_FILE_PATH}. Creating with default settings.")
        save_config(DEFAULT_CONFIG) # Save defaults if file doesn't exist
        return DEFAULT_CONFIG.copy() # Return a copy of defaults

    try:
        with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
            loaded_settings = json.load(f)
            # TODO: Add schema validation or migration logic here if config structure changes
            logger.info(f"Configuration loaded successfully from {CONFIG_FILE_PATH}")
            return loaded_settings
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {CONFIG_FILE_PATH}: {e}. Backing up and using default settings.")
        backup_path = CONFIG_FILE_PATH + ".corrupt_backup"
        try:
            os.rename(CONFIG_FILE_PATH, backup_path)
            logger.info(f"Backed up corrupted config to {backup_path}")
        except OSError as backup_e:
            logger.error(f"Could not backup corrupted config file: {backup_e}")

        save_config(DEFAULT_CONFIG) # Save defaults to overwrite corrupted file
        return DEFAULT_CONFIG.copy()
    except Exception as e: # Catch other potential errors during file read
        logger.error(f"Failed to load configuration from {CONFIG_FILE_PATH} due to an unexpected error: {e}. Using default settings.", exc_info=True)
        return DEFAULT_CONFIG.copy()


def save_config(settings_dict: Dict[str, Any]) -> bool:
    """
    Writes the settings dictionary to 'devenvaudit_config.json'.

    Args:
        settings_dict (dict): The configuration dictionary to save.

    Returns:
        bool: True if save was successful, False otherwise.
    """
    _ensure_config_dir_exists()

    try:
        with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(settings_dict, f, indent=4)
        logger.info(f"Configuration saved successfully to {CONFIG_FILE_PATH}")
        return True
    except IOError as e:
        logger.error(f"Could not write configuration to {CONFIG_FILE_PATH}: {e}")
        return False
    except TypeError as e: # e.g. if settings_dict is not JSON serializable
        logger.error(f"Configuration data is not serializable (TypeError): {e}")
        return False

def get_scan_options() -> Dict[str, Any]:
    """Convenience function to get just the 'scan_options' part of the config."""
    config = load_config()
    return config.get("scan_options", DEFAULT_CONFIG["scan_options"])

def get_ignored_identifiers() -> List[str]:
    """Convenience function to get the list of ignored tool identifiers."""
    config = load_config()
    return config.get("ignored_tools_identifiers", DEFAULT_CONFIG["ignored_tools_identifiers"])

def add_to_ignored_identifiers(identifier: str):
    """Adds a tool identifier to the ignored list and saves the config."""
    config = load_config()
    if "ignored_tools_identifiers" not in config:
        config["ignored_tools_identifiers"] = []

    if identifier not in config["ignored_tools_identifiers"]:
        config["ignored_tools_identifiers"].append(identifier)
        save_config(config)
        logger.info(f"Added '{identifier}' to ignored tools list.")
    else:
        logger.info(f"'{identifier}' is already in the ignored tools list.")

def remove_from_ignored_identifiers(identifier: str):
    """Removes a tool identifier from the ignored list and saves the config."""
    config = load_config()
    if "ignored_tools_identifiers" in config and identifier in config["ignored_tools_identifiers"]:
        config["ignored_tools_identifiers"].remove(identifier)
        save_config(config)
        logger.info(f"Removed '{identifier}' from ignored tools list.")
    else:
        logger.warning(f"'{identifier}' not found in the ignored tools list.")

# Example of how to use it (optional, for direct testing of this module)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG) # Set to DEBUG for detailed output from this module

    print(f"Config file will be managed at: {CONFIG_FILE_PATH}")

    # Ensure directory exists for the test
    _ensure_config_dir_exists()

    # Test loading (will create default if not exists)
    current_settings = load_config()
    print("\nInitial or Loaded Settings:")
    print(json.dumps(current_settings, indent=4))

    # Test modifying and saving
    current_settings["user_preferences"]["theme"] = "dark_custom"
    current_settings["scan_options"]["perform_update_checks"] = False
    if save_config(current_settings):
        print("\nModified settings saved.")

        # Test reloading
        reloaded_settings = load_config()
        print("\nReloaded Settings:")
        print(json.dumps(reloaded_settings, indent=4))

        # Verify changes
        assert reloaded_settings["user_preferences"]["theme"] == "dark_custom"
        assert not reloaded_settings["scan_options"]["perform_update_checks"]
    else:
        print("\nFailed to save modified settings.")

    # Test scan options retrieval
    scan_opts = get_scan_options()
    print("\nScan Options:")
    print(json.dumps(scan_opts, indent=4))

    # Test ignored identifiers
    print("\nTesting ignored identifiers:")
    add_to_ignored_identifiers("python_3.9_system")
    add_to_ignored_identifiers("vscode_1.80_user")
    add_to_ignored_identifiers("python_3.9_system") # Test adding duplicate
    print(f"Current ignored list: {get_ignored_identifiers()}")
    remove_from_ignored_identifiers("vscode_1.80_user")
    remove_from_ignored_identifiers("non_existent_tool") # Test removing non-existent
    print(f"Final ignored list: {get_ignored_identifiers()}")

    # Test with a potentially corrupted file (manual step: corrupt the JSON file, then run)
    # print("\nTesting resilience against corrupted config (manual step needed)...")
    # Manually corrupt devenvaudit_config.json here, then uncomment and run the load_config() below
    # corrupted_settings = load_config()
    # print("Settings after attempting to load corrupted file:")
    # print(json.dumps(corrupted_settings, indent=4))
    # assert corrupted_settings["user_preferences"]["theme"] == DEFAULT_CONFIG["user_preferences"]["theme"] # Should revert to default
    print("\nConfig manager tests complete.")
