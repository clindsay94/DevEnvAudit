"""
Detects installed package managers and queries them for latest versions and update commands.
"""
import platform
import subprocess
import re
import logging
import shutil # For shutil.which

logger = logging.getLogger(__name__)

# Structure for package manager commands
# { 'name': 'readable_name', 'detection_command': ['cmd', '--version'], 'list_command': ..., 'search_command_template': ..., 'update_command_template': ...}
# For search/update, use {package_name} as placeholder

PACKAGE_MANAGERS = {
    "winget": {
        "name": "Winget",
        "detection_exe": "winget",
        "version_args": ["--version"], # winget --version
        "list_installed_cmd": ["winget", "list"], # [6, 42]
        "search_latest_cmd_template": ["winget", "search", "--exact", "{package_name}"], # winget search --exact <package_id>
        "update_cmd_template": ["winget", "upgrade", "--exact", "{package_name}"],
        "os": ["Windows"]
    },
    "choco": {
        "name": "Chocolatey",
        "detection_exe": "choco",
        "version_args": ["--version"], # choco --version or choco -v
        "list_installed_cmd": ["choco", "list", "--local-only"], # [11, 20, 27]
        "search_latest_cmd_template": ["choco", "search", "{package_name}", "--exact"], # choco search <package_id> --exact
        "update_cmd_template": ["choco", "upgrade", "{package_name}", "-y"],
        "os": ["Windows"]
    },
    "scoop": {
        "name": "Scoop",
        "detection_exe": "scoop",
        "version_args": ["--version"], # scoop --version
        "list_installed_cmd": ["scoop", "list"],
        "search_latest_cmd_template": ["scoop", "search", "{package_name}"], # scoop search <package_name> (exactness varies)
        "update_cmd_template": ["scoop", "update", "{package_name}"],
        "os": ["Windows"]
    },
    "brew": {
        "name": "Homebrew",
        "detection_exe": "brew",
        "version_args": ["--version"],
        "list_installed_cmd": ["brew", "list", "--versions"], # [4, 7, 21]
        "search_latest_cmd_template": ["brew", "info", "{package_name}"], # brew info <formula>
        "update_cmd_template": ["brew", "upgrade", "{package_name}"],
        "os": ["Darwin", "Linux"] # Linuxbrew
    },
    "apt": {
        "name": "APT",
        "detection_exe": "apt-get", # apt itself is often a script, apt-get is more fundamental
        "version_args": ["--version"],
        # apt list --installed {package_name} is better for specific check
        "search_latest_cmd_template": ["apt-cache", "policy", "{package_name}"], # apt-cache policy <package_name> or apt show <package_name>
        "update_cmd_template": ["sudo", "apt", "install", "--only-upgrade", "{package_name}"], # Or apt upgrade {package_name}
        "os": ["Linux"]
    },
    "dnf": {
        "name": "DNF",
        "detection_exe": "dnf",
        "version_args": ["--version"],
        "list_installed_cmd": ["dnf", "list", "installed"], # [10, 30, 33]
        "search_latest_cmd_template": ["dnf", "info", "{package_name}"], # dnf info <package_name>
        "update_cmd_template": ["sudo", "dnf", "upgrade", "-y", "{package_name}"],
        "os": ["Linux"]
    },
    "yum": {
        "name": "YUM",
        "detection_exe": "yum",
        "version_args": ["--version"],
        "list_installed_cmd": ["yum", "list", "installed"], # [12, 17, 22, 25]
        "search_latest_cmd_template": ["yum", "info", "{package_name}"], # yum info <package_name>
        "update_cmd_template": ["sudo", "yum", "update", "-y", "{package_name}"],
        "os": ["Linux"]
    },
    "pacman": {
        "name": "Pacman",
        "detection_exe": "pacman",
        "version_args": ["--version"],
        "list_installed_cmd": ["pacman", "-Q"], # [1, 5, 34]
        "search_latest_cmd_template": ["pacman", "-Si", "{package_name}"], # pacman -Si <package_name> (sync DB info)
        "update_cmd_template": ["sudo", "pacman", "-Syu", "{package_name}"], # This updates all then installs, or just -S for specific
        "os": ["Linux"]
    },
    "snap": {
        "name": "Snap",
        "detection_exe": "snap",
        "version_args": ["--version"], # snap version
        "list_installed_cmd": ["snap", "list"], # [3, 9, 35]
        "search_latest_cmd_template": ["snap", "info", "{package_name}"], # snap info <snap_name>
        "update_cmd_template": ["sudo", "snap", "refresh", "{package_name}"],
        "os": ["Linux"]
    },
    "flatpak": {
        "name": "Flatpak",
        "detection_exe": "flatpak",
        "version_args": ["--version"],
        "list_installed_cmd": ["flatpak", "list"], # [1, 14, 36]
        "search_latest_cmd_template": ["flatpak", "remote-info", "--user", "flathub", "{package_id}"], # Assumes flathub, package_id is like org.example.App
        "update_cmd_template": ["flatpak", "update", "-y", "--user", "{package_id}"], # For user installation
        "os": ["Linux"]
    }
}

# Tool name to package manager ID mapping (heuristic, can be complex)
# This mapping helps find the right package name for a given tool.
# Key: lowercase tool ID from scan_logic.TOOLS_DB
# Value: dict of {package_manager_id: package_name_in_that_pm}
TOOL_TO_PM_PACKAGE_MAP = {
    "python": {"apt": "python3", "brew": "python3", "choco": "python3", "winget": "Python.Python.3"},
    "pip": {"apt": "python3-pip", "brew": "python3", "choco": "python3"}, # pip comes with python
    "java": { # This is tricky due to JDK/JRE and vendors
        "apt": "openjdk-17-jdk", "brew": "openjdk@17", "choco": "openjdk",
        "winget": "Oracle.JavaRuntimeEnvironment" # Example, many Javas in winget
    },
    "node": {"apt": "nodejs", "brew": "node", "choco": "nodejs", "winget": "OpenJS.NodeJS"},
    "npm": {"apt": "npm", "brew": "node", "choco": "nodejs"}, # Comes with node
    "git": {"apt": "git", "brew": "git", "choco": "git", "winget": "Git.Git"},
    "docker": {"apt": "docker-ce", "brew": "docker", "choco": "docker-desktop", "winget": "Docker.DockerDesktop"},
    "kubectl": {"apt": "kubectl", "brew": "kubernetes-cli", "choco": "kubernetes-cli", "winget": "Kubernetes.kubectl"},
    "vscode": {"snap": "code", "brew": "visual-studio-code", "choco": "vscode", "winget": "Microsoft.VisualStudioCode"},
    "maven": {"apt": "maven", "brew": "maven", "choco": "maven", "winget": "Apache.Maven"},
    "gradle": {"apt": "gradle", "brew": "gradle", "choco": "gradle", "winget": "Gradle.Gradle"},
    "aws_cli": {"apt": "awscli", "brew": "awscli", "choco": "awscli", "winget": "Amazon.AWSCLI"},
    "azure_cli": {"apt": "azure-cli", "brew": "azure-cli", "choco": "azure-cli", "winget": "Microsoft.AzureCLI"},
    "gcloud_sdk": {"apt": "google-cloud-sdk", "brew": "google-cloud-sdk", "choco": "gcloudsdk", "snap": "google-cloud-cli"},
    # Add more mappings
}


def _run_pm_command(command_parts, timeout=15):
    """Runs a package manager command."""
    try:
        logger.debug(f"Running PM command: {' '.join(command_parts)}")
        # For Linux commands that might need sudo, it's better to inform the user to run the app with sudo
        # or provide copyable commands. Auto-sudo is risky.
        # However, for read-only commands like search/list, sudo is usually not needed.
        process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        stdout, stderr = process.communicate(timeout=timeout)
        if process.returncode != 0:
            logger.warning(f"PM Command '{' '.join(command_parts)}' failed with code {process.returncode}. Stderr: {stderr.strip()}")
            return None, stderr # Return stderr for parsing if version is there
        return stdout, stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"PM Command '{' '.join(command_parts)}' timed out.")
        return None, "TimeoutExpired"
    except FileNotFoundError:
        logger.warning(f"PM Command not found: {command_parts[0]}")
        return None, "FileNotFoundError"
    except Exception as e:
        logger.error(f"Error running PM command '{' '.join(command_parts)}': {e}")
        return None, str(e)

def detect_package_managers():
    """
    Detects available package managers on the system.
    Returns:
        dict: A dictionary of detected package manager IDs and their full path.
              e.g., {"brew": "/usr/local/bin/brew"}
    """
    detected_pms = {}
    current_os = platform.system()
    for pm_id, pm_config in PACKAGE_MANAGERS.items():
        if current_os in pm_config["os"]:
            exe_path = shutil.which(pm_config["detection_exe"])
            if exe_path:
                detected_pms[pm_id] = {"name": pm_config["name"], "path": exe_path}
                logger.info(f"Detected package manager: {pm_config['name']} at {exe_path}")
    return detected_pms

def get_pm_package_name(tool_id, pm_id):
    """
    Gets the package name for a tool in a specific package manager.
    Args:
        tool_id (str): The internal ID of the tool (e.g., "python", "vscode").
        pm_id (str): The ID of the package manager (e.g., "apt", "brew").
    Returns:
        str or None: The package name if found, else None.
    """
    return TOOL_TO_PM_PACKAGE_MAP.get(tool_id, {}).get(pm_id)


def parse_version_from_output(output, pm_id, package_name_in_pm):
    """
    Parses the latest version from package manager command output.
    This is highly specific to each package manager's output format.
    Args:
        output (str): The stdout from the package manager command.
        pm_id (str): The package manager ID (e.g., "apt", "brew").
        package_name_in_pm (str): The name of the package as known by the PM.
    Returns:
        str or None: The latest version string, or None if not found.
    """
    if not output:
        return None

    logger.debug(f"Parsing version for '{package_name_in_pm}' from {pm_id} output:\n{output[:500]}")

    version = None
    if pm_id == "winget": # Example: Name Id Version Available Source
                         #        -----------------------------------------------------------
                         #        Python 3 Python.Python.3 3.9.7 3.9.150.0 winget
        # winget search output:
        # Name        Id               Version Matched By
        # --------------------------------------------------
        # Python 3.11 Python.Python.3.11 3.11.4  Moniker
        # Python 3.10 Python.Python.3.10 3.10.11 Moniker
        # ...
        # We need to find the exact package_name_in_pm (Id)
        lines = output.strip().split('\n')
        header_found = False
        id_col, version_col = -1, -1

        for line in lines:
            if "Id" in line and "Version" in line: # Header
                header_found = True
                parts = [p.strip() for p in re.split(r'\s{2,}', line)] # Split by 2+ spaces
                try:
                    id_col = parts.index("Id")
                    version_col = parts.index("Version")
                except ValueError:
                    logger.warning(f"Could not find Id/Version columns in winget output: {line}")
                    return None
                continue

            if header_found and id_col != -1 and version_col != -1:
                parts = [p.strip() for p in re.split(r'\s{2,}', line)]
                if len(parts) > max(id_col, version_col) and parts[id_col] == package_name_in_pm:
                    version = parts[version_col]
                    break
        if not version: logger.debug(f"Winget: No exact match for ID '{package_name_in_pm}' or version not found.")


    elif pm_id == "choco": # choco search <pkg> --exact
                           # <package_name_in_pm>|<version>
        match = re.search(rf"^{re.escape(package_name_in_pm)}\|([0-9a-zA-Z\.\-]+)", output, re.MULTILINE)
        if match:
            version = match.group(1)

    elif pm_id == "scoop": # scoop search <pkg> -> often shows <name> (<version>)
        # This is less reliable as scoop search isn't always exact.
        # `scoop info <pkg>` might be better but `search` is for discovery.
        # Assuming package_name_in_pm is the exact name.
        match = re.search(rf"{re.escape(package_name_in_pm)}\s+\(([0-9a-zA-Z\.\-]+)\)", output)
        if match:
            version = match.group(1)

    elif pm_id == "brew": # brew info <formula>
                          # Output: <formula>: stable <version>, HEAD
        match = re.search(rf"{re.escape(package_name_in_pm)}: stable\s+([0-9a-zA-Z\.\-]+)", output)
        if not match: # Sometimes it's just <formula> <version>
             match = re.search(rf"^{re.escape(package_name_in_pm)}\s+([0-9]+\.[0-9]+(?:[\.\_][0-9a-zA-Z]+)*)", output, re.MULTILINE) # e.g., python@3.11: 3.11.4
        if match:
            version = match.group(1)

    elif pm_id == "apt": # apt-cache policy <package_name>
                         # Candidate: <version>
        match = re.search(r"Candidate:\s*([0-9a-zA-Z\.\-\+\~\:]+)", output)
        if match:
            version = match.group(1)
        else: # Try apt show <package_name>
            match = re.search(r"Version:\s*([0-9a-zA-Z\.\-\+\~\:]+)", output)
            if match:
                version = match.group(1)


    elif pm_id == "dnf" or pm_id == "yum": # dnf info <package_name> or yum info <package_name>
                                          # Version      : <version>
        match = re.search(r"Version\s*:\s*([0-9a-zA-Z\.\-]+)", output)
        if match:
            version = match.group(1)

    elif pm_id == "pacman": # pacman -Si <package_name>
                            # Version           : <version>
        match = re.search(r"Version\s*:\s*([0-9a-zA-Z\.\-]+)", output)
        if match:
            version = match.group(1)

    elif pm_id == "snap": # snap info <snap_name>
                          # latest/stable: <version>
        match = re.search(r"latest/stable:\s*([0-9a-zA-Z\.\-]+)\s*", output) # Tracks a channel
        if not match: # or version: <version>
            match = re.search(r"version:\s*([0-9a-zA-Z\.\-]+)", output)
        if match:
            version = match.group(1)

    elif pm_id == "flatpak": # flatpak remote-info flathub <app_id>
                             # Version: <version>
        match = re.search(r"Version:\s*([0-9a-zA-Z\.\-]+)", output)
        if match:
            version = match.group(1)

    if version:
        logger.info(f"Parsed version for '{package_name_in_pm}' via {pm_id}: {version}")
    else:
        logger.warning(f"Could not parse version for '{package_name_in_pm}' via {pm_id} from output.")

    return version


def get_latest_version_and_update_command(tool_id, tool_name, installed_version, preferred_pms_os_specific):
    """
    Queries preferred package managers for the latest version of a given tool and its update command.

    Args:
        tool_id (str): The internal ID of the tool (e.g., "python").
        tool_name (str): The display name of the tool (e.g., "Python").
        installed_version (str): The currently installed version.
        preferred_pms_os_specific (list): List of preferred package manager IDs for the current OS.

    Returns:
        dict or None: A dictionary with 'latest_version', 'package_manager', 'update_command',
                      'package_name_in_pm' if an update is found, else None.
    """
    logger.debug(f"Checking updates for {tool_name} (ID: {tool_id}, Installed: {installed_version}) via {preferred_pms_os_specific}")
    detected_system_pms = detect_package_managers() # Get paths to PMs

    for pm_id in preferred_pms_os_specific:
        if pm_id not in PACKAGE_MANAGERS or pm_id not in detected_system_pms:
            logger.debug(f"Skipping {pm_id}: not configured or not detected on system.")
            continue

        pm_config = PACKAGE_MANAGERS[pm_id]
        package_name_in_pm = get_pm_package_name(tool_id, pm_id)

        if not package_name_in_pm:
            logger.debug(f"No package mapping for tool '{tool_id}' in package manager '{pm_id}'.")
            continue

        logger.info(f"Querying {pm_config['name']} for {tool_name} (package: {package_name_in_pm})...")

        search_cmd_template = pm_config.get("search_latest_cmd_template")
        if not search_cmd_template:
            logger.warning(f"No search command template for {pm_id}.")
            continue

        search_cmd = [part.replace("{package_name}", package_name_in_pm).replace("{package_id}", package_name_in_pm) for part in search_cmd_template]

        # Prepend PM executable path if not already in command
        if not any(pm_config["detection_exe"] in part for part in search_cmd):
             search_cmd.insert(0, detected_system_pms[pm_id]["path"])

        stdout, _ = _run_pm_command(search_cmd)

        if stdout:
            latest_version = parse_version_from_output(stdout, pm_id, package_name_in_pm)
            if latest_version:
                update_command_template = pm_config.get("update_cmd_template")
                update_cmd_str = ""
                if update_command_template:
                    # Construct the update command string, ensuring the PM executable is present
                    base_cmd_parts = [part.replace("{package_name}", package_name_in_pm).replace("{package_id}", package_name_in_pm) for part in update_command_template]
                    if not any(pm_config["detection_exe"] in part for part in base_cmd_parts):
                        update_cmd_str = f"{pm_config['detection_exe']} {' '.join(base_cmd_parts)}"
                    else:
                        update_cmd_str = ' '.join(base_cmd_parts)


                # Basic version comparison (can be improved with packaging library for semantic versioning)
                is_update_available = False
                if installed_version and latest_version and installed_version != "Unknown":
                    try:
                        from packaging.version import parse as parse_version # Keep import here for clarity
                        if parse_version(latest_version) > parse_version(installed_version):
                            is_update_available = True
                    except ImportError:
                        logger.warning("The 'packaging' library is not installed. Falling back to string comparison for versions. Run 'pip install packaging' for more accurate version handling.")
                        if latest_version > installed_version: # Lexicographical
                            is_update_available = True
                    except Exception as e_parse: # Handles packaging.version.InvalidVersion and other parsing errors
                        logger.warning(f"Could not parse/compare versions '{installed_version}' and '{latest_version}' using packaging.version: {e_parse}. Falling back to string comparison.")
                        if latest_version > installed_version: # Lexicographical
                            is_update_available = True
                elif not installed_version or installed_version == "Unknown":
                    is_update_available = True

                return {
                    "latest_version": latest_version,
                    "package_manager_id": pm_id,
                    "package_manager_name": pm_config["name"],
                    "update_command": update_cmd_str,
                    "package_name_in_pm": package_name_in_pm,
                    "is_update_available": is_update_available
                }
        else:
            logger.debug(f"No output from {pm_id} for package {package_name_in_pm}.")

    logger.info(f"No update information found for {tool_name} via preferred package managers.")
    return None


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    print("Detected Package Managers:")
    detected_pms = detect_package_managers()
    for pm_id, pm_info in detected_pms.items():
        print(f"- {pm_info['name']} (ID: {pm_id}) at {pm_info['path']}")

    # Example: Test getting latest version for Git
    # Ensure you have some of these PMs installed to test effectively
    current_os_type = platform.system()
    if current_os_type == "Windows":
        prefs = ["winget", "choco"]
    elif current_os_type == "Darwin":
        prefs = ["brew"]
    else: # Linux
        prefs = ["apt", "snap"] # Example, adjust to your system

    print(f"\nTesting update check for Git on {current_os_type} using {prefs}...")
    # First, try to get installed Git version (mocked or use scan_logic if available)
    # For standalone test, assume a version or "Unknown"
    installed_git_version = "2.30.0" # Mock installed version

    # Try to find git using scan_logic's method (if it were here) or mock it
    git_tool_id = "git"
    git_tool_name = "Git"

    update_info = get_latest_version_and_update_command(git_tool_id, git_tool_name, installed_git_version, prefs)

    if update_info:
        print("\nUpdate Information for Git:")
        print(f"  Package Name in PM: {update_info['package_name_in_pm']}")
        print(f"  Latest Version: {update_info['latest_version']}")
        print(f"  Package Manager: {update_info['package_manager_name']}")
        print(f"  Update Command: {update_info['update_command']}")
        print(f"  Update Available: {update_info['is_update_available']}")
    else:
        print("\nNo update information found for Git via preferred package managers.")

    # Example for a tool that might not be installed or has complex naming
    print(f"\nTesting update check for 'NonExistentTool'...")
    update_info_nonexistent = get_latest_version_and_update_command("nonexistenttool", "NonExistentTool", "1.0", prefs)
    if update_info_nonexistent:
        print(f"  Found something for NonExistentTool (unexpected): {update_info_nonexistent}")
    else:
        print("  Correctly found no update info for NonExistentTool.")