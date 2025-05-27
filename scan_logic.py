import os
import platform
import subprocess
import re
import logging
import fnmatch
import stat
from pathlib import Path
import json # For parsing specific config files if needed
if platform.system() == "Windows":
    import winreg # Keep for potential future use, though not used in current logic
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

from config_manager import load_config, get_scan_options, CONFIG_FILE_PATH # Assuming config_manager.py is in the same directory or PYTHONPATH

logger = logging.getLogger(__name__)

# --- Constants ---
SOFTWARE_CATEGORIZATION_DB_PATH = os.path.join(os.path.dirname(__file__), "software_categorization_database.json") # Corrected filename

# Placeholder for TOOLS_DB - This needs to be populated with actual tool definitions
# as per your original specification for identify_tools to work correctly.
TOOLS_DB = [
    {
        "id": "python", "name": "Python", "category": "Language",
        "executables": {"Windows": ["python.exe", "python3.exe"], "Linux": ["python", "python3"], "Darwin": ["python", "python3"]},
        "version_args": ["--version"],
        "version_regex": r"Python\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "env_vars": ["PYTHONHOME", "PYTHONPATH"],
        "related_files": ["Lib/site-packages"]
    },
    # Add many more tool definitions here based on your original detailed prompt
]

# Placeholder for SENSITIVE_ENV_VARS
SENSITIVE_ENV_VARS = ["API_KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
                      "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS"]


# --- Data Classes ---
@dataclass
class ScanIssue:
    description: str
    severity: str # e.g., "Critical", "Warning", "Info"
    category: Optional[str] = "General"
    component_id: Optional[str] = None # Link to a DetectedComponent ID
    related_path: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "description": self.description,
            "category": self.category,
            "component_id": self.component_id,
            "related_path": self.related_path,
            "recommendation": self.recommendation,
        }

@dataclass
class DetectedComponent:
    id: str # Unique identifier
    name: str
    category: Optional[str] = "Unknown"
    version: Optional[str] = "Unknown"
    path: Optional[str] = None # Installation path or main executable path
    executable_path: Optional[str] = None
    publisher: Optional[str] = None
    install_date: Optional[str] = None
    source_detection: Optional[str] = None # How this component was found
    matched_db_name: Optional[str] = None # Specific name from categorization DB
    details: Dict[str, Any] = field(default_factory=dict)
    issues: List[ScanIssue] = field(default_factory=list)
    update_info: Optional[Dict[str, Any]] = None # From package_manager_integrator

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "path": self.path,
            "executable_path": self.executable_path,
            "publisher": self.publisher,
            "install_date": self.install_date,
            "source_detection": self.source_detection,
            "matched_db_name": self.matched_db_name,
            "details": self.details,
            "issues": [issue.to_dict() for issue in self.issues],
            "update_info": self.update_info,
        }

@dataclass
class EnvironmentVariableInfo:
    name: str
    value: str
    scope: str = "active_session" # e.g., "User", "System", "active_session"
    issues: List[ScanIssue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "scope": self.scope,
            "issues": [issue.to_dict() for issue in self.issues]
        }


class SoftwareCategorizer:
    def __init__(self, db_path: str = SOFTWARE_CATEGORIZATION_DB_PATH):
        self.db_path = db_path
        self.categorization_data: Dict[str, List[Dict[str, Any]]] = self._load_database()
        if not self.categorization_data:
            logger.warning("Software categorization database is empty or failed to load. Categorization will be limited.")

    def _load_database(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                content = f.read()
                json_start_index = content.find('{')
                if json_start_index == -1:
                    logger.error(f"Categorization DB {self.db_path} does not appear to contain valid JSON.")
                    return {}

                json_content = content[json_start_index:]
                data = json.loads(json_content)

                normalized_data: Dict[str, List[Dict[str, Any]]] = {}
                for category_name, entries in data.items():
                    if (isinstance(entries, list) and entries and
                        isinstance(entries[0], dict) and "category" in entries[0] and "items" in entries[0]):
                        for sub_category_group in entries:
                            sub_cat_name = sub_category_group.get("category", "Unknown Sub-Category")
                            full_cat_name = f"{category_name} - {sub_cat_name}"
                            normalized_data[full_cat_name] = sub_category_group.get("items", [])
                    elif isinstance(entries, list):
                        normalized_data[category_name] = entries
                    else:
                        logger.warning(f"Unexpected structure for category '{category_name}' in DB. Skipping.")
                logger.info(f"Successfully loaded and normalized software categorization database from {self.db_path}")
                return normalized_data
        except FileNotFoundError:
            logger.error(f"Software categorization database not found at {self.db_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding software categorization database {self.db_path}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error loading software categorization database {self.db_path}: {e}", exc_info=True)
            return {}

    def _get_executable_name(self, path_string: Optional[str]) -> Optional[str]:
        if not path_string:
            return None
        if any(path_string.lower().endswith(ext) for ext in ['.exe', '.bat', '.cmd', '.sh', '.py', '.jar']):
             return os.path.basename(path_string).lower()

        match = re.match(r'("?)([^"]+\.(?:exe|bat|cmd|sh|py|jar))\1(?:,\d+)?', path_string, re.IGNORECASE)
        if match:
            return os.path.basename(match.group(2)).lower()
        return None

    def categorize_component(self, component_name: Optional[str],
                             executable_path_or_hint: Optional[str] = None,
                             publisher: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        if not self.categorization_data:
            return None, None
        if not component_name and not executable_path_or_hint:
            return None, None

        comp_name_lower = component_name.lower() if component_name else ""
        exe_name_lower = self._get_executable_name(executable_path_or_hint)
        publisher_lower = publisher.lower() if publisher else ""

        if exe_name_lower:
            for category, entries in self.categorization_data.items():
                for entry in entries:
                    db_executables = [e.lower() for e in entry.get("executables", []) if e]
                    if exe_name_lower in db_executables:
                        return category, entry.get("name")

        if comp_name_lower:
            for category, entries in self.categorization_data.items():
                for entry in entries:
                    db_entry_name_lower = entry.get("name", "").lower()
                    if db_entry_name_lower and db_entry_name_lower in comp_name_lower:
                        return category, entry.get("name")

                    keywords = [kw.lower() for kw in entry.get("keywords", [])]
                    if any(kw in comp_name_lower for kw in keywords):
                        return category, entry.get("name")
        if publisher_lower:
            for category, entries in self.categorization_data.items():
                for entry in entries:
                    db_publisher_lower = entry.get("publisher", "").lower()
                    if db_publisher_lower and db_publisher_lower in publisher_lower:
                        db_entry_name_lower = entry.get("name", "").lower()
                        keywords = [kw.lower() for kw in entry.get("keywords", [])]
                        if comp_name_lower:
                            if db_entry_name_lower and db_entry_name_lower in comp_name_lower:
                                return category, entry.get("name")
                            if any(kw in comp_name_lower for kw in keywords):
                                return category, entry.get("name")
        return None, None


class EnvironmentScanner:
    def __init__(self, progress_callback=None, status_callback=None):
        self.system = platform.system()
        self.config = load_config()
        self.scan_options = get_scan_options() # Correctly call the function
        self.detected_components: List[DetectedComponent] = []
        self.environment_variables: List[EnvironmentVariableInfo] = []
        self.issues: List[ScanIssue] = []
        self.found_executables: Dict[str, str] = {}
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.ignored_identifiers: set = set(self.config.get("ignored_tools_identifiers", []))
        self.categorizer = SoftwareCategorizer()

    def _update_progress(self, current, total, message):
        if self.progress_callback:
            self.progress_callback(current, total, message)

    def _update_status(self, message):
        if self.status_callback:
            self.status_callback(message)

    def _run_command(self, command_parts: List[str], timeout: int = 5) -> Tuple[str, str, int]:
        process: Optional[subprocess.Popen] = None # Type hint for clarity
        try:
            logger.debug(f"Running command: {' '.join(command_parts)}")
            process = subprocess.Popen(
                command_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode
        except subprocess.TimeoutExpired:
            logger.warning(f"Command '{' '.join(command_parts)}' timed out after {timeout}s.")
            if process: # Check if process was successfully created before timeout
                process.kill()
                # Communicate after kill to get any final output/errors
                stdout, stderr_timeout = process.communicate()
                return stdout, f"TimeoutExpired: {stderr_timeout}", -1
            return "", "TimeoutExpired: Process creation might have failed before timeout or was already handled.", -1
        except FileNotFoundError:
            logger.warning(f"Command not found: {command_parts[0]}")
            return "", "FileNotFoundError", -1
        except Exception as e:
            logger.error(f"Error running command '{' '.join(command_parts)}': {e}")
            return "", str(e), -1

    def _get_version_from_command(self, exe_path: str, version_args: List[str], version_regex_str: str) -> Optional[str]:
        if not exe_path or not os.path.exists(exe_path):
            return None

        full_command = [exe_path] + version_args
        stdout, stderr, return_code = self._run_command(full_command)

        output_to_parse = ""
        if stdout:
            output_to_parse += stdout
        if stderr:
            output_to_parse += stderr

        if not output_to_parse.strip():
            logger.debug(f"No output from version command for {exe_path}")
            return None
        try:
            output_to_parse.encode('utf-8').decode('utf-8')
        except UnicodeEncodeError:
            try:
                output_to_parse = output_to_parse.encode('latin-1').decode('utf-8', errors='replace')
                logger.debug(f"Had to re-decode output for {exe_path}")
            except Exception as e:
                logger.warning(f"Could not re-decode output for {exe_path}: {e}")

        match = re.search(version_regex_str, output_to_parse, re.MULTILINE | re.IGNORECASE)
        if match:
            if match.groups():
                version = match.group(1).strip()
                logger.info(f"Found version for {exe_path}: {version} using command.")
                return version
            else:
                logger.warning(f"Version regex '{version_regex_str}' for {exe_path} matched but found no capture group in output: {output_to_parse[:200]}")
        else:
            logger.debug(f"Version regex '{version_regex_str}' did not match for {exe_path}. Output: {output_to_parse[:200]}")
        return None

    def _find_executable_in_path(self, exe_name: str) -> Optional[str]:
        if exe_name in self.found_executables:
            return self.found_executables[exe_name]

        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            if not path_dir: continue
            try:
                exe_path = Path(path_dir) / exe_name
                if exe_path.is_file() and os.access(exe_path, os.X_OK):
                    resolved_path = str(exe_path.resolve()) # Resolve symlinks
                    self.found_executables[exe_name] = resolved_path
                    return resolved_path
            except OSError: # Path might be invalid (e.g. too long on Windows for resolve())
                logger.warning(f"Could not process PATH entry: {path_dir} when searching for {exe_name}")
                continue
            except Exception as e: # Catch other potential errors with Path operations
                logger.error(f"Error checking executable {exe_name} in {path_dir}: {e}")
                continue
        return None


    def _find_executables_for_tool(self, tool_config: Dict[str, Any]) -> List[str]:
        exe_paths_found = set()
        current_system = platform.system()
        os_specific_executables = tool_config.get("executables", {}).get(current_system, [])
        if not os_specific_executables and current_system != "Windows": # Fallback for Unix-like
            os_specific_executables = tool_config.get("executables", {}).get("Linux", [])


        for exe_name in os_specific_executables:
            path_in_env = self._find_executable_in_path(exe_name)
            if path_in_env:
                exe_paths_found.add(os.path.realpath(path_in_env))

        common_install_paths = tool_config.get("install_paths", {}).get(current_system, [])
        for common_path_str in common_install_paths:
            try:
                common_path = Path(common_path_str)
                if common_path.is_file() and os.access(common_path, os.X_OK):
                    if common_path.name in os_specific_executables:
                        exe_paths_found.add(os.path.realpath(common_path))
            except Exception as e:
                logger.warning(f"Error processing common install path {common_path_str}: {e}")
        return list(exe_paths_found)

    def _generate_component_id(self, name: str, version: Optional[str], path: Optional[str]) -> str:
        name_slug = name.lower().replace(' ', '_').replace('.', '_')
        version_slug = version.replace('.', '_') if version else "unknown"
        path_slug = Path(path).name if path else "unknownpath"
        return f"{name_slug}_{version_slug}_{path_slug}"

    def _parse_gitconfig(self, file_path: str) -> Dict[str, str]:
        details = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                name_match = re.search(r"^\s*name\s*=\s*(.+)$", content, re.MULTILINE)
                email_match = re.search(r"^\s*email\s*=\s*(.+)$", content, re.MULTILINE)
                if name_match:
                    details["user.name"] = name_match.group(1).strip()
                if email_match:
                    details["user.email"] = email_match.group(1).strip()
        except Exception as e:
            logger.warning(f"Could not parse gitconfig {file_path}: {e}")
        return details

    def _get_tool_details(self, tool_config: Dict[str, Any], install_path: Optional[str], exe_path: Optional[str]) -> Dict[str, Any]:
        details = {}
        if "config_files" in tool_config:
            for cf_info in tool_config["config_files"]:
                raw_path_str = cf_info["path"]
                conf_path: Optional[Path] = None
                if raw_path_str.startswith("~/"):
                    conf_path = Path(os.path.expanduser(raw_path_str))
                elif Path(raw_path_str).is_absolute():
                    conf_path = Path(raw_path_str)
                else:
                    base_dir_str = install_path if install_path else (str(Path(exe_path).parent) if exe_path else None)
                    if base_dir_str:
                        conf_path = Path(base_dir_str) / raw_path_str

                if conf_path and conf_path.exists() and conf_path.is_file():
                    parser_name = cf_info.get("parser")
                    if parser_name == "parse_gitconfig":
                        parsed_data = self._parse_gitconfig(str(conf_path))
                        for key in cf_info.get("keys", []):
                            if key in parsed_data:
                                details[f"{conf_path.name}:{key}"] = parsed_data[key]
                    else:
                        logger.warning(f"Unknown parser '{parser_name}' for config file {conf_path}")
        return details

    def identify_tools(self):
        self._update_status("Identifying installed tools...")
        if not TOOLS_DB:
            logger.warning("TOOLS_DB is empty. Cannot identify specific tools.")
            self._update_progress(1,1, "Tool identification skipped (TOOLS_DB empty).")
            return

        num_tools_defined = len(TOOLS_DB)
        for i, tool_cfg in enumerate(TOOLS_DB):
            tool_name = tool_cfg.get("name", "UnknownTool")
            self._update_status(f"Scanning for {tool_name}...")
            self._update_progress(i + 1, num_tools_defined, f"Scanning for {tool_name}")

            found_exe_paths = self._find_executables_for_tool(tool_cfg)

            if not found_exe_paths:
                logger.info(f"No executables found for {tool_name} via PATH or common locations.")
                continue

            for exe_path_str in found_exe_paths:
                exe_path_obj = Path(exe_path_str)
                version = self._get_version_from_command(
                    str(exe_path_obj),
                    tool_cfg.get("version_args", ["--version"]),
                    tool_cfg.get("version_regex", r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)") # Default generic regex
                )

                version = version if version else "Unknown"
                install_path = str(exe_path_obj.parent)

                component_id = self._generate_component_id(tool_name, version, str(exe_path_obj))

                if any(c.id == component_id for c in self.detected_components):
                    logger.debug(f"Skipping already detected instance: {component_id}")
                    continue
                if component_id in self.ignored_identifiers:
                    logger.info(f"Skipping ignored component: {component_id}")
                    continue

                details = self._get_tool_details(tool_cfg, install_path, str(exe_path_obj))
                related_env_vars_info = {}
                for env_var_name in tool_cfg.get("env_vars", []):
                    env_var_value = os.environ.get(env_var_name)
                    if env_var_value is not None:
                        if any(s.lower() in env_var_name.lower() for s in SENSITIVE_ENV_VARS):
                           related_env_vars_info[env_var_name] = "Present (sensitive)"
                        else:
                           related_env_vars_info[env_var_name] = env_var_value
                    else:
                        related_env_vars_info[env_var_name] = "Not set"
                if related_env_vars_info:
                    details["environment_variables"] = related_env_vars_info

                category, matched_db_name = self.categorizer.categorize_component(
                    tool_name, str(exe_path_obj)
                )

                component = DetectedComponent(
                    id=component_id,
                    name=tool_name,
                    category=category or tool_cfg.get("category", "Unknown"),
                    version=version,
                    path=install_path,
                    executable_path=str(exe_path_obj),
                    details=details,
                    source_detection=f"TOOLS_DB ({exe_path_obj.name})",
                    matched_db_name=matched_db_name
                )
                self.detected_components.append(component)
                logger.info(f"Detected via TOOLS_DB: {tool_name} {version} at {exe_path_obj}")
        self._update_progress(num_tools_defined, num_tools_defined, "Tool identification complete.")

    def collect_environment_variables(self):
        self._update_status("Collecting environment variables...")
        self.environment_variables = []
        key_vars_to_analyze = [
            "PATH", "JAVA_HOME", "PYTHONHOME", "PYTHONPATH", "NODE_PATH", "GOPATH", "GOROOT",
            "RUSTUP_HOME", "CARGO_HOME", ".NET_ROOT", "DOTNET_ROOT", "M2_HOME", "MAVEN_HOME", "GRADLE_HOME",
            "ANDROID_HOME", "ANDROID_SDK_ROOT", "FLUTTER_HOME",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLI_HOME", "GOOGLE_APPLICATION_CREDENTIALS",
            "HOME", "USERPROFILE", "TEMP", "TMP", "PROGRAMFILES", "PROGRAMFILES(X86)", "APPDATA",
            "LOCALAPPDATA", "ProgramData", "USER", "SHELL", "LANG"
        ]

        for name, value in os.environ.items():
            var_issues: List[ScanIssue] = []
            is_sensitive = any(s.lower() in name.lower() for s in SENSITIVE_ENV_VARS)
            display_value = "****SENSITIVE_VALUE****" if is_sensitive and name not in ["PATH"] else value # Show PATH

            if name.upper() == "PATH":
                parsed_paths = value.split(os.pathsep)
                seen_paths = set()
                duplicates = set()
                for p_idx, p_val in enumerate(parsed_paths):
                    if not p_val:
                        var_issues.append(ScanIssue(f"PATH entry {p_idx+1} is empty.", "Warning", category="PATH"))
                        continue
                    if not os.path.exists(p_val):
                        var_issues.append(ScanIssue(f"PATH entry '{p_val}' does not exist.", "Critical", category="PATH", related_path=p_val))
                    elif not os.path.isdir(p_val):
                         var_issues.append(ScanIssue(f"PATH entry '{p_val}' is not a directory.", "Warning", category="PATH", related_path=p_val))

                    norm_pval = os.path.normcase(os.path.normpath(p_val))
                    if norm_pval in seen_paths:
                        duplicates.add(p_val)
                    seen_paths.add(norm_pval)
                if duplicates:
                    for dup_path in duplicates:
                        var_issues.append(ScanIssue(f"PATH entry '{dup_path}' is duplicated.", "Warning", category="PATH", related_path=dup_path))

            elif name.upper() in [v.upper() for v in key_vars_to_analyze if "_HOME" in v or "_ROOT" in v]:
                if value and not os.path.exists(value):
                    var_issues.append(ScanIssue(f"Path '{value}' for '{name}' does not exist.", "Critical", category="Environment Variable", related_path=value))
                elif value and not os.path.isdir(value):
                     var_issues.append(ScanIssue(f"Path '{value}' for '{name}' is not a directory.", "Warning", category="Environment Variable", related_path=value))

            env_var_info = EnvironmentVariableInfo(name, display_value, issues=var_issues) # scope defaults to active_session
            self.environment_variables.append(env_var_info)
            if var_issues:
                self.issues.extend(var_issues)
        self.environment_variables.sort(key=lambda x: x.name)
        logger.info(f"Collected {len(self.environment_variables)} environment variables.")

    def _get_os_specific_scan_roots(self) -> List[str]:
        roots = set()
        if self.system == "Windows":
            import string
            for drive in string.ascii_uppercase:
                drive_path = f"{drive}:\\"
                if os.path.exists(drive_path):
                    roots.add(drive_path)
        elif self.system == "Darwin":
            roots.add("/")
        elif self.system == "Linux":
            roots.add("/")

        custom_paths_settings = self.config.get("scan_paths", {})
        for custom_path in custom_paths_settings.get("custom_paths", []):
            if os.path.exists(custom_path) and os.path.isdir(custom_path):
                roots.add(custom_path)
            else:
                logger.warning(f"Custom scan path '{custom_path}' does not exist or is not a directory.")
        return list(roots)

    def _get_prioritized_scan_dirs(self) -> List[str]:
        scan_dirs = []
        path_env = os.environ.get("PATH", "")
        for p_dir in path_env.split(os.pathsep):
            if p_dir and os.path.isdir(p_dir) and p_dir not in scan_dirs:
                scan_dirs.append(p_dir)

        common_paths_config = self.config.get("scan_paths", {})
        paths_to_add = set()
        user_home = Path.home()

        if common_paths_config.get("include_system_common_paths", True):
            if self.system == "Windows":
                paths_to_add.update(filter(None, [
                    os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                    os.environ.get("ProgramData"),
                    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
                    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64"),
                ]))
            elif self.system == "Darwin":
                paths_to_add.update(["/Applications", "/Library", "/usr/local", "/opt"])
            elif self.system == "Linux":
                paths_to_add.update(["/usr/bin", "/usr/local/bin", "/opt", "/snap/bin", "/etc", "/var"])

        if common_paths_config.get("include_user_common_paths", True):
            if self.system == "Windows":
                paths_to_add.update(filter(None, [
                    user_home / "AppData" / "Local", user_home / "AppData" / "Roaming",
                    user_home / "AppData" / "Local" / "Programs",
                ]))
            elif self.system == "Darwin":
                paths_to_add.update([user_home / "Applications", user_home / "Library", user_home / "bin"])
            elif self.system == "Linux":
                paths_to_add.update([user_home / "bin", user_home / ".local" / "bin",
                                     user_home / ".config", user_home / "snap"])

        for p_item in paths_to_add:
            p = str(p_item) # Ensure it's a string
            if p and os.path.isdir(p) and p not in scan_dirs:
                scan_dirs.append(p)

        custom_paths = common_paths_config.get("custom_paths", [])
        for c_path in custom_paths:
            if c_path and os.path.isdir(c_path) and c_path not in scan_dirs:
                scan_dirs.append(c_path)
        logger.info(f"Prioritized scan directories: {scan_dirs}")
        return scan_dirs

    def _is_excluded(self, path_obj: Path, root_path_obj: Path, patterns: Dict[str, List[str]]) -> bool:
        try:
            relative_parts = path_obj.relative_to(root_path_obj).parts
        except ValueError: # path_obj is not under root_path_obj, should not happen if os.walk is used correctly
            relative_parts = path_obj.parts

        for part in relative_parts:
            for pattern in patterns.get("exclude_directories", []):
                if fnmatch.fnmatch(part, pattern.strip('/\\')): # Match individual directory names
                    return True
        for pattern in patterns.get("exclude_directories", []):
            if fnmatch.fnmatch(str(path_obj), pattern): # Match full path
                return True
        if path_obj.is_file():
            for pattern in patterns.get("exclude_files", []):
                if fnmatch.fnmatch(path_obj.name, pattern):
                    return True
        return False

    def scan_file_system(self):
        self._update_status("Starting file system scan (prioritized locations)...")
        scan_dirs_to_check = self._get_prioritized_scan_dirs()
        scan_patterns = self.config.get("scan_patterns", {})
        max_depth = self.scan_options.get("max_recursion_depth", 10)

        common_exec_extensions = {'.exe', '.bat', '.sh', '.cmd', ''}
        os_exec_ext = {'.exe', '.bat', '.cmd'} if self.system == "Windows" else \
                      ({'', '.sh', '.app'} if self.system == "Darwin" else {'', '.sh', '.AppImage'})

        total_dirs_to_scan = len(scan_dirs_to_check)
        scanned_dirs_count = 0
        processed_exe_paths = {comp.executable_path for comp in self.detected_components if comp.executable_path}

        for start_dir_str in scan_dirs_to_check:
            start_dir = Path(start_dir_str)
            scanned_dirs_count += 1
            self._update_progress(scanned_dirs_count, total_dirs_to_scan, f"Scanning: {start_dir_str}")
            self._update_status(f"Scanning: {start_dir_str}...")

            for root, dirs, files in os.walk(start_dir, topdown=True, onerror=lambda e: logger.warning(f"os.walk error: {e}")):
                current_root_path = Path(root)
                current_depth = len(current_root_path.relative_to(start_dir).parts) if current_root_path.is_relative_to(start_dir) else 0

                if current_depth >= max_depth:
                    logger.debug(f"Max recursion depth {max_depth} reached in {root}. Pruning.")
                    dirs[:] = []
                    continue

                dirs[:] = [d for d in dirs if not self._is_excluded(current_root_path / d, start_dir, scan_patterns)]

                for name in files:
                    file_path = current_root_path / name
                    if str(file_path) in processed_exe_paths or self._is_excluded(file_path, start_dir, scan_patterns):
                        continue
                    try:
                        file_stat = file_path.stat()
                        is_executable_by_mode = bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                        ext = file_path.suffix.lower()
                        is_known_exec_ext = ext in os_exec_ext

                        if is_executable_by_mode or is_known_exec_ext: # Prioritize mode, then extension
                            if self.system != "Windows" and not is_executable_by_mode and ext == '': # Unix non-extension needs exec bit
                                continue

                            version = self._get_version_from_command(str(file_path), ["--version"], r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)") or \
                                      self._get_version_from_command(str(file_path), ["version"], r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
                            version = version if version else "Unknown"
                            comp_name = file_path.name
                            comp_id = self._generate_component_id(comp_name, version, str(file_path))

                            if comp_id in self.ignored_identifiers or any(c.id == comp_id for c in self.detected_components):
                                continue

                            category, matched_db_name = self.categorizer.categorize_component(comp_name, str(file_path))
                            component = DetectedComponent(
                                id=comp_id, name=comp_name,
                                category=category or "Utility/Executable",
                                version=version, path=str(file_path.parent),
                                executable_path=str(file_path),
                                source_detection=f"File System Scan ({start_dir_str})",
                                matched_db_name=matched_db_name
                            )
                            self.detected_components.append(component)
                            logger.info(f"Found generic executable: {comp_name} {version} at {file_path}")
                            processed_exe_paths.add(str(file_path))
                    except FileNotFoundError:
                        logger.warning(f"File not found during stat: {file_path}")
                    except PermissionError:
                        logger.warning(f"Permission denied accessing: {file_path}")
                        # self.issues.append(ScanIssue("Permission denied", "Warning", category="File System", related_path=str(file_path))) # Redundant if not used
                    except Exception as e:
                        logger.error(f"Error processing file {file_path}: {e}")
        self._update_progress(total_dirs_to_scan, total_dirs_to_scan, "File system scan (prioritized) complete.")
        logger.info("File system scan (prioritized locations) finished.")

    def cross_reference_and_analyze(self):
        self._update_status("Analyzing findings...")
        path_dirs_str = os.environ.get("PATH", "")
        path_dirs = [os.path.normcase(os.path.normpath(p)) for p in path_dirs_str.split(os.pathsep) if p]

        for component in self.detected_components:
            if component.executable_path:
                try:
                    exe_dir = os.path.normcase(os.path.normpath(os.path.dirname(component.executable_path)))
                    if exe_dir not in path_dirs:
                        issue_desc = f"Tool '{component.name}' ({component.executable_path}) dir not in PATH."
                        issue = ScanIssue(issue_desc, "Warning", component_id=component.id, category="PATH", related_path=component.executable_path)
                        component.issues.append(issue)
                        self.issues.append(issue)
                except Exception as e:
                    logger.warning(f"Error processing path for component {component.name}: {e}")


            tool_cfg_id_match = component.id.split('_')[0] if component.id else None # Heuristic for tool_id
            tool_cfg = next((t for t in TOOLS_DB if t.get("id") == tool_cfg_id_match), None)
            if not tool_cfg:
                 tool_cfg = next((t for t in TOOLS_DB if t.get("name") == component.name), None)

            if tool_cfg and "env_vars" in tool_cfg:
                for env_var_name in tool_cfg["env_vars"]:
                    env_var_value = os.environ.get(env_var_name)
                    if env_var_value is None:
                        issue_desc = f"'{component.name}' related env var '{env_var_name}' not set."
                        issue = ScanIssue(issue_desc, "Warning", component_id=component.id, category="Environment Variable")
                        component.issues.append(issue)
                        self.issues.append(issue)
                    elif (env_var_name.endswith("_HOME") or env_var_name.endswith("_ROOT")) and component.path:
                        try:
                            norm_env_path = os.path.normcase(os.path.normpath(env_var_value))
                            norm_comp_install_path = os.path.normcase(os.path.normpath(component.path))
                            if not norm_comp_install_path.startswith(norm_env_path) and \
                               not norm_env_path.startswith(norm_comp_install_path): # Check both ways
                                issue_desc = (f"Env var '{env_var_name}' ({env_var_value}) may not match "
                                              f"'{component.name}' install path ({component.path}).")
                                issue = ScanIssue(issue_desc, "Info", component_id=component.id, category="Environment Variable", related_path=env_var_value)
                                component.issues.append(issue)
                                self.issues.append(issue)
                        except Exception as e:
                            logger.warning(f"Error comparing paths for {env_var_name} and {component.name}: {e}")


        from collections import defaultdict
        components_by_name = defaultdict(list)
        for comp in self.detected_components:
            components_by_name[comp.name].append(comp)

        for name, comp_list in components_by_name.items():
            if len(comp_list) > 1:
                versions_found = [c.version or "Unknown" for c in comp_list]
                paths_found = [c.executable_path or "N/A" for c in comp_list]
                issue_desc = f"Multiple versions of '{name}' detected: {', '.join(versions_found)} at paths {', '.join(paths_found)}."
                active_version_path = None
                for p in paths_found:
                    if p and p != "N/A":
                        try:
                            if os.path.normcase(os.path.normpath(os.path.dirname(p))) in path_dirs:
                                active_version_path = p
                                break
                        except Exception: # Path could be invalid
                            pass
                if active_version_path:
                    active_comp = next((c for c in comp_list if c.executable_path == active_version_path), None)
                    if active_comp:
                        issue_desc += f" Active version appears to be {active_comp.version or 'Unknown'} (via PATH)."
                issue = ScanIssue(issue_desc, "Info", component_id=comp_list[0].id, category="VersionConflict")
                for c in comp_list: c.issues.append(issue)
                self.issues.append(issue)
        logger.info("Cross-referencing and analysis complete.")

    def run_scan(self) -> Tuple[List[DetectedComponent], List[EnvironmentVariableInfo], List[ScanIssue]]:
        self._update_status("Starting environment audit...")
        self.detected_components = []
        self.environment_variables = []
        self.issues = []
        self.found_executables = {}
        self.ignored_identifiers = set(self.config.get("ignored_tools_identifiers", []))

        self.identify_tools()
        self.scan_file_system() # This can find more tools or duplicate if not careful with processed_exe_paths
        self.collect_environment_variables()
        self.cross_reference_and_analyze()

        self._update_status("Scan complete.")
        logger.info("Full scan process finished.")
        return self.detected_components, self.environment_variables, self.issues

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')

    from config_manager import CONFIG_FILE_PATH, save_config, DEFAULT_CONFIG # Import necessary items

    # Create a dummy software_categorization_database.json for testing if it doesn't exist
    dummy_db_path = SOFTWARE_CATEGORIZATION_DB_PATH
    if not os.path.exists(dummy_db_path):
        dummy_db_content = {
            "Programming Languages": [
                {"name": "Python", "executables": ["python.exe", "python3.exe", "python", "python3"], "keywords": ["py", "conda"]},
                {"name": "Java Development Kit", "executables": ["java.exe", "javac.exe", "java", "javac"], "keywords": ["jdk", "jre"]}
            ],
            "Code Editors": [
                {"name": "Visual Studio Code", "executables": ["code.exe", "code"], "keywords": ["vscode", "vs code"]}
            ]
        }
        try:
            with open(dummy_db_path, 'w', encoding='utf-8') as f_db:
                json.dump(dummy_db_content, f_db, indent=2)
            logger.info(f"Created dummy categorization database at {dummy_db_path}")
        except IOError as e:
            logger.error(f"Could not create dummy categorization database: {e}")


    def dummy_progress(curr, total, msg):
        print(f"Progress: {curr}/{total} - {msg}")
    def dummy_status(msg):
        print(f"Status: {msg}")

    scanner = EnvironmentScanner(progress_callback=dummy_progress, status_callback=dummy_status)
    if not os.path.exists(CONFIG_FILE_PATH): # Use CONFIG_FILE_PATH from config_manager
        from config_manager import save_config, DEFAULT_CONFIG # Import here to avoid circular if run directly
        save_config(DEFAULT_CONFIG)

    components, env_vars, issues = scanner.run_scan()

    print("\n--- Detected Components ---")
    for comp in components:
        print(f"ID: {comp.id}, Name: {comp.name}, Version: {comp.version}, Path: {comp.executable_path or comp.path}, Category: {comp.category}, Matched DB: {comp.matched_db_name}")
        if comp.issues:
            for issue in comp.issues: print(f"  Issue: {issue.severity} - {issue.description}")
        if comp.details: print(f"  Details: {comp.details}")

    print("\n--- Environment Variables (First 10) ---")
    for i, ev in enumerate(env_vars):
        if i >= 10 and len(env_vars) > 20 :
            if i == 10: print("...")
            if i < len(env_vars) -10: continue
        print(f"{ev.name}: {ev.value[:100]}{'...' if len(ev.value)>100 else ''} (Scope: {ev.scope})")
        if ev.issues:
            for issue in ev.issues: print(f"  Issue: {issue.severity} - {issue.description}")

    print("\n--- Identified Issues ---")
    if not issues: print("No major issues identified.")
    for issue in issues: print(f"- {issue.severity} ({issue.category}): {issue.description} (Component: {issue.component_id}, Path: {issue.related_path})")