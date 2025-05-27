"""Manages the GUI for the Developer Environment Auditor.
Takes raw data from scans and structures it for GUI display and export.

Handles formatting for TXT, MD, JSON, and HTML reports.
"""
import json
import logging
import html
from datetime import datetime
from typing import List, Dict, Any, Optional, Union

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from scan_logic import DetectedComponent, EnvironmentVariableInfo, ScanIssue, EnvironmentScanner # Added EnvironmentScanner

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Formats a single component for different output types."""

    def __init__(self,
                 detected_components: List[DetectedComponent],
                 environment_variables: List[EnvironmentVariableInfo],
                 issues: List[ScanIssue]):
        self.detected_components = sorted(
            detected_components, key=lambda x: (x.category, x.name, x.version)
        )
        self.environment_variables = sorted(
            environment_variables, key=lambda x: x.name
        )
        self.issues = sorted(
            issues, key=lambda x: (x.severity, x.category, x.description)
        )
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _format_component(self, component, format_type="txt"):
        lines = []
        name_version = f"{component.name} ({component.version})"
        if format_type == "md":
            lines.append(f"### {name_version}")
            lines.append(f"- **ID:** `{component.id}`")
            lines.append(f"- **Category:** {component.category}")
            lines.append(f"- **Path:** `{component.path}`")
            if component.executable_path and component.executable_path != component.path:
                lines.append(f"- **Executable:** `{component.executable_path}`")
        elif format_type == "html":
            lines.append(f"<h3>{html.escape(name_version)}</h3>")
            lines.append("<ul>")
            lines.append(f"<li><b>ID:</b> <code>{html.escape(component.id)}</code></li>")
            lines.append(f"<li><b>Category:</b> {html.escape(component.category)}</li>")
            lines.append(f"<li><b>Path:</b> <code>{html.escape(component.path)}</code></li>")
            if component.executable_path and component.executable_path != component.path:
                lines.append(f"<li><b>Executable:</b> <code>{html.escape(component.executable_path)}</code></li>")
        else:  # txt
            lines.append(f"Tool: {name_version}")
            lines.append(f"  ID: {component.id}")
            lines.append(f"  Category: {component.category}")
            lines.append(f"  Path: {component.path}")
            if component.executable_path and component.executable_path != component.path:
                lines.append(f"  Executable: {component.executable_path}")

        if component.details:
            if format_type == "html":
                lines.append("<li><b>Details:</b><ul>")
            else:
                lines.append(f"  Details:")
            for key, value in component.details.items():
                if format_type == "md":
                    lines.append(f"  - **{key}:** {value}")
                elif format_type == "html":
                    lines.append(
                        f"<li><em>{html.escape(key)}:</em> {html.escape(str(value))}</li>"
                    )
                else:
                    lines.append(f"    {key}: {value}")
            if format_type == "html":
                lines.append("</ul></li>")

        if component.update_info:
            ui = component.update_info
            status = (
                "Update Available"
                if ui.get("is_update_available")
                else "Up-to-date"
            )
            if ui.get("latest_version"):
                update_line = (
                    f"{status}: Installed {component.version} -> Latest {ui['latest_version']} (via {ui['package_manager_name']})"
                )
                cmd_line = (
                    f"Update Command: `{ui['update_command']}`"
                    if ui.get("update_command")
                    else ""
                )

                if format_type == "md":
                    lines.append(f"- **Update Status:** {update_line}")
                    if cmd_line:
                        lines.append(f"  - {cmd_line}")
                elif format_type == "html":
                    lines.append(
                        f"<li><b>Update Status:</b> {html.escape(update_line)}"
                    )
                    if cmd_line:
                        lines.append(f"<br/>&nbsp;&nbsp;<em>{html.escape(cmd_line)}</em>")
                    lines.append("</li>")
                else:
                    lines.append(f"  Update Status: {update_line}")
                    if cmd_line:
                        lines.append(f"    {cmd_line}")

        if component.issues:
            if format_type == "html":
                lines.append("<li><b>Issues:</b><ul>")
            else:
                lines.append(f"  Issues:")
            for issue in component.issues:  # issue is already a string or ScanIssue object
                desc = issue.description if hasattr(issue, 'description') else str(issue)
                sev = f" ({issue.severity})" if hasattr(issue, 'severity') else ""
                if format_type == "md":
                    lines.append(f"  - *{desc}{sev}*")
                elif format_type == "html":
                    lines.append(f"<li><em>{html.escape(desc)}{html.escape(sev)}</em></li>")
                else:
                    lines.append(f"    - {desc}{sev}")
            if format_type == "html":
                lines.append("</ul></li>")

        if format_type == "html":
            lines.append("</ul>")
        return "\n".join(lines)

    def _format_env_var(self, env_var, format_type="txt"):
        lines = []
        val_display = env_var.value
        if len(val_display) > 200 and format_type != "json":  # Truncate long values for readability
            val_display = val_display[:200] + "..."

        if format_type == "md":
            lines.append(f"- **`{env_var.name}`** (`{env_var.scope}`): `{val_display}`")
        elif format_type == "html":
            lines.append(
                f"<li><code>{html.escape(env_var.name)}</code> (<i>{html.escape(env_var.scope)}</i>): <code>{html.escape(val_display)}</code>"
            )
        else:  # txt
            lines.append(f"{env_var.name} ({env_var.scope}): {val_display}")

        if env_var.issues:
            if format_type == "html":
                lines.append("<ul>")
            for issue in env_var.issues:
                desc = issue.description if hasattr(issue, 'description') else str(issue)
                sev = f" ({issue.severity})" if hasattr(issue, 'severity') else ""
                if format_type == "md":
                    lines.append(f"  - *Issue:{sev} {desc}*")
                elif format_type == "html":
                    lines.append(
                        f"<li><em>Issue:{html.escape(sev)} {html.escape(desc)}</em></li>"
                    )
                else:
                    lines.append(f"  - Issue:{sev} {desc}")
            if format_type == "html":
                lines.append("</ul>")
        if format_type == "html":
            lines.append("</li>")
        return "\n".join(lines)

    def _format_issue(self, issue, format_type="txt"):
        line = ""
        comp_info = f" (Component: {issue.component_id})" if issue.component_id else ""
        path_info = f" (Path: {issue.related_path})" if issue.related_path else ""

        if format_type == "md":
            line = f"- **{issue.severity} ({issue.category}):** {issue.description}{comp_info}{path_info}"
        elif format_type == "html":
            line = f"<li><b>{html.escape(issue.severity)} ({html.escape(issue.category)}):</b> {html.escape(issue.description)}{html.escape(comp_info)}{html.escape(path_info)}</li>"
        else:  # txt
            line = f"- {issue.severity} ({issue.category}): {issue.description}{comp_info}{path_info}"
        return line

    def generate_report_data_for_gui(self):
        """Prepares data in a structured way suitable for the GUI."""
        # This can return the raw lists, and the GUI can format them.
        # Or, it can return pre-formatted strings if the GUI needs that.
        # For now, let's assume GUI will handle its own formatting from these objects.
        return {
            "report_time": self.report_time,
            "detected_components": [comp.to_dict() for comp in self.detected_components],
            "environment_variables": [ev.to_dict() for ev in self.environment_variables],
            "issues": [iss.to_dict() for iss in self.issues]
        }

    def export_to_txt(self, filepath):
        logger.info(f"Exporting report to TXT: {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Developer Environment Audit Report\n")
                f.write(f"Generated: {self.report_time}\n")
                f.write("=" * 40 + "\n\n")

                f.write("Detected Tools & Versions\n")
                f.write("-" * 30 + "\n")
                if self.detected_components:
                    for comp in self.detected_components:
                        f.write(self._format_component(comp, "txt") + "\n\n")
                else:
                    f.write("No components detected.\n\n")

                f.write("Active Environment Variables\n")
                f.write("-" * 30 + "\n")
                if self.environment_variables:
                    for ev in self.environment_variables:
                        f.write(self._format_env_var(ev, "txt") + "\n")
                else:
                    f.write("No environment variables collected or to display.\n")
                f.write("\n")

                f.write("Identified Issues & Warnings\n")
                f.write("-" * 30 + "\n")
                if self.issues:
                    for issue in self.issues:
                        f.write(self._format_issue(issue, "txt") + "\n")
                else:
                    f.write("No issues identified.\n")
            logger.info(f"TXT report saved to {filepath}")
            return True
        except IOError as e:
            logger.error(f"Failed to write TXT report to {filepath}: {e}")
            return False

    def export_to_markdown(self, filepath):
        logger.info(f"Exporting report to Markdown: {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"# Developer Environment Audit Report\n\n")
                f.write(f"**Generated:** {self.report_time}\n\n")
                f.write("---\n\n")

                f.write("## Detected Tools & Versions\n\n")
                if self.detected_components:
                    for comp in self.detected_components:
                        f.write(self._format_component(comp, "md") + "\n\n")
                else:
                    f.write("No components detected.\n\n")
                f.write("---\n\n")

                f.write("## Active Environment Variables\n\n")
                if self.environment_variables:
                    for ev in self.environment_variables:
                        f.write(self._format_env_var(ev, "md") + "\n")
                else:
                    f.write("No environment variables collected or to display.\n")
                f.write("\n---\n\n")

                f.write("## Identified Issues & Warnings\n\n")
                if self.issues:
                    for issue in self.issues:
                        f.write(self._format_issue(issue, "md") + "\n")
                else:
                    f.write("No issues identified.\n\n")
            logger.info(f"Markdown report saved to {filepath}")
            return True
        except IOError as e:
            logger.error(f"Failed to write Markdown report to {filepath}: {e}")
            return False

    def export_to_json(self, filepath):
        logger.info(f"Exporting report to JSON: {filepath}")
        report_data = self.generate_report_data_for_gui()  # Use the same structure
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"JSON report saved to {filepath}")
            return True
        except (IOError, TypeError) as e:  # TypeError for objects not serializable
            logger.error(f"Failed to write JSON report to {filepath}: {e}")
            return False

    def export_to_html(self, filepath):
        logger.info(f"Exporting report to HTML: {filepath}")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("<!DOCTYPE html>\n<html lang='en'>\n<head>\n")
                f.write("  <meta charset='UTF-8'>\n")
                f.write("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n")
                f.write("  <title>Developer Environment Audit Report</title>\n")
                f.write("""
  <style>
    body { font-family: sans-serif; margin: 20px; line-height: 1.6; }
    .container { max-width: 1000px; margin: auto; background: #f9f9f9; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1, h2, h3 { color: #333; }
    h1 { text-align: center; }
    h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 30px; }
    h3 { margin-top: 20px; color: #555; }
    ul { list-style-type: none; padding-left: 0; }
    li { margin-bottom: 10px; }
    code { background-color: #eef; padding: 2px 5px; border-radius: 4px; font-family: monospace; }
    .issue { border-left: 5px solid; padding-left: 10px; margin-bottom: 10px; }
    .issue.Critical { border-color: red; background-color: #ffebee; }
    .issue.Warning { border-color: orange; background-color: #fff3e0; }
    .issue.Info { border-color: dodgerblue; background-color: #e3f2fd; }
    .collapsible { background-color: #777; color: white; cursor: pointer; padding: 10px; width: 100%; border: none; text-align: left; outline: none; font-size: 1.1em; margin-top:10px; border-radius: 5px; }
    .collapsible:hover { background-color: #555; }
    .collapsible.active:after { content: "\\2212"; } /* Minus sign */
    .collapsible:not(.active):after { content: '\\002B'; } /* Plus sign */
    .collapsible:after { font-weight: bold; float: right; margin-left: 5px; }
    .content { padding: 0 18px; max-height: 0; overflow: hidden; transition: max-height 0.2s ease-out; background-color: #f1f1f1; border-radius: 0 0 5px 5px; }
    .timestamp { text-align: center; color: #777; margin-bottom: 20px; }
  </style>
""")
                f.write("</head>\n<body>\n<div class='container'>\n")
                f.write("<h1>Developer Environment Audit Report</h1>\n")
                f.write(f"<p class='timestamp'>Generated: {html.escape(self.report_time)}</p>\n")

                # Detected Components Section
                f.write("<button type='button' class='collapsible active'>Detected Tools & Versions</button>\n")
                f.write("<div class='content' style='max-height: initial;'>\n")  # Start expanded
                if self.detected_components:
                    for comp in self.detected_components:
                        f.write(self._format_component(comp, "html") + "<hr/>\n")
                else:
                    f.write("<p>No components detected.</p>\n")
                f.write("</div>\n")

                # Environment Variables Section
                f.write("<button type='button' class='collapsible'>Active Environment Variables</button>\n")
                f.write("<div class='content'>\n<ul>\n")
                if self.environment_variables:
                    for ev in self.environment_variables:
                        f.write(self._format_env_var(ev, "html") + "\n")
                else:
                    f.write("<li>No environment variables collected or to display.</li>\n")
                f.write("</ul>\n</div>\n")

                # Issues Section
                f.write("<button type='button' class='collapsible'>Identified Issues & Warnings</button>\n")
                f.write("<div class='content'>\n<ul>\n")
                if self.issues:
                    for issue in self.issues:
                        f.write(f"<div class='issue {html.escape(issue.severity)}'>")
                        f.write(self._format_issue(issue, "html") + "</div>\n")
                else:
                    f.write("<li>No issues identified.</li>\n")
                f.write("</ul>\n</div>\n")

                f.write("""
<script>
  var coll = document.getElementsByClassName("collapsible");
  for (var i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", function() {
      this.classList.toggle("active");
      var content = this.nextElementSibling;
      if (content.style.maxHeight){
        content.style.maxHeight = null;
      } else {
        content.style.maxHeight = content.scrollHeight + "px";
      }
    });
  }
</script>
""")
                f.write("</div>\n</body>\n</html>")
            logger.info(f"HTML report saved to {filepath}")
            return True
        except IOError as e:
            logger.error(f"Failed to write HTML report to {filepath}: {e}")
            return False


class ScanData:
    """Holds and processes the data from an environment scan."""

    def __init__(
        self,
        detected_components: List[DetectedComponent],
        environment_variables: List[EnvironmentVariableInfo],
        issues: List[ScanIssue],
        scan_summary: Optional[Dict[str, Any]] = None,
    ):
        self.detected_components: List[DetectedComponent] = sorted(
            detected_components, key=lambda x: (x.category, x.name, x.version)
        )
        self.environment_variables: List[EnvironmentVariableInfo] = sorted(
            environment_variables, key=lambda x: x.name
        )
        self.issues: List[ScanIssue] = sorted(
            issues, key=lambda x: (x.severity, x.category, x.description)
        )
        self.scan_summary = scan_summary if scan_summary else {}


class MainAppWindow(tk.Tk):
    def __init__(self, initial_config: Dict[str, Any]): # Changed 'config' to 'initial_config' to avoid clash if a 'config' attribute is used later
        super().__init__()
        self.title("Developer Environment Auditor")
        self.geometry("1000x700")
        self.initial_config = initial_config # Store initial config

        self.scanner: Optional[EnvironmentScanner] = None # Initialize and type hint scanner
        self.scan_data: Optional[ScanData] = None

        # Pre-declare button attributes for type hinting and earlier access if needed by methods like after_scan_actions
        self.export_button: Optional[ttk.Button] = None
        self.rescan_button: Optional[ttk.Button] = None
        self.scan_progress_bar: Optional[ttk.Progressbar] = None
        self.status_bar_label: Optional[ttk.Label] = None
        self.results_notebook: Optional[ttk.Notebook] = None
        # ... (other UI elements that might be accessed by helper methods before full UI build if not careful)

        self._setup_ui()

    def _setup_ui(self):
        # ... (rest of your UI setup code, where buttons like export_button are actually created)
        # Example of where export_button would be initialized:
        # self.export_button = ttk.Button(..., state=tk.DISABLED)
        # self.rescan_button = ttk.Button(...)
        pass # Placeholder for the rest of _setup_ui

    def _populate_treeview(self):
        # ...existing code...
        pass

    def _update_statusbar(self, text):
        # ...existing code...
        pass

    def after_scan_actions(self):
        """Actions to perform after a scan is complete, like populating UI."""
        if self.scan_data:
            self._populate_treeview()
            self._update_statusbar(f"Scan complete. Displaying {len(self.scan_data.detected_components)} components, {len(self.scan_data.environment_variables)} variables, {len(self.scan_data.issues)} issues.")
            if self.export_button: self.export_button.config(state=tk.NORMAL)
            if self.rescan_button: self.rescan_button.config(state=tk.NORMAL)
        else:
            self._update_statusbar("Scan finished, but no data was processed.")
            messagebox.showwarning("Scan Results", "Scan completed, but no data was available to display.")
            if self.export_button: self.export_button.config(state=tk.DISABLED)
            if self.rescan_button: self.rescan_button.config(state=tk.NORMAL)

    def _start_scan(self):
        # ... (Progress bar and status updates)
        try:
            self._update_statusbar("Starting scan...")
            if self.scan_progress_bar: self.scan_progress_bar['value'] = 0

            # Instantiate the scanner properly
            self.scanner = EnvironmentScanner(
                progress_callback=self._update_progress,
                status_callback=self._update_scan_status_message
            )

            # Use the correct scan method name from scan_logic.py
            self.scanner.run_scan()

            self.scan_data = ScanData(
                self.scanner.detected_components,
                self.scanner.environment_variables,
                self.scanner.issues,
                # self.scanner.get_summary() # If you have a summary method
            )
            self.after_scan_actions()
        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            messagebox.showerror("Scan Error", f"An error occurred during the scan: {e}")
            self._update_statusbar(f"Scan failed: {e}")
        finally:
            if self.scan_progress_bar: self.scan_progress_bar['value'] = 0
            # Re-enable scan button, etc.
            if self.rescan_button: self.rescan_button.config(state=tk.NORMAL) # Or specific scan button

    def _update_progress(self, current_step: int, total_steps: int, message: str):
        if self.scan_progress_bar:
            self.scan_progress_bar['value'] = (current_step / total_steps) * 100
        self._update_statusbar(message)
        self.update_idletasks() # Force UI update

    def _update_scan_status_message(self, message: str):
        self._update_statusbar(message)
        self.update_idletasks() # Force UI update

    # ...existing code...


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Test ReportGenerator (as per previous state)
    # ... (ReportGenerator test code remains unchanged) ...

    # Test MainAppWindow
    # Create dummy config for testing MainAppWindow
    test_config = {
        "scan_options": {
            "scan_paths": ["~"],
            "excluded_paths": ["~/Library", "/System"],
            "scan_env_vars": True,
            "cross_reference_tools": True,
            "perform_update_checks": False
        },
        "logging": {"level": "INFO", "file": "devenvaudit.log"}
    }
    app = MainAppWindow(initial_config=test_config) # Use 'initial_config'

    # Create mock data for ScanData for GUI testing
    mock_components = [
        DetectedComponent("python_3.9_main", "Python", "Language", "3.9.12", "/usr/bin/python3.9", executable_path="/usr/bin/python3.9", details={"architecture": "x64"}),
        DetectedComponent("git_2.30_main", "Git", "VCS", "2.30.1", "/usr/bin/git", executable_path="/usr/bin/git", details={"user.name": "Test User"})
    ]
    mock_env_vars = [
        EnvironmentVariableInfo("PATH", "/usr/local/bin:/usr/bin:/bin", "active_session"),
        EnvironmentVariableInfo("JAVA_HOME", "/opt/java/jdk-11", "active_session")
    ]
    mock_issues = [
        ScanIssue("Old Git version detected", "Warning", component_id="git_2.30_main", category="Version"),
        ScanIssue("JAVA_HOME not pointing to a recent JDK", "Info", category="Environment")
    ]

    app.scan_data = ScanData(mock_components, mock_env_vars, mock_issues)
    app.after_scan_actions() # Call the new method to populate UI

    app.mainloop()