"""
Developer Environment Auditor (DevEnvAudit)

Main entry point for the application. Initializes and launches the GUI.
"""
import logging
import os
import tkinter as tk
from gui_manager import MainAppWindow
from config_manager import load_config, save_config, DEFAULT_CONFIG, CONFIG_FILE_PATH

# --- Global Constants ---
APP_NAME = "Developer Environment Auditor"
APP_VERSION = "1.1.0" # Corresponds to prompt version
LOG_FILE_NAME = "devenvaudit.log"

def setup_logging():
    """Configures logging for the application."""
    log_dir = os.path.dirname(CONFIG_FILE_PATH) # Place log file near config file
    log_file = os.path.join(log_dir, LOG_FILE_NAME)

    # Ensure log directory exists
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            # Fallback to current directory if user home is not writable for logs
            print(f"Warning: Could not create log directory {log_dir}: {e}. Logging to current directory.")
            log_file = LOG_FILE_NAME


    logging.basicConfig(
        level=logging.INFO, # Default level for file and console
        format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file, mode='a', encoding='utf-8'), # Append mode
            logging.StreamHandler() # Outputs to console (stderr by default)
        ]
    )
    # You can set different levels for different handlers or loggers if needed
    # e.g., file_handler.setLevel(logging.DEBUG)

    # Test log message
    logging.info(f"{APP_NAME} v{APP_VERSION} logging initialized. Log file: {log_file}")


def main():
    """Main function to initialize and run the application."""

    # Initialize configuration (load or create default devenvaudit_config.json)
    # This ensures the config file exists with defaults before GUI tries to load it.
    try:
        config = load_config()
        # If config was newly created or updated with defaults, save_config was already called by load_config.
        logging.info(f"Configuration loaded from: {CONFIG_FILE_PATH}")
    except Exception as e:
        logging.error(f"Fatal error during configuration loading: {e}", exc_info=True)
        # Fallback or exit if config is critical and cannot be loaded/created
        # For now, load_config returns defaults, so we should be okay.
        config = DEFAULT_CONFIG # Ensure config is not None

    # Setup application-wide logging (after config dir is potentially created)
    setup_logging() # Call this after load_config as it might use CONFIG_FILE_PATH for log dir

    # Instantiate and run the main GUI application window
    try:
        app = MainAppWindow(initial_config=config) # Pass the loaded config
        app.mainloop()
    except Exception as e:
        logging.critical(f"An unhandled exception occurred in the GUI: {e}", exc_info=True)
        # Optionally, show a simple error dialog if Tkinter is still partially functional
        # import tkinter as tk
        # from tkinter import messagebox
        # root = tk.Tk()
        # root.withdraw() # Hide the main Tk window
        # messagebox.showerror("Fatal Error", f"A critical error occurred: {e}\nSee log for details.")
        # root.destroy()

    logging.info(f"{APP_NAME} finished.")

if __name__ == "__main__":
    main()