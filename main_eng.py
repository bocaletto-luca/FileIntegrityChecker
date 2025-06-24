#!/usr/bin/env python3
"""
File Integrity Checker - Final Release
-----------------------------------------
A Linux application that monitors critical files or entire directories by calculating and comparing
their SHA256 hashes to detect unauthorized modifications.

Features:
  - Select a directory to monitor.
  - Recursively calculate the SHA256 hash for every file (reading in 4096-byte chunks).
  - Save the initial state (file paths and hashes) in a JSON file.
  - Manually or periodically verify the integrity by comparing the current hashes with the initial state.
  - Visual notifications via the output area and message boxes when changes are detected.
  - Scheduled scan option with the ability to stop the scheduled scan.
  - Clean, user-friendly GUI built with Tkinter.
  - Advanced logging (all operations and errors are stored in "file_integrity_checker.log").

Author: [Your Name]
License: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Configure logging
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("File Integrity Checker started.")

# Constants
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Scheduled scan interval in milliseconds (60 seconds)

def calculate_hash(file_path):
    """
    Calculates the SHA256 hash for the given file.
    Reads the file in 4096-byte blocks to handle large files.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Recursively scans the given directory (excluding directories in EXCLUDE_DIRS)
    and calculates the SHA256 hash for every file.
    
    Returns a dictionary in the form {file_path: hash}.
    """
    logger.info(f"Scanning directory: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Exclude directories from EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Graphical interface for the File Integrity Checker."""
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker")
        self.geometry("800x600")
        self.initial_state = {}       # Initial state (file: hash)
        self.monitored_directory = "" # Selected directory
        self.scheduled_scan_active = False
        self.after_id = None          # ID returned by after() for scheduled scanning
        self.create_widgets()

    def create_widgets(self):
        # Directory selection frame
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Directory to Monitor:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Select", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Buttons frame
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Calculate Initial Hashes", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Save State", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Verify Integrity", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Start Scheduled Scan", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Stop Scheduled Scan", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Output text area
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Status label
        self.lbl_status = ttk.Label(self, text="Ready")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Selected directory: {directory}\n")
            self.lbl_status.config(text="Directory selected.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Please select a directory to monitor first.")
            return
        self.lbl_status.config(text="Calculating initial hashes...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Initial hashes calculated:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Initial hashes calculated.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Error", "No state to save. Please calculate the hashes first.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"State saved in: {filename}\n")
            self.lbl_status.config(text="State saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving file: {e}")
            self.lbl_status.config(text="Error saving state.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Error", "Please calculate the initial hashes first.")
            return
        self.lbl_status.config(text="Verifying integrity...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Check for modified or missing files
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"File removed: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modification detected in: {path}")
        # Check for new files
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"New file detected: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modifications detected:\n" + msg + "\n")
            messagebox.showwarning("Modifications Detected", msg)
        else:
            self.text_output.insert(tk.END, "No modifications detected.\n")
            messagebox.showinfo("Integrity Verification", "No modifications detected.")
        self.lbl_status.config(text="Integrity verification completed.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Please select a directory to monitor first.")
            return
        self.lbl_status.config(text="Scheduled scan started.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Schedule the next scan after the specified interval
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Scheduled scan stopped.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
