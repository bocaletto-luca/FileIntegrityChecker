#!/usr/bin/env python3
"""
Datei-Integritätsprüfer - Finale Version
------------------------------------------
Eine Linux-Anwendung, die kritische Dateien oder ganze Verzeichnisse überwacht, indem sie
ihre SHA256-Hashes berechnet und vergleicht, um unautorisierte Änderungen festzustellen.

Funktionen:
  - Wählen Sie ein Verzeichnis zur Überwachung aus.
  - Berechnen Sie rekursiv den SHA256-Hash für jede Datei (in 4096-Byte-Blöcken lesend).
  - Speichern Sie den Ausgangszustand (Dateipfade und Hashes) in einer JSON-Datei.
  - Überprüfen Sie manuell oder periodisch die Integrität, indem Sie die aktuellen Hashes mit dem Ausgangszustand vergleichen.
  - Erhalten Sie visuelle Benachrichtigungen über den Ausgabebereich und Meldungsfelder, wenn Änderungen festgestellt werden.
  - Option für geplante Scans mit der Möglichkeit, den geplanten Scan zu stoppen.
  - Saubere, benutzerfreundliche grafische Oberfläche (GUI) erstellt mit Tkinter.
  - Erweiterte Protokollierung (alle Operationen und Fehler werden in "file_integrity_checker.log" gespeichert).

Autor: [Ihr Name]
Lizenz: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Logging konfigurieren
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Datei-Integritätsprüfer gestartet.")

# Konstanten
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Intervall für den geplanten Scan in Millisekunden (60 Sekunden)

def calculate_hash(file_path):
    """
    Berechnet den SHA256-Hash für die angegebene Datei.
    Liest die Datei in 4096-Byte-Blöcken, um große Dateien zu handhaben.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des Hashes für {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Durchsucht rekursiv das angegebene Verzeichnis (unter Ausschluss der in EXCLUDE_DIRS enthaltenen Verzeichnisse)
    und berechnet den SHA256-Hash für jede Datei.
    
    Gibt ein Dictionary in der Form {Dateipfad: Hash} zurück.
    """
    logger.info(f"Durchsuche Verzeichnis: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Schließt Verzeichnisse aus, die in EXCLUDE_DIRS aufgeführt sind
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Grafische Benutzeroberfläche für den Datei-Integritätsprüfer."""
    def __init__(self):
        super().__init__()
        self.title("Datei-Integritätsprüfer")
        self.geometry("800x600")
        self.initial_state = {}       # Ausgangszustand (Datei: Hash)
        self.monitored_directory = "" # Ausgewähltes Verzeichnis
        self.scheduled_scan_active = False
        self.after_id = None          # Von after() zurückgegebene ID für den geplanten Scan
        self.create_widgets()

    def create_widgets(self):
        # Rahmen für die Verzeichnisauswahl
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Zu überwachendes Verzeichnis:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Auswählen", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Rahmen für die Schaltflächen
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Initiale Hashes berechnen", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Zustand speichern", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Integrität überprüfen", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Geplanten Scan starten", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Geplanten Scan stoppen", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Ausgabebereich
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Statusanzeige
        self.lbl_status = ttk.Label(self, text="Bereit")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Verzeichnis zur Überwachung auswählen")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Ausgewähltes Verzeichnis: {directory}\n")
            self.lbl_status.config(text="Verzeichnis ausgewählt.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Fehler", "Bitte wählen Sie zunächst ein Verzeichnis zur Überwachung aus.")
            return
        self.lbl_status.config(text="Berechne initiale Hashes...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Initiale Hashes berechnet:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Initiale Hashes berechnet.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Fehler", "Kein Zustand zum Speichern vorhanden. Bitte berechnen Sie zuerst die Hashes.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Zustand gespeichert in: {filename}\n")
            self.lbl_status.config(text="Zustand erfolgreich gespeichert.")
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Speichern der Datei: {e}")
            self.lbl_status.config(text="Fehler beim Speichern des Zustands.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Fehler", "Bitte berechnen Sie zunächst die initialen Hashes.")
            return
        self.lbl_status.config(text="Überprüfe Integrität...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Überprüfe auf geänderte oder fehlende Dateien
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Datei entfernt: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modifikation festgestellt in: {path}")
        # Überprüfe auf neue Dateien
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Neue Datei festgestellt: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modifikationen festgestellt:\n" + msg + "\n")
            messagebox.showwarning("Modifikationen festgestellt", msg)
        else:
            self.text_output.insert(tk.END, "Keine Modifikationen festgestellt.\n")
            messagebox.showinfo("Integritätsprüfung", "Keine Modifikationen festgestellt.")
        self.lbl_status.config(text="Integritätsprüfung abgeschlossen.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Fehler", "Bitte wählen Sie zunächst ein Verzeichnis zur Überwachung aus.")
            return
        self.lbl_status.config(text="Geplanter Scan gestartet.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Den nächsten Scan nach dem angegebenen Intervall planen
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Geplanter Scan gestoppt.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
