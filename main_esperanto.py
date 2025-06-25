#!/usr/bin/env python3
"""
Dosiero-Integritkontrolilo - Finfina Eldono
--------------------------------------------
Linux-aplikaĵo, kiu kontrolas kritikajn dosierojn aŭ tutaĵojn de dosierujo per kalkulado kaj komparo
de iliaj SHA256-hashoj por detekti nepermesitajn modifojn.

Aŭtomatoj:
  - Elektu dosierujon por kontroli.
  - Rekursive kalkulu la SHA256-hash por ĉiu dosiero (legante en pecoj de 4096 bajtoj).
  - Konservu la komencan staton (dosiera vojo kaj hashoj) en JSON-dosiero.
  - Kontrolu la integrecon mane aŭ periodike, komparante la aktualajn hashojn kun la komenca stato.
  - Vidaj sciigoj per la eliga areo kaj mesaĝaj fenestroj, kiam ŝanĝoj estas detektitaj.
  - Opcio por planita skanado kun ebleco haltigi la planitan skanadon.
  - Pura, uzanto-amika GUI konstruita per Tkinter.
  - Altnivela registroado (ĉiuj operacioj kaj eraroj estas registritaj en "file_integrity_checker.log").

Aŭtoro: [Via Nomo]
Licenco: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Agordu la registroadon
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Dosiero-Integritkontrolilo ekfunkciis.")

# Konstantoj
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Intervallo por planita skanado en milisekundoj (60 sekundoj)

def calculate_hash(file_path):
    """
    Kalkulas la SHA256-hash de la donita dosiero.
    Legas la dosieron en pecoj de 4096 bajtoj por prilabori grandajn dosierojn.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Eraro dum kalkulado de la hash por {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Rekursive skanas la donitan dosierujon (elspezante la dosierujojn en EXCLUDE_DIRS)
    kaj kalkulas la SHA256-hash por ĉiu dosiero.
    
    Revenigas vortaron en la formo {dosiera_vojo: hash}.
    """
    logger.info(f"Skanado de dosierujo: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Elspicu la dosierujojn listitajn en EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Grafika interfaco por la Dosiero-Integritkontrolilo."""
    def __init__(self):
        super().__init__()
        self.title("Dosiero-Integritkontrolilo")
        self.geometry("800x600")
        self.initial_state = {}       # Komenca stato (dosiero: hash)
        self.monitored_directory = "" # Elektita dosierujo
        self.scheduled_scan_active = False
        self.after_id = None          # ID de after() por la planita skanado
        self.create_widgets()

    def create_widgets(self):
        # Dosieruja elekto
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Dosierujo por kontroli:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Elekti", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Butonoj
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Kalkuli komencajn hashojn", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Savi staton", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Kontroli integrecon", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Ekstarti planitan skanadon", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Halti planitan skanadon", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Teksta areo por eligo
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Stata etikedo
        self.lbl_status = ttk.Label(self, text="Pretas")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Elektu dosierujon por kontroli")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Elektita dosierujo: {directory}\n")
            self.lbl_status.config(text="Dosierujo elektita.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Eraro", "Bonvolu unue elekti dosierujon por kontroli.")
            return
        self.lbl_status.config(text="Kalkulante komencajn hashojn...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Komencaj hashoj kalkulitaj:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Komencaj hashoj kalkulitaj.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Eraro", "Neniu stato por savi. Bonvolu kalkuli la hashojn unue.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Savita stato en: {filename}\n")
            self.lbl_status.config(text="Stato savita sukcese.")
        except Exception as e:
            messagebox.showerror("Eraro", f"Eraro dum savado de la dosiero: {e}")
            self.lbl_status.config(text="Eraro dum savado de la stato.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Eraro", "Bonvolu kalkuli la komencajn hashojn unue.")
            return
        self.lbl_status.config(text="Kontrolante integrecon...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Kontroli modifitajn aŭ forigitajn dosierojn
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Dosiero forigita: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modifo detektita ĉe: {path}")
        # Kontroli novajn dosierojn
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Nova dosiero detektita: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Detektitaj modifoj:\n" + msg + "\n")
            messagebox.showwarning("Detektitaj modifoj", msg)
        else:
            self.text_output.insert(tk.END, "Neniu modifo detektita.\n")
            messagebox.showinfo("Kontrolo de integreco", "Neniu modifo detektita.")
        self.lbl_status.config(text="Kontrolo de integreco finita.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Eraro", "Bonvolu unue elekti dosierujon por kontroli.")
            return
        self.lbl_status.config(text="Planita skanado komencita.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Plani la sekvan skanadon post la difinita intervalo
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Planita skanado haltita.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
