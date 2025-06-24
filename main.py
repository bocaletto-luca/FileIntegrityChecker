#!/usr/bin/env python3
"""
File Integrity Checker - Release Finale
------------------------------------------
Un'applicazione per monitorare i file critici o intere directory, calcolando e confrontando
i loro hash SHA256 per rilevare modifiche non autorizzate.

Funzionalità:
  - Selezione di una directory da monitorare.
  - Calcolo ricorsivo degli hash dei file in SHA256 (lettura a blocchi).
  - Salvataggio dello stato iniziale in un file JSON.
  - Verifica manuale o programmata per segnalare file modificati, rimossi o nuovi.
  - Notifiche visive nella GUI (area di output e messagebox).
  - Supporto per scansione programmata e possibilità di interromperla.
  - Logging avanzato per tracciare operazioni e errori.

Autore: [Il Tuo Nome]
Licenza: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Configurazione del logging
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("File Integrity Checker avviato.")

# Costanti
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # intervallo per la scansione programmata: 60.000 ms = 60 sec

def calcola_hash(file_path):
    """
    Calcola l'hash SHA256 del file specificato.
    Legge il file a blocchi di 4096 byte, utile per file di grandi dimensioni.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for blocco in iter(lambda: fp.read(4096), b""):
                sha256.update(blocco)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Errore nel calcolo dell'hash per {file_path}: {e}")
        return None

def scansiona_directory(directory):
    """
    Scansiona ricorsivamente la directory, escludendo le directory in EXCLUDE_DIRS,
    e calcola l'hash SHA256 per ogni file.
    
    Restituisce un dizionario formato {percorso: hash}.
    """
    logger.info(f"Effettuo la scansione della directory: {directory}")
    stato = {}
    for root, dirs, files in os.walk(directory):
        # Escludi directory da EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            percorso = os.path.join(root, file)
            hash_val = calcola_hash(percorso)
            if hash_val:
                stato[percorso] = hash_val
    return stato

class FileIntegrityCheckerGUI(tk.Tk):
    """Interfaccia grafica per il File Integrity Checker."""
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker")
        self.geometry("800x600")
        
        # Stato della scansione
        self.stato_iniziale = {}     # Stato iniziale (file: hash)
        self.directory_monitorata = ""   # Directory selezionata
        self.scan_programmata_attiva = False
        self.after_id = None         # ID dell'after() per la scansione programmata
        self.create_widgets()

    def create_widgets(self):
        # Sezione: selezione della directory
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Directory da monitorare:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_sel = ttk.Button(frame_dir, text="Seleziona", command=self.seleziona_directory)
        btn_sel.pack(side=tk.LEFT, padx=5)

        # Sezione: pulsanti di azione
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calcola = ttk.Button(frame_buttons, text="Calcola Hash Iniziale", command=self.calcola_hash_iniziale)
        btn_calcola.pack(side=tk.LEFT, padx=5)
        btn_salva = ttk.Button(frame_buttons, text="Salva Stato", command=self.salva_stato)
        btn_salva.pack(side=tk.LEFT, padx=5)
        btn_verifica = ttk.Button(frame_buttons, text="Verifica Integrità", command=self.verifica_integrita)
        btn_verifica.pack(side=tk.LEFT, padx=5)
        btn_avvia_prog = ttk.Button(frame_buttons, text="Avvia Scansione Programmata", command=self.avvia_scansione_programmata)
        btn_avvia_prog.pack(side=tk.LEFT, padx=5)
        btn_ferma_prog = ttk.Button(frame_buttons, text="Ferma Scansione Programmata", command=self.ferma_scansione_programmata)
        btn_ferma_prog.pack(side=tk.LEFT, padx=5)

        # Area per output dei risultati
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Etichetta di stato
        self.lbl_stato = ttk.Label(self, text="Pronto")
        self.lbl_stato.pack(padx=10, pady=5)

    def seleziona_directory(self):
        directory = filedialog.askdirectory(title="Seleziona la directory da monitorare")
        if directory:
            self.directory_monitorata = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Directory selezionata: {directory}\n")
            self.lbl_stato.config(text="Directory selezionata.")

    def calcola_hash_iniziale(self):
        if not self.directory_monitorata:
            messagebox.showerror("Errore", "Seleziona prima una directory da monitorare.")
            return
        self.lbl_stato.config(text="Calcolando hash iniziali...")
        self.update_idletasks()
        stato = scansiona_directory(self.directory_monitorata)
        self.stato_iniziale = stato.copy()
        self.text_output.insert(tk.END, "Hash iniziali calcolati:\n")
        for percorso, hash_val in stato.items():
            self.text_output.insert(tk.END, f"{percorso}: {hash_val}\n")
        self.lbl_stato.config(text="Hash iniziali calcolati con successo.")

    def salva_stato(self):
        if not self.stato_iniziale:
            messagebox.showerror("Errore", "Nessuno stato da salvare. Calcola prima gli hash.")
            return
        try:
            filename = os.path.join(self.directory_monitorata, "stato_integrita.json")
            with open(filename, "w") as f:
                json.dump(self.stato_iniziale, f, indent=4)
            self.text_output.insert(tk.END, f"Stato salvato in: {filename}\n")
            self.lbl_stato.config(text="Stato salvato con successo.")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nel salvataggio: {e}")
            self.lbl_stato.config(text="Errore nel salvataggio del file.")

    def verifica_integrita(self):
        if not self.stato_iniziale:
            messagebox.showerror("Errore", "Calcola prima lo stato iniziale degli hash.")
            return
        self.lbl_stato.config(text="Verifica integrità in corso...")
        self.update_idletasks()
        nuovo_stato = scansiona_directory(self.directory_monitorata)
        modifiche = []
        # Verifica file modificati o mancanti
        for percorso, hash_iniziale in self.stato_iniziale.items():
            nuovo_hash = nuovo_stato.get(percorso)
            if nuovo_hash is None:
                modifiche.append(f"File rimosso: {percorso}")
            elif nuovo_hash != hash_iniziale:
                modifiche.append(f"Modifica rilevata in: {percorso}")
        # Verifica file nuovi
        for percorso in nuovo_stato:
            if percorso not in self.stato_iniziale:
                modifiche.append(f"Nuovo file rilevato: {percorso}")
        if modifiche:
            msg = "\n".join(modifiche)
            self.text_output.insert(tk.END, "Modifiche rilevate:\n" + msg + "\n")
            messagebox.showwarning("Modifiche rilevate", msg)
        else:
            self.text_output.insert(tk.END, "Nessuna modifica rilevata.\n")
            messagebox.showinfo("Verifica Integrità", "Nessuna modifica rilevata.")
        self.lbl_stato.config(text="Verifica completata.")

    def avvia_scansione_programmata(self):
        if not self.directory_monitorata:
            messagebox.showerror("Errore", "Seleziona prima una directory da monitorare.")
            return
        self.lbl_stato.config(text="Scansione programmata avviata.")
        self.scan_programmata_attiva = True
        self.scansione_programmata()

    def scansione_programmata(self):
        if self.scan_programmata_attiva:
            self.verifica_integrita()
            # Pianifica la prossima esecuzione dopo l'intervallo specificato
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scansione_programmata)

    def ferma_scansione_programmata(self):
        self.scan_programmata_attiva = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_stato.config(text="Scansione programmata fermata.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
