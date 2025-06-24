#!/usr/bin/env python3
"""
File Integrity Checker
------------------------
Un'applicazione per Linux che monitora file critici o intere directory calcolando
e verificando i loro hash (SHA256) per rilevare modifiche non autorizzate.

Funzionalità:
  - Selezione di directory da monitorare.
  - Calcolo iniziale degli hash (SHA256) e salvataggio dello stato in un file JSON.
  - Scansione manuale o programmata per rilevare eventuali differenze.
  - Notifica visiva (pop-up e aggiornamento della lista) in caso di modifiche rilevate.

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

# Funzione per calcolare l'hash SHA256 di un file
def calcola_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Leggi il file a blocchi per gestire file grandi
            for blocco in iter(lambda: f.read(4096), b""):
                sha256.update(blocco)
        return sha256.hexdigest()
    except Exception as e:
        return f"Errore: {e}"

# Funzione per scansionare ricorsivamente una directory e calcolare gli hash di tutti i file
def scansiona_directory(dir_path):
    stato = {}
    for root, dirs, files in os.walk(dir_path):
        # Possiamo escludere alcune directory se necessario, ad esempio:
        if any(exclude in root for exclude in ["/proc", "/sys", "/dev"]):
            continue
        for file in files:
            percorso = os.path.join(root, file)
            stato[percorso] = calcola_hash(percorso)
    return stato

# La classe dell'interfaccia grafica
class FileIntegrityCheckerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker")
        self.geometry("800x600")
        self.integrity_data = {}   # Stato iniziale (file: hash)
        self.directory_monitorata = ""  # Directory selezionata
        self.scansione_programmata_attiva = False
        self.after_id = None       # ID per l'after (scansione programmata)
        self.interval = 60000      # Interval di scansione programmata in millisecondi (60 sec)
        self.create_widgets()

    def create_widgets(self):
        # Sezione per la selezione della directory
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Directory da monitorare:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_sel = ttk.Button(frame_dir, text="Seleziona", command=self.seleziona_directory)
        btn_sel.pack(side=tk.LEFT, padx=5)

        # Pulsanti principali
        frame_bottoni = ttk.Frame(self)
        frame_bottoni.pack(fill=tk.X, padx=10, pady=5)
        btn_calcola = ttk.Button(frame_bottoni, text="Calcola Hash Iniziale", command=self.calcola_hash_iniziale)
        btn_calcola.pack(side=tk.LEFT, padx=5)
        btn_salva = ttk.Button(frame_bottoni, text="Salva Stato", command=self.salva_stato)
        btn_salva.pack(side=tk.LEFT, padx=5)
        btn_verifica = ttk.Button(frame_bottoni, text="Verifica Integrità", command=self.verifica_integrita)
        btn_verifica.pack(side=tk.LEFT, padx=5)
        btn_avvia_prog = ttk.Button(frame_bottoni, text="Avvia Scansione Programmata", command=self.avvia_scansione_programmata)
        btn_avvia_prog.pack(side=tk.LEFT, padx=5)
        btn_ferma_prog = ttk.Button(frame_bottoni, text="Ferma Scansione Programmata", command=self.ferma_scansione_programmata)
        btn_ferma_prog.pack(side=tk.LEFT, padx=5)

        # Area per mostrare lo stato / i risultati
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Etichetta di stato in basso
        self.lbl_stato = ttk.Label(self, text="Pronto")
        self.lbl_stato.pack(padx=10, pady=5)

    def seleziona_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_monitorata = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Directory selezionata: {directory}\n")

    def calcola_hash_iniziale(self):
        if not self.directory_monitorata:
            messagebox.showerror("Errore", "Seleziona prima una directory da monitorare.")
            return
        self.lbl_stato.config(text="Calcolo hash iniziale in corso...")
        self.update_idletasks()
        self.integrity_data = scansiona_directory(self.directory_monitorata)
        self.text_output.insert(tk.END, "Hash iniziale calcolati:\n")
        for percorso, hash_val in self.integrity_data.items():
            self.text_output.insert(tk.END, f"{percorso}: {hash_val}\n")
        self.lbl_stato.config(text="Hash iniziali calcolati.")

    def salva_stato(self):
        if not self.integrity_data:
            messagebox.showerror("Errore", "Non ci sono dati di integrità da salvare. Calcola prima gli hash iniziali.")
            return
        try:
            filename = os.path.join(self.directory_monitorata, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.integrity_data, f, indent=4)
            self.text_output.insert(tk.END, f"Stato salvato in: {filename}\n")
            self.lbl_stato.config(text="Stato salvato con successo.")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nella scrittura del file: {e}")
            self.lbl_stato.config(text="Errore nello salvataggio.")

    def verifica_integrita(self):
        if not self.integrity_data:
            messagebox.showerror("Errore", "Calcola prima lo stato iniziale.")
            return
        self.lbl_stato.config(text="Verifica integrità in corso...")
        self.update_idletasks()
        nuovo_stato = scansiona_directory(self.directory_monitorata)
        modifiche = []
        # Verifica file modificati
        for percorso, hash_iniziale in self.integrity_data.items():
            nuovo_hash = nuovo_stato.get(percorso)
            if nuovo_hash is None:
                modifiche.append(f"File rimosso: {percorso}")
            elif nuovo_hash != hash_iniziale:
                modifiche.append(f"Modifica rilevata in: {percorso}")
        # Verifica nuovi file non monitorati
        for percorso in nuovo_stato:
            if percorso not in self.integrity_data:
                modifiche.append(f"Nuovo file rilevato: {percorso}")
        if modifiche:
            messaggio = "\n".join(modifiche)
            self.text_output.insert(tk.END, "Modifiche rilevate:\n" + messaggio + "\n")
            messagebox.showwarning("Modifiche Rilevate", messaggio)
        else:
            self.text_output.insert(tk.END, "Nessuna modifica rilevata.\n")
            messagebox.showinfo("Verifica Integrità", "Nessuna modifica rilevata.")
        self.lbl_stato.config(text="Verifica completata.")

    def avvia_scansione_programmata(self):
        if not self.directory_monitorata:
            messagebox.showerror("Errore", "Seleziona prima una directory da monitorare.")
            return
        self.lbl_stato.config(text="Scansione programmata avviata.")
        self.scansione_programmata_attiva = True
        self.scansione_programmata()

    def scansione_programmata(self):
        if self.scansione_programmata_attiva:
            # Esegui la verifica integrità
            self.verifica_integrita()
            # Pianifica la prossima scansione dopo l'intervallo specificato
            self.after_id = self.after(self.interval, self.scansione_programmata)

    def ferma_scansione_programmata(self):
        self.scansione_programmata_attiva = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_stato.config(text="Scansione programmata fermata.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
