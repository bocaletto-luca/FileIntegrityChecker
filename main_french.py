#!/usr/bin/env python3
"""
Vérificateur d'intégrité des fichiers - Version finale
-------------------------------------------------------
Une application Linux qui surveille des fichiers critiques ou des répertoires entiers en calculant et en comparant
leurs hachages SHA256 pour détecter des modifications non autorisées.

Fonctionnalités :
  - Sélectionnez un répertoire à surveiller.
  - Calcule récursivement le hachage SHA256 de chaque fichier (en lisant par blocs de 4096 octets).
  - Enregistrez l'état initial (chemins de fichiers et hachages) dans un fichier JSON.
  - Vérifiez manuellement ou périodiquement l'intégrité en comparant les hachages actuels avec l'état initial.
  - Notifications visuelles via la zone de sortie et des boîtes de message lors de la détection de modifications.
  - Option d'analyse planifiée avec la possibilité d'arrêter l'analyse planifiée.
  - Interface graphique propre et conviviale construite avec Tkinter.
  - Journalisation avancée (toutes les opérations et erreurs sont stockées dans "file_integrity_checker.log").

Auteur : [Votre Nom]
Licence : GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Configurer la journalisation
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Vérificateur d'intégrité des fichiers démarré.")

# Constantes
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Intervalle d'analyse planifiée en millisecondes (60 secondes)

def calculate_hash(file_path):
    """
    Calcule le hachage SHA256 du fichier donné.
    Lit le fichier en blocs de 4096 octets pour gérer les fichiers volumineux.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Erreur lors du calcul du hachage pour {file_path} : {e}")
        return None

def scan_directory(directory):
    """
    Scanne récursivement le répertoire donné (en excluant les répertoires dans EXCLUDE_DIRS)
    et calcule le hachage SHA256 de chaque fichier.
    
    Retourne un dictionnaire sous la forme {chemin_fichier: hachage}.
    """
    logger.info(f"Analyse du répertoire : {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Exclure les répertoires listés dans EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Interface graphique pour le vérificateur d'intégrité des fichiers."""
    def __init__(self):
        super().__init__()
        self.title("Vérificateur d'intégrité des fichiers")
        self.geometry("800x600")
        self.initial_state = {}       # État initial (fichier : hachage)
        self.monitored_directory = "" # Répertoire sélectionné
        self.scheduled_scan_active = False
        self.after_id = None          # ID retourné par after() pour l'analyse planifiée
        self.create_widgets()

    def create_widgets(self):
        # Cadre de sélection de répertoire
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Répertoire à surveiller :")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Sélectionner", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Cadre des boutons
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Calculer les hachages initiaux", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Enregistrer l'état", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Vérifier l'intégrité", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Démarrer l'analyse planifiée", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Arrêter l'analyse planifiée", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Zone de texte de sortie
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Étiquette de statut
        self.lbl_status = ttk.Label(self, text="Prêt")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Sélectionnez le répertoire à surveiller")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Répertoire sélectionné : {directory}\n")
            self.lbl_status.config(text="Répertoire sélectionné.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Erreur", "Veuillez d'abord sélectionner un répertoire à surveiller.")
            return
        self.lbl_status.config(text="Calcul des hachages initiaux...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Hachages initiaux calculés :\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path} : {hash_val}\n")
        self.lbl_status.config(text="Hachages initiaux calculés.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Erreur", "Aucun état à enregistrer. Veuillez d'abord calculer les hachages.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"État enregistré dans : {filename}\n")
            self.lbl_status.config(text="État enregistré avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'enregistrement du fichier : {e}")
            self.lbl_status.config(text="Erreur lors de l'enregistrement de l'état.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Erreur", "Veuillez d'abord calculer les hachages initiaux.")
            return
        self.lbl_status.config(text="Vérification de l'intégrité...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Vérifier les fichiers modifiés ou manquants
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Fichier supprimé : {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modification détectée dans : {path}")
        # Vérifier les nouveaux fichiers
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Nouveau fichier détecté : {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modifications détectées :\n" + msg + "\n")
            messagebox.showwarning("Modifications détectées", msg)
        else:
            self.text_output.insert(tk.END, "Aucune modification détectée.\n")
            messagebox.showinfo("Vérification de l'intégrité", "Aucune modification détectée.")
        self.lbl_status.config(text="Vérification de l'intégrité terminée.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Erreur", "Veuillez d'abord sélectionner un répertoire à surveiller.")
            return
        self.lbl_status.config(text="Analyse planifiée démarrée.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Planifier la prochaine analyse après l'intervalle spécifié
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Analyse planifiée arrêtée.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
