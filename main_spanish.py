#!/usr/bin/env python3
"""
Verificador de integridad de archivos - Versión final
------------------------------------------------------
Una aplicación de Linux que monitoriza archivos críticos o directorios enteros calculando y comparando
sus hashes SHA256 para detectar modificaciones no autorizadas.

Características:
  - Seleccionar un directorio para monitorizar.
  - Calcular recursivamente el hash SHA256 para cada archivo (leyendo en bloques de 4096 bytes).
  - Guardar el estado inicial (rutas de archivos y hashes) en un archivo JSON.
  - Verificar manual o periódicamente la integridad comparando los hashes actuales con el estado inicial.
  - Notificaciones visuales a través del área de salida y cuadros de mensaje cuando se detectan cambios.
  - Opción de escaneo programado con la capacidad de detener el escaneo programado.
  - Interfaz gráfica limpia y amigable construida con Tkinter.
  - Registro avanzado (todas las operaciones y errores se almacena en "file_integrity_checker.log").

Autor: [Su Nombre]
Licencia: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Configurar el registro
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Verificador de integridad de archivos iniciado.")

# Constantes
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Intervalo de escaneo programado en milisegundos (60 segundos)

def calculate_hash(file_path):
    """
    Calcula el hash SHA256 para el archivo dado.
    Lee el archivo en bloques de 4096 bytes para manejar archivos de gran tamaño.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error al calcular el hash para {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Escanea recursivamente el directorio dado (excluyendo los directorios en EXCLUDE_DIRS)
    y calcula el hash SHA256 de cada archivo.
    
    Retorna un diccionario en la forma {ruta_archivo: hash}.
    """
    logger.info(f"Escaneando directorio: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Excluir los directorios listados en EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Interfaz gráfica para el verificador de integridad de archivos."""
    def __init__(self):
        super().__init__()
        self.title("Verificador de integridad de archivos")
        self.geometry("800x600")
        self.initial_state = {}       # Estado inicial (archivo: hash)
        self.monitored_directory = "" # Directorio seleccionado
        self.scheduled_scan_active = False
        self.after_id = None          # ID retornado por after() para el escaneo programado
        self.create_widgets()

    def create_widgets(self):
        # Marco para la selección de directorio
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Directorio a monitorizar:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Seleccionar", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Marco para los botones
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Calcular hashes iniciales", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Guardar estado", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Verificar integridad", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Iniciar escaneo programado", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Detener escaneo programado", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Área de texto para la salida
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Etiqueta de estado
        self.lbl_status = ttk.Label(self, text="Listo")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Selecciona el directorio a monitorizar")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Directorio seleccionado: {directory}\n")
            self.lbl_status.config(text="Directorio seleccionado.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Por favor, seleccione primero un directorio para monitorizar.")
            return
        self.lbl_status.config(text="Calculando hashes iniciales...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Hashes iniciales calculados:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Hashes iniciales calculados.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Error", "No hay estado para guardar. Por favor, calcule primero los hashes.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Estado guardado en: {filename}\n")
            self.lbl_status.config(text="Estado guardado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar el archivo: {e}")
            self.lbl_status.config(text="Error al guardar el estado.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Error", "Por favor, calcule primero los hashes iniciales.")
            return
        self.lbl_status.config(text="Verificando integridad...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Verificar archivos modificados o eliminados
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Archivo eliminado: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modificación detectada en: {path}")
        # Verificar nuevos archivos
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Nuevo archivo detectado: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modificaciones detectadas:\n" + msg + "\n")
            messagebox.showwarning("Modificaciones detectadas", msg)
        else:
            self.text_output.insert(tk.END, "No se han detectado modificaciones.\n")
            messagebox.showinfo("Verificación de integridad", "No se han detectado modificaciones.")
        self.lbl_status.config(text="Verificación de integridad completada.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Por favor, seleccione primero un directorio para monitorizar.")
            return
        self.lbl_status.config(text="Escaneo programado iniciado.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Programar el próximo escaneo después del intervalo especificado
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Escaneo programado detenido.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
