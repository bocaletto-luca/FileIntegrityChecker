#!/usr/bin/env python3
"""
Verificador de Integridade de Arquivos - Versão Final
-----------------------------------------------------
Uma aplicação Linux que monitora arquivos críticos ou diretórios inteiros calculando e comparando
seus hashes SHA256 para detectar modificações não autorizadas.

Recursos:
  - Selecione um diretório para monitorar.
  - Calcule recursivamente o hash SHA256 para cada arquivo (lendo em blocos de 4096 bytes).
  - Salve o estado inicial (caminhos dos arquivos e hashes) em um arquivo JSON.
  - Verifique manual ou periodicamente a integridade ao comparar os hashes atuais com o estado inicial.
  - Receba notificações visuais através da área de saída e caixas de mensagem quando alterações forem detectadas.
  - Opção de varredura agendada com a possibilidade de interromper a varredura.
  - Interface gráfica limpa e amigável construída com Tkinter.
  - Registro avançado (todas as operações e erros são registrados em "file_integrity_checker.log").

Autor: [Seu Nome]
Licença: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Configurar o registro de logs
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Verificador de Integridade de Arquivos iniciado.")

# Constantes
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Intervalo de varredura agendada em milissegundos (60 segundos)

def calculate_hash(file_path):
    """
    Calcula o hash SHA256 para o arquivo fornecido.
    Lê o arquivo em blocos de 4096 bytes para lidar com arquivos grandes.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Erro ao calcular o hash para {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Varre recursivamente o diretório fornecido (excluindo os diretórios em EXCLUDE_DIRS)
    e calcula o hash SHA256 para cada arquivo.
    
    Retorna um dicionário no formato {caminho_arquivo: hash}.
    """
    logger.info(f"Varrendo o diretório: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Excluir diretórios listados em EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Interface gráfica para o verificador de integridade de arquivos."""
    def __init__(self):
        super().__init__()
        self.title("Verificador de Integridade de Arquivos")
        self.geometry("800x600")
        self.initial_state = {}       # Estado inicial (arquivo: hash)
        self.monitored_directory = "" # Diretório selecionado
        self.scheduled_scan_active = False
        self.after_id = None          # ID retornado pelo after() para a varredura agendada
        self.create_widgets()

    def create_widgets(self):
        # Frame para seleção de diretório
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Diretório a monitorar:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Selecionar", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Frame para os botões
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Calcular hashes iniciais", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Salvar estado", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Verificar integridade", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Iniciar varredura agendada", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Parar varredura agendada", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Área de saída de texto
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Rótulo de status
        self.lbl_status = ttk.Label(self, text="Pronto")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Selecione o diretório a monitorar")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Diretório selecionado: {directory}\n")
            self.lbl_status.config(text="Diretório selecionado.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Erro", "Por favor, selecione primeiro um diretório para monitorar.")
            return
        self.lbl_status.config(text="Calculando hashes iniciais...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Hashes iniciais calculados:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Hashes iniciais calculados.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Erro", "Nenhum estado para salvar. Por favor, calcule os hashes primeiro.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Estado salvo em: {filename}\n")
            self.lbl_status.config(text="Estado salvo com sucesso.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar o arquivo: {e}")
            self.lbl_status.config(text="Erro ao salvar o estado.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Erro", "Por favor, calcule os hashes iniciais primeiro.")
            return
        self.lbl_status.config(text="Verificando integridade...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Verifica arquivos modificados ou removidos
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Arquivo removido: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modificação detectada em: {path}")
        # Verifica novos arquivos
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Novo arquivo detectado: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modificações detectadas:\n" + msg + "\n")
            messagebox.showwarning("Modificações detectadas", msg)
        else:
            self.text_output.insert(tk.END, "Nenhuma modificação detectada.\n")
            messagebox.showinfo("Verificação de integridade", "Nenhuma modificação detectada.")
        self.lbl_status.config(text="Verificação de integridade concluída.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Erro", "Por favor, selecione primeiro um diretório para monitorar.")
            return
        self.lbl_status.config(text="Varredura agendada iniciada.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Agenda a próxima varredura após o intervalo especificado
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Varredura agendada parada.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
