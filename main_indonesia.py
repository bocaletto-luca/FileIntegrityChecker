#!/usr/bin/env python3
"""
Pemeriksa Integritas Berkas - Rilis Final
-----------------------------------------
Sebuah aplikasi Linux yang memonitor berkas penting atau seluruh direktori dengan cara menghitung dan membandingkan
nilai hash SHA256 dari berkas-berkas tersebut untuk mendeteksi perubahan yang tidak sah.

Fitur:
  - Pilih direktori yang akan dipantau.
  - Hitung nilai hash SHA256 untuk setiap berkas secara rekursif (dengan membaca berkas dalam potongan 4096 byte).
  - Simpan kondisi awal (jalur berkas dan nilai hash) ke dalam berkas JSON.
  - Verifikasi integritas secara manual ataupun berkala dengan membandingkan nilai hash saat ini dengan kondisi awal.
  - Tampilkan notifikasi visual melalui area keluaran dan kotak pesan ketika perubahan terdeteksi.
  - Opsi pemindaian terjadwal dengan kemampuan untuk menghentikan pemindaian tersebut.
  - GUI yang bersih dan ramah pengguna yang dibuat menggunakan Tkinter.
  - Pencatatan yang canggih (semua operasi dan kesalahan dicatat di dalam "file_integrity_checker.log").

Penulis: [Nama Anda]
Lisensi: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Konfigurasi pencatatan (logging)
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Pemeriksa Integritas Berkas dimulai.")

# Konstanta
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Interval pemindaian terjadwal dalam milidetik (60 detik)

def calculate_hash(file_path):
    """
    Menghitung nilai hash SHA256 untuk berkas yang diberikan.
    Fungsi ini membaca berkas dalam potongan 4096 byte untuk menangani berkas-berkas besar.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Terjadi kesalahan saat menghitung hash untuk {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Melakukan pemindaian secara rekursif pada direktori yang diberikan (dengan mengesampingkan direktori yang tercantum di EXCLUDE_DIRS)
    dan menghitung nilai hash SHA256 untuk setiap berkas.
    
    Fungsi ini mengembalikan sebuah kamus dengan format {jalur_berkas: hash}.
    """
    logger.info(f"Memindai direktori: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Mengesampingkan direktori yang ada di EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Antarmuka Grafis untuk Pemeriksa Integritas Berkas."""
    def __init__(self):
        super().__init__()
        self.title("Pemeriksa Integritas Berkas")
        self.geometry("800x600")
        self.initial_state = {}       # Kondisi awal (berkas: hash)
        self.monitored_directory = "" # Direktori yang dipilih
        self.scheduled_scan_active = False
        self.after_id = None          # ID dari fungsi after() untuk pemindaian terjadwal
        self.create_widgets()

    def create_widgets(self):
        # Frame pemilihan direktori
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Direktori untuk dipantau:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Pilih", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Frame tombol-tombol
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Hitung Hash Awal", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Simpan Kondisi", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Verifikasi Integritas", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Mulai Pemindaian Terjadwal", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Hentikan Pemindaian Terjadwal", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Area teks untuk output
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Label status
        self.lbl_status = ttk.Label(self, text="Siap")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Pilih Direktori untuk Dipantau")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Direktori yang dipilih: {directory}\n")
            self.lbl_status.config(text="Direktori telah dipilih.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Kesalahan", "Silakan pilih direktori yang akan dipantau terlebih dahulu.")
            return
        self.lbl_status.config(text="Menghitung hash awal...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Hash awal telah dihitung:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Hash awal telah selesai dihitung.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Kesalahan", "Tidak ada kondisi yang disimpan. Silakan hitung hash terlebih dahulu.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Kondisi telah disimpan di: {filename}\n")
            self.lbl_status.config(text="Kondisi berhasil disimpan.")
        except Exception as e:
            messagebox.showerror("Kesalahan", f"Terjadi kesalahan saat menyimpan berkas: {e}")
            self.lbl_status.config(text="Kesalahan saat menyimpan kondisi.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Kesalahan", "Silakan hitung hash awal terlebih dahulu.")
            return
        self.lbl_status.config(text="Memverifikasi integritas...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Memeriksa berkas yang telah diubah atau dihapus
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Berkas telah dihapus: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Perubahan terdeteksi: {path}")
        # Memeriksa berkas baru
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Berkas baru terdeteksi: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Perubahan terdeteksi:\n" + msg + "\n")
            messagebox.showwarning("Perubahan Terdeteksi", msg)
        else:
            self.text_output.insert(tk.END, "Tidak ada perubahan yang terdeteksi.\n")
            messagebox.showinfo("Verifikasi Integritas", "Tidak ada perubahan yang terdeteksi.")
        self.lbl_status.config(text="Verifikasi integritas selesai.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Kesalahan", "Silakan pilih direktori yang akan dipantau terlebih dahulu.")
            return
        self.lbl_status.config(text="Memulai pemindaian terjadwal...")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Menjadwalkan pemindaian berikutnya setelah interval yang telah ditentukan
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Pemindaian terjadwal dihentikan.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
