#!/usr/bin/env python3
"""
Dosya Bütünlüğü Denetleyici - Nihai Sürüm
-------------------------------------------
Bu Linux uygulaması, kritik dosyaları veya tüm dizinleri izler. Yetkisiz değişiklikleri tespit etmek için
dosyaların SHA256 özetlerini hesaplayıp karşılaştırır.

Özellikler:
  - İzlenecek bir dizin seçin.
  - Her dosyanın SHA256 özetini özyinelemeli olarak hesaplayın (4096 baytlık bloklar halinde okuyun).
  - İlk durumu (dosya yolları ve özetler) bir JSON dosyasında kaydedin.
  - Mevcut özetleri ilk durumla karşılaştırarak manuel veya periyodik bütünlük doğrulaması yapın.
  - Değişiklik tespit edildiğinde, çıktı alanı ve mesaj kutuları aracılığıyla görsel bildirimler sağlayın.
  - Planlanmış tarama seçeneği (taramayı durdurma imkanı ile).
  - Tkinter ile geliştirilmiş temiz, kullanıcı dostu bir GUI.
  - Gelişmiş günlük kaydı (tüm işlemler ve hatalar "file_integrity_checker.log" dosyasında tutulur).

Yazar: [Adınız]
Lisans: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Günlük kaydı ayarla
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Dosya Bütünlüğü Denetleyici başlatıldı.")

# Sabitler
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Planlanmış tarama aralığı (milisaniye cinsinden, 60 saniye)

def calculate_hash(file_path):
    """
    Belirtilen dosyanın SHA256 özetini hesaplar.
    Büyük dosyaları işlemek adına dosyayı 4096 baytlık bloklar halinde okur.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"{file_path} için özet hesaplanırken hata: {e}")
        return None

def scan_directory(directory):
    """
    Belirtilen dizini özyinelemeli olarak tarar (EXCLUDE_DIRS’de bulunan dizinler hariç)
    ve her dosyanın SHA256 özetini hesaplar.
    
    {dosya_yolu: özet} biçiminde bir sözlük döndürür.
    """
    logger.info(f"Dizin taranıyor: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # EXCLUDE_DIRS’de yer alan dizinleri hariç tut
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Dosya Bütünlüğü Denetleyici'nin Grafiksel Kullanıcı Arayüzü"""
    def __init__(self):
        super().__init__()
        self.title("Dosya Bütünlüğü Denetleyici")
        self.geometry("800x600")
        self.initial_state = {}       # İlk durum (dosya: özet)
        self.monitored_directory = "" # Seçilen dizin
        self.scheduled_scan_active = False
        self.after_id = None          # after() fonksiyonundan dönen planlanmış tarama ID'si
        self.create_widgets()

    def create_widgets(self):
        # Dizin seçim çerçevesi
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="İzlenecek Dizin:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Seç", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Düğme çerçevesi
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="İlk Özetleri Hesapla", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Durumu Kaydet", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Bütünlüğü Doğrula", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Planlanmış Tarama Başlat", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Planlanmış Tarama Durdur", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Çıktı metin alanı
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Durum etiketi
        self.lbl_status = ttk.Label(self, text="Hazır")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="İzlenecek Dizin Seçin")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Seçilen Dizin: {directory}\n")
            self.lbl_status.config(text="Dizin seçildi.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Hata", "Lütfen önce izlenecek bir dizin seçin.")
            return
        self.lbl_status.config(text="İlk özetler hesaplanıyor...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "İlk özetler hesaplandı:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="İlk özetler hesaplandı.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Hata", "Kaydedilecek durum yok. Lütfen önce özetleri hesaplayın.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Durum kaydedildi: {filename}\n")
            self.lbl_status.config(text="Durum başarıyla kaydedildi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {e}")
            self.lbl_status.config(text="Durum kaydedilirken hata oluştu.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Hata", "Lütfen önce ilk özetleri hesaplayın.")
            return
        self.lbl_status.config(text="Bütünlük doğrulanıyor...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Değiştirilen veya silinen dosyaları kontrol et
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Dosya silindi: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Değişiklik tespit edildi: {path}")
        # Yeni dosyaları kontrol et
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Yeni dosya tespit edildi: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Tespit edilen değişiklikler:\n" + msg + "\n")
            messagebox.showwarning("Değişiklikler tespit edildi", msg)
        else:
            self.text_output.insert(tk.END, "Hiçbir değişiklik tespit edilmedi.\n")
            messagebox.showinfo("Bütünlük Doğrulama", "Hiçbir değişiklik tespit edilmedi.")
        self.lbl_status.config(text="Bütünlük doğrulama tamamlandı.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Hata", "Lütfen önce izlenecek bir dizin seçin.")
            return
        self.lbl_status.config(text="Planlanmış tarama başlatıldı.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Belirlenen aralıktan sonra sonraki taramayı planla
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Planlanmış tarama durduruldu.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
