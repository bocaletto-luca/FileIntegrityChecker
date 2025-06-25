#!/usr/bin/env python3
"""
Проверка целостности файлов - Финальная версия
------------------------------------------------
Linux-приложение, которое отслеживает критические файлы или целые каталоги,
вычисляя и сравнивая их SHA256 хэши для обнаружения несанкционированных изменений.

Функции:
  - Выберите каталог для мониторинга.
  - Рекурсивно вычисляет SHA256 хэш для каждого файла (с чтением блоками по 4096 байт).
  - Сохраняет начальное состояние (пути к файлам и хэши) в JSON-файл.
  - Ручная или периодическая проверка целостности путем сравнения текущих хэшей с исходным состоянием.
  - Визуальные уведомления через область вывода и диалоговые окна при обнаружении изменений.
  - Опция запланированного сканирования с возможностью остановки.
  - Чистый и удобный графический интерфейс, созданный с помощью Tkinter.
  - Расширенное ведение журнала (все операции и ошибки записываются в "file_integrity_checker.log").

Автор: [Ваше имя]
Лицензия: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Настройка ведения журнала
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Проверка целостности файлов запущена.")

# Константы
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Интервал запланированного сканирования в миллисекундах (60 секунд)

def calculate_hash(file_path):
    """
    Вычисляет SHA256 хэш указанного файла.
    Читает файл блоками по 4096 байт для обработки больших файлов.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Ошибка при вычислении хэша для {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Рекурсивно сканирует указанный каталог (исключая каталоги из EXCLUDE_DIRS)
    и вычисляет SHA256 хэш для каждого файла.
    
    Возвращает словарь вида {путь_к_файлу: хэш}.
    """
    logger.info(f"Сканирование каталога: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Исключаем каталоги, указанные в EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Графический интерфейс для проверки целостности файлов."""
    def __init__(self):
        super().__init__()
        self.title("Проверка целостности файлов")
        self.geometry("800x600")
        self.initial_state = {}       # Начальное состояние (файл: хэш)
        self.monitored_directory = "" # Выбранный каталог
        self.scheduled_scan_active = False
        self.after_id = None          # ID, возвращаемый функцией after() для запланированного сканирования
        self.create_widgets()

    def create_widgets(self):
        # Фрейм для выбора каталога
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Каталог для мониторинга:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Выбрать", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Фрейм для кнопок
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Вычислить начальные хэши", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Сохранить состояние", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Проверить целостность", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Запустить запланированное сканирование", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Остановить запланированное сканирование", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Текстовая область вывода
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Строка состояния
        self.lbl_status = ttk.Label(self, text="Готов")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Выберите каталог для мониторинга")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Выбран каталог: {directory}\n")
            self.lbl_status.config(text="Каталог выбран.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Ошибка", "Пожалуйста, сначала выберите каталог для мониторинга.")
            return
        self.lbl_status.config(text="Вычисление начальных хэшей...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Начальные хэши вычислены:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Начальные хэши вычислены.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Ошибка", "Нет состояния для сохранения. Сначала вычислите хэши.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Состояние сохранено в: {filename}\n")
            self.lbl_status.config(text="Состояние успешно сохранено.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при сохранении файла: {e}")
            self.lbl_status.config(text="Ошибка сохранения состояния.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Ошибка", "Сначала вычислите начальные хэши.")
            return
        self.lbl_status.config(text="Проверка целостности...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Проверка изменённых или удалённых файлов
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Файл удалён: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Обнаружено изменение в: {path}")
        # Проверка новых файлов
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Обнаружен новый файл: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Обнаружены изменения:\n" + msg + "\n")
            messagebox.showwarning("Обнаружены изменения", msg)
        else:
            self.text_output.insert(tk.END, "Изменений не обнаружено.\n")
            messagebox.showinfo("Проверка целостности", "Изменений не обнаружено.")
        self.lbl_status.config(text="Проверка целостности завершена.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Ошибка", "Пожалуйста, сначала выберите каталог для мониторинга.")
            return
        self.lbl_status.config(text="Запланированное сканирование запущено.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Планирование следующего сканирования через указанный интервал
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Запланированное сканирование остановлено.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
