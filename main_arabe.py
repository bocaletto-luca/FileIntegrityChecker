#!/usr/bin/env python3
"""
محقق سلامة الملفات - النسخة النهائية
---------------------------------------
تطبيق Linux يقوم بمراقبة الملفات الحرجة أو الدلائل بأكملها عبر حساب ومقارنة 
هاش SHA256 الخاص بها للكشف عن التعديلات غير المصرح بها.

المزايا:
  - اختيار دليل للمراقبة.
  - حساب هاش SHA256 لكل ملف بشكل تكراري (يقرأ بكتل 4096 بايت).
  - حفظ الحالة الأولية (مسارات الملفات والهاشات) في ملف JSON.
  - التحقق اليدوي أو الدوري من السلامة عبر مقارنة الهاشات الحالية مع الحالة الأولية.
  - إشعارات بصرية عبر منطقة الإخراج ونوافذ الرسائل عند اكتشاف التعديلات.
  - خيار الفحص المجدول مع القدرة على إيقاف الفحص المجدول.
  - واجهة رسومية نظيفة وسهلة الاستخدام مبنية باستخدام Tkinter.
  - سجل مفصل (يتم تسجيل جميع العمليات والأخطاء في "file_integrity_checker.log").

المؤلف: [اسمك]
الرخصة: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# إعداد سجل الأحداث
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("تم تشغيل محقق سلامة الملفات.")

# الثوابت
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # فترة الفحص المجدول بالمللي ثانية (60 ثانية)

def calculate_hash(file_path):
    """
    يحسب هاش SHA256 للملف المحدد.
    يُقرأ الملف بكتل من 4096 بايت للتعامل مع الملفات الكبيرة.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"خطأ في حساب الهاش للملف {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    يفحص الدليل المحدد بشكل تكراري (مع استبعاد الدلائل المذكورة في EXCLUDE_DIRS)
    ويحسب هاش SHA256 لكل ملف.
    
    يُرجع قاموس بالشكل {مسار_الملف: الهاش}.
    """
    logger.info(f"فحص الدليل: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # استبعاد الدلائل المدرجة في EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """الواجهة الرسومية لمحقق سلامة الملفات."""
    def __init__(self):
        super().__init__()
        self.title("محقق سلامة الملفات")
        self.geometry("800x600")
        self.initial_state = {}       # الحالة الأولية (ملف: هاش)
        self.monitored_directory = "" # الدليل المُختار
        self.scheduled_scan_active = False
        self.after_id = None          # المعرف الذي يُرجع من after() للفحص المجدول
        self.create_widgets()

    def create_widgets(self):
        # إطار اختيار الدليل
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="الدليل للمراقبة:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="اختر", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # إطار الأزرار
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="احسب الهاشات الأولية", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="احفظ الحالة", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="تحقق من السلامة", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="ابدأ الفحص المجدول", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="أوقف الفحص المجدول", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # منطقة إخراج النص
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # تسمية الحالة
        self.lbl_status = ttk.Label(self, text="جاهز")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="اختر الدليل للمراقبة")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"تم اختيار الدليل: {directory}\n")
            self.lbl_status.config(text="تم اختيار الدليل.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("خطأ", "يرجى اختيار الدليل للمراقبة أولاً.")
            return
        self.lbl_status.config(text="جاري حساب الهاشات الأولية...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "تم حساب الهاشات الأولية:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="تم حساب الهاشات الأولية.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("خطأ", "لا توجد حالة لحفظها. يرجى حساب الهاشات أولاً.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"تم حفظ الحالة في: {filename}\n")
            self.lbl_status.config(text="تم حفظ الحالة بنجاح.")
        except Exception as e:
            messagebox.showerror("خطأ", f"حدث خطأ أثناء حفظ الملف: {e}")
            self.lbl_status.config(text="خطأ في حفظ الحالة.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("خطأ", "يرجى حساب الهاشات الأولية أولاً.")
            return
        self.lbl_status.config(text="جاري التحقق من السلامة...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # التحقق من الملفات التي تم تعديلها أو حذفها
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"تم حذف الملف: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"تم اكتشاف تعديل في: {path}")
        # التحقق من الملفات الجديدة
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"تم اكتشاف ملف جديد: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "التعديلات المكتشفة:\n" + msg + "\n")
            messagebox.showwarning("تم اكتشاف تعديلات", msg)
        else:
            self.text_output.insert(tk.END, "لم يتم اكتشاف أي تعديلات.\n")
            messagebox.showinfo("التحقق من السلامة", "لم يتم اكتشاف أي تعديلات.")
        self.lbl_status.config(text="اكتمل التحقق من السلامة.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("خطأ", "يرجى اختيار الدليل للمراقبة أولاً.")
            return
        self.lbl_status.config(text="تم بدء الفحص المجدول.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # جدولة الفحص التالي بعد الفاصل الزمني المحدد
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="تم إيقاف الفحص المجدول.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
