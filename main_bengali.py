#!/usr/bin/env python3
"""
ফাইল অখণ্ডতা পরীক্ষক - চূড়ান্ত সংস্করণ
-------------------------------------------
একটি Linux অ্যাপ্লিকেশন যা গুরুত্বপূর্ণ ফাইল বা পুরো ডিরেক্টরি পর্যবেক্ষণ করে, তাদের SHA256 হ্যাশ গণনা ও তুলনা করে, 
অবাধ্য পরিবর্তন সনাক্ত করতে।

বৈশিষ্ট্যসমূহ:
  - পর্যবেক্ষণের জন্য একটি ডিরেক্টরি নির্বাচন করুন।
  - প্রতিটি ফাইলের SHA256 হ্যাশ পুনরাবৃত্তিমূলকভাবে গণনা করুন (4096 বাইটের ব্লকে পড়ুন)।
  - প্রাথমিক অবস্থা (ফাইলের পথ এবং হ্যাশ) একটি JSON ফাইলে সংরক্ষণ করুন।
  - হস্তচালিত বা নির্দিষ্ট সময়ের ব্যবধানে, বর্তমান হ্যাশকে প্রাথমিক অবস্থার সাথে তুলনা করে অখণ্ডতা যাচাই করুন।
  - পরিবর্তন সনাক্ত হলে, আউটপুট এলাকা ও মেসেজ বাক্সের মাধ্যমে দৃশ্যমান বিজ্ঞপ্তি প্রদান করুন।
  - নির্ধারিত স্ক্যান অপশন, যার সাহায্যে স্ক্যান বন্ধ করা যাবে।
  - Tkinter ব্যবহার করে নির্মিত একটি পরিষ্কার, ব্যবহারকারী-বান্দব GUI।
  - উন্নত লগিং (সমস্ত ক্রিয়া ও ত্রুটি "file_integrity_checker.log" ফাইলে সংরক্ষণ করা হয়)।

লেখক: [আপনার নাম]
লাইসেন্স: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# লগিং কনফিগারেশন
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("ফাইল অখণ্ডতা পরীক্ষক শুরু হয়েছে।")

# ধ্রুবকসমূহ
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # নির্ধারিত স্ক্যানের ব্যবধানে (মিলিসেকেন্ডে, 60 সেকেন্ড)

def calculate_hash(file_path):
    """
    নির্দিষ্ট ফাইলের SHA256 হ্যাশ গণনা করে।
    বড় ফাইল পরিচালনার জন্য, ফাইলটি 4096 বাইটের ব্লকে পড়ে।
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"{file_path} এর হ্যাশ গণনায় ত্রুটি: {e}")
        return None

def scan_directory(directory):
    """
    নির্দিষ্ট ডিরেক্টরিটি পুনরাবৃত্তিমূলকভাবে স্ক্যান করে (EXCLUDE_DIRS-এ উল্লেখিত ডিরেক্টরি বাদ দিয়ে)
    এবং প্রতিটি ফাইলের SHA256 হ্যাশ গণনা করে।
    
    {ফাইল_পথ: হ্যাশ} আকারে একটি অভিধান প্রদান করে।
    """
    logger.info(f"ডিরেক্টরি স্ক্যান: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # EXCLUDE_DIRS-এ তালিকাভুক্ত ডিরেক্টরি বাদ দিন
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """ফাইল অখণ্ডতা পরীক্ষকের গ্রাফিকাল ইউজার ইন্টারফেস"""
    def __init__(self):
        super().__init__()
        self.title("ফাইল অখণ্ডতা পরীক্ষক")
        self.geometry("800x600")
        self.initial_state = {}       # প্রাথমিক অবস্থা (ফাইল: হ্যাশ)
        self.monitored_directory = "" # নির্বাচিত ডিরেক্টরি
        self.scheduled_scan_active = False
        self.after_id = None          # নির্ধারিত স্ক্যানের জন্য after() থেকে প্রাপ্ত ID
        self.create_widgets()

    def create_widgets(self):
        # ডিরেক্টরি নির্বাচন ফ্রেম
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="পর্যবেক্ষণের জন্য ডিরেক্টরি:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="নির্বাচন", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # বোতাম ফ্রেম
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="প্রাথমিক হ্যাশ গণনা", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="অবস্থা সংরক্ষণ", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="অখণ্ডতা যাচাই", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="নির্ধারিত স্ক্যান শুরু", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="নির্ধারিত স্ক্যান বন্ধ", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # আউটপুট টেক্সট এরিয়া
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # স্ট্যাটাস লেবেল
        self.lbl_status = ttk.Label(self, text="প্রস্তুত")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="পর্যবেক্ষণের জন্য ডিরেক্টরি নির্বাচন করুন")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"নির্বাচিত ডিরেক্টরি: {directory}\n")
            self.lbl_status.config(text="ডিরেক্টরি নির্বাচন হয়েছে।")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে প্রথমে পর্যবেক্ষণের জন্য ডিরেক্টরি নির্বাচন করুন।")
            return
        self.lbl_status.config(text="প্রাথমিক হ্যাশ গণনা চলছে...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "প্রাথমিক হ্যাশ গণনা সম্পন্ন হয়েছে:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="প্রাথমিক হ্যাশ গণনা শেষ।")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("ত্রুটি", "সংরক্ষণের জন্য কোনো অবস্থা নেই। অনুগ্রহ করে প্রথমে হ্যাশ গণনা করুন।")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"অবস্থা সংরক্ষিত হয়েছে: {filename}\n")
            self.lbl_status.config(text="অবস্থা সফলভাবে সংরক্ষিত হয়েছে।")
        except Exception as e:
            messagebox.showerror("ত্রুটি", f"ফাইল সংরক্ষণে ত্রুটি: {e}")
            self.lbl_status.config(text="অবস্থা সংরক্ষণে ত্রুটি ঘটেছে।")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে প্রথমে প্রাথমিক হ্যাশ গণনা করুন।")
            return
        self.lbl_status.config(text="অখণ্ডতা যাচাই চলছে...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # পরিবর্তিত বা মুছে ফেলা ফাইল যাচাই
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"ফাইল মুছে ফেলা হয়েছে: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"পরিবর্তন সনাক্ত হয়েছে: {path}")
        # নতুন ফাইল যাচাই
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"নতুন ফাইল সনাক্ত: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "সনাক্ত করা পরিবর্তনসমূহ:\n" + msg + "\n")
            messagebox.showwarning("পরিবর্তন সনাক্ত হয়েছে", msg)
        else:
            self.text_output.insert(tk.END, "কোনো পরিবর্তন সনাক্ত হয়নি।\n")
            messagebox.showinfo("অখণ্ডতা যাচাই", "কোনো পরিবর্তন সনাক্ত হয়নি।")
        self.lbl_status.config(text="অখণ্ডতা যাচাই সম্পন্ন হয়েছে।")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে প্রথমে পর্যবেক্ষণের জন্য ডিরেক্টরি নির্বাচন করুন।")
            return
        self.lbl_status.config(text="নির্ধারিত স্ক্যান শুরু করা হয়েছে।")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # নির্দিষ্ট ব্যবধানে পরবর্তী স্ক্যান নির্ধারণ করুন
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="নির্ধারিত স্ক্যান বন্ধ করা হয়েছে।")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
