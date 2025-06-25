#!/usr/bin/env python3
"""
फ़ाइल अखंडता परीक्षक - अंतिम संस्करण
-------------------------------------------
यह एक Linux एप्लिकेशन है जो महत्वपूर्ण फ़ाइलें या पूरे डायरेक्टरी की निगरानी करता है, उनके SHA256 हैश की गणना और तुलना करके अवैध संशोधनों का पता लगाने के लिए।

विशेषताएँ:
  - निगरानी के लिए एक डायरेक्टरी चुनें।
  - हर फ़ाइल के लिए पुनरावृत्ति से SHA256 हैश की गणना करें (4096 बाइट के ब्लॉकों में पढ़ते हुए)।
  - प्रारंभिक स्थिति (फ़ाइल पथ और हैश) को JSON फ़ाइल में सहेजें।
  - वर्तमान हैश की तुलना प्रारंभिक स्थिति के साथ करके मैनुअल या आवधिक रूप से अखंडता की जांच करें।
  - संशोधनों का पता चलने पर आउटपुट क्षेत्र और संदेश बॉक्स के माध्यम से दृश्य सूचना दें।
  - निर्धारित स्कैन विकल्प, जिसके अंतर्गत स्कैन को रोकने की सुविधा है।
  - Tkinter के साथ निर्मित एक साफ-सुथरा और उपयोगकर्ता-मित्रवत ग्राफिकल इंटरफ़ेस।
  - उन्नत लॉगिंग (सभी क्रियाएं और त्रुटियाँ "file_integrity_checker.log" में दर्ज की जाती हैं)।

लेखक: [आपका नाम]
लाइसेंस: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# लॉगिंग विन्यास
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("फ़ाइल अखंडता परीक्षक शुरू हो गया।")

# स्थिरांक
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # निर्धारित स्कैन का अंतराल मिलीसेकंड में (60 सेकंड)

def calculate_hash(file_path):
    """
    दिए गए फ़ाइल का SHA256 हैश की गणना करता है।
    बड़े फ़ाइलों को संभालने के लिए, फ़ाइल को 4096 बाइट के ब्लॉकों में पढ़ता है।
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"{file_path} के हैश की गणना में त्रुटि: {e}")
        return None

def scan_directory(directory):
    """
    दिए गए डायरेक्टरी को पुनरावृत्ति से स्कैन करता है (EXCLUDE_DIRS में शामिल डायरेक्टरी को छोड़कर)
    और हर फ़ाइल का SHA256 हैश की गणना करता है।
    
    यह {फ़ाइल_पथ: हैश} के रूप में एक शब्दकोश लौटाता है।
    """
    logger.info(f"डायरेक्टरी स्कैन कर रहे हैं: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # EXCLUDE_DIRS में सूचीबद्ध डायरेक्टरी को छोड़ दें
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """फ़ाइल अखंडता परीक्षक का ग्राफिकल इंटरफ़ेस।"""
    def __init__(self):
        super().__init__()
        self.title("फ़ाइल अखंडता परीक्षक")
        self.geometry("800x600")
        self.initial_state = {}       # प्रारंभिक स्थिति (फ़ाइल: हैश)
        self.monitored_directory = "" # चयनित डायरेक्टरी
        self.scheduled_scan_active = False
        self.after_id = None          # निर्धारित स्कैन के लिए after() द्वारा लौटाया गया ID
        self.create_widgets()

    def create_widgets(self):
        # डायरेक्टरी चयन फ्रेम
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="निगरानी के लिए डायरेक्टरी:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="चुनें", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # बटन फ्रेम
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="प्रारंभिक हैश गणना करें", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="स्थिति सहेजें", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="अखंडता जाँचें", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="निर्धारित स्कैन शुरू करें", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="निर्धारित स्कैन रोकें", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # आउटपुट टेक्स्ट एरिया
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # स्थिति लेबल
        self.lbl_status = ttk.Label(self, text="तैयार")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="निगरानी के लिए डायरेक्टरी चुनें")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"चुनिंदा डायरेक्टरी: {directory}\n")
            self.lbl_status.config(text="डायरेक्टरी चुनी गई है।")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("त्रुटि", "कृपया पहले निगरानी के लिए डायरेक्टरी चुनें।")
            return
        self.lbl_status.config(text="प्रारंभिक हैश गणना चल रही है...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "प्रारंभिक हैश गणना पूरी हुई:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="प्रारंभिक हैश गणना पूरी हुई।")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("त्रुटि", "सहेजने के लिए कोई स्थिति नहीं है। कृपया पहले हैश गणना करें।")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"स्थिति सहेजी गई: {filename}\n")
            self.lbl_status.config(text="स्थिति सफलतापूर्वक सहेजी गई।")
        except Exception as e:
            messagebox.showerror("त्रुटि", f"फ़ाइल सहेजते समय त्रुटि: {e}")
            self.lbl_status.config(text="स्थिति सहेजने में त्रुटि।")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("त्रुटि", "कृपया पहले प्रारंभिक हैश गणना करें।")
            return
        self.lbl_status.config(text="अखंडता जाँची जा रही है...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # संशोधित या हटाई गई फ़ाइलों की जाँच करें
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"फ़ाइल हटाई गई: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"परिवर्तन पता चला: {path}")
        # नई फ़ाइलों की जाँच करें
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"नई फ़ाइल मिली: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "पता चले परिवर्तन:\n" + msg + "\n")
            messagebox.showwarning("परिवर्तन पता चले", msg)
        else:
            self.text_output.insert(tk.END, "कोई परिवर्तन नहीं मिला।\n")
            messagebox.showinfo("अखंडता जाँच", "कोई परिवर्तन नहीं मिला।")
        self.lbl_status.config(text="अखंडता जाँच पूरी हुई।")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("त्रुटि", "कृपया पहले निगरानी के लिए डायरेक्टरी चुनें।")
            return
        self.lbl_status.config(text="निर्धारित स्कैन शुरू किया गया है।")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # निर्दिष्ट अंतराल के बाद अगला स्कैन शेड्यूल करें
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="निर्धारित स्कैन रोक दिया गया है।")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
