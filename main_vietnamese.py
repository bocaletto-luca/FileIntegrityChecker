#!/usr/bin/env python3
"""
Bộ Kiểm Tra Tính Toàn Vẹn Tập Tin - Phát Hành Cuối Cùng
----------------------------------------------------------
Một ứng dụng Linux theo dõi các tập tin quan trọng hoặc toàn bộ thư mục bằng cách tính toán và so sánh
các giá trị băm SHA256 của chúng để phát hiện các thay đổi trái phép.

Tính năng:
  - Chọn một thư mục để theo dõi.
  - Tính toán giá trị băm SHA256 cho mỗi tập tin một cách đệ quy (đọc theo khối 4096 byte).
  - Lưu trạng thái ban đầu (đường dẫn tập tin và giá trị băm) vào một tập tin JSON.
  - Xác thực tính toàn vẹn theo cách thủ công hoặc định kỳ bằng cách so sánh các giá trị băm hiện tại với trạng thái ban đầu.
  - Cung cấp thông báo trực quan qua khu vực hiển thị và hộp thoại khi có thay đổi được phát hiện.
  - Tùy chọn quét theo lịch trình với khả năng dừng quá trình quét theo lịch.
  - Giao diện người dùng đồ họa (GUI) sạch sẽ, thân thiện được xây dựng bằng Tkinter.
  - Ghi nhật ký nâng cao (tất cả các thao tác và lỗi được ghi vào "file_integrity_checker.log").

Tác giả: [Tên của bạn]
Giấy phép: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# Cấu hình ghi nhật ký
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("Bộ Kiểm Tra Tính Toàn Vẹn Tập Tin đã được khởi động.")

# Hằng số
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # Khoảng thời gian quét theo lịch (tính bằng mili giây, 60 giây)

def calculate_hash(file_path):
    """
    Tính giá trị băm SHA256 cho tập tin được chỉ định.
    Tập tin được đọc theo khối 4096 byte để xử lý các tập tin lớn.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Lỗi khi tính giá trị băm cho {file_path}: {e}")
        return None

def scan_directory(directory):
    """
    Quét thư mục được chỉ định một cách đệ quy (bỏ qua các thư mục có trong EXCLUDE_DIRS)
    và tính giá trị băm SHA256 cho mỗi tập tin.
    
    Trả về một từ điển với định dạng {đường_dẫn_tập_tin: giá_trị_băm}.
    """
    logger.info(f"Đang quét thư mục: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # Bỏ qua các thư mục nằm trong EXCLUDE_DIRS
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """Giao diện đồ họa của Bộ Kiểm Tra Tính Toàn Vẹn Tập Tin."""
    def __init__(self):
        super().__init__()
        self.title("Bộ Kiểm Tra Tính Toàn Vẹn Tập Tin")
        self.geometry("800x600")
        self.initial_state = {}       # Trạng thái ban đầu (tập tin: giá_trị_băm)
        self.monitored_directory = "" # Thư mục được chọn
        self.scheduled_scan_active = False
        self.after_id = None          # ID trả về bởi hàm after() cho quét theo lịch
        self.create_widgets()

    def create_widgets(self):
        # Khung chọn thư mục
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="Thư mục để theo dõi:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="Chọn", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # Khung các nút
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="Tính giá trị băm ban đầu", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="Lưu trạng thái", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="Kiểm tra tính toàn vẹn", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="Bắt đầu quét theo lịch", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="Dừng quét theo lịch", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # Khu vực hiển thị kết quả
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # Nhãn trạng thái
        self.lbl_status = ttk.Label(self, text="Sẵn sàng")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Chọn thư mục để theo dõi")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Thư mục được chọn: {directory}\n")
            self.lbl_status.config(text="Đã chọn thư mục.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Lỗi", "Vui lòng chọn thư mục để theo dõi trước.")
            return
        self.lbl_status.config(text="Đang tính giá trị băm ban đầu...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Đã tính giá trị băm ban đầu:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Đã tính giá trị băm ban đầu.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Lỗi", "Không có trạng thái nào để lưu. Vui lòng tính giá trị băm trước.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"Trạng thái đã được lưu tại: {filename}\n")
            self.lbl_status.config(text="Trạng thái được lưu thành công.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi lưu tập tin: {e}")
            self.lbl_status.config(text="Đã xảy ra lỗi khi lưu trạng thái.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Lỗi", "Vui lòng tính giá trị băm ban đầu trước.")
            return
        self.lbl_status.config(text="Đang kiểm tra tính toàn vẹn...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # Kiểm tra các tập tin bị thay đổi hoặc bị xóa
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"Tập tin đã bị xóa: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Đã phát hiện thay đổi: {path}")
        # Kiểm tra các tập tin mới
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"Đã phát hiện tập tin mới: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Các thay đổi được phát hiện:\n" + msg + "\n")
            messagebox.showwarning("Phát hiện thay đổi", msg)
        else:
            self.text_output.insert(tk.END, "Không phát hiện thay đổi nào.\n")
            messagebox.showinfo("Kiểm Tra Toàn Vẹn", "Không phát hiện thay đổi nào.")
        self.lbl_status.config(text="Kiểm tra tính toàn vẹn hoàn tất.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Lỗi", "Vui lòng chọn thư mục để theo dõi trước.")
            return
        self.lbl_status.config(text="Đang khởi động quét theo lịch...")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # Lên lịch quét tiếp theo sau khoảng thời gian đã định
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Quét theo lịch đã dừng.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
