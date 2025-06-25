#!/usr/bin/env python3
"""
文件完整性检查器 - 最终版本
--------------------------
一个 Linux 应用程序，通过计算和比较关键文件或整个目录的 SHA256 哈希值来检测未授权修改。

功能：
  - 选择需要监控的目录。
  - 递归地计算每个文件的 SHA256 哈希值（以 4096 字节为单位读取）。
  - 将初始状态（文件路径和哈希值）保存到 JSON 文件中。
  - 手动或定期通过比较当前哈希值与初始状态来验证完整性。
  - 当检测到修改时，通过输出区域和消息框提供视觉提示。
  - 提供定时扫描选项，并支持停止定时扫描。
  - 使用 Tkinter 构建的简洁且用户友好的图形界面。
  - 高级日志记录（所有操作和错误均记录在 "file_integrity_checker.log" 中）。

作者: [你的名字]
许可证: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# 配置日志记录
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("文件完整性检查器已启动。")

# 常量
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # 定时扫描间隔，单位毫秒（60秒）

def calculate_hash(file_path):
    """
    计算指定文件的 SHA256 哈希值。
    以 4096 字节的块读取文件，以便处理大文件。
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"计算 {file_path} 的哈希值时出错：{e}")
        return None

def scan_directory(directory):
    """
    递归扫描指定目录（排除 EXCLUDE_DIRS 中的目录），
    并为每个文件计算 SHA256 哈希值。
    
    返回格式为 {文件路径: 哈希值} 的字典。
    """
    logger.info(f"扫描目录：{directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # 排除在 EXCLUDE_DIRS 中的目录
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """文件完整性检查器的图形用户界面"""
    def __init__(self):
        super().__init__()
        self.title("文件完整性检查器")
        self.geometry("800x600")
        self.initial_state = {}       # 初始状态（文件：哈希值）
        self.monitored_directory = "" # 选中的目录
        self.scheduled_scan_active = False
        self.after_id = None          # after() 返回的定时扫描 ID
        self.create_widgets()

    def create_widgets(self):
        # 目录选择区域
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="监控目录：")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="选择", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # 按钮区域
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="计算初始哈希值", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="保存状态", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="验证完整性", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="启动定时扫描", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="停止定时扫描", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # 输出文本区域
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # 状态标签
        self.lbl_status = ttk.Label(self, text="就绪")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="选择要监控的目录")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"已选择目录：{directory}\n")
            self.lbl_status.config(text="目录已选择。")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("错误", "请先选择要监控的目录。")
            return
        self.lbl_status.config(text="正在计算初始哈希值...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "初始哈希值计算完成：\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="初始哈希值已计算。")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("错误", "没有可保存的状态，请先计算哈希值。")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"状态已保存至：{filename}\n")
            self.lbl_status.config(text="状态保存成功。")
        except Exception as e:
            messagebox.showerror("错误", f"保存文件时出错：{e}")
            self.lbl_status.config(text="保存状态时出错。")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("错误", "请先计算初始哈希值。")
            return
        self.lbl_status.config(text="正在验证完整性...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # 检查被修改或删除的文件
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"文件已删除：{path}")
            elif new_hash != initial_hash:
                modifications.append(f"检测到修改：{path}")
        # 检查新增的文件
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"检测到新文件：{path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "检测到的修改：\n" + msg + "\n")
            messagebox.showwarning("检测到修改", msg)
        else:
            self.text_output.insert(tk.END, "未检测到任何修改。\n")
            messagebox.showinfo("验证完整性", "未检测到任何修改。")
        self.lbl_status.config(text="完整性验证完成。")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("错误", "请先选择要监控的目录。")
            return
        self.lbl_status.config(text="定时扫描已启动。")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # 在指定间隔后安排下一次扫描
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="定时扫描已停止。")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
