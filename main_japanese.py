#!/usr/bin/env python3
"""
ファイル整合性チェッカー - 最終リリース
----------------------------------------
このLinuxアプリケーションは、重要なファイルまたはディレクトリ全体を監視し、
SHA256ハッシュを計算および比較することで、不正な改ざんを検出します。

機能:
  - 監視するディレクトリを選択する。
  - 各ファイルのSHA256ハッシュを再帰的に計算する（4096バイト単位で読み込む）。
  - 初期状態（ファイルパスとハッシュ）をJSONファイルに保存する。
  - 初期状態と現在のハッシュを比較することで、手動または定期的に整合性を検証する。
  - 改ざんが検出された場合、出力エリアとメッセージボックスで視覚的に通知する。
  - 定期スキャンのオプション（定期スキャンを停止する機能付き）。
  - Tkinterを使用して構築された、クリーンでユーザーフレンドリーなGUI。
  - 高度なログ記録（すべての操作とエラーが "file_integrity_checker.log" に記録される）。

著者: [あなたの名前]
ライセンス: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# ログ設定
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("ファイル整合性チェッカーが起動しました。")

# 定数
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # 定期スキャンの間隔（ミリ秒単位、60秒）

def calculate_hash(file_path):
    """
    指定されたファイルのSHA256ハッシュを計算します。
    大きなファイルを扱うために、4096バイトごとにファイルを読み込みます。
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"{file_path} のハッシュ計算中にエラーが発生: {e}")
        return None

def scan_directory(directory):
    """
    指定されたディレクトリを再帰的にスキャンし（EXCLUDE_DIRSに含まれるディレクトリを除外して）、
    各ファイルのSHA256ハッシュを計算します。
    
    {ファイルパス: ハッシュ} の形式で辞書を返します。
    """
    logger.info(f"ディレクトリのスキャン: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # EXCLUDE_DIRSに含まれるディレクトリを除外する
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """ファイル整合性チェッカーのグラフィカルユーザーインターフェース"""
    def __init__(self):
        super().__init__()
        self.title("ファイル整合性チェッカー")
        self.geometry("800x600")
        self.initial_state = {}       # 初期状態（ファイル: ハッシュ）
        self.monitored_directory = "" # 選択したディレクトリ
        self.scheduled_scan_active = False
        self.after_id = None          # 定期スキャン用にafter()から返されるID
        self.create_widgets()

    def create_widgets(self):
        # ディレクトリ選択フレーム
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="監視するディレクトリ:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="選択", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # ボタンフレーム
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="初期ハッシュを計算", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="状態を保存", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="整合性を検証", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="定期スキャン開始", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="定期スキャン停止", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # 出力用テキストエリア
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # ステータスラベル
        self.lbl_status = ttk.Label(self, text="準備完了")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="監視するディレクトリを選択")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"選択されたディレクトリ: {directory}\n")
            self.lbl_status.config(text="ディレクトリが選択されました。")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("エラー", "まず監視するディレクトリを選択してください。")
            return
        self.lbl_status.config(text="初期ハッシュを計算中...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "初期ハッシュが計算されました:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="初期ハッシュ計算完了。")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("エラー", "保存する状態がありません。まずハッシュを計算してください。")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"状態が保存されました: {filename}\n")
            self.lbl_status.config(text="状態を正常に保存しました。")
        except Exception as e:
            messagebox.showerror("エラー", f"ファイル保存中にエラーが発生しました: {e}")
            self.lbl_status.config(text="状態保存中にエラーが発生しました。")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("エラー", "まず初期ハッシュを計算してください。")
            return
        self.lbl_status.config(text="整合性を検証中...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # 変更または削除されたファイルの検証
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"ファイルが削除されました: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"変更が検出されました: {path}")
        # 新しいファイルの検証
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"新しいファイルが検出されました: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "検出された変更:\n" + msg + "\n")
            messagebox.showwarning("変更が検出されました", msg)
        else:
            self.text_output.insert(tk.END, "変更は検出されませんでした。\n")
            messagebox.showinfo("整合性検証", "変更は検出されませんでした。")
        self.lbl_status.config(text="整合性検証完了。")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("エラー", "まず監視するディレクトリを選択してください。")
            return
        self.lbl_status.config(text="定期スキャンを開始しました。")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # 定義された間隔後に次のスキャンをスケジュールする
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="定期スキャンが停止されました。")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
