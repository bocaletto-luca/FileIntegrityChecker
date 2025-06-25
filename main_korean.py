#!/usr/bin/env python3
"""
파일 무결성 검사기 - 최종 릴리스
---------------------------------
이 Linux 애플리케이션은 중요한 파일이나 전체 디렉토리를 모니터링하며, 
SHA256 해시를 계산 및 비교하여 무단 변경을 감지합니다.

기능:
  - 모니터링할 디렉토리를 선택합니다.
  - 각 파일의 SHA256 해시를 재귀적으로 계산합니다 (4096 바이트 블록 단위로 읽음).
  - 초기 상태(파일 경로와 해시)를 JSON 파일에 저장합니다.
  - 초기 상태와 현재 해시를 비교하여 수동 또는 주기적으로 무결성을 확인합니다.
  - 변경 사항이 감지되면 출력 영역과 메시지 상자를 통해 시각적으로 알립니다.
  - 예약 스캔 옵션 (예약 스캔 중지 기능 포함).
  - Tkinter로 구축된 깔끔하고 사용자 친화적인 GUI.
  - 고급 로깅 (모든 작업 및 오류가 "file_integrity_checker.log"에 기록됨).

작성자: [당신의 이름]
라이선스: GPL
"""

import os
import hashlib
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import logging

# 로깅 설정
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("파일 무결성 검사기가 시작되었습니다.")

# 상수
EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000  # 예약 스캔 간격 (밀리초, 60초)

def calculate_hash(file_path):
    """
    지정한 파일의 SHA256 해시를 계산합니다.
    큰 파일 처리를 위해 파일을 4096 바이트 블록 단위로 읽습니다.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"{file_path}의 해시 계산 중 오류 발생: {e}")
        return None

def scan_directory(directory):
    """
    지정한 디렉토리를 재귀적으로 스캔하고 (EXCLUDE_DIRS에 포함된 디렉토리는 제외),
    각 파일의 SHA256 해시를 계산합니다.
    
    {파일 경로: 해시} 형태의 딕셔너리를 반환합니다.
    """
    logger.info(f"디렉토리 스캔: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        # EXCLUDE_DIRS에 포함된 디렉토리는 제외
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(tk.Tk):
    """파일 무결성 검사기의 그래픽 사용자 인터페이스"""
    def __init__(self):
        super().__init__()
        self.title("파일 무결성 검사기")
        self.geometry("800x600")
        self.initial_state = {}       # 초기 상태 (파일: 해시)
        self.monitored_directory = "" # 선택한 디렉토리
        self.scheduled_scan_active = False
        self.after_id = None          # 예약 스캔을 위한 after()의 ID
        self.create_widgets()

    def create_widgets(self):
        # 디렉토리 선택 프레임
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=tk.X, padx=10, pady=5)
        lbl_dir = ttk.Label(frame_dir, text="모니터링할 디렉토리:")
        lbl_dir.pack(side=tk.LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=50)
        self.entry_dir.pack(side=tk.LEFT, padx=5)
        btn_select = ttk.Button(frame_dir, text="선택", command=self.select_directory)
        btn_select.pack(side=tk.LEFT, padx=5)

        # 버튼 프레임
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=tk.X, padx=10, pady=5)
        btn_calc = ttk.Button(frame_buttons, text="초기 해시 계산", command=self.calculate_initial_hashes)
        btn_calc.pack(side=tk.LEFT, padx=5)
        btn_save = ttk.Button(frame_buttons, text="상태 저장", command=self.save_state)
        btn_save.pack(side=tk.LEFT, padx=5)
        btn_verify = ttk.Button(frame_buttons, text="무결성 확인", command=self.verify_integrity)
        btn_verify.pack(side=tk.LEFT, padx=5)
        btn_start_sched = ttk.Button(frame_buttons, text="예약 스캔 시작", command=self.start_scheduled_scan)
        btn_start_sched.pack(side=tk.LEFT, padx=5)
        btn_stop_sched = ttk.Button(frame_buttons, text="예약 스캔 중지", command=self.stop_scheduled_scan)
        btn_stop_sched.pack(side=tk.LEFT, padx=5)

        # 출력 텍스트 영역
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=20)
        self.text_output.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        # 상태 레이블
        self.lbl_status = ttk.Label(self, text="준비 완료")
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="모니터링할 디렉토리 선택")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"선택한 디렉토리: {directory}\n")
            self.lbl_status.config(text="디렉토리 선택됨.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("오류", "먼저 모니터링할 디렉토리를 선택하세요.")
            return
        self.lbl_status.config(text="초기 해시 계산 중...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "초기 해시 계산 완료:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="초기 해시 계산 완료.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("오류", "저장할 상태가 없습니다. 먼저 해시를 계산하세요.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"상태 저장됨: {filename}\n")
            self.lbl_status.config(text="상태가 성공적으로 저장되었습니다.")
        except Exception as e:
            messagebox.showerror("오류", f"파일 저장 중 오류 발생: {e}")
            self.lbl_status.config(text="상태 저장 중 오류 발생.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("오류", "먼저 초기 해시를 계산하세요.")
            return
        self.lbl_status.config(text="무결성 확인 중...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        # 변경되거나 삭제된 파일 확인
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"파일 삭제됨: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"변경 감지됨: {path}")
        # 새로운 파일 확인
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"새 파일 감지: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "감지된 변경사항:\n" + msg + "\n")
            messagebox.showwarning("변경사항 감지됨", msg)
        else:
            self.text_output.insert(tk.END, "변경사항이 감지되지 않음.\n")
            messagebox.showinfo("무결성 확인", "변경사항이 감지되지 않음.")
        self.lbl_status.config(text="무결성 확인 완료.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("오류", "먼저 모니터링할 디렉토리를 선택하세요.")
            return
        self.lbl_status.config(text="예약 스캔 시작됨.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            # 지정된 간격 후 다음 스캔 예약
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="예약 스캔 중지됨.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
