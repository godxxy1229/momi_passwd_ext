import argparse
import ctypes
import datetime
import os
import queue
import subprocess
import sys
import threading
import traceback
import tkinter as tk
from tkinter import messagebox, ttk

from momi_passwd_lib import get_latest_password, iter_processes_by_name, scan_process

DEFAULT_PROCESS_NAMES = [
    "pdcxtaloc",
    "gucakyxs",
    "shgflzshu",
    "seaignhou",
    "ControlMenuM",
]


def parse_process_names(values):
    names = []
    for value in values:
        if "," in value:
            names.extend(part for part in value.split(",") if part)
        else:
            names.append(value)
    return names


MB_OK = 0x00000000
MB_ICONERROR = 0x00000010
MB_ICONWARNING = 0x00000030
MB_ICONINFORMATION = 0x00000040


def show_message(title, text, flags=MB_OK):
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
    except Exception:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    exe = sys.executable
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        script = os.path.abspath(__file__)
        params = subprocess.list2cmdline([script] + sys.argv[1:])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


def ensure_admin():
    if is_admin():
        return True
    show_message(
        "맘아이 비밀번호 추출기",
        "관리자 권한이 필요합니다.\n권한 요청 창이 표시됩니다.",
        MB_ICONINFORMATION,
    )
    try:
        result = relaunch_as_admin()
        if result <= 32:
            show_message(
                "맘아이 비밀번호 추출기",
                "관리자 권한 승인에 실패했습니다.",
                MB_ICONWARNING,
            )
    except Exception as exc:
        show_message(
            "맘아이 비밀번호 추출기",
            f"관리자 권한 요청에 실패했습니다: {exc}",
            MB_ICONERROR,
        )
    return False


def run_scan(process_names, region_size_limit_mb, max_urls_per_process):
    processes = iter_processes_by_name(process_names)
    if not processes:
        return 1, []

    passwords = []
    seen = set()
    for proc in processes:
        result = scan_process(
            proc.pid,
            proc.name,
            region_size_limit_mb,
            max_urls_per_process,
        )
        latest_pw = get_latest_password(result.urls, result.passwords)
        if latest_pw:
            if latest_pw not in seen:
                passwords.append(latest_pw)
                seen.add(latest_pw)

    if not passwords:
        return 2, []

    return 0, passwords


class App(tk.Tk):
    def __init__(self, args):
        super().__init__()
        self.args = args
        self.title("맘아이 비밀번호 추출기")
        self.geometry("720x420")
        self.minsize(560, 320)

        self.queue = queue.Queue()
        self.scan_thread = None
        self.passwords = []

        self.status_var = tk.StringVar(value="대기 중")
        self.summary_var = tk.StringVar(value="아직 스캔하지 않았습니다.")

        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        container = ttk.Frame(self, padding=14)
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)

        header = ttk.Label(
            container,
            text="맘아이 비밀번호 추출기",
            font=("Segoe UI", 16, "bold"),
        )
        header.grid(row=0, column=0, sticky="w")

        desc = ttk.Label(
            container,
            text="실행 중인 맘아이 프로세스에서 비밀번호를 찾아 표시합니다.",
        )
        desc.grid(row=1, column=0, sticky="w", pady=(4, 12))

        result_frame = ttk.LabelFrame(container, text="결과", padding=10)
        result_frame.grid(row=2, column=0, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(1, weight=1)

        summary = ttk.Label(result_frame, textvariable=self.summary_var)
        summary.grid(row=0, column=0, sticky="w")

        self.listbox = tk.Listbox(result_frame, height=6)
        self.listbox.grid(row=1, column=0, sticky="nsew", pady=(8, 0))

        status_row = ttk.Frame(container)
        status_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        status_row.columnconfigure(0, weight=1)

        status_label = ttk.Label(status_row, textvariable=self.status_var)
        status_label.grid(row=0, column=0, sticky="w")

        self.progress = ttk.Progressbar(status_row, mode="indeterminate", length=180)
        self.progress.grid(row=0, column=1, sticky="e")

        button_row = ttk.Frame(container)
        button_row.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        button_row.columnconfigure(1, weight=1)

        self.scan_btn = ttk.Button(button_row, text="스캔", command=self.on_scan)
        self.scan_btn.grid(row=0, column=0, sticky="w")

        self.copy_btn = ttk.Button(button_row, text="복사", command=self.on_copy)
        self.copy_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))

        close_btn = ttk.Button(button_row, text="닫기", command=self.on_close)
        close_btn.grid(row=0, column=2, sticky="e")

        self.after(150, self.on_scan)

    def set_results(self, passwords):
        self.listbox.delete(0, tk.END)
        self.passwords = passwords
        if not passwords:
            return
        for pw in passwords:
            self.listbox.insert(tk.END, pw)

    def on_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.scan_btn.configure(state=tk.DISABLED)
        self.copy_btn.configure(state=tk.DISABLED)
        self.progress.start(10)
        self.status_var.set("스캔 중...")
        self.summary_var.set("검색 중입니다. 잠시만 기다려 주세요.")
        self.listbox.delete(0, tk.END)

        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        self.after(100, self.poll_queue)

    def _scan_worker(self):
        try:
            process_names = parse_process_names(self.args.process_names)
            code, passwords = run_scan(
                process_names,
                self.args.region_size_limit_mb,
                self.args.max_urls_per_process,
            )
            self.queue.put(("result", code, passwords))
        except Exception as exc:
            self.queue.put(("error", exc))

    def poll_queue(self):
        try:
            item = self.queue.get_nowait()
        except queue.Empty:
            if self.scan_thread and self.scan_thread.is_alive():
                self.after(100, self.poll_queue)
            return

        self.progress.stop()
        self.scan_btn.configure(state=tk.NORMAL)
        self.copy_btn.configure(state=tk.NORMAL)

        if item[0] == "error":
            exc = item[1]
            self.status_var.set("오류 발생")
            self.summary_var.set("스캔 중 오류가 발생했습니다.")
            if self.args.debug:
                traceback.print_exc()
            messagebox.showerror("맘아이 비밀번호 추출기", f"스캔 실패: {exc}")
            return

        _, code, passwords = item
        self.set_results(passwords)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if code == 0:
            self.status_var.set(f"완료 · {now}")
            self.summary_var.set(f"비밀번호 {len(passwords)}개를 찾았습니다.")
        elif code == 1:
            self.status_var.set(f"대상 없음 · {now}")
            self.summary_var.set("대상 프로세스를 찾을 수 없습니다.")
        else:
            self.status_var.set(f"결과 없음 · {now}")
            self.summary_var.set("비밀번호를 찾지 못했습니다.")

    def on_copy(self):
        if not self.passwords:
            messagebox.showinfo("맘아이 비밀번호 추출기", "복사할 내용이 없습니다.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(self.passwords))
        self.status_var.set("클립보드에 복사했습니다.")

    def on_close(self):
        self.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(description="One-click Momi password scanner.")
    parser.add_argument(
        "--process-names",
        nargs="+",
        default=DEFAULT_PROCESS_NAMES,
        help="Process names to scan (space or comma separated).",
    )
    parser.add_argument("--region-size-limit-mb", type=int, default=20)
    parser.add_argument("--max-urls-per-process", type=int, default=5)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not ensure_admin():
            return 1
        app = App(args)
        app.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if args.debug:
            traceback.print_exc()
        show_message("맘아이 비밀번호 추출기", f"오류: {exc}", MB_ICONERROR)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
