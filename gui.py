import tkinter as tk
from tkinter import ttk, scrolledtext
import ctypes
import queue
import sys
import threading
import time

from divert_engine import DivertEngine


class LibertyGSMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LibertyGSM - System-wide Bypass")
        self.root.geometry("620x680")
        self.root.configure(bg="#121214")
        self.root.resizable(False, False)

        self.engine = None
        self.is_running = False
        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()   # ('start', bool) from the worker thread

        self._setup_styles()
        self._build_ui()
        self.root.after(100, self._tick)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TCombobox",
                             fieldbackground="#1e1e24", background="#2e2e38",
                             foreground="#ffffff", arrowcolor="#a855f7", bordercolor="#2e2e38")
        self.style.map("TCombobox",
                       fieldbackground=[('readonly', '#1e1e24')],
                       foreground=[('readonly', '#ffffff')])

    def _build_ui(self):
        main = tk.Frame(self.root, bg="#121214", padx=25, pady=20)
        main.pack(fill=tk.BOTH, expand=True)

        # --- Header ---
        header = tk.Frame(main, bg="#121214")
        header.pack(fill=tk.X, pady=(0, 15))
        tk.Label(header, text="LibertyGSM", font=("Segoe UI", 28, "bold"),
                 fg="#a855f7", bg="#121214").pack(anchor="w")
        tk.Label(header, text="System-wide DPI / SNI Bypass  ·  WinDivert + DNS-over-HTTPS",
                 font=("Segoe UI", 10), fg="#9ca3af", bg="#121214").pack(anchor="w")

        # --- Status & control panel ---
        self.status_card = tk.Frame(main, bg="#1e1e24", padx=15, pady=15)
        self.status_card.pack(fill=tk.X, pady=(0, 15))
        self.status_card.config(highlightbackground="#2e2e38", highlightcolor="#2e2e38", highlightthickness=1)

        info = tk.Frame(self.status_card, bg="#1e1e24")
        info.pack(side=tk.LEFT, fill=tk.Y)
        self.status_title = tk.Label(info, text="BYPASS INACTIVE", font=("Segoe UI", 16, "bold"),
                                     fg="#ef4444", bg="#1e1e24")
        self.status_title.pack(anchor="w")
        self.stats_label = tk.Label(info, text="DNS: 0   HTTPS: 0   resets: 0",
                                    font=("Segoe UI", 10), fg="#9ca3af", bg="#1e1e24")
        self.stats_label.pack(anchor="w", pady=(3, 0))

        self.toggle_btn = tk.Button(self.status_card, text="START", font=("Segoe UI", 12, "bold"),
                                    bg="#ef4444", fg="#ffffff", activebackground="#dc2626",
                                    activeforeground="#ffffff", bd=0, padx=25, pady=8,
                                    cursor="hand2", command=self.toggle)
        self.toggle_btn.pack(side=tk.RIGHT, anchor="center")

        # --- Config ---
        config = tk.Frame(main, bg="#121214")
        config.pack(fill=tk.X, pady=(0, 15))
        tk.Label(config, text="Bypass Intensity", font=("Segoe UI", 10, "bold"),
                 fg="#d1d5db", bg="#121214").pack(anchor="w", pady=(0, 4))
        self.mode_combo = ttk.Combobox(config, values=["Standard", "Advanced", "Extreme"],
                                       state="readonly", font=("Segoe UI", 10))
        self.mode_combo.set("Standard")
        self.mode_combo.pack(fill=tk.X, ipady=4)
        self.mode_combo.bind("<<ComboboxSelected>>", self._on_mode_change)
        tk.Label(config, text="DNS-over-HTTPS and SNI fragmentation are always on. "
                              "No proxy or browser setup needed — every app is covered.",
                 font=("Segoe UI", 9), fg="#6b7280", bg="#121214", wraplength=560, justify="left"
                 ).pack(anchor="w", pady=(8, 0))

        # --- Log console ---
        head = tk.Frame(main, bg="#121214")
        head.pack(fill=tk.X, pady=(10, 4))
        tk.Label(head, text="Real-time Log Console", font=("Segoe UI", 10, "bold"),
                 fg="#d1d5db", bg="#121214").pack(side=tk.LEFT)
        tk.Button(head, text="Clear Log", font=("Segoe UI", 9), bg="#1e1e24", fg="#9ca3af",
                  activebackground="#2e2e38", activeforeground="#ffffff", bd=0, padx=8,
                  cursor="hand2", command=self.clear_logs).pack(side=tk.RIGHT)

        self.console = scrolledtext.ScrolledText(main, font=("Consolas", 9), bg="#18181b",
                                                 fg="#a7f3d0", insertbackground="#ffffff", bd=1,
                                                 relief=tk.FLAT, highlightbackground="#2e2e38",
                                                 highlightthickness=1)
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.config(state=tk.DISABLED)

    # -- logging / periodic UI update ------------------------------------- #
    def log_message(self, message):
        self.log_queue.put(message)

    def _tick(self):
        # Drain log lines.
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.console.config(state=tk.NORMAL)
                self.console.insert(tk.END, msg + "\n")
                self.console.see(tk.END)
                self.console.config(state=tk.DISABLED)
        except queue.Empty:
            pass

        # Handle a finished start() from the worker thread.
        try:
            while True:
                kind, ok = self.result_queue.get_nowait()
                if kind == "start":
                    self._finish_start(ok)
        except queue.Empty:
            pass

        # Live stats.
        if self.is_running and self.engine:
            s = self.engine.stats
            self.stats_label.config(
                text=f"DNS: {s['dns']}   HTTPS: {s['https_total']}   "
                     f"QUIC blk: {s['quic']}   resets: {s['https_reset']}")

        self.root.after(100, self._tick)

    def clear_logs(self):
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)

    # -- control ----------------------------------------------------------- #
    def _on_mode_change(self, _event=None):
        mode = self.mode_combo.get()
        if self.engine:
            self.engine.mode = mode  # applies to the next connection immediately
        self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] Bypass intensity set to {mode}.")

    def toggle(self):
        if self.is_running:
            self.stop_bypass()
        else:
            self.start_bypass()

    def start_bypass(self):
        self.toggle_btn.config(state=tk.DISABLED, text="...")
        self.mode_combo.config(state=tk.DISABLED)
        self.engine = DivertEngine(mode=self.mode_combo.get(), log_callback=self.log_message)
        # start() does a (blocking) DoH probe + driver open -> run off the UI thread.
        threading.Thread(target=self._start_worker, daemon=True).start()

    def _start_worker(self):
        ok = False
        try:
            ok = self.engine.start()
        except Exception as exc:
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] Start failed: {exc}")
        self.result_queue.put(("start", ok))

    def _finish_start(self, ok):
        if ok:
            self.is_running = True
            self.status_title.config(text="BYPASS ACTIVE", fg="#10b981")
            self.status_card.config(highlightbackground="#10b981", highlightcolor="#10b981")
            self.toggle_btn.config(text="STOP", bg="#10b981", activebackground="#059669", state=tk.NORMAL)
            self.mode_combo.config(state="readonly")  # keep it changeable while running
        else:
            self.engine = None
            self.toggle_btn.config(text="START", bg="#ef4444", activebackground="#dc2626", state=tk.NORMAL)
            self.mode_combo.config(state="readonly")

    def stop_bypass(self):
        self.toggle_btn.config(state=tk.DISABLED, text="...")
        engine, self.engine = self.engine, None
        self.is_running = False
        if engine:
            threading.Thread(target=engine.stop, daemon=True).start()
        self.status_title.config(text="BYPASS INACTIVE", fg="#ef4444")
        self.status_card.config(highlightbackground="#2e2e38", highlightcolor="#2e2e38")
        self.toggle_btn.config(text="START", bg="#ef4444", activebackground="#dc2626", state=tk.NORMAL)
        self.stats_label.config(text="DNS: 0   HTTPS: 0   QUIC blk: 0   resets: 0")

    def on_closing(self):
        if self.engine:
            try:
                self.engine.stop()
            except Exception:
                pass
        self.root.destroy()
        sys.exit(0)


# --------------------------------------------------------------------------- #
# Administrator elevation (WinDivert loads a kernel driver -> needs admin)
# --------------------------------------------------------------------------- #
def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    if getattr(sys, "frozen", False):
        # Packaged .exe: re-run the exe itself.
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        target = sys.executable
    else:
        # Script: re-run python with this script.
        params = " ".join(f'"{a}"' for a in sys.argv)
        target = sys.executable
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)


if __name__ == "__main__":
    if not _is_admin():
        # Trigger a UAC prompt and relaunch elevated; the un-elevated process exits.
        try:
            _relaunch_as_admin()
        finally:
            sys.exit(0)

    root = tk.Tk()
    app = LibertyGSMApp(root)
    root.mainloop()
