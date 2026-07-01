import tkinter as tk
from tkinter import ttk, scrolledtext
import ctypes
import os
import queue
import sys
import threading
import time

from engines import UnsupportedPlatformError, create_engine, get_engine_info, sniff_outbound_ports

# Optional system-tray support (run in the background like Cloudflare WARP).
# Falls back gracefully to a normal window if pystray/Pillow aren't installed.
try:
    import pystray
    from PIL import Image, ImageDraw
    _HAS_TRAY = True
except Exception:
    _HAS_TRAY = False

VERSION = "1.2.0"


def _make_tray_image():
    img = Image.new("RGBA", (64, 64), (18, 18, 20, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([4, 4, 60, 60], radius=12, fill=(18, 18, 20, 255),
                        outline=(168, 85, 247, 255), width=4)
    d.text((23, 20), "L", fill=(168, 85, 247, 255))
    return img


class LibertyGSMApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"LibertyGSM v{VERSION}")
        self.root.geometry("620x680")
        self.root.configure(bg="#121214")
        self.root.resizable(False, False)

        self.engine = None
        self.is_running = False
        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()   # ('start'|'sniff'|'show'|'quit', ...)
        self.tray_icon = None
        self.first_success_notified = False
        self.toast_timer_id = None
        self.engine_info = get_engine_info()

        self._setup_styles()
        self._build_ui()
        self._apply_engine_availability()
        self._setup_tray()
        self.root.after(100, self._tick)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_tray(self):
        """Build a system-tray icon so closing the window keeps the bypass
        running in the background (like Cloudflare WARP)."""
        if not _HAS_TRAY:
            return
        # Tray callbacks run on pystray's thread; marshal to the Tk thread via
        # the result queue (drained by _tick) to stay thread-safe.
        menu = pystray.Menu(
            pystray.MenuItem("창 열기", lambda *_: self.result_queue.put(("show",)), default=True),
            pystray.MenuItem("종료", lambda *_: self.result_queue.put(("quit",))),
        )
        try:
            self.tray_icon = pystray.Icon("LibertyGSM", _make_tray_image(), "LibertyGSM", menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except Exception:
            self.tray_icon = None

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
        subtitle = f"v{VERSION}  ·  System-wide DPI / SNI Bypass  ·  DNS-over-HTTPS"
        if self.engine_info.supported:
            subtitle = f"{subtitle}  ·  {self.engine_info.name}"
        tk.Label(header, text=subtitle,
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
                                    font=("Segoe UI", 10), fg="#9ca3af", bg="#1e1e24",
                                    wraplength=380, justify="left")
        self.stats_label.pack(anchor="w", pady=(3, 0))

        self.toast_label = tk.Label(info, text="", font=("Segoe UI", 9, "bold"), fg="#a855f7", bg="#1e1e24")
        self.toast_label.pack(anchor="w", pady=(2, 0))

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
        detail_text = "DNS-over-HTTPS and SNI fragmentation are always on."
        if self.engine_info.transparent:
            detail_text += " No proxy or browser setup needed — every app is covered."
        elif self.engine_info.supported:
            detail_text += f" {self.engine_info.reason}"
        else:
            detail_text += " A platform packet engine is required before this OS can run the bypass."
        tk.Label(config, text=detail_text,
                 font=("Segoe UI", 9), fg="#6b7280", bg="#121214", wraplength=560, justify="left"
                 ).pack(anchor="w", pady=(8, 0))

        if _HAS_TRAY:
            tray_info = "💡 [트레이 안내] 창을 닫아도 백그라운드(시스템 트레이)에서 계속 실행됩니다.\n완전히 종료하려면 트레이 아이콘을 우클릭하여 '종료'를 선택하세요."
            tk.Label(config, text=tray_info, font=("Segoe UI", 9), fg="#a855f7", bg="#121214",
                     wraplength=560, justify="left").pack(anchor="w", pady=(6, 0))


        # Buttons frame (Diagnostic + Excluded Hosts)
        btn_frame = tk.Frame(config, bg="#121214")
        btn_frame.pack(anchor="w", pady=(10, 0))

        self.sniff_btn = tk.Button(btn_frame, text="🔍 게임 포트 찾기 (30초 진단)",
                                   font=("Segoe UI", 9, "bold"), bg="#2e2e38", fg="#d1d5db",
                                   activebackground="#3e3e48", activeforeground="#ffffff",
                                   bd=0, padx=12, pady=6, cursor="hand2", command=self.find_game_port)
        self.sniff_btn.pack(side=tk.LEFT)

        self.exclude_btn = tk.Button(btn_frame, text="🛠️ 제외 도메인 설정",
                                     font=("Segoe UI", 9, "bold"), bg="#2e2e38", fg="#d1d5db",
                                     activebackground="#3e3e48", activeforeground="#ffffff",
                                     bd=0, padx=12, pady=6, cursor="hand2", command=self.open_exclude_hosts)
        self.exclude_btn.pack(side=tk.LEFT, padx=(10, 0))

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

    def _apply_engine_availability(self):
        if self.engine_info.supported:
            self.log_message(
                f"[{time.strftime('%H:%M:%S')}] [SYSTEM] Engine loaded: {self.engine_info.name}."
            )
            if not self.engine_info.supports_port_diagnostics:
                self.sniff_btn.config(state=tk.DISABLED)
            return

        self.status_title.config(text="ENGINE UNAVAILABLE", fg="#f59e0b")
        self.status_card.config(highlightbackground="#f59e0b", highlightcolor="#f59e0b")
        self.stats_label.config(text=self.engine_info.reason)
        self.toggle_btn.config(
            text="UNSUPPORTED",
            bg="#6b7280",
            activebackground="#6b7280",
            state=tk.DISABLED,
        )
        self.sniff_btn.config(state=tk.DISABLED)
        self.log_message(
            f"[{time.strftime('%H:%M:%S')}] [SYSTEM] {self.engine_info.reason}"
        )

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
                item = self.result_queue.get_nowait()
                kind = item[0]
                if kind == "start":
                    self._finish_start(item[1])
                elif kind == "sniff":
                    self.sniff_btn.config(state=tk.NORMAL, text="🔍 게임 포트 찾기 (30초 진단)")
                elif kind == "show":
                    self.root.deiconify()
                    self.root.lift()
                    self.root.focus_force()
                elif kind == "quit":
                    self._real_quit()
                elif kind == "bypass_success":
                    domain = item[1]
                    self.show_gui_toast(f"✨ 우회 성공: {domain}")
                    self.spawn_floating_message(f"흐흐... [{domain}] 우회 성공...", True)
                elif kind == "bypass_fail":
                    domain = item[1]
                    self.show_gui_toast(f"❌ 우회 실패: {domain}")
                    self.spawn_floating_message(f"ㅠㅠ... [{domain}] 우회 실패...", False)
        except queue.Empty:
            pass

        # Live stats.
        if self.is_running and self.engine:
            s = self.engine.stats
            self.stats_label.config(
                text=f"DNS: {s['dns']}   HTTPS: {s['https_total']}   "
                     f"QUIC blk: {s['quic']}   resets: {s['https_reset']}")

            if s['https_total'] > 0 and not self.first_success_notified:
                self.first_success_notified = True
                if self.tray_icon is not None:
                    try:
                        self.tray_icon.notify("첫 우회 성공! LibertyGSM이 백그라운드에서 작동 중입니다.", "LibertyGSM")
                    except Exception:
                        pass

        self.root.after(100, self._tick)

    def show_gui_toast(self, message):
        self.toast_label.config(text=message)
        if self.toast_timer_id is not None:
            self.root.after_cancel(self.toast_timer_id)
        self.toast_timer_id = self.root.after(3000, self._clear_toast)

    def _clear_toast(self):
        self.toast_label.config(text="")
        self.toast_timer_id = None

    def open_exclude_hosts(self):
        import subprocess
        from tls_frag import get_exclude_hosts_path, load_exclude_hosts
        path = get_exclude_hosts_path()
        load_exclude_hosts()  # ensures the file exists
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] exclude_hosts.txt 열기 실패: {exc}")

    def spawn_floating_message(self, text, is_success):
        import random
        # Green for success, red for failure
        fg_color = "#10b981" if is_success else "#ef4444"
        bg_color = "#1e1e24"  # sleek card dark grey
        border_color = "#3e3e48"

        # Create a nice floating card/bubble with a 1px border
        label = tk.Label(
            self.root,
            text=text,
            font=("Segoe UI", 11, "bold"),
            fg=fg_color,
            bg=bg_color,
            relief=tk.SOLID,
            bd=1,
            padx=10,
            pady=6
        )

        # Random starting coordinates (within window bounds: 620x680)
        start_x = random.randint(30, 320)
        start_y = random.randint(250, 520)

        try:
            label.place(x=start_x, y=start_y)
        except Exception:
            return

        steps = 60
        step_ms = 25
        y_velocity = -1.5

        def animate(current_step, current_y):
            if not self.is_running:
                # If bypass is stopped, clean up the label
                try:
                    label.destroy()
                except Exception:
                    pass
                return

            if current_step >= steps:
                try:
                    label.destroy()
                except Exception:
                    pass
                return

            new_y = current_y + y_velocity
            try:
                label.place(y=int(new_y))
                self.root.after(step_ms, animate, current_step + 1, new_y)
            except Exception:
                try:
                    label.destroy()
                except Exception:
                    pass

        animate(0, start_y)

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

    def find_game_port(self):
        if not self.engine_info.supports_port_diagnostics:
            self.log_message(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] 포트 진단은 Windows WinDivert 엔진에서만 지원됩니다."
            )
            return
        self.sniff_btn.config(state=tk.DISABLED, text="진단 중... 막힌 게임을 새로고침하세요 (30초)")

        def cb(msg, level="INFO"):
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [{level}] {msg}")

        def worker():
            try:
                sniff_outbound_ports(cb, duration=30.0)
            except Exception as exc:
                cb(f"진단 오류: {exc}", "ERROR")
            self.result_queue.put(("sniff", True))

        threading.Thread(target=worker, daemon=True).start()

    def toggle(self):
        if self.is_running:
            self.stop_bypass()
        else:
            self.start_bypass()

    def start_bypass(self):
        if not self.engine_info.supported:
            self.log_message(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] 시작 불가: {self.engine_info.reason}"
            )
            return
        self.toggle_btn.config(state=tk.DISABLED, text="...")
        self.mode_combo.config(state=tk.DISABLED)
        self.first_success_notified = False
        try:
            self.engine = create_engine(
                mode=self.mode_combo.get(),
                log_callback=self.log_message,
                event_callback=self.handle_engine_event,
            )
        except UnsupportedPlatformError as exc:
            self.engine = None
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] Start failed: {exc}")
            self._finish_start(False)
            return
        # start() does a (blocking) DoH probe + driver open -> run off the UI thread.
        threading.Thread(target=self._start_worker, daemon=True).start()

    def handle_engine_event(self, event_type, data):
        self.result_queue.put((event_type, data))

    def _start_worker(self):
        ok = False
        try:
            if self.engine is not None:
                ok = self.engine.start()
        except Exception as exc:
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] Start failed: {exc}")
        self.result_queue.put(("start", ok))

    def _finish_start(self, ok):
        if ok:
            self.is_running = True
            title = "BYPASS ACTIVE" if self.engine_info.transparent else "LOCAL PROXY ACTIVE"
            self.status_title.config(text=title, fg="#10b981")
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
        # With a tray icon, the [X] button hides to the background instead of
        # quitting -- the bypass keeps running. Quit from the tray menu.
        if self.tray_icon is not None:
            self.root.withdraw()
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] "
                             f"트레이에서 백그라운드 실행 중. (트레이 아이콘 우클릭 → 종료)")
        else:
            self._real_quit()

    def _real_quit(self):
        if self.engine:
            try:
                self.engine.stop()
            except Exception:
                pass

        if sys.platform == "win32":
            # Unload the WinDivert DLL to release the file lock for PyInstaller cleanup.
            try:
                import ctypes
                import pydivert.windivert_dll as w
                handle = ctypes.windll.kernel32.GetModuleHandleW(w.DLL_PATH)
                if handle:
                    while ctypes.windll.kernel32.FreeLibrary(handle):
                        pass
            except Exception:
                pass

        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
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
    engine_info = get_engine_info()
    if engine_info.requires_admin and not _is_admin():
        # Trigger a UAC prompt and relaunch elevated; the un-elevated process exits.
        try:
            _relaunch_as_admin()
        finally:
            sys.exit(0)

    root = tk.Tk()
    app = LibertyGSMApp(root)
    root.mainloop()
