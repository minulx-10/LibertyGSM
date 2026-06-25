import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import sys
import os

# Import local modules
import sys_proxy
from bypass_proxy import BypassProxyServer

class LibertyGSMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LibertyGSM - Wi-Fi Bypass Utility")
        self.root.geometry("620x700")
        self.root.configure(bg="#121214")
        self.root.resizable(False, False)

        # Application State
        self.server = None
        self.log_queue = queue.Queue()
        self.is_running = False

        # Apply UI styling and build elements
        self._setup_styles()
        self._build_ui()
        
        # Start queue checking loop for thread-safe UI updates
        self.root.after(100, self._check_log_queue)

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_styles(self):
        # Configure TTK styles (for dropdowns etc.)
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TCombobox", 
                             fieldbackground="#1e1e24", 
                             background="#2e2e38", 
                             foreground="#ffffff", 
                             arrowcolor="#a855f7",
                             bordercolor="#2e2e38")
        self.style.map("TCombobox", 
                       fieldbackground=[('readonly', '#1e1e24')],
                       foreground=[('readonly', '#ffffff')])

    def _build_ui(self):
        # Main Container
        main_container = tk.Frame(self.root, bg="#121214", padx=25, pady=20)
        main_container.pack(fill=tk.BOTH, expand=True)

        # --- HEADER SECTION ---
        header_frame = tk.Frame(main_container, bg="#121214")
        header_frame.pack(fill=tk.X, pady=(0, 15))

        title_label = tk.Label(header_frame, text="LibertyGSM", font=("Segoe UI", 28, "bold"), fg="#a855f7", bg="#121214")
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(header_frame, text="DPI & SNI Bypass Local Utility", font=("Segoe UI", 10), fg="#9ca3af", bg="#121214")
        subtitle_label.pack(anchor="w")

        # --- STATUS & CONTROL PANEL ---
        self.status_card = tk.Frame(main_container, bg="#1e1e24", bd=1, relief=tk.FLAT, padx=15, pady=15)
        self.status_card.pack(fill=tk.X, pady=(0, 15))
        # Add a subtle border highlight effect
        self.status_card.config(highlightbackground="#2e2e38", highlightcolor="#2e2e38", highlightthickness=1)

        # Status text layout
        status_info_frame = tk.Frame(self.status_card, bg="#1e1e24")
        status_info_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.status_title_label = tk.Label(status_info_frame, text="BYPASS INACTIVE", font=("Segoe UI", 16, "bold"), fg="#ef4444", bg="#1e1e24")
        self.status_title_label.pack(anchor="w")

        self.conn_label = tk.Label(status_info_frame, text="Active Connections: 0", font=("Segoe UI", 10), fg="#9ca3af", bg="#1e1e24")
        self.conn_label.pack(anchor="w", pady=(3, 0))

        # Toggle Button
        self.toggle_btn = tk.Button(self.status_card, text="START", font=("Segoe UI", 12, "bold"), 
                                    bg="#ef4444", fg="#ffffff", activebackground="#dc2626", activeforeground="#ffffff",
                                    bd=0, padx=25, pady=8, cursor="hand2", command=self.toggle_bypass)
        self.toggle_btn.pack(side=tk.RIGHT, anchor="center")

        # --- CONFIGURATION PANEL ---
        config_frame = tk.Frame(main_container, bg="#121214")
        config_frame.pack(fill=tk.X, pady=(0, 15))

        # Left Column (Port & Bypass Mode)
        left_col = tk.Frame(config_frame, bg="#121214")
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Port Field
        port_label = tk.Label(left_col, text="Local Proxy Port", font=("Segoe UI", 10, "bold"), fg="#d1d5db", bg="#121214")
        port_label.pack(anchor="w", pady=(0, 4))
        
        self.port_entry = tk.Entry(left_col, font=("Segoe UI", 11), bg="#1e1e24", fg="#ffffff", insertbackground="#ffffff",
                                   bd=1, relief=tk.FLAT, highlightbackground="#2e2e38", highlightthickness=1)
        self.port_entry.insert(0, "10809")
        self.port_entry.pack(fill=tk.X, ipady=4, pady=(0, 10))

        # Bypass Mode Field
        mode_label = tk.Label(left_col, text="Bypass Intensity", font=("Segoe UI", 10, "bold"), fg="#d1d5db", bg="#121214")
        mode_label.pack(anchor="w", pady=(0, 4))

        self.mode_combo = ttk.Combobox(left_col, values=["Standard", "Advanced", "Extreme"], state="readonly", font=("Segoe UI", 10))
        self.mode_combo.set("Standard")
        self.mode_combo.pack(fill=tk.X, ipady=4)

        # Right Column (Options Checkboxes)
        right_col = tk.Frame(config_frame, bg="#121214")
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))

        options_label = tk.Label(right_col, text="Bypass Options", font=("Segoe UI", 10, "bold"), fg="#d1d5db", bg="#121214")
        options_label.pack(anchor="w", pady=(0, 8))

        # DoH Toggle
        self.var_doh = tk.BooleanVar(value=True)
        self.chk_doh = tk.Checkbutton(right_col, text="Enable DNS-over-HTTPS (DoH)", variable=self.var_doh, 
                                      font=("Segoe UI", 10), bg="#121214", fg="#d1d5db", selectcolor="#1e1e24", 
                                      activebackground="#121214", activeforeground="#ffffff", cursor="hand2")
        self.chk_doh.pack(anchor="w", pady=(0, 6))

        # System Proxy Auto-Toggle
        self.var_sys_proxy = tk.BooleanVar(value=True)
        self.chk_sys_proxy = tk.Checkbutton(right_col, text="Auto Set System Proxy", variable=self.var_sys_proxy, 
                                            font=("Segoe UI", 10), bg="#121214", fg="#d1d5db", selectcolor="#1e1e24", 
                                            activebackground="#121214", activeforeground="#ffffff", cursor="hand2")
        self.chk_sys_proxy.pack(anchor="w")

        # Auto-launch browser on start (replaces the old manual launch button)
        self.var_autolaunch = tk.BooleanVar(value=True)
        self.chk_autolaunch = tk.Checkbutton(right_col, text="Auto-launch Chrome on START", variable=self.var_autolaunch,
                                             font=("Segoe UI", 10), bg="#121214", fg="#d1d5db", selectcolor="#1e1e24",
                                             activebackground="#121214", activeforeground="#ffffff", cursor="hand2")
        self.chk_autolaunch.pack(anchor="w", pady=(8, 0))

        # --- LOG CONSOLE PANEL ---
        log_header_frame = tk.Frame(main_container, bg="#121214")
        log_header_frame.pack(fill=tk.X, pady=(10, 4))

        log_title = tk.Label(log_header_frame, text="Real-time Log Console", font=("Segoe UI", 10, "bold"), fg="#d1d5db", bg="#121214")
        log_title.pack(side=tk.LEFT)

        clear_btn = tk.Button(log_header_frame, text="Clear Log", font=("Segoe UI", 9), bg="#1e1e24", fg="#9ca3af",
                              activebackground="#2e2e38", activeforeground="#ffffff", bd=0, padx=8, cursor="hand2",
                              command=self.clear_logs)
        clear_btn.pack(side=tk.RIGHT)

        # ScrolledText console
        self.console = scrolledtext.ScrolledText(main_container, font=("Consolas", 9), bg="#18181b", fg="#a7f3d0", 
                                                 insertbackground="#ffffff", bd=1, relief=tk.FLAT, highlightbackground="#2e2e38", highlightthickness=1)
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.config(state=tk.DISABLED)

    def log_message(self, message):
        """Thread-safe logging by pushing to a queue."""
        self.log_queue.put(message)

    def _check_log_queue(self):
        """Drains the log queue and appends to the text console widget."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.console.config(state=tk.NORMAL)
                self.console.insert(tk.END, message + "\n")
                self.console.see(tk.END)
                self.console.config(state=tk.DISABLED)
        except queue.Empty:
            pass

        # Update connection count label if server is running
        if self.is_running and self.server:
            conn_count = self.server.active_connections
            self.conn_label.config(text=f"Active Connections: {conn_count}")

        self.root.after(100, self._check_log_queue)

    def clear_logs(self):
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)

    def toggle_bypass(self):
        if self.is_running:
            self.stop_bypass()
        else:
            self.start_bypass()

    def launch_chrome_proxy(self):
        # Open the user's NORMAL Chrome (default profile -- their logins and
        # bookmarks), not an isolated/incognito-style profile. The Windows system
        # proxy set on START routes its traffic through us, so no special flags
        # or throwaway --user-data-dir are needed.
        self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] Opening Chrome (normal profile; routed via system proxy)...")
        try:
            os.system('start "" chrome')
        except Exception as e:
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [WARNING] Chrome launch failed: {e}. Trying Edge...")
            try:
                os.system('start "" msedge')
            except Exception as e2:
                self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to launch Edge: {e2}")

    def start_bypass(self):
        # Read parameters
        port_str = self.port_entry.get().strip()
        if not port_str.isdigit():
            messagebox.showerror("Error", "Port must be a number!")
            return
        
        port = int(port_str)
        bypass_mode = self.mode_combo.get()
        use_doh = self.var_doh.get()
        auto_sys = self.var_sys_proxy.get()

        # Disable input fields
        self.port_entry.config(state=tk.DISABLED)
        self.chk_doh.config(state=tk.DISABLED)
        self.chk_sys_proxy.config(state=tk.DISABLED)
        self.chk_autolaunch.config(state=tk.DISABLED)

        # Initialize and start proxy server
        self.server = BypassProxyServer(
            host="127.0.0.1",
            port=port,
            bypass_mode=bypass_mode,
            use_doh=use_doh,
            log_callback=self.log_message
        )

        success = self.server.start()
        if success:
            self.is_running = True
            
            # Configure system proxy if enabled
            if auto_sys:
                self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] Setting Windows system proxy...")
                proxy_server = f"127.0.0.1:{port}"
                set_success = sys_proxy.set_proxy(True, proxy_server)
                if set_success:
                    self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] System proxy set to {proxy_server}")
                else:
                    self.log_message(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to set system proxy.")

            # Update UI to running state
            self.status_title_label.config(text="BYPASS ACTIVE", fg="#10b981")
            self.status_card.config(highlightbackground="#10b981", highlightcolor="#10b981")
            self.toggle_btn.config(text="STOP", bg="#10b981", activebackground="#059669")

            # Auto-launch the proxied browser so no extra button press is needed.
            if self.var_autolaunch.get():
                self.launch_chrome_proxy()
        else:
            # Re-enable inputs if starting server failed
            self.port_entry.config(state=tk.NORMAL)
            self.chk_doh.config(state=tk.NORMAL)
            self.chk_sys_proxy.config(state=tk.NORMAL)
            self.chk_autolaunch.config(state=tk.NORMAL)

    def stop_bypass(self):
        # Stop proxy server
        if self.server:
            self.server.stop()
            self.server = None

        # Restore system proxy if auto-set was selected
        if self.var_sys_proxy.get():
            self.log_message(f"[{time.strftime('%H:%M:%S')}] [SYSTEM] Restoring original Windows system proxy settings...")
            sys_proxy.restore_proxy_settings()

        self.is_running = False

        # Re-enable input fields
        self.port_entry.config(state=tk.NORMAL)
        self.chk_doh.config(state=tk.NORMAL)
        self.chk_sys_proxy.config(state=tk.NORMAL)
        self.chk_autolaunch.config(state=tk.NORMAL)

        # Update UI to stopped state
        self.status_title_label.config(text="BYPASS INACTIVE", fg="#ef4444")
        self.status_card.config(highlightbackground="#2e2e38", highlightcolor="#2e2e38")
        self.toggle_btn.config(text="START", bg="#ef4444", activebackground="#dc2626")
        self.conn_label.config(text="Active Connections: 0")

    def on_closing(self):
        if self.is_running:
            # Confirm if they want to exit, stop the bypass and clean up
            self.stop_bypass()
        self.root.destroy()
        sys.exit(0)

# Import time here for log formatting in callbacks
import time

if __name__ == "__main__":
    # Back up the proxy settings immediately on launch so we always know the starting state
    sys_proxy.backup_proxy_settings()
    
    root = tk.Tk()
    app = LibertyGSMApp(root)
    root.mainloop()
