import sys
import os
import hashlib
import psutil
import threading
import json
import ctypes
import time
from pathlib import Path
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── UAC elevation (Windows) ──────────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# ── Config ───────────────────────────────────────────────────────────────────
CONFIG_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "Heartove"
CONFIG_FILE = CONFIG_DIR / "setup.json"
VERSION     = "0.2.0"
AUTHOR      = "@gojo_80 Discord"

SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ("EICAR-Test-File",   "Test",        "FAIBLE"),
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": ("RansomEXX.Win",     "Ransomware",  "CRITIQUE"),
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899": ("XMRig.Miner",        "Cryptominer", "ÉLEVÉ"),
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe": ("Backdoor.Win.RAT",   "Backdoor",    "CRITIQUE"),
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": ("Trojan.GenericKD",   "Trojan",      "ÉLEVÉ"),
}

SUSPICIOUS_NAMES = ["xmrig","minerd","cpuminer","ratclient","keylogger","mimikatz","netcat","nmap","metasploit"]
SUSPICIOUS_PATHS = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\"]
SUSPICIOUS_PORTS = [4444, 1337, 31337, 6666, 9999, 1234, 8888]  # ports RAT/backdoor connus

# ── Core scan functions ───────────────────────────────────────────────────────
def hash_file(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def scan_file(path: str) -> dict:
    result = {"path": path, "status": "clean", "threat": None, "severity": None}
    h = hash_file(path)
    if h is None:
        result["status"] = "error"
        return result
    if h in SIGNATURES:
        name, cat, sev = SIGNATURES[h]
        result.update({"status": "infected", "threat": name, "severity": sev})
        return result
    path_lower = path.lower()
    name_lower = os.path.basename(path_lower)
    for s in SUSPICIOUS_NAMES:
        if s in name_lower:
            result.update({"status": "suspicious", "threat": f"Nom suspect : {s}", "severity": "MOYEN"})
            return result
    for p in SUSPICIOUS_PATHS:
        if p in path_lower:
            try:
                with open(path, "rb") as f:
                    header = f.read(4)
                if header[:2] == b"MZ":
                    result.update({"status": "suspicious", "threat": "Exécutable dans dossier temporaire", "severity": "MOYEN"})
                    return result
            except:
                pass
    return result

def scan_directory(path: str, recursive: bool = True, callback=None) -> list:
    results = []
    p = Path(path)
    try:
        iterator = p.rglob("*") if recursive else p.glob("*")
        for f in iterator:
            if f.is_file():
                try:
                    if f.stat().st_size > 2 * 1024 * 1024 * 1024:
                        continue
                except:
                    continue
                r = scan_file(str(f))
                results.append(r)
                if callback:
                    callback(r)
    except:
        pass
    return results

def scan_processes() -> list:
    results = []
    for proc in psutil.process_iter(["pid","name","exe","cmdline"]):
        try:
            info = proc.info
            suspicious = False
            reason = None
            name = (info.get("name") or "").lower()
            exe  = (info.get("exe")  or "").lower()
            cmd  = " ".join(info.get("cmdline") or []).lower()
            for s in SUSPICIOUS_NAMES:
                if s in name or s in cmd:
                    suspicious = True
                    reason = f"Nom suspect : {s}"
                    break
            if not suspicious:
                for p in SUSPICIOUS_PATHS:
                    if p in exe:
                        suspicious = True
                        reason = "EXE dans dossier temporaire"
                        break
            results.append({
                "pid": info["pid"],
                "name": info.get("name","?"),
                "exe": info.get("exe") or "?",
                "suspicious": suspicious,
                "reason": reason,
            })
        except:
            pass
    return sorted(results, key=lambda x: x["pid"])

def scan_network() -> list:
    """Analyse les connexions réseau actives et détecte les ports suspects."""
    results = []
    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            suspicious = False
            reason = None
            lport = conn.laddr.port if conn.laddr else 0
            rport = conn.raddr.port if conn.raddr else 0
            raddr = conn.raddr.ip if conn.raddr else None

            # Port local ou distant suspect
            if lport in SUSPICIOUS_PORTS:
                suspicious = True
                reason = f"Port local suspect : {lport} (RAT/Backdoor connu)"
            elif rport in SUSPICIOUS_PORTS:
                suspicious = True
                reason = f"Port distant suspect : {rport} (RAT/Backdoor connu)"

            # Connexion établie vers l'extérieur
            if raddr and conn.status == "ESTABLISHED":
                proc_name = "?"
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except:
                    pass
                results.append({
                    "pid": conn.pid or 0,
                    "process": proc_name,
                    "local": f"{conn.laddr.ip}:{lport}" if conn.laddr else "?",
                    "remote": f"{raddr}:{rport}",
                    "status": conn.status,
                    "suspicious": suspicious,
                    "reason": reason,
                })
    except Exception as e:
        pass
    return results

# ── Real-time watchdog handler ────────────────────────────────────────────────
class HeartoveWatchHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._check(event.src_path, "CRÉÉ")

    def on_modified(self, event):
        if not event.is_directory:
            self._check(event.src_path, "MODIFIÉ")

    def on_moved(self, event):
        if not event.is_directory:
            self._check(event.dest_path, "DÉPLACÉ")

    def _check(self, path, event_type):
        r = scan_file(path)
        self.callback(path, event_type, r)

# ── Config ────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return {}

def save_config(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2))

def reset_config():
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()

# ── First Launch Window ───────────────────────────────────────────────────────
class FirstLaunchWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.result = None
        self.title(f"Heartove — Premier lancement — by {AUTHOR}")
        self.geometry("520x620")
        self.resizable(False, False)
        self.configure(fg_color="#0a0a0f")
        self._build()
        self.lift()
        self.focus_force()

    def _build(self):
        ctk.CTkLabel(self, text="🛡️", font=("Segoe UI Emoji", 64)).pack(pady=(30,0))
        ctk.CTkLabel(self, text="HEARTOVE", font=("Courier New", 28, "bold"),
                     text_color="#e63946").pack()
        ctk.CTkLabel(self, text=f"Antivirus Windows — v{VERSION}",
                     font=("Courier New", 12), text_color="#666").pack(pady=(2,2))
        ctk.CTkLabel(self, text=f"by {AUTHOR}",
                     font=("Courier New", 11, "bold"), text_color="#e63946").pack(pady=(0,20))

        ctk.CTkLabel(self, text="Choisissez votre langue / Choose language",
                     font=("Courier New", 13), text_color="#ccc").pack()
        self.lang_var = ctk.StringVar(value="fr")
        lang_frame = ctk.CTkFrame(self, fg_color="transparent")
        lang_frame.pack(pady=10)
        ctk.CTkRadioButton(lang_frame, text="Français", variable=self.lang_var, value="fr",
                           font=("Courier New", 12), fg_color="#e63946").pack(side="left", padx=20)
        ctk.CTkRadioButton(lang_frame, text="English", variable=self.lang_var, value="en",
                           font=("Courier New", 12), fg_color="#e63946").pack(side="left", padx=20)

        perms_frame = ctk.CTkFrame(self, fg_color="#111118", corner_radius=12)
        perms_frame.pack(padx=40, pady=20, fill="x")
        ctk.CTkLabel(perms_frame, text="🔐 Permissions requises",
                     font=("Courier New", 13, "bold"), text_color="#e63946").pack(pady=(14,6))
        perms = [
            "• Lire et analyser vos fichiers",
            "• Accéder aux processus actifs",
            "• Surveiller les connexions réseau",
            "• Surveiller les dossiers en temps réel",
            "• Déplacer des fichiers en quarantaine",
        ]
        for p in perms:
            ctk.CTkLabel(perms_frame, text=p, font=("Courier New", 11),
                         text_color="#aaa").pack(anchor="w", padx=20, pady=1)
        ctk.CTkLabel(perms_frame, text="ℹ Ces accès restent locaux sur votre machine.",
                     font=("Courier New", 10), text_color="#555").pack(pady=(6,14))

        ctk.CTkButton(self, text="✓  Autoriser & Continuer",
                      font=("Courier New", 14, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=8, height=44,
                      command=self._accept).pack(padx=40, pady=(0,10), fill="x")
        ctk.CTkButton(self, text="Refuser",
                      font=("Courier New", 11),
                      fg_color="transparent", hover_color="#1a1a22",
                      border_width=1, border_color="#333",
                      corner_radius=8, height=36,
                      command=self._decline).pack(padx=40, fill="x")

    def _accept(self):
        self.result = {"lang": self.lang_var.get(), "accepted": True}
        self.destroy()

    def _decline(self):
        self.result = {"lang": self.lang_var.get(), "accepted": False}
        self.destroy()

# ── Main App ──────────────────────────────────────────────────────────────────
class HeartoveApp(ctk.CTk):
    def __init__(self, config: dict):
        super().__init__()
        self.config_data = config
        self.lang = config.get("lang", "fr")
        self.scanning = False
        self.watch_observer = None

        self.title(f"Heartove Antivirus — by {AUTHOR}")
        self.geometry("960x660")
        self.minsize(820, 580)
        self.configure(fg_color="#0a0a0f")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._build()
        self.lift()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        if self.watch_observer:
            self.watch_observer.stop()
        self.destroy()

    def t(self, fr, en):
        return fr if self.lang == "fr" else en

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar ──
        sidebar = ctk.CTkFrame(self, width=210, fg_color="#0f0f1a", corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="🛡️", font=("Segoe UI Emoji", 36)).pack(pady=(28,0))
        ctk.CTkLabel(sidebar, text="HEARTOVE", font=("Courier New", 16, "bold"),
                     text_color="#e63946").pack()
        ctk.CTkLabel(sidebar, text=f"v{VERSION}", font=("Courier New", 10),
                     text_color="#444").pack(pady=(0,2))
        ctk.CTkLabel(sidebar, text=f"by {AUTHOR}", font=("Courier New", 9),
                     text_color="#e63946").pack(pady=(0,24))

        self.nav_buttons = {}
        nav_items = [
            ("home",      "🏠 " + self.t("Accueil","Home")),
            ("scan",      "🔍 " + self.t("Scanner","Scan")),
            ("fullscan",  "💻 " + self.t("Scan Complet","Full Scan")),
            ("watch",     "👁  " + self.t("Surveillance","Watch")),
            ("processes", "⚙️  " + self.t("Processus","Processes")),
            ("network",   "🌐 " + self.t("Réseau","Network")),
            ("sigs",      "📋 " + self.t("Signatures","Signatures")),
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=label, anchor="w",
                font=("Courier New", 12),
                fg_color="transparent", hover_color="#1a1a2e",
                text_color="#ccc", corner_radius=6, height=38,
                command=lambda k=key: self._show_page(k)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn

        ctk.CTkFrame(sidebar, fg_color="transparent").pack(expand=True)

        ctk.CTkButton(
            sidebar, text="🔄 Reset",
            font=("Courier New", 11),
            fg_color="transparent", hover_color="#1a1a2e",
            text_color="#555", corner_radius=6, height=32,
            command=self._reset
        ).pack(fill="x", padx=10, pady=(0,4))
        ctk.CTkLabel(sidebar, text=f"{AUTHOR}", font=("Courier New", 9),
                     text_color="#2a2a3a").pack(pady=(0,14))

        # ── Content ──
        self.content = ctk.CTkFrame(self, fg_color="#0d0d16", corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self._build_home()
        self._build_scan()
        self._build_fullscan()
        self._build_watch()
        self._build_processes()
        self._build_network()
        self._build_sigs()
        self._show_page("home")

    def _show_page(self, key):
        for page in self.pages.values():
            page.grid_remove()
        self.pages[key].grid(row=0, column=0, sticky="nsew")
        for k, btn in self.nav_buttons.items():
            btn.configure(
                fg_color="#1e1e30" if k == key else "transparent",
                text_color="#e63946" if k == key else "#ccc"
            )

    # ── Home ──
    def _build_home(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        self.pages["home"] = page

        ctk.CTkLabel(page, text="🛡️", font=("Segoe UI Emoji", 72)).pack(pady=(50,0))
        ctk.CTkLabel(page, text="HEARTOVE ANTIVIRUS",
                     font=("Courier New", 26, "bold"), text_color="#e63946").pack()
        ctk.CTkLabel(page, text=f"by {AUTHOR}",
                     font=("Courier New", 13, "bold"), text_color="#e63946").pack(pady=(2,4))
        ctk.CTkLabel(page, text=self.t(
            "Protection Windows — SHA256 · Heuristique · Réseau · Temps réel",
            "Windows Protection — SHA256 · Heuristic · Network · Real-time"),
                     font=("Courier New", 11), text_color="#444").pack(pady=(0,36))

        cards_frame = ctk.CTkFrame(page, fg_color="transparent")
        cards_frame.pack()
        cards = [
            ("🔐", self.t("Signatures","Signatures"), str(len(SIGNATURES))),
            ("⚡", "Engine", "SHA256 + Heuristique"),
            ("🌐", self.t("Réseau","Network"), self.t("Surveillance active","Active monitoring")),
            ("👁", self.t("Temps réel","Real-time"), self.t("Watchdog intégré","Built-in watchdog")),
        ]
        for icon, label, val in cards:
            card = ctk.CTkFrame(cards_frame, fg_color="#111118", corner_radius=12, width=160, height=90)
            card.pack(side="left", padx=8)
            card.pack_propagate(False)
            ctk.CTkLabel(card, text=icon, font=("Segoe UI Emoji", 24)).pack(pady=(12,0))
            ctk.CTkLabel(card, text=val, font=("Courier New", 11, "bold"), text_color="#e63946").pack()
            ctk.CTkLabel(card, text=label, font=("Courier New", 9), text_color="#444").pack()

        ctk.CTkButton(page, text="🔍 " + self.t("Lancer un scan","Start scan"),
                      font=("Courier New", 14, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=8, height=44, width=240,
                      command=lambda: self._show_page("scan")).pack(pady=36)

    # ── Scan ──
    def _build_scan(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(4, weight=1)
        self.pages["scan"] = page

        ctk.CTkLabel(page, text="🔍 " + self.t("Scanner fichier / dossier","Scan file / folder"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,16), padx=30, sticky="w")

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.grid(row=1, column=0, padx=30, sticky="w")
        ctk.CTkButton(btn_frame, text="📄 " + self.t("Fichier","File"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=7, height=38,
                      command=self._scan_file).pack(side="left", padx=(0,10))
        ctk.CTkButton(btn_frame, text="📁 " + self.t("Dossier","Folder"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#1e1e30", hover_color="#2a2a40",
                      border_width=1, border_color="#e63946",
                      corner_radius=7, height=38,
                      command=self._scan_folder).pack(side="left", padx=(0,10))
        self.scan_recursive = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(btn_frame, text=self.t("Récursif","Recursive"),
                        variable=self.scan_recursive,
                        font=("Courier New", 11), fg_color="#e63946").pack(side="left", padx=10)

        self.scan_progress = ctk.CTkProgressBar(page, fg_color="#111118", progress_color="#e63946", height=6)
        self.scan_progress.grid(row=2, column=0, padx=30, pady=(14,0), sticky="ew")
        self.scan_progress.set(0)
        self.scan_status_lbl = ctk.CTkLabel(page, text="", font=("Courier New", 10), text_color="#555")
        self.scan_status_lbl.grid(row=3, column=0, padx=30, sticky="w")

        self.scan_box = ctk.CTkTextbox(page, font=("Courier New", 11),
                                       fg_color="#0a0a0f", text_color="#ccc",
                                       corner_radius=10, border_width=1, border_color="#1e1e30")
        self.scan_box.grid(row=4, column=0, padx=30, pady=(8,28), sticky="nsew")

    def _scan_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.scan_box.delete("1.0","end")
            r = scan_file(path)
            self._append_scan_result(self.scan_box, r)
            self._show_summary(self.scan_box, [r])

    def _scan_folder(self):
        path = filedialog.askdirectory()
        if not path:
            return
        self.scan_box.delete("1.0","end")
        self.scan_progress.configure(mode="indeterminate")
        self.scan_progress.start()
        results = []
        def worker():
            def cb(r):
                results.append(r)
                self._append_scan_result(self.scan_box, r)
                self.scan_status_lbl.configure(text=os.path.basename(r["path"]))
            scan_directory(path, self.scan_recursive.get(), cb)
            self.scan_progress.stop()
            self.scan_progress.configure(mode="determinate")
            self.scan_progress.set(1)
            self.scan_status_lbl.configure(text=self.t("Terminé ✓","Done ✓"))
            self._show_summary(self.scan_box, results)
        threading.Thread(target=worker, daemon=True).start()

    def _append_scan_result(self, box, r):
        s = r["status"]
        if s == "clean":
            box.insert("end", f"  ✓  {r['path']}\n")
        elif s == "infected":
            box.insert("end", f"  ✗  {r['path']}  →  {r['threat']} [{r['severity']}]\n")
        elif s == "suspicious":
            box.insert("end", f"  ⚠  {r['path']}  →  {r['threat']}\n")
        else:
            box.insert("end", f"  ?  {r['path']}\n")
        box.see("end")

    def _show_summary(self, box, results):
        total     = len(results)
        infected  = sum(1 for r in results if r["status"] == "infected")
        suspicious= sum(1 for r in results if r["status"] == "suspicious")
        clean     = sum(1 for r in results if r["status"] == "clean")
        box.insert("end",
            f"\n{'─'*60}\n"
            f"  RAPPORT — {datetime.now().strftime('%H:%M:%S')}\n"
            f"  Fichiers analysés : {total}\n"
            f"  ✓ Propres  : {clean}   ✗ Infectés : {infected}   ⚠ Suspects : {suspicious}\n"
            f"{'─'*60}\n"
        )
        box.see("end")

    # ── Full Scan ──
    def _build_fullscan(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(4, weight=1)
        self.pages["fullscan"] = page

        ctk.CTkLabel(page, text="💻 " + self.t("Scan complet du PC","Full PC Scan"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,4), padx=30, sticky="w")
        ctk.CTkLabel(page, text=self.t("Analyse tous les disques Windows","Scans all Windows drives"),
                     font=("Courier New", 11), text_color="#555").grid(
                     row=1, column=0, padx=30, sticky="w")

        self.fullscan_btn = ctk.CTkButton(
            page, text="▶  " + self.t("Démarrer","Start"),
            font=("Courier New", 13, "bold"),
            fg_color="#e63946", hover_color="#c1121f",
            corner_radius=8, height=42, width=200,
            command=self._start_fullscan
        )
        self.fullscan_btn.grid(row=2, column=0, padx=30, pady=14, sticky="w")

        self.fullscan_progress = ctk.CTkProgressBar(page, fg_color="#111118", progress_color="#e63946", height=6)
        self.fullscan_progress.grid(row=2, column=0, padx=30, pady=(68,0), sticky="ew")
        self.fullscan_progress.set(0)

        self.fullscan_lbl = ctk.CTkLabel(page, text="", font=("Courier New", 10), text_color="#555")
        self.fullscan_lbl.grid(row=3, column=0, padx=30, sticky="w", pady=(2,0))

        self.fullscan_box = ctk.CTkTextbox(page, font=("Courier New", 11),
                                           fg_color="#0a0a0f", text_color="#ccc",
                                           corner_radius=10, border_width=1, border_color="#1e1e30")
        self.fullscan_box.grid(row=4, column=0, padx=30, pady=(8,28), sticky="nsew")

    def _start_fullscan(self):
        if self.scanning:
            return
        self.scanning = True
        self.fullscan_box.delete("1.0","end")
        self.fullscan_progress.configure(mode="indeterminate")
        self.fullscan_progress.start()
        self.fullscan_btn.configure(state="disabled")

        targets = []
        if sys.platform == "win32":
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    targets.append(drive)
        else:
            targets = [str(Path.home())]

        results = []
        def worker():
            for target in targets:
                def cb(r):
                    results.append(r)
                    if r["status"] != "clean":
                        self.fullscan_box.insert("end",
                            f"  {'✗' if r['status']=='infected' else '⚠'}  {r['path']}  →  {r['threat']}\n")
                        self.fullscan_box.see("end")
                    self.fullscan_lbl.configure(text=f"→ {r['path'][:72]}")
                scan_directory(target, True, cb)
            self.fullscan_progress.stop()
            self.fullscan_progress.configure(mode="determinate")
            self.fullscan_progress.set(1)
            self.scanning = False
            self.fullscan_btn.configure(state="normal")
            self._show_summary(self.fullscan_box, results)
        threading.Thread(target=worker, daemon=True).start()

    # ── Watch (temps réel) ──
    def _build_watch(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.pages["watch"] = page

        ctk.CTkLabel(page, text="👁  " + self.t("Surveillance temps réel","Real-time Watch"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,16), padx=30, sticky="w")

        ctrl_frame = ctk.CTkFrame(page, fg_color="transparent")
        ctrl_frame.grid(row=1, column=0, padx=30, sticky="w")

        self.watch_path_var = ctk.StringVar(value=str(Path.home() / "Downloads"))
        ctk.CTkEntry(ctrl_frame, textvariable=self.watch_path_var,
                     font=("Courier New", 11), width=320,
                     fg_color="#111118", border_color="#2a2a3a").pack(side="left", padx=(0,8))
        ctk.CTkButton(ctrl_frame, text="📁", width=36, height=36,
                      fg_color="#1e1e30", hover_color="#2a2a40",
                      command=lambda: self.watch_path_var.set(filedialog.askdirectory() or self.watch_path_var.get())
                      ).pack(side="left", padx=(0,8))

        self.watch_btn = ctk.CTkButton(ctrl_frame,
                      text="▶ " + self.t("Démarrer","Start"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=7, height=36,
                      command=self._toggle_watch)
        self.watch_btn.pack(side="left")

        self.watch_status = ctk.CTkLabel(ctrl_frame, text="",
                     font=("Courier New", 10), text_color="#555")
        self.watch_status.pack(side="left", padx=12)

        self.watch_box = ctk.CTkTextbox(page, font=("Courier New", 11),
                                        fg_color="#0a0a0f", text_color="#ccc",
                                        corner_radius=10, border_width=1, border_color="#1e1e30")
        self.watch_box.grid(row=2, column=0, padx=30, pady=(10,28), sticky="nsew")

    def _toggle_watch(self):
        if self.watch_observer and self.watch_observer.is_alive():
            self.watch_observer.stop()
            self.watch_observer = None
            self.watch_btn.configure(text="▶ " + self.t("Démarrer","Start"), fg_color="#e63946")
            self.watch_status.configure(text=self.t("Arrêté","Stopped"), text_color="#555")
        else:
            path = self.watch_path_var.get()
            if not os.path.isdir(path):
                messagebox.showerror("Erreur", self.t("Dossier introuvable","Folder not found"))
                return
            def on_event(file_path, event_type, result):
                s = result["status"]
                icon = "✓" if s=="clean" else ("✗" if s=="infected" else "⚠")
                threat = f"  →  {result['threat']}" if result["threat"] else ""
                line = f"  [{datetime.now().strftime('%H:%M:%S')}] {event_type}  {icon}  {os.path.basename(file_path)}{threat}\n"
                self.watch_box.insert("end", line)
                self.watch_box.see("end")

            handler = HeartoveWatchHandler(on_event)
            self.watch_observer = Observer()
            self.watch_observer.schedule(handler, path, recursive=True)
            self.watch_observer.start()
            self.watch_btn.configure(text="⏹ " + self.t("Arrêter","Stop"), fg_color="#555")
            self.watch_status.configure(
                text=self.t(f"Surveillance active : {path}", f"Watching: {path}"),
                text_color="#4caf50"
            )
            self.watch_box.insert("end", f"  Surveillance démarrée → {path}\n")

    # ── Processes ──
    def _build_processes(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.pages["processes"] = page

        ctk.CTkLabel(page, text="⚙️  " + self.t("Processus actifs","Active Processes"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,16), padx=30, sticky="w")

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.grid(row=1, column=0, padx=30, sticky="w")
        ctk.CTkButton(btn_frame, text="🔄 " + self.t("Analyser","Analyse"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=7, height=38,
                      command=self._load_processes).pack(side="left", padx=(0,10))
        self.only_susp_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(btn_frame, text=self.t("Suspects seulement","Suspicious only"),
                        variable=self.only_susp_var,
                        font=("Courier New", 11), fg_color="#e63946",
                        command=self._load_processes).pack(side="left", padx=10)

        self.proc_box = ctk.CTkTextbox(page, font=("Courier New", 11),
                                       fg_color="#0a0a0f", text_color="#ccc",
                                       corner_radius=10, border_width=1, border_color="#1e1e30")
        self.proc_box.grid(row=2, column=0, padx=30, pady=(10,28), sticky="nsew")

    def _load_processes(self):
        self.proc_box.delete("1.0","end")
        self.proc_box.insert("end", self.t("  Analyse...\n","  Analysing...\n"))
        def worker():
            procs = scan_processes()
            self.proc_box.delete("1.0","end")
            only = self.only_susp_var.get()
            susp = 0
            for p in procs:
                if only and not p["suspicious"]:
                    continue
                if p["suspicious"]:
                    susp += 1
                    self.proc_box.insert("end",
                        f"  ⚠  PID {p['pid']:<6} {p['name']:<22} → {p['reason']}\n"
                        f"      exe: {p['exe']}\n")
                else:
                    self.proc_box.insert("end",
                        f"  ✓  PID {p['pid']:<6} {p['name']}\n")
            self.proc_box.insert("end",
                f"\n  {'─'*50}\n  {len(procs)} processus | {susp} suspects\n")
        threading.Thread(target=worker, daemon=True).start()

    # ── Network ──
    def _build_network(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.pages["network"] = page

        ctk.CTkLabel(page, text="🌐 " + self.t("Surveillance réseau","Network Monitor"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,16), padx=30, sticky="w")

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.grid(row=1, column=0, padx=30, sticky="w")
        ctk.CTkButton(btn_frame, text="🔄 " + self.t("Analyser connexions","Scan connections"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=7, height=38,
                      command=self._load_network).pack(side="left", padx=(0,10))
        self.only_susp_net = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(btn_frame, text=self.t("Suspects seulement","Suspicious only"),
                        variable=self.only_susp_net,
                        font=("Courier New", 11), fg_color="#e63946",
                        command=self._load_network).pack(side="left", padx=10)

        self.net_box = ctk.CTkTextbox(page, font=("Courier New", 11),
                                      fg_color="#0a0a0f", text_color="#ccc",
                                      corner_radius=10, border_width=1, border_color="#1e1e30")
        self.net_box.grid(row=2, column=0, padx=30, pady=(10,28), sticky="nsew")

    def _load_network(self):
        self.net_box.delete("1.0","end")
        self.net_box.insert("end", self.t("  Analyse du réseau...\n","  Scanning network...\n"))
        def worker():
            conns = scan_network()
            self.net_box.delete("1.0","end")
            only = self.only_susp_net.get()
            susp = 0
            total = 0
            self.net_box.insert("end",
                f"  {'─'*70}\n"
                f"  {'PROCESSUS':<20} {'LOCAL':<22} {'DISTANT':<22} STATUT\n"
                f"  {'─'*70}\n")
            for c in conns:
                if only and not c["suspicious"]:
                    continue
                total += 1
                if c["suspicious"]:
                    susp += 1
                    icon = "⚠"
                else:
                    icon = "✓"
                self.net_box.insert("end",
                    f"  {icon}  {c['process']:<18} {c['local']:<22} {c['remote']:<22} {c['status']}\n")
                if c["suspicious"]:
                    self.net_box.insert("end",
                        f"      → {c['reason']}\n")
            self.net_box.insert("end",
                f"  {'─'*70}\n"
                f"  {total} connexions affichées | {susp} suspectes\n")
        threading.Thread(target=worker, daemon=True).start()

    # ── Signatures ──
    def _build_sigs(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        self.pages["sigs"] = page

        ctk.CTkLabel(page, text="📋 " + self.t("Base de signatures","Signature Database"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(28,16), padx=30, sticky="w")

        box = ctk.CTkTextbox(page, font=("Courier New", 11),
                             fg_color="#0a0a0f", text_color="#ccc",
                             corner_radius=10, border_width=1, border_color="#1e1e30")
        box.grid(row=1, column=0, padx=30, pady=(0,28), sticky="nsew")
        box.insert("end", f"  {'─'*62}\n")
        box.insert("end", f"  {'NOM':<30} {'CATÉGORIE':<16} SÉVÉRITÉ\n")
        box.insert("end", f"  {'─'*62}\n")
        for h, (name, cat, sev) in SIGNATURES.items():
            box.insert("end", f"  {name:<30} {cat:<16} {sev}\n")
            box.insert("end", f"    hash: {h[:28]}...\n")
        box.insert("end", f"  {'─'*62}\n")
        box.insert("end", f"  {len(SIGNATURES)} signatures | Heartove by {AUTHOR}\n")
        box.configure(state="disabled")

    # ── Reset ──
    def _reset(self):
        if messagebox.askyesno("Reset Heartove", self.t(
            "Réinitialiser ? Le premier lancement s'affichera à la prochaine ouverture.",
            "Reset? First launch will show on next open.")):
            if self.watch_observer:
                self.watch_observer.stop()
            reset_config()
            self.destroy()

# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    request_admin()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    config = load_config()
    if not config:
        fl = FirstLaunchWindow()
        fl.mainloop()
        if fl.result is None or not fl.result.get("accepted"):
            sys.exit()
        config = fl.result
        save_config(config)

    app = HeartoveApp(config)
    app.mainloop()

if __name__ == "__main__":
    main()
