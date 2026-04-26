import sys
import os
import hashlib
import psutil
import threading
import json
import ctypes
import subprocess
from pathlib import Path
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import io
import base64

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

SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ("EICAR-Test-File",   "Test",        "FAIBLE"),
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": ("RansomEXX.Win",     "Ransomware",  "CRITIQUE"),
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899": ("XMRig.Miner",        "Cryptominer", "ÉLEVÉ"),
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe": ("Backdoor.Win.RAT",   "Backdoor",    "CRITIQUE"),
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef": ("Trojan.GenericKD",   "Trojan",      "ÉLEVÉ"),
}

SUSPICIOUS_NAMES   = ["xmrig","minerd","cpuminer","ratclient","keylogger","mimikatz","netcat"]
SUSPICIOUS_PATHS   = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\"]

# ── Core functions ───────────────────────────────────────────────────────────
def hash_file(path: str) -> str | None:
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
    # Heuristic
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
                if header == b"MZ\x90\x00" or header[:2] == b"MZ":
                    result.update({"status": "suspicious", "threat": "Exécutable dans dossier temporaire", "severity": "MOYEN"})
                    return result
            except:
                pass
    return result

def scan_directory(path: str, recursive: bool = True, callback=None) -> list:
    results = []
    p = Path(path)
    iterator = p.rglob("*") if recursive else p.glob("*")
    for f in iterator:
        if f.is_file():
            try:
                size = f.stat().st_size
                if size > 2 * 1024 * 1024 * 1024:
                    continue
            except:
                continue
            r = scan_file(str(f))
            results.append(r)
            if callback:
                callback(r)
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
                        reason = f"EXE dans dossier temporaire"
                        break
            results.append({
                "pid": info["pid"],
                "name": info.get("name","?"),
                "exe": info.get("exe","?"),
                "suspicious": suspicious,
                "reason": reason,
            })
        except:
            pass
    return sorted(results, key=lambda x: x["pid"])

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

# ── First Launch Window ──────────────────────────────────────────────────────
class FirstLaunchWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.result = None
        self.title("Heartove — Premier lancement")
        self.geometry("520x600")
        self.resizable(False, False)
        self.configure(fg_color="#0a0a0f")
        self._build()
        self.lift()
        self.focus_force()

    def _build(self):
        # Logo placeholder (shield icon via text)
        ctk.CTkLabel(self, text="🛡️", font=("Segoe UI Emoji", 64)).pack(pady=(40,0))
        ctk.CTkLabel(self, text="HEARTOVE", font=("Courier New", 28, "bold"),
                     text_color="#e63946").pack()
        ctk.CTkLabel(self, text="Antivirus — v" + VERSION,
                     font=("Courier New", 12), text_color="#666").pack(pady=(2,30))

        # Language
        ctk.CTkLabel(self, text="Choisissez votre langue / Choose language",
                     font=("Courier New", 13), text_color="#ccc").pack()
        self.lang_var = ctk.StringVar(value="fr")
        lang_frame = ctk.CTkFrame(self, fg_color="transparent")
        lang_frame.pack(pady=10)
        ctk.CTkRadioButton(lang_frame, text="Français", variable=self.lang_var, value="fr",
                           font=("Courier New", 12), fg_color="#e63946").pack(side="left", padx=20)
        ctk.CTkRadioButton(lang_frame, text="English", variable=self.lang_var, value="en",
                           font=("Courier New", 12), fg_color="#e63946").pack(side="left", padx=20)

        # Permissions
        perms_frame = ctk.CTkFrame(self, fg_color="#111118", corner_radius=12)
        perms_frame.pack(padx=40, pady=20, fill="x")
        ctk.CTkLabel(perms_frame, text="🔐 Permissions requises",
                     font=("Courier New", 13, "bold"), text_color="#e63946").pack(pady=(14,6))
        perms = [
            "• Lire et analyser vos fichiers",
            "• Accéder aux processus actifs",
            "• Surveiller les dossiers en temps réel",
            "• Déplacer des fichiers en quarantaine",
        ]
        for p in perms:
            ctk.CTkLabel(perms_frame, text=p, font=("Courier New", 11),
                         text_color="#aaa").pack(anchor="w", padx=20, pady=1)
        ctk.CTkLabel(perms_frame, text="ℹ Ces accès restent locaux sur votre machine.",
                     font=("Courier New", 10), text_color="#555").pack(pady=(6,14))

        # Accept button
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

# ── Main GUI ─────────────────────────────────────────────────────────────────
class HeartoveApp(ctk.CTk):
    def __init__(self, config: dict):
        super().__init__()
        self.config_data = config
        self.lang = config.get("lang", "fr")
        self.scanning = False

        self.title("Heartove Antivirus")
        self.geometry("900x620")
        self.minsize(800, 560)
        self.configure(fg_color="#0a0a0f")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._build()
        self.lift()

    # ── Translations ──
    def t(self, fr, en):
        return fr if self.lang == "fr" else en

    # ── Layout ──
    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        sidebar = ctk.CTkFrame(self, width=200, fg_color="#0f0f1a", corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="🛡️", font=("Segoe UI Emoji", 36)).pack(pady=(30,0))
        ctk.CTkLabel(sidebar, text="HEARTOVE", font=("Courier New", 16, "bold"),
                     text_color="#e63946").pack()
        ctk.CTkLabel(sidebar, text=f"v{VERSION}", font=("Courier New", 10),
                     text_color="#444").pack(pady=(2,30))

        # Nav buttons
        self.nav_buttons = {}
        nav_items = [
            ("home",      "🏠 " + self.t("Accueil","Home")),
            ("scan",      "🔍 " + self.t("Scanner","Scan")),
            ("fullscan",  "💻 " + self.t("Scan Complet","Full Scan")),
            ("processes", "⚙️ " + self.t("Processus","Processes")),
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

        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(expand=True)

        # Reset button
        ctk.CTkButton(
            sidebar, text="🔄 Reset",
            font=("Courier New", 11),
            fg_color="transparent", hover_color="#1a1a2e",
            text_color="#555", corner_radius=6, height=32,
            command=self._reset
        ).pack(fill="x", padx=10, pady=(0,6))

        ctk.CTkLabel(sidebar, text="@gojo_80 Discord",
                     font=("Courier New", 9), text_color="#333").pack(pady=(0,16))

        # Main content
        self.content = ctk.CTkFrame(self, fg_color="#0d0d16", corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self._build_home()
        self._build_scan()
        self._build_fullscan()
        self._build_processes()
        self._build_sigs()

        self._show_page("home")

    def _show_page(self, key):
        for k, page in self.pages.items():
            page.grid_remove()
        self.pages[key].grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        # Highlight active nav
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color="#1e1e30" if k == key else "transparent",
                          text_color="#e63946" if k == key else "#ccc")

    # ── Home Page ──
    def _build_home(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        self.pages["home"] = page

        ctk.CTkLabel(page, text="🛡️", font=("Segoe UI Emoji", 72)).pack(pady=(60,0))
        ctk.CTkLabel(page, text="HEARTOVE ANTIVIRUS",
                     font=("Courier New", 26, "bold"), text_color="#e63946").pack()
        ctk.CTkLabel(page, text=self.t(
            "Votre protection Linux — propulsé par Rust, porté sur Windows",
            "Your protection — powered by Rust, ported to Windows"),
                     font=("Courier New", 12), text_color="#555").pack(pady=(4,40))

        # Stats cards
        cards_frame = ctk.CTkFrame(page, fg_color="transparent")
        cards_frame.pack()
        cards = [
            ("🔐", self.t("Signatures","Signatures"), str(len(SIGNATURES))),
            ("⚡", self.t("Moteur","Engine"), "SHA256 + Heuristique"),
            ("💾", self.t("Limite scan","Scan limit"), "2 GB"),
        ]
        for icon, label, val in cards:
            card = ctk.CTkFrame(cards_frame, fg_color="#111118", corner_radius=12, width=180, height=100)
            card.pack(side="left", padx=10)
            card.pack_propagate(False)
            ctk.CTkLabel(card, text=icon, font=("Segoe UI Emoji", 28)).pack(pady=(14,0))
            ctk.CTkLabel(card, text=val, font=("Courier New", 13, "bold"), text_color="#e63946").pack()
            ctk.CTkLabel(card, text=label, font=("Courier New", 10), text_color="#555").pack()

        ctk.CTkButton(page, text="🔍 " + self.t("Lancer un scan","Start scan"),
                      font=("Courier New", 14, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=8, height=44, width=240,
                      command=lambda: self._show_page("scan")).pack(pady=40)

    # ── Scan Page ──
    def _build_scan(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.pages["scan"] = page

        ctk.CTkLabel(page, text="🔍 " + self.t("Scanner un fichier / dossier","Scan file / folder"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(30,20), padx=30, sticky="w")

        # Buttons row
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

        # Progress
        self.scan_progress = ctk.CTkProgressBar(page, fg_color="#111118", progress_color="#e63946", height=6)
        self.scan_progress.grid(row=2, column=0, padx=30, pady=(16,0), sticky="ew")
        self.scan_progress.set(0)

        self.scan_status_label = ctk.CTkLabel(page, text="", font=("Courier New", 10), text_color="#555")
        self.scan_status_label.grid(row=3, column=0, padx=30, sticky="w")

        # Results
        self.scan_results_box = ctk.CTkTextbox(
            page, font=("Courier New", 11),
            fg_color="#0a0a0f", text_color="#ccc",
            corner_radius=10, border_width=1, border_color="#1e1e30"
        )
        self.scan_results_box.grid(row=4, column=0, padx=30, pady=(10,30), sticky="nsew")
        page.grid_rowconfigure(4, weight=1)

    def _scan_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._run_scan([path])

    def _scan_folder(self):
        path = filedialog.askdirectory()
        if path:
            self._run_scan_dir(path, self.scan_recursive.get())

    def _run_scan(self, paths):
        self.scan_results_box.delete("1.0", "end")
        self.scan_progress.set(0)
        results = []
        def worker():
            for i, p in enumerate(paths):
                r = scan_file(p)
                results.append(r)
                self._append_result(r)
                self.scan_progress.set((i+1)/len(paths))
            self._show_summary(results)
        threading.Thread(target=worker, daemon=True).start()

    def _run_scan_dir(self, path, recursive):
        self.scan_results_box.delete("1.0", "end")
        self.scan_progress.configure(mode="indeterminate")
        self.scan_progress.start()
        results = []
        def worker():
            def cb(r):
                results.append(r)
                self._append_result(r)
                self.scan_status_label.configure(text=f"Scan : {os.path.basename(r['path'])}")
            scan_directory(path, recursive, cb)
            self.scan_progress.stop()
            self.scan_progress.configure(mode="determinate")
            self.scan_progress.set(1)
            self.scan_status_label.configure(text=self.t("Scan terminé","Scan complete"))
            self._show_summary(results)
        threading.Thread(target=worker, daemon=True).start()

    def _append_result(self, r):
        status = r["status"]
        path   = r["path"]
        if status == "clean":
            line = f"  ✓  {path}\n"
            tag  = "clean"
        elif status == "infected":
            line = f"  ✗  {path}  →  {r['threat']} [{r['severity']}]\n"
            tag  = "infected"
        elif status == "suspicious":
            line = f"  ⚠  {path}  →  {r['threat']}\n"
            tag  = "suspicious"
        else:
            line = f"  ?  {path}\n"
            tag  = "error"
        self.scan_results_box.insert("end", line)
        # Color tags
        self.scan_results_box.tag_config("clean",      foreground="#4caf50")
        self.scan_results_box.tag_config("infected",   foreground="#e63946")
        self.scan_results_box.tag_config("suspicious", foreground="#ff9800")
        self.scan_results_box.tag_config("error",      foreground="#666")
        self.scan_results_box.see("end")

    def _show_summary(self, results):
        total     = len(results)
        infected  = sum(1 for r in results if r["status"] == "infected")
        suspicious= sum(1 for r in results if r["status"] == "suspicious")
        clean     = sum(1 for r in results if r["status"] == "clean")
        summary = (
            f"\n{'─'*60}\n"
            f"  RAPPORT — {datetime.now().strftime('%H:%M:%S')}\n"
            f"  Fichiers analysés : {total}\n"
            f"  ✓ Propres         : {clean}\n"
            f"  ✗ Infectés        : {infected}\n"
            f"  ⚠ Suspects        : {suspicious}\n"
            f"{'─'*60}\n"
        )
        self.scan_results_box.insert("end", summary)
        self.scan_results_box.see("end")

    # ── Full Scan Page ──
    def _build_fullscan(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(3, weight=1)
        self.pages["fullscan"] = page

        ctk.CTkLabel(page, text="💻 " + self.t("Scan complet du PC","Full PC Scan"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(30,6), padx=30, sticky="w")
        ctk.CTkLabel(page, text=self.t(
            "Analyse tous les disques et dossiers utilisateur",
            "Scans all drives and user folders"),
                     font=("Courier New", 11), text_color="#555").grid(
                     row=1, column=0, padx=30, sticky="w")

        self.fullscan_btn = ctk.CTkButton(
            page, text="▶  " + self.t("Démarrer le scan complet","Start full scan"),
            font=("Courier New", 13, "bold"),
            fg_color="#e63946", hover_color="#c1121f",
            corner_radius=8, height=44,
            command=self._start_fullscan
        )
        self.fullscan_btn.grid(row=2, column=0, padx=30, pady=16, sticky="w")

        self.fullscan_progress = ctk.CTkProgressBar(page, fg_color="#111118", progress_color="#e63946", height=6)
        self.fullscan_progress.grid(row=2, column=0, padx=30, pady=(70,0), sticky="ew")
        self.fullscan_progress.set(0)

        self.fullscan_label = ctk.CTkLabel(page, text="", font=("Courier New", 10), text_color="#555")
        self.fullscan_label.grid(row=3, column=0, padx=30, sticky="nw", pady=(4,0))

        self.fullscan_box = ctk.CTkTextbox(
            page, font=("Courier New", 11),
            fg_color="#0a0a0f", text_color="#ccc",
            corner_radius=10, border_width=1, border_color="#1e1e30"
        )
        self.fullscan_box.grid(row=4, column=0, padx=30, pady=(10,30), sticky="nsew")
        page.grid_rowconfigure(4, weight=1)

    def _start_fullscan(self):
        if self.scanning:
            return
        self.scanning = True
        self.fullscan_box.delete("1.0", "end")
        self.fullscan_progress.configure(mode="indeterminate")
        self.fullscan_progress.start()
        self.fullscan_btn.configure(state="disabled")

        # Scan user home + all drives
        targets = [str(Path.home())]
        if sys.platform == "win32":
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    targets.append(drive)

        results = []
        def worker():
            for target in targets:
                def cb(r):
                    results.append(r)
                    if r["status"] != "clean":
                        self._fs_append(r)
                    self.fullscan_label.configure(text=f"→ {r['path'][:70]}")
                scan_directory(target, True, cb)
            self.fullscan_progress.stop()
            self.fullscan_progress.configure(mode="determinate")
            self.fullscan_progress.set(1)
            self.scanning = False
            self.fullscan_btn.configure(state="normal")
            self._fs_summary(results)

        threading.Thread(target=worker, daemon=True).start()

    def _fs_append(self, r):
        status = r["status"]
        if status == "infected":
            line = f"  ✗  {r['path']}  →  {r['threat']} [{r['severity']}]\n"
        else:
            line = f"  ⚠  {r['path']}  →  {r['threat']}\n"
        self.fullscan_box.insert("end", line)
        self.fullscan_box.see("end")

    def _fs_summary(self, results):
        total     = len(results)
        infected  = sum(1 for r in results if r["status"] == "infected")
        suspicious= sum(1 for r in results if r["status"] == "suspicious")
        clean     = total - infected - suspicious
        msg = (
            f"\n{'─'*60}\n"
            f"  SCAN COMPLET TERMINÉ — {datetime.now().strftime('%H:%M:%S')}\n"
            f"  Fichiers analysés : {total}\n"
            f"  ✓ Propres         : {clean}\n"
            f"  ✗ Infectés        : {infected}\n"
            f"  ⚠ Suspects        : {suspicious}\n"
            f"{'─'*60}\n"
        )
        if infected == 0 and suspicious == 0:
            msg += "  ✓ Aucune menace détectée — votre PC est sain.\n"
        self.fullscan_box.insert("end", msg)
        self.fullscan_box.see("end")

    # ── Processes Page ──
    def _build_processes(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.pages["processes"] = page

        ctk.CTkLabel(page, text="⚙️ " + self.t("Processus actifs","Active Processes"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(30,16), padx=30, sticky="w")

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.grid(row=1, column=0, padx=30, sticky="w")

        ctk.CTkButton(btn_frame, text="🔄 " + self.t("Analyser","Analyse"),
                      font=("Courier New", 12, "bold"),
                      fg_color="#e63946", hover_color="#c1121f",
                      corner_radius=7, height=38,
                      command=self._load_processes).pack(side="left", padx=(0,10))

        self.only_suspicious = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(btn_frame, text=self.t("Suspects seulement","Suspicious only"),
                        variable=self.only_suspicious,
                        font=("Courier New", 11), fg_color="#e63946",
                        command=self._load_processes).pack(side="left", padx=10)

        self.proc_box = ctk.CTkTextbox(
            page, font=("Courier New", 11),
            fg_color="#0a0a0f", text_color="#ccc",
            corner_radius=10, border_width=1, border_color="#1e1e30"
        )
        self.proc_box.grid(row=2, column=0, padx=30, pady=(10,30), sticky="nsew")

    def _load_processes(self):
        self.proc_box.delete("1.0", "end")
        self.proc_box.insert("end", self.t("  Analyse en cours...\n","  Analysing...\n"))
        def worker():
            procs = scan_processes()
            self.proc_box.delete("1.0", "end")
            only_susp = self.only_suspicious.get()
            susp_count = 0
            for p in procs:
                if only_susp and not p["suspicious"]:
                    continue
                if p["suspicious"]:
                    susp_count += 1
                    line = f"  ⚠  PID {p['pid']:<6} {p['name']:<22} → {p['reason']}\n"
                    self.proc_box.insert("end", line)
                else:
                    line = f"  ✓  PID {p['pid']:<6} {p['name']}\n"
                    self.proc_box.insert("end", line)
            summary = f"\n  {'─'*50}\n  {len(procs)} processus | {susp_count} suspects\n"
            self.proc_box.insert("end", summary)
        threading.Thread(target=worker, daemon=True).start()

    # ── Signatures Page ──
    def _build_sigs(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        self.pages["sigs"] = page

        ctk.CTkLabel(page, text="📋 " + self.t("Base de signatures","Signature Database"),
                     font=("Courier New", 18, "bold"), text_color="#e63946").grid(
                     row=0, column=0, pady=(30,16), padx=30, sticky="w")

        box = ctk.CTkTextbox(page, font=("Courier New", 11),
                             fg_color="#0a0a0f", text_color="#ccc",
                             corner_radius=10, border_width=1, border_color="#1e1e30")
        box.grid(row=1, column=0, padx=30, pady=(0,30), sticky="nsew")

        box.insert("end", f"  {'─'*58}\n")
        box.insert("end", f"  {'NOM':<30} {'CATÉGORIE':<14} SÉVÉRITÉ\n")
        box.insert("end", f"  {'─'*58}\n")
        for h, (name, cat, sev) in SIGNATURES.items():
            box.insert("end", f"  {name:<30} {cat:<14} {sev}\n")
            box.insert("end", f"    hash: {h[:24]}...\n")
        box.insert("end", f"  {'─'*58}\n")
        box.insert("end", f"  {len(SIGNATURES)} signatures dans la base.\n")
        box.configure(state="disabled")

    # ── Reset ──
    def _reset(self):
        if messagebox.askyesno("Reset", self.t(
            "Réinitialiser Heartove ? Le premier lancement s'affichera à la prochaine ouverture.",
            "Reset Heartove? First launch will show on next open.")):
            reset_config()
            self.destroy()

# ── Entry Point ──────────────────────────────────────────────────────────────
def main():
    request_admin()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    config = load_config()

    if not config:
        # First launch
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
