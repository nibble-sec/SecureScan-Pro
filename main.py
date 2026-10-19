import customtkinter as ctk
from tkinter import filedialog
import threading
import os
import time
import hashlib
import sqlite3
from datetime import datetime

from heuristic_engine import HeuristicScanner
from ml_engine import MLScanner
from yara_engine import YaraScanner

ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")


class HybridAntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AI Malware Analysis & Suspicious File Detection System")
        self.geometry("1280x860")
        self.minsize(1180, 760)

        # Use Inter if available, otherwise Segoe UI
        self.font_family = "Inter"
        self.mono_font_family = "ui-monospace"

        self.colors = {
            "bg": "#f8fafc",
            "sidebar": "#1e293b",
            "panel": "#ffffff",
            "panel_alt": "#ffffff",
            "card": "#ffffff",
            "card_2": "#f1f5f9",
            "card_3": "#e2e8f0",
            "soft_dark": "#f8fafc",
            "border": "#e2e8f0",
            "text": "#0f172a",
            "muted": "#64748b",
            "blue": "#2563eb",
            "blue_hover": "#1d4ed8",
            "cyan": "#0ea5e9",
            "green": "#16a34a",
            "yellow": "#d97706",
            "red": "#dc2626",
            "purple": "#7c3aed",
            "pink": "#db2777",
            "white": "#ffffff",
            "dark_badge": "#e2e8f0"
        }

        self.configure(fg_color=self.colors["bg"])

        self.heuristic_scanner = HeuristicScanner()
        self.ml_scanner = MLScanner()
        self.yara_scanner = YaraScanner()

        self.stats = {
            "scans": 0,
            "threats": 0,
            "clean": 0,
            "suspicious": 0
        }

        self.current_report_data = None
        self.result_popup = None

        self.history_items = []
        self.quarantine_items = []

        self.db_path = "scanner_data.db"
        self.init_database()
        self.load_saved_data()

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.setup_sidebar()
        self.setup_frames()
        self.show_frame("dashboard")
        self.update_dashboard_stats()

    def heading_font(self, size=28):
        return ctk.CTkFont(family=self.font_family, size=size, weight="bold")

    def subheading_font(self, size=18):
        return ctk.CTkFont(family=self.font_family, size=size, weight="bold")

    def body_font(self, size=14, weight="normal"):
        return ctk.CTkFont(family=self.font_family, size=size, weight=weight)

    def mono_font(self, size=12, weight="normal"):
        return ctk.CTkFont(family=self.mono_font_family, size=size, weight=weight)

    def get_db_connection(self):
        return sqlite3.connect(self.db_path)

    def init_database(self):
        conn = self.get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk TEXT,
                heuristic TEXT,
                ml TEXT,
                final_score TEXT,
                file_hash TEXT,
                scan_time TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                score REAL NOT NULL,
                added_time TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def load_saved_data(self):
        conn = self.get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time
            FROM scan_history
            ORDER BY id DESC
        """)
        history_rows = cursor.fetchall()

        self.history_items = []
        clean_count = 0
        suspicious_count = 0
        threat_count = 0

        for row in history_rows:
            item = {
                "filename": row[0],
                "verdict": row[1],
                "risk": row[2],
                "heuristic": row[3],
                "ml": row[4],
                "final_score": row[5],
                "hash": row[6],
                "time": row[7]
            }
            self.history_items.append(item)

            if row[1] == "File Appears Safe":
                clean_count += 1
            elif row[1] == "Suspicious File Detected":
                suspicious_count += 1
            elif row[1] == "High-Risk File":
                threat_count += 1

        cursor.execute("""
            SELECT filename, score, added_time
            FROM quarantine
            ORDER BY id DESC
        """)
        quarantine_rows = cursor.fetchall()

        self.quarantine_items = []
        for row in quarantine_rows:
            self.quarantine_items.append({
                "filename": row[0],
                "score": row[1],
                "time": row[2]
            })

        conn.close()

        self.stats["scans"] = len(self.history_items)
        self.stats["clean"] = clean_count
        self.stats["suspicious"] = suspicious_count
        self.stats["threats"] = threat_count

    def save_history_to_db(self, filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time):
        conn = self.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time))
        conn.commit()
        conn.close()

    def save_quarantine_to_db(self, filename, score, added_time):
        conn = self.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO quarantine (filename, score, added_time)
            VALUES (?, ?, ?)
        """, (filename, score, added_time))
        conn.commit()
        conn.close()

    def setup_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=255,
            fg_color=self.colors["sidebar"],
            corner_radius=0
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="SecureScan",
            font=self.heading_font(24),
            text_color="#ffffff"
        )
        self.logo_label.grid(row=0, column=0, padx=24, pady=(32, 8))

        self.logo_sub = ctk.CTkLabel(
            self.sidebar_frame,
            text="Hybrid Malware Analysis System",
            font=self.body_font(12),
            text_color="#94a3b8"
        )
        self.logo_sub.grid(row=1, column=0, padx=24, pady=(0, 24))

        self.btn_dashboard = self.create_nav_btn(2, "Overview Dashboard", "dashboard")
        self.btn_scan = self.create_nav_btn(3, "Analyze File", "scan")
        self.btn_history = self.create_nav_btn(4, "Scan Logs", "history")
        self.btn_quarantine = self.create_nav_btn(5, "Quarantine Management", "quarantine")

        self.nav_buttons = {
            "dashboard": self.btn_dashboard,
            "scan": self.btn_scan,
            "history": self.btn_history,
            "quarantine": self.btn_quarantine
        }

    def create_nav_btn(self, row, text, view_name):
        btn = ctk.CTkButton(
            self.sidebar_frame,
            text=text,
            command=lambda: self.show_frame(view_name),
            anchor="w",
            height=50,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#334155",
            text_color="#ffffff",
            font=self.body_font(15, "bold")
        )
        btn.grid(row=row, column=0, padx=18, pady=7, sticky="ew")
        return btn

    def setup_frames(self):
        self.frames = {}
        self.setup_dashboard_frame()
        self.setup_scan_frame()
        self.setup_history_frame()
        self.setup_quarantine_frame()

    def setup_dashboard_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        frame.grid_columnconfigure((0, 1), weight=1)
        frame.grid_rowconfigure(3, weight=1)
        self.frames["dashboard"] = frame

        self.status_frame = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel_alt"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"],
            height=220
        )
        self.status_frame.grid(row=0, column=0, columnspan=2, padx=22, pady=22, sticky="ew")

        self.status_icon = ctk.CTkLabel(
            self.status_frame,
            text="📄",
            font=self.heading_font(52),
            text_color=self.colors["text"]
        )
        self.status_icon.pack(pady=(24, 4))

        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="System Ready",
            font=self.heading_font(30),
            text_color=self.colors["text"]
        )
        self.status_label.pack(pady=(0, 5))

        self.status_subtext = ctk.CTkLabel(
            self.status_frame,
            text="Upload a file to begin behavioral analysis and risk assessment.",
            font=self.body_font(14),
            text_color=self.colors["muted"]
        )
        self.status_subtext.pack(pady=(0, 22))

        self.stat_scans_lbl = self.create_stat_card(frame, 1, 0, "Files Processed", "0", self.colors["blue"])
        self.stat_threats_lbl = self.create_stat_card(frame, 1, 1, "Threat Indicators", "0", self.colors["red"])
        self.stat_clean_lbl = self.create_stat_card(frame, 2, 0, "Safe Files", "0", self.colors["green"])
        self.stat_suspicious_lbl = self.create_stat_card(frame, 2, 1, "Suspicious Files", "0", self.colors["yellow"])

        activity_frame = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        activity_frame.grid(row=3, column=0, columnspan=2, padx=22, pady=(8, 22), sticky="nsew")

        ctk.CTkLabel(
            activity_frame,
            text="Recent Activity",
            font=self.subheading_font(19),
            text_color=self.colors["text"]
        ).pack(anchor="w", padx=22, pady=(18, 10))

        self.activity_log_mod = ctk.CTkTextbox(
            activity_frame,
            fg_color=self.colors["soft_dark"],
            text_color=self.colors["text"],
            corner_radius=16,
            border_width=1,
            border_color=self.colors["border"],
            font=self.body_font(14)
        )
        self.activity_log_mod.pack(fill="both", expand=True, padx=22, pady=(0, 22))
        self.activity_log_mod.insert("end", "• Scanner initialized successfully.\n• Waiting for file upload.\n")
        self.activity_log_mod.configure(state="disabled")

    def setup_scan_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        self.frames["scan"] = frame

        ctk.CTkLabel(
            frame,
            text="Analyze File",
            font=self.heading_font(28),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, padx=22, pady=(22, 14), sticky="w")

        top_btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        top_btn_frame.grid(row=1, column=0, padx=22, sticky="ew")
        top_btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.btn_select_file = ctk.CTkButton(
            top_btn_frame,
            text="Initialize Analysis",
            command=self.custom_scan,
            height=54,
            corner_radius=8,
            fg_color=self.colors["blue"],
            hover_color=self.colors["blue_hover"],
            font=self.body_font(15, "bold")
        )
        self.btn_select_file.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.btn_view_report = ctk.CTkButton(
            top_btn_frame,
            text="View Latest Assessment",
            command=self.open_result_popup,
            height=54,
            corner_radius=8,
            fg_color=self.colors["purple"],
            hover_color="#6d28d9",
            font=self.body_font(15, "bold"),
            state="disabled"
        )
        self.btn_view_report.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        self.scan_status_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.scan_status_card.grid(row=2, column=0, padx=22, pady=18, sticky="ew")
        self.scan_status_card.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            self.scan_status_card,
            text="Analysis Progress",
            font=self.subheading_font(19),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, padx=22, pady=(18, 8), sticky="w")

        self.scan_step_badge = ctk.CTkLabel(
            self.scan_status_card,
            text="READY",
            font=self.body_font(12, "bold"),
            text_color=self.colors["white"],
            fg_color=self.colors["card_3"],
            corner_radius=12,
            padx=14,
            pady=6
        )
        self.scan_step_badge.grid(row=0, column=1, padx=22, pady=(18, 8), sticky="e")

        self.scan_lbl = ctk.CTkLabel(
            self.scan_status_card,
            text="Ready. Select a file to begin risk assessment.",
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"]
        )
        self.scan_lbl.grid(row=1, column=0, columnspan=2, padx=22, pady=(0, 8), sticky="w")

        self.selected_file_label = ctk.CTkLabel(
            self.scan_status_card,
            text="Selected File: -",
            font=self.body_font(14),
            text_color=self.colors["muted"],
            wraplength=980,
            justify="left"
        )
        self.selected_file_label.grid(row=2, column=0, columnspan=2, padx=22, pady=(0, 12), sticky="w")

        self.progressbar = ctk.CTkProgressBar(
            self.scan_status_card,
            height=14,
            progress_color=self.colors["blue"],
            fg_color="#243247"
        )
        self.progressbar.grid(row=3, column=0, columnspan=2, padx=22, pady=(0, 18), sticky="ew")
        self.progressbar.set(0)

        self.res_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.res_card.grid(row=3, column=0, padx=22, pady=(0, 22), sticky="nsew")
        self.res_card.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            self.res_card,
            text="Latest Scan Result",
            font=self.subheading_font(20),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, columnspan=2, padx=22, pady=(18, 10), sticky="w")

        self.result_banner = ctk.CTkFrame(
            self.res_card,
            fg_color=self.colors["card_2"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.result_banner.grid(row=1, column=0, columnspan=2, padx=22, pady=(0, 16), sticky="ew")
        self.result_banner.grid_columnconfigure(1, weight=1)

        self.result_badge = ctk.CTkLabel(
            self.result_banner,
            text="NO RESULT",
            font=self.body_font(13, "bold"),
            text_color=self.colors["white"],
            fg_color="#2a3548",
            corner_radius=12,
            padx=16,
            pady=7
        )
        self.result_badge.grid(row=0, column=0, padx=16, pady=16, sticky="w")

        self.result_summary = ctk.CTkLabel(
            self.result_banner,
            text="Select a file to begin analysis.",
            font=self.body_font(14, "bold"),
            text_color=self.colors["muted"],
            anchor="w",
            justify="left"
        )
        self.result_summary.grid(row=0, column=1, padx=(0, 16), pady=16, sticky="ew")

        self.file_info_card = ctk.CTkFrame(
            self.res_card,
            fg_color=self.colors["card"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.file_info_card.grid(row=2, column=0, padx=(22, 10), pady=(0, 14), sticky="nsew")

        ctk.CTkLabel(
            self.file_info_card,
            text="File Information",
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", padx=16, pady=(16, 10))

        ctk.CTkLabel(
            self.file_info_card,
            text="File Name",
            font=self.body_font(12, "bold"),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=16)

        self.lbl_fname = ctk.CTkLabel(
            self.file_info_card,
            text="-",
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"],
            wraplength=470,
            justify="left"
        )
        self.lbl_fname.pack(anchor="w", padx=16, pady=(2, 10))

        ctk.CTkLabel(
            self.file_info_card,
            text="SHA-256 Hash",
            font=self.body_font(12, "bold"),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=16)

        self.lbl_hash = ctk.CTkTextbox(
            self.file_info_card,
            height=95,
            font=self.mono_font(12, "bold"),
            fg_color=self.colors["soft_dark"],
            text_color=self.colors["text"],
            corner_radius=12,
            border_width=1,
            border_color=self.colors["border"],
            wrap="word"
        )
        self.lbl_hash.pack(fill="x", padx=16, pady=(4, 16))
        self.lbl_hash.insert("1.0", "-")
        self.lbl_hash.configure(state="disabled")

        self.summary_card = ctk.CTkFrame(
            self.res_card,
            fg_color=self.colors["card"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.summary_card.grid(row=2, column=1, padx=(10, 22), pady=(0, 14), sticky="nsew")

        ctk.CTkLabel(
            self.summary_card,
            text="Scan Summary",
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", padx=16, pady=(16, 10))

        self.lbl_status = self.create_info_value(self.summary_card, "Scan Status", "Idle")
        self.lbl_risk = self.create_info_value(self.summary_card, "Risk Level", "-")
        self.lbl_heur = self.create_info_value(self.summary_card, "Heuristic Score", "-")
        self.lbl_ml = self.create_info_value(self.summary_card, "ML Confidence", "-")
        self.lbl_yara = self.create_info_value(self.summary_card, "YARA Match", "-")

        ctk.CTkLabel(
            self.summary_card,
            text="Final Verdict",
            font=self.body_font(12, "bold"),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=16)

        self.lbl_verdict = ctk.CTkLabel(
            self.summary_card,
            text="-",
            font=self.heading_font(22),
            text_color=self.colors["text"]
        )
        self.lbl_verdict.pack(anchor="w", padx=16, pady=(2, 16))

        self.action_card = ctk.CTkFrame(
            self.res_card,
            fg_color=self.colors["card_2"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.action_card.grid(row=3, column=0, columnspan=2, padx=22, pady=(0, 16), sticky="ew")

        ctk.CTkLabel(
            self.action_card,
            text="Recommended Action",
            font=self.body_font(14, "bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", padx=16, pady=(16, 8))

        self.lbl_action = ctk.CTkLabel(
            self.action_card,
            text="-",
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"],
            wraplength=960,
            justify="left"
        )
        self.lbl_action.pack(anchor="w", padx=16, pady=(0, 16))

    def create_info_value(self, parent, title, value):
        ctk.CTkLabel(
            parent,
            text=title,
            font=self.body_font(12, "bold"),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=16)
        lbl = ctk.CTkLabel(
            parent,
            text=value,
            font=self.body_font(15, "bold"),
            text_color=self.colors["text"]
        )
        lbl.pack(anchor="w", padx=16, pady=(2, 10))
        return lbl

    def setup_history_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        self.frames["history"] = frame

        ctk.CTkLabel(
            frame,
            text="Scan History",
            font=self.heading_font(28),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, padx=22, pady=(22, 12), sticky="w")

        self.history_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.history_card.grid(row=1, column=0, padx=22, pady=(0, 22), sticky="nsew")
        self.history_card.grid_rowconfigure(1, weight=1)
        self.history_card.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(self.history_card, fg_color="transparent")
        top_bar.grid(row=0, column=0, padx=18, pady=(18, 10), sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top_bar,
            text="Recent Scan Records",
            font=self.subheading_font(18),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, sticky="w")


        self.history_scroll = ctk.CTkScrollableFrame(
            self.history_card,
            fg_color=self.colors["soft_dark"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.history_scroll.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="nsew")
        self.history_scroll.grid_columnconfigure(0, weight=1)

        self.render_history_items()

    def setup_quarantine_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        self.frames["quarantine"] = frame

        ctk.CTkLabel(
            frame,
            text="Quarantine",
            font=self.heading_font(28),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, padx=22, pady=(22, 12), sticky="w")

        self.quarantine_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.quarantine_card.grid(row=1, column=0, padx=22, pady=(0, 22), sticky="nsew")
        self.quarantine_card.grid_rowconfigure(1, weight=1)
        self.quarantine_card.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(self.quarantine_card, fg_color="transparent")
        top_bar.grid(row=0, column=0, padx=18, pady=(18, 10), sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top_bar,
            text="Flagged Files",
            font=self.subheading_font(18),
            text_color=self.colors["text"]
        ).grid(row=0, column=0, sticky="w")

        self.quarantine_scroll = ctk.CTkScrollableFrame(
            self.quarantine_card,
            fg_color=self.colors["soft_dark"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        self.quarantine_scroll.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="nsew")
        self.quarantine_scroll.grid_columnconfigure(0, weight=1)

        self.render_quarantine_items()

    def create_stat_card(self, parent, row, col, title, value, val_color):
        card = ctk.CTkFrame(
            parent,
            fg_color=self.colors["card"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        card.grid(row=row, column=col, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(
            card,
            text=title,
            font=self.body_font(15, "bold"),
            text_color=self.colors["muted"]
        ).pack(pady=(18, 4))

        val_lbl = ctk.CTkLabel(
            card,
            text=value,
            font=self.heading_font(34),
            text_color=val_color
        )
        val_lbl.pack(pady=(0, 18))
        return val_lbl

    def show_frame(self, name):
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=1, sticky="nsew")

        for btn in self.nav_buttons.values():
            btn.configure(fg_color="transparent")
        self.nav_buttons[name].configure(fg_color="#1d2840")

    def update_dashboard_status(self, text, color, icon, subtext=""):
        self.status_label.configure(text=text)
        self.status_frame.configure(fg_color=color)
        self.status_icon.configure(text=icon)
        self.status_subtext.configure(text=subtext)

    def update_dashboard_stats(self):
        self.stat_scans_lbl.configure(text=str(self.stats["scans"]))
        self.stat_threats_lbl.configure(text=str(self.stats["threats"]))
        self.stat_clean_lbl.configure(text=str(self.stats["clean"]))
        self.stat_suspicious_lbl.configure(text=str(self.stats["suspicious"]))

    def log_activity(self, message):
        self.activity_log_mod.configure(state="normal")
        date_str = datetime.now().strftime("%H:%M:%S")
        self.activity_log_mod.insert("1.0", f"• [{date_str}] {message}\n")
        self.activity_log_mod.configure(state="disabled")

    def get_verdict_color(self, verdict):
        if verdict == "High-Risk File":
            return self.colors["red"]
        if verdict == "Suspicious File Detected":
            return self.colors["yellow"]
        return self.colors["green"]

    def render_history_items(self):
        for widget in self.history_scroll.winfo_children():
            widget.destroy()

        if not self.history_items:
            empty_card = ctk.CTkFrame(
                self.history_scroll,
                fg_color=self.colors["card"],
                corner_radius=18,
                border_width=1,
                border_color=self.colors["border"]
            )
            empty_card.grid(row=0, column=0, padx=12, pady=12, sticky="ew")

            ctk.CTkLabel(
                empty_card,
                text="No scan history available yet",
                font=self.body_font(16, "bold"),
                text_color=self.colors["text"]
            ).pack(anchor="w", padx=18, pady=(16, 4))

            ctk.CTkLabel(
                empty_card,
                text="Scanned files will appear here and stay saved in the database.",
                font=self.body_font(13),
                text_color=self.colors["muted"]
            ).pack(anchor="w", padx=18, pady=(0, 16))
            return

        for index, item in enumerate(self.history_items):
            verdict_color = self.get_verdict_color(item["verdict"])

            card = ctk.CTkFrame(
                self.history_scroll,
                fg_color=self.colors["card"],
                corner_radius=18,
                border_width=1,
                border_color=self.colors["border"]
            )
            card.grid(row=index, column=0, padx=12, pady=10, sticky="ew")
            card.grid_columnconfigure(1, weight=1)

            serial_box = ctk.CTkLabel(
                card,
                text=str(index + 1),
                font=self.body_font(14, "bold"),
                text_color=self.colors["white"],
                fg_color=self.colors["blue"],
                corner_radius=14,
                width=42,
                height=42
            )
            serial_box.grid(row=0, column=0, rowspan=3, padx=(14, 12), pady=14, sticky="n")

            ctk.CTkLabel(
                card,
                text=item["filename"],
                font=self.body_font(16, "bold"),
                text_color=self.colors["text"],
                anchor="w",
                justify="left",
                wraplength=700
            ).grid(row=0, column=1, padx=(0, 10), pady=(14, 6), sticky="w")

            ctk.CTkLabel(
                card,
                text=item["verdict"],
                font=self.body_font(12, "bold"),
                text_color=self.colors["white"],
                fg_color=verdict_color,
                corner_radius=12,
                padx=14,
                pady=6
            ).grid(row=0, column=2, padx=(0, 14), pady=(14, 6), sticky="e")

            ctk.CTkLabel(
                card,
                text=f"Risk: {item.get('risk', '-')}",
                font=self.body_font(12, "bold"),
                text_color=self.colors["cyan"]
            ).grid(row=1, column=1, padx=(0, 10), pady=(0, 2), sticky="w")

            ctk.CTkLabel(
                card,
                text=item["time"],
                font=self.body_font(13),
                text_color=self.colors["muted"]
            ).grid(row=2, column=1, padx=(0, 10), pady=(0, 14), sticky="w")

    def render_quarantine_items(self):
        for widget in self.quarantine_scroll.winfo_children():
            widget.destroy()

        if not self.quarantine_items:
            empty_card = ctk.CTkFrame(
                self.quarantine_scroll,
                fg_color=self.colors["card"],
                corner_radius=18,
                border_width=1,
                border_color=self.colors["border"]
            )
            empty_card.grid(row=0, column=0, padx=12, pady=12, sticky="ew")

            ctk.CTkLabel(
                empty_card,
                text="No files in quarantine",
                font=self.body_font(16, "bold"),
                text_color=self.colors["text"]
            ).pack(anchor="w", padx=18, pady=(16, 4))

            ctk.CTkLabel(
                empty_card,
                text="Malicious files will appear here and stay saved in the database.",
                font=self.body_font(13),
                text_color=self.colors["muted"]
            ).pack(anchor="w", padx=18, pady=(0, 16))
            return

        for index, item in enumerate(self.quarantine_items):
            card = ctk.CTkFrame(
                self.quarantine_scroll,
                fg_color=self.colors["card"],
                corner_radius=18,
                border_width=1,
                border_color=self.colors["border"]
            )
            card.grid(row=index, column=0, padx=12, pady=10, sticky="ew")
            card.grid_columnconfigure(1, weight=1)

            serial_box = ctk.CTkLabel(
                card,
                text=str(index + 1),
                font=self.body_font(14, "bold"),
                text_color=self.colors["white"],
                fg_color=self.colors["red"],
                corner_radius=14,
                width=42,
                height=42
            )
            serial_box.grid(row=0, column=0, rowspan=3, padx=(14, 12), pady=14, sticky="n")

            ctk.CTkLabel(
                card,
                text=item["filename"],
                font=self.body_font(16, "bold"),
                text_color=self.colors["text"],
                anchor="w",
                justify="left",
                wraplength=680
            ).grid(row=0, column=1, padx=(0, 10), pady=(14, 6), sticky="w")

            ctk.CTkLabel(
                card,
                text=f"{item['score']:.1f}/100",
                font=self.body_font(12, "bold"),
                text_color=self.colors["white"],
                fg_color=self.colors["red"],
                corner_radius=12,
                padx=14,
                pady=6
            ).grid(row=0, column=2, padx=(0, 14), pady=(14, 6), sticky="e")

            ctk.CTkLabel(
                card,
                text="Stored as detected threat",
                font=self.body_font(12, "bold"),
                text_color="#ff9ca3"
            ).grid(row=1, column=1, padx=(0, 10), pady=(0, 2), sticky="w")

            ctk.CTkLabel(
                card,
                text=item["time"],
                font=self.body_font(13),
                text_color=self.colors["muted"]
            ).grid(row=2, column=1, padx=(0, 10), pady=(0, 14), sticky="w")

    def add_history_item(self, filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time):
        self.history_items.insert(0, {
            "filename": filename,
            "verdict": verdict,
            "risk": risk,
            "heuristic": heuristic,
            "ml": ml,
            "final_score": final_score,
            "hash": file_hash,
            "time": scan_time
        })
        self.save_history_to_db(filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time)
        self.render_history_items()

    def add_to_quarantine(self, fname, score, added_time):
        self.quarantine_items.insert(0, {
            "filename": fname,
            "score": score,
            "time": added_time
        })
        self.save_quarantine_to_db(fname, score, added_time)
        self.render_quarantine_items()

    def compute_sha256(self, filepath):
        if not os.path.isfile(filepath):
            return "Unavailable"
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def set_hash_box_text(self, text_value):
        self.lbl_hash.configure(state="normal")
        self.lbl_hash.delete("1.0", "end")
        self.lbl_hash.insert("1.0", text_value)
        self.lbl_hash.configure(state="disabled")

    def update_result_banner(self, badge_text, badge_color, summary_text):
        self.result_badge.configure(text=badge_text, fg_color=badge_color)
        self.result_summary.configure(text=summary_text, text_color=self.colors["text"])

    def update_scan_stage(self, stage_text, button_text, badge_text, badge_color):
        self.scan_lbl.configure(text=stage_text)
        self.btn_select_file.configure(text=button_text)
        self.scan_step_badge.configure(text=badge_text, fg_color=badge_color)

    def reset_results_card(self, filename="Waiting..."):
        self.lbl_fname.configure(text=filename)
        self.lbl_status.configure(text="Scanning...", text_color=self.colors["yellow"])
        self.set_hash_box_text("Generating hash...")
        self.lbl_risk.configure(text="Analyzing...", text_color=self.colors["text"])
        self.lbl_heur.configure(text="Analyzing...")
        self.lbl_ml.configure(text="Analyzing...")
        self.lbl_yara.configure(text="Analyzing...")
        self.lbl_verdict.configure(text="Pending", text_color=self.colors["text"])
        self.lbl_action.configure(text="Waiting for scan completion...")
        self.selected_file_label.configure(text=f"Selected File: {filename}")
        self.update_result_banner(
            "SCANNING",
            self.colors["blue"],
            "The selected file is being analyzed by the scan engines."
        )

    def custom_scan(self):
        filename = filedialog.askopenfilename(title="Select File to Analyze")
        if filename:
            self.start_scan(filename)

    def start_scan(self, target):
        filename = os.path.basename(target)

        self.show_frame("scan")
        self.reset_results_card(filename)
        self.progressbar.set(0)
        self.progressbar.start()
        self.btn_view_report.configure(state="disabled")
        self.btn_select_file.configure(state="disabled")

        self.update_scan_stage(
            f"Analyzing file: {filename}",
            "Checking File Hash...",
            "HASH",
            self.colors["blue"]
        )

        self.update_dashboard_status(
            "Analyzing File...",
            self.colors["blue"],
            "🔍",
            f"Selected file: {filename}"
        )
        self.log_activity(f"File scan started: {filename}")

        threading.Thread(target=self.run_engines, args=(target,), daemon=True).start()

    def run_engines(self, target):
        filename = os.path.basename(target)

        self.after(0, lambda: self.update_scan_stage(
            f"Checking file hash for: {filename}",
            "Checking File Hash...",
            "HASH",
            self.colors["blue"]
        ))
        file_hash = self.compute_sha256(target)

        self.after(0, lambda: self.progressbar.set(0.28))
        time.sleep(0.4)

        self.after(0, lambda: self.update_scan_stage(
            f"Running heuristic analysis on: {filename}",
            "Checking Heuristic...",
            "HEURISTIC",
            self.colors["cyan"]
        ))
        h_res = self.heuristic_scanner.scan_file(target)

        self.after(0, lambda: self.progressbar.set(0.60))
        time.sleep(0.4)

        self.after(0, lambda: self.update_scan_stage(
            f"Evaluating machine learning model for: {filename}",
            "Checking ML Model...",
            "ML MODEL",
            self.colors["purple"]
        ))
        m_res = self.ml_scanner.scan_file(target)

        self.after(0, lambda: self.progressbar.set(0.74))
        time.sleep(0.4)

        self.after(0, lambda: self.update_scan_stage(
            f"Running YARA rules for: {filename}",
            "Running YARA...",
            "YARA",
            self.colors["blue"]
        ))
        y_res = self.yara_scanner.scan_file(target)

        self.after(0, lambda: self.progressbar.set(0.88))
        self.after(0, lambda: self.update_scan_stage(
            f"Preparing final result for: {filename}",
            "Preparing Result...",
            "FINALIZING",
            self.colors["yellow"]
        ))
        time.sleep(0.5)

        self.after(0, self.progressbar.set, 1.0)
        self.after(0, self.finish_scan, target, filename, file_hash, h_res, m_res, y_res)

    def finish_scan(self, target, filename, file_hash, h_res, m_res, y_res):
        self.progressbar.stop()
        self.progressbar.set(1)

        self.stats["scans"] += 1

        h_score = 0
        h_text = "Unavailable"
        if "error" in h_res:
            h_text = f"Error: {h_res['error']}"
        else:
            h_score = h_res.get("score", 0)
            h_text = f"{h_score}/100 (Clean)" if h_score < 30 else f"{h_score}/100"

        m_score = 0
        m_text = "Unavailable"
        if "error" in m_res:
            m_text = f"Warning: {m_res['error']}"
        else:
            m_score = m_res.get("score", 0)
            m_family = m_res.get("family", "Unknown Malware")
            if m_score < 30:
                m_text = f"Benign ({m_score:.2f}%)"
            else:
                m_text = f"{m_family} ({m_score:.2f}%)"

        y_score = 0
        y_text = "Clean"
        if "error" in y_res:
            y_text = f"Warning: {y_res['error']}"
        elif y_res.get("matches"):
            y_score = y_res.get("score", 0)
            y_text = f"{len(y_res['matches'])} Matches ({y_score} risk)"

        base_score = (h_score * 0.4) + (m_score * 0.6) if m_score > 0 else h_score
        final_score_value = max(base_score, y_score)
        final_score_text = f"{final_score_value:.2f}/100"
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        h_combined_text = f"H:{h_score} Y:{y_score}"

        if final_score_value >= 60:
            verdict = "MALICIOUS"
            risk = "HIGH"
            v_color = self.colors["red"]
            action = "Move this file to quarantine or delete it."
            summary = "Potential malware detected. Immediate action is recommended."
            self.stats["threats"] += 1
            self.add_to_quarantine(filename, final_score_value, scan_time)
        elif final_score_value >= 30:
            verdict = "SUSPICIOUS"
            risk = "MEDIUM"
            v_color = self.colors["yellow"]
            action = "Avoid opening this file until reviewed."
            summary = "The file shows suspicious indicators and should be reviewed carefully."
            self.stats["suspicious"] += 1
        else:
            verdict = "CLEAN"
            risk = "LOW"
            v_color = self.colors["green"]
            action = "No action required."
            summary = "No major threat indicators were detected in this file."
            self.stats["clean"] += 1

        self.update_dashboard_stats()

        self.lbl_fname.configure(text=filename)
        self.lbl_status.configure(text="Completed", text_color=self.colors["green"])
        self.set_hash_box_text(file_hash)
        self.lbl_risk.configure(text=risk, text_color=v_color)
        self.lbl_heur.configure(text=h_text)
        self.lbl_ml.configure(text=m_text)
        self.lbl_yara.configure(text=y_text)
        self.lbl_verdict.configure(text=verdict, text_color=v_color)
        self.lbl_action.configure(text=action)
        self.update_result_banner(verdict, v_color, summary)

        self.current_report_data = {
            "filename": filename,
            "hash": file_hash,
            "risk": risk,
            "heuristic": h_text,
            "ml": m_text,
            "yara": y_text,
            "verdict": verdict,
            "action": action,
            "final_score": final_score_text,
            "time": scan_time,
            "color": v_color,
            "summary": summary
        }

        self.add_history_item(filename, verdict, risk, h_combined_text, m_text, final_score_text, file_hash, scan_time)

        self.btn_view_report.configure(state="normal")
        self.btn_select_file.configure(state="normal", text="Select File")
        self.scan_step_badge.configure(text="COMPLETED", fg_color=self.colors["green"])
        self.scan_lbl.configure(text=f"Scan completed successfully for: {filename}")

        if verdict == "MALICIOUS":
            self.update_dashboard_status("Threat Detected", self.colors["red"], "⚠️", f"Malicious file detected: {filename}")
            self.log_activity(f"Malicious file detected: {filename}")
        elif verdict == "SUSPICIOUS":
            self.update_dashboard_status("Suspicious File", self.colors["yellow"], "⚠️", f"Suspicious file detected: {filename}")
            self.log_activity(f"Suspicious file detected: {filename}")
        else:
            self.update_dashboard_status("File Appears Safe", self.colors["green"], "✅", f"No significant threat indicators found in {filename}.")
            self.log_activity(f"File scan completed: no threat detected in {filename}")

        self.open_result_popup()

    def create_popup_single_info(self, parent, title, value, value_color=None, mono=False):
        card = ctk.CTkFrame(
            parent,
            fg_color=self.colors["card"],
            corner_radius=18,
            border_width=1,
            border_color=self.colors["border"]
        )
        card.pack(fill="x", padx=16, pady=8)

        ctk.CTkLabel(
            card,
            text=title,
            font=self.body_font(12, "bold"),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=18, pady=(14, 5))

        if mono:
            box = ctk.CTkTextbox(
                card,
                height=95,
                font=self.mono_font(12, "bold"),
                fg_color=self.colors["soft_dark"],
                text_color=self.colors["text"],
                corner_radius=12,
                border_width=1,
                border_color=self.colors["border"],
                wrap="word"
            )
            box.pack(fill="x", padx=18, pady=(0, 14))
            box.insert("1.0", value)
            box.configure(state="disabled")
        else:
            ctk.CTkLabel(
                card,
                text=value,
                font=self.body_font(15, "bold"),
                text_color=value_color if value_color else self.colors["text"],
                wraplength=760,
                justify="left"
            ).pack(anchor="w", padx=18, pady=(0, 14))

    def open_result_popup(self):
        if not self.current_report_data:
            return

        if self.result_popup is not None and self.result_popup.winfo_exists():
            self.result_popup.destroy()

        data = self.current_report_data
        self.result_popup = ctk.CTkToplevel(self)
        self.result_popup.title("Scan Result Report")
        self.result_popup.geometry("900x760")
        self.result_popup.minsize(840, 680)
        self.result_popup.configure(fg_color=self.colors["bg"])
        self.result_popup.grab_set()

        popup = self.result_popup
        popup.grid_columnconfigure(0, weight=1)
        popup.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(
            popup,
            fg_color=data["color"],
            corner_radius=24
        )
        header.grid(row=0, column=0, padx=22, pady=22, sticky="ew")

        ctk.CTkLabel(
            header,
            text="File Scan Report",
            font=self.heading_font(30),
            text_color="white"
        ).pack(pady=(22, 6))

        ctk.CTkLabel(
            header,
            text=data["verdict"],
            font=self.body_font(15, "bold"),
            text_color="white",
            fg_color=self.colors["dark_badge"],
            corner_radius=12,
            padx=18,
            pady=8
        ).pack(pady=(0, 10))

        ctk.CTkLabel(
            header,
            text=data["summary"],
            font=self.body_font(14, "bold"),
            text_color="#f8fbff",
            wraplength=760,
            justify="center"
        ).pack(pady=(0, 18))

        body = ctk.CTkScrollableFrame(
            popup,
            fg_color=self.colors["panel"],
            corner_radius=22,
            border_width=1,
            border_color=self.colors["border"]
        )
        body.grid(row=1, column=0, padx=22, pady=(0, 18), sticky="nsew")

        top_highlight = ctk.CTkFrame(
            body,
            fg_color=self.colors["card_2"],
            corner_radius=20,
            border_width=1,
            border_color=self.colors["border"]
        )
        top_highlight.pack(fill="x", padx=16, pady=(16, 10))

        ctk.CTkLabel(
            top_highlight,
            text="Result Overview",
            font=self.subheading_font(18),
            text_color=self.colors["text"]
        ).pack(anchor="w", padx=18, pady=(16, 4))

        ctk.CTkLabel(
            top_highlight,
            text=f"File: {data['filename']}",
            font=self.body_font(14, "bold"),
            text_color=self.colors["text"],
            wraplength=760,
            justify="left"
        ).pack(anchor="w", padx=18, pady=(0, 4))

        ctk.CTkLabel(
            top_highlight,
            text=f"Scan Time: {data['time']}",
            font=self.body_font(13),
            text_color=self.colors["muted"]
        ).pack(anchor="w", padx=18, pady=(0, 16))

        self.create_popup_single_info(body, "Final Verdict", data["verdict"], data["color"])
        self.create_popup_single_info(body, "Risk Level", data["risk"], data["color"])
        self.create_popup_single_info(body, "Combined Threat Score", data["final_score"], data["color"])
        self.create_popup_single_info(body, "Heuristic Score", data["heuristic"])
        self.create_popup_single_info(body, "Machine Learning Confidence", data["ml"])
        self.create_popup_single_info(body, "YARA Signature Match", data["yara"])
        self.create_popup_single_info(body, "SHA-256 Hash", data["hash"], mono=True)
        self.create_popup_single_info(body, "Recommended Action", data["action"])

        close_btn = ctk.CTkButton(
            popup,
            text="Close Report",
            command=popup.destroy,
            height=46,
            corner_radius=14,
            fg_color=self.colors["blue"],
            hover_color=self.colors["blue_hover"],
            font=self.body_font(15, "bold")
        )
        close_btn.grid(row=2, column=0, padx=22, pady=(0, 22), sticky="e")


if __name__ == "__main__":
    app = HybridAntivirusApp()
    app.mainloop()
