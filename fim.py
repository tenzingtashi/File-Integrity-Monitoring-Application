#!/usr/bin/env python3
import faulthandler
faulthandler.enable()
import queue
import webbrowser  # Added for auto-opening the browser

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QFileDialog, QLabel, 
    QStatusBar, QSplitter, QProgressBar, QMainWindow, QToolBar, QSizePolicy, QMessageBox
)
from PyQt6.QtCore import QTimer, pyqtSignal, Qt, QSize
from PyQt6.QtGui import QIcon, QFont, QPixmap, QColor, QLinearGradient, QPalette
from plyer import notification
import sys
import threading
import os
import time
import sqlite3
import hashlib
import plotly.express as px
from collections import defaultdict
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
import networkx as nx
import re  # For parsing chat queries

class FileIntegrityMonitor(QMainWindow):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.initUI()
        self.directory_to_watch = ""
        self.file_hashes = {}
        self.running = False
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.init_db()
        self.start_log_processor()
        self.log_signal.connect(self.update_log_text)

    def initUI(self):
        # Set window properties
        self.setWindowTitle("File Integrity Monitoring System")
        self.setGeometry(100, 100, 1000, 700)
        self.setWindowIcon(QIcon("logo.png"))

        # Set the default light theme
        self.set_light_mode()

        # Create a central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Add a toolbar
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # Add logo and title
        logo = QLabel()
        logo.setPixmap(QPixmap("logo.png").scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio))
        toolbar.addWidget(logo)
        title = QLabel("File Integrity Monitor")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        toolbar.addWidget(title)

        # Add spacer to push buttons to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        toolbar.addWidget(spacer)

        # Add buttons to the toolbar
        self.selectDirBtn = QPushButton("Select Directory")
        self.selectDirBtn.setIcon(QIcon.fromTheme("folder"))
        self.selectDirBtn.setObjectName("selectDirBtn")
        self.selectDirBtn.clicked.connect(self.select_directory)
        toolbar.addWidget(self.selectDirBtn)

        self.startNormalBtn = QPushButton("Start Normal Mode")
        self.startNormalBtn.setIcon(QIcon.fromTheme("media-playback-start"))
        self.startNormalBtn.setObjectName("startNormalBtn")
        self.startNormalBtn.clicked.connect(self.start_normal_mode)
        toolbar.addWidget(self.startNormalBtn)

        self.startAggressiveBtn = QPushButton("Start Aggressive Mode")
        self.startAggressiveBtn.setIcon(QIcon.fromTheme("media-playback-start"))
        self.startAggressiveBtn.setObjectName("startAggressiveBtn")
        self.startAggressiveBtn.clicked.connect(self.start_aggressive_mode)
        toolbar.addWidget(self.startAggressiveBtn)

        self.stopBtn = QPushButton("Stop Monitoring")
        self.stopBtn.setIcon(QIcon.fromTheme("media-playback-stop"))
        self.stopBtn.setObjectName("stopBtn")
        self.stopBtn.clicked.connect(self.stop_monitoring)
        toolbar.addWidget(self.stopBtn)

        self.visualizeBtn = QPushButton("Visualize Data")
        self.visualizeBtn.setIcon(QIcon.fromTheme("chart-bar"))
        self.visualizeBtn.setObjectName("visualizeBtn")
        self.visualizeBtn.clicked.connect(self.launch_dashboard)  # Connect to launch_dashboard
        toolbar.addWidget(self.visualizeBtn)

        self.clearLogsBtn = QPushButton("Clear Logs")
        self.clearLogsBtn.setIcon(QIcon.fromTheme("edit-clear"))
        self.clearLogsBtn.setObjectName("clearLogsBtn")
        self.clearLogsBtn.clicked.connect(self.clear_logs)
        toolbar.addWidget(self.clearLogsBtn)

        # Add a light bulb toggle button for dark/light mode
        self.themeToggleBtn = QPushButton()
        self.themeToggleBtn.setIcon(QIcon("lightbulb_on.png"))
        self.themeToggleBtn.setObjectName("themeToggleBtn")
        self.themeToggleBtn.setToolTip("Toggle Dark Mode")
        self.themeToggleBtn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
        """)
        self.themeToggleBtn.clicked.connect(self.toggle_theme)
        toolbar.addWidget(self.themeToggleBtn)

        # Add a label to display the selected directory
        self.label = QLabel("No directory selected.")
        self.label.setFont(QFont("Segoe UI", 10))
        main_layout.addWidget(self.label)

        # Splitter for Logs and Summary
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Log Section
        self.logText = QTextEdit()
        self.logText.setReadOnly(True)
        self.logText.setFont(QFont("Consolas", 10))
        splitter.addWidget(self.logText)

        # Summary Section
        summary_widget = QWidget()
        summary_layout = QVBoxLayout()
        self.summaryLabel = QLabel("Summary will appear here.")
        self.summaryLabel.setFont(QFont("Segoe UI", 10))
        summary_layout.addWidget(self.summaryLabel)
        summary_widget.setLayout(summary_layout)
        splitter.addWidget(summary_widget)

        # Add the splitter to the main layout
        main_layout.addWidget(splitter)

        # Status Bar
        self.statusBar = QStatusBar()
        self.statusBar.setFont(QFont("Segoe UI", 10))
        self.statusBar.showMessage("Status: Monitoring not started.")
        self.setStatusBar(self.statusBar)

        # Progress Bar
        self.progressBar = QProgressBar()
        self.progressBar.setMaximum(100)
        self.progressBar.setVisible(False)
        self.statusBar.addPermanentWidget(self.progressBar)

        # Set size policies for responsiveness
        self.logText.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.summaryLabel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_light_mode(self):
        """Set the application to light mode."""
        light_palette = QPalette()
        light_palette.setColor(QPalette.ColorRole.Window, QColor(245, 245, 245))  # Light gray
        light_palette.setColor(QPalette.ColorRole.WindowText, QColor(51, 51, 51))  # Dark gray
        light_palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))  # White
        light_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))  # Light gray
        light_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))  # White
        light_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(51, 51, 51))  # Dark gray
        light_palette.setColor(QPalette.ColorRole.Text, QColor(51, 51, 51))  # Dark gray
        light_palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))  # Light gray
        light_palette.setColor(QPalette.ColorRole.ButtonText, QColor(51, 51, 51))  # Dark gray
        light_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 255, 255))  # White
        light_palette.setColor(QPalette.ColorRole.Highlight, QColor(33, 150, 243))  # Blue
        light_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))  # White
        QApplication.setPalette(light_palette)

        # Apply styles
        self.setStyleSheet("""
            QWidget {
                background-color: #F5F5F5;
                color: #333333;
            }
            QPushButton {
                color: #FFFFFF;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
            QPushButton:pressed {
                opacity: 0.8;
            }
            QPushButton#selectDirBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF9800, stop:1 #F57C00);  /* Orange */
            }
            QPushButton#startNormalBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4CAF50, stop:1 #388E3C);  /* Green */
            }
            QPushButton#startAggressiveBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F44336, stop:1 #D32F2F);  /* Red */
            }
            QPushButton#stopBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9C27B0, stop:1 #7B1FA2);  /* Purple */
            }
            QPushButton#visualizeBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2196F3, stop:1 #1976D2);  /* Blue */
            }
            QPushButton#clearLogsBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #607D8B, stop:1 #455A64);  /* Gray */
            }
            QPushButton#themeToggleBtn {
                background-color: transparent;
                border: none;
            }
            QToolTip {
                background-color: #FFFFFF;
                color: #333333;
                border: 1px solid #CCCCCC;
            }
            QTextEdit {
                background-color: #FFFFFF;
                color: #000000;  /* Ensure text color is black in light mode */
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas;
                font-size: 10pt;
            }
            QLabel {
                color: #333333;
                font-family: Segoe UI;
                font-size: 10pt;
            }
            QStatusBar {
                background-color: #FFFFFF;
                color: #333333;
                border-top: 1px solid #CCCCCC;
                font-family: Segoe UI;
                font-size: 10pt;
            }
            QProgressBar {
                background-color: #FFFFFF;
                color: #333333;
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 4px;
            }
            QToolBar {
                background-color: #FFFFFF;
                border-bottom: 1px solid #CCCCCC;
            }
        """)

    def set_dark_mode(self):
        """Set the application to dark mode."""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))  # Dark gray
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))  # White
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))  # Darker gray
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))  # Dark gray
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(53, 53, 53))  # Dark gray
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))  # White
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))  # White
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))  # Dark gray
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))  # White
        dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))  # Red
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))  # Blue
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))  # White
        QApplication.setPalette(dark_palette)

        # Apply styles
        self.setStyleSheet("""
            QWidget {
                background-color: #353535;
                color: #FFFFFF;
            }
            QPushButton {
                color: #FFFFFF;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                opacity: 0.9;
            }
            QPushButton:pressed {
                opacity: 0.8;
            }
            QPushButton#selectDirBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF9800, stop:1 #F57C00);  /* Orange */
            }
            QPushButton#startNormalBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4CAF50, stop:1 #388E3C);  /* Green */
            }
            QPushButton#startAggressiveBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F44336, stop:1 #D32F2F);  /* Red */
            }
            QPushButton#stopBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9C27B0, stop:1 #7B1FA2);  /* Purple */
            }
            QPushButton#visualizeBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2196F3, stop:1 #1976D2);  /* Blue */
            }
            QPushButton#clearLogsBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #607D8B, stop:1 #455A64);  /* Gray */
            }
            QPushButton#themeToggleBtn {
                background-color: transparent;
                border: none;
            }
            QToolTip {
                background-color: #353535;
                color: #FFFFFF;
                border: 1px solid #444444;
            }
            QTextEdit {
                background-color: #2E2E2E;
                color: #FFFFFF;  /* Ensure text color is white in dark mode */
                border: 1px solid #444444;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas;
                font-size: 10pt;
            }
            QLabel {
                color: #FFFFFF;
                font-family: Segoe UI;
                font-size: 10pt;
            }
            QStatusBar {
                background-color: #2E2E2E;
                color: #FFFFFF;
                border-top: 1px solid #444444;
                font-family: Segoe UI;
                font-size: 10pt;
            }
            QProgressBar {
                background-color: #2E2E2E;
                color: #FFFFFF;
                border: 1px solid #444444;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 4px;
            }
            QToolBar {
                background-color: #2E2E2E;
                border-bottom: 1px solid #444444;
            }
        """)

    def toggle_theme(self):
        """Toggle between light and dark mode."""
        if self.themeToggleBtn.toolTip() == "Toggle Dark Mode":
            self.set_dark_mode()
            self.themeToggleBtn.setIcon(QIcon("lightbulb_off.png"))  # Dark mode icon
            self.themeToggleBtn.setToolTip("Toggle Light Mode")
        else:
            self.set_light_mode()
            self.themeToggleBtn.setIcon(QIcon("lightbulb_on.png"))  # Light mode icon
            self.themeToggleBtn.setToolTip("Toggle Dark Mode")

    def select_directory(self):
        """Open a dialog to select a directory to monitor."""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path:
            self.directory_to_watch = dir_path
            self.label.setText(f"Monitoring: {dir_path}")

    def log(self, message):
        """Log a message to the log text area and database."""
        self.log_signal.emit(message)
        self.log_queue.put(message)
        self.log_queue.put(("summary", None))
        notification.notify(
            title="File Integrity Alert", message=message, timeout=5)

    def init_db(self):
        """Initialize the SQLite database for logging."""
        self.conn = sqlite3.connect("file_monitor.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            'CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, message TEXT)'
        )
        self.conn.commit()
    
    def start_log_processor(self):
        """Start a timer to process the log queue."""
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.process_log_queue)
        self.log_timer.start(100)

    def process_log_queue(self):
        """Process messages in the log queue."""
        while not self.log_queue.empty():
            item = self.log_queue.get()
            if isinstance(item, tuple) and item[0] == "summary":
                self._update_summary()
            else:
                self.store_log_in_db(item)
    
    def store_log_in_db(self, message):
        """Store a log message in the database with a timestamp."""
        timestamp = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')  # Convert to string
        self.cursor.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (timestamp, message))
        self.conn.commit()

    def start_normal_mode(self):
        """Start monitoring in normal mode (60-second interval)."""
        if self.directory_to_watch:
            self.stop_event.clear()
            self.running = True
            threading.Thread(target=self.monitor_directory, args=(60,), daemon=True).start()
            self.log("Started Normal Mode")
            self.update_status("Normal Mode - Monitoring in progress.")
        else:
            self.log("Select a directory first!")

    def start_aggressive_mode(self):
        """Start monitoring in aggressive mode (10-second interval)."""
        if self.directory_to_watch:
            self.stop_event.clear()
            self.running = True
            threading.Thread(target=self.monitor_directory, args=(10,), daemon=True).start()
            self.log("Started Aggressive Mode")
            self.update_status("Aggressive Mode - Monitoring in progress.")
        else:
            self.log("Select a directory first!")

    def monitor_directory(self, interval):
        """Monitor the directory for changes."""
        self.file_hashes = self.calculate_file_hashes()
        try:
            while self.running and not self.stop_event.is_set():
                time.sleep(1)
                if self.stop_event.is_set():
                    break
                new_hashes = self.calculate_file_hashes()
                self.detect_changes(self.file_hashes, new_hashes)
                self.file_hashes = new_hashes
        except Exception as e:
            self.log(f"Error in monitor_directory: {e}")

    def calculate_file_hashes(self):
        """Calculate SHA-256 hashes for all files in the directory."""
        hashes = {}
        if not self.directory_to_watch:
            return hashes
        for root, dirs, files in os.walk(self.directory_to_watch):
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                hashes[dir_path] = {
                    "type": "directory",
                    "mtime": os.path.getmtime(dir_path),
                    "mode": os.stat(dir_path).st_mode
                }
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    hashes[file_path] = {
                        "type": "file",
                        "hash": file_hash,
                        "mode": os.stat(file_path).st_mode
                    }
                except Exception as e:
                    self.log(f"Error reading {file}: {e}")
        return hashes

    def detect_changes(self, old_hashes, new_hashes):
        """Detect changes between old and new file hashes."""
        added_items = set(new_hashes.keys()) - set(old_hashes.keys())
        deleted_items = set(old_hashes.keys()) - set(new_hashes.keys())
        modified_files = {}
        modified_dirs = {}

        for item in new_hashes:
            if item in old_hashes:
                if old_hashes[item].get("type") == "directory":
                    if (new_hashes[item]["mtime"] != old_hashes[item]["mtime"] or
                        new_hashes[item]["mode"] != old_hashes[item]["mode"]):
                        modified_dirs[item] = new_hashes[item]
                else:
                    if (new_hashes[item]["hash"] != old_hashes[item]["hash"] or
                        new_hashes[item]["mode"] != old_hashes[item]["mode"]):
                        modified_files[item] = new_hashes[item]

        renamed_files = {}
        for deleted_item in deleted_items:
            if old_hashes[deleted_item].get("type") == "directory":
                continue
            for added_item in added_items:
                if new_hashes[added_item].get("type") == "directory":
                    continue
                if old_hashes[deleted_item]["hash"] == new_hashes[added_item]["hash"]:
                    renamed_files[deleted_item] = added_item
                    break

        for old_path, new_path in renamed_files.items():
            added_items.discard(new_path)
            deleted_items.discard(old_path)

        permission_changes = {}
        for item in new_hashes:
            if item in old_hashes and new_hashes[item]["mode"] != old_hashes[item]["mode"]:
                permission_changes[item] = {
                    "old_mode": old_hashes[item]["mode"],
                    "new_mode": new_hashes[item]["mode"]
                }
                # Log permission changes for debugging
                self.log(f"Permission change detected for {item}: {oct(old_hashes[item]['mode'])} -> {oct(new_hashes[item]['mode'])})")

        for item in added_items:
            if new_hashes[item].get("type") == "directory":
                self.log(f"directory added: {item}")
            else:
                self.log(f"file added: {item}")

        for item in deleted_items:
            if old_hashes[item].get("type") == "directory":
                self.log(f"directory deleted: {item}")
            else:
                self.log(f"file deleted: {item}")

        for file, data in modified_files.items():
            self.log(f"file modified: {file}")

        for dir, data in modified_dirs.items():
            self.log(f"directory modified: {dir}")

        for old_path, new_path in renamed_files.items():
            self.log(f"file renamed: {old_path} -> {new_path}")

        for item, modes in permission_changes.items():
            self.log(f"permissions changed: {item} (old: {oct(modes['old_mode'])}, new: {oct(modes['new_mode'])})")

    def stop_monitoring(self):
        """Stop the monitoring process."""
        self.stop_event.set()
        self.running = False
        self.log("Monitoring stopped.")
        self.update_status("Monitoring stopped.")

    def visualize_data(self):
        """Visualize the log data using Plotly."""
        self.cursor.execute("SELECT message FROM logs")
        logs = [row[0] for row in self.cursor.fetchall()]

        event_count = defaultdict(int)
        for log in logs:
            log_lower = log.lower()
            if "file added" in log_lower or "directory added" in log_lower:
                event_count["Added"] += 1
            elif "file deleted" in log_lower or "directory deleted" in log_lower:
                event_count["Deleted"] += 1
            elif "file modified" in log_lower or "directory modified" in log_lower:
                event_count["Modified"] += 1
            elif "file renamed" in log_lower:
                event_count["Renamed"] += 1
            elif "permissions changed" in log_lower:
                event_count["Permissions Changed"] += 1

        if not event_count:
            self.log("No relevant events to visualize.")
            return

        labels = list(event_count.keys())
        values = list(event_count.values())

        fig = px.bar(
            x=labels,
            y=values,
            labels={'x': 'Event Type', 'y': 'Occurrences'},
            title="File Integrity Monitoring Events",
            text=values,
            color=labels,
            color_discrete_map={
                "Added": "green",
                "Deleted": "red",
                "Modified": "blue",
                "Renamed": "orange",
                "Permissions Changed": "purple"
            }
        )
        fig.update_traces(textposition='outside')
        fig.show()

    def update_log_text(self, message):
        """Update the log text area with a new message."""
        # Determine the default text color based on the current theme
        if self.themeToggleBtn.toolTip() == "Toggle Light Mode":
            # Light mode colors
            default_color = "#000000"  # Black for light mode
            added_color = "#4CAF50"    # Green
            deleted_color = "#F44336"  # Red
            modified_color = "#2196F3" # Blue
            renamed_color = "#FF9800"  # Orange
            permission_color = "#9C27B0" # Purple
        else:
            # Dark mode colors
            default_color = "#FFFFFF"  # White for dark mode
            added_color = "#81C784"    # Light green
            deleted_color = "#E57373"  # Light red
            modified_color = "#64B5F6" # Light blue
            renamed_color = "#FFB74D"  # Light orange
            permission_color = "#BA68C8" # Light purple

        # Apply colors based on message content
        if "added" in message.lower():
            self.logText.append(f'<span style="color: {added_color};">{message}</span>')
        elif "deleted" in message.lower():
            self.logText.append(f'<span style="color: {deleted_color};">{message}</span>')
        elif "modified" in message.lower():
            self.logText.append(f'<span style="color: {modified_color};">{message}</span>')
        elif "renamed" in message.lower():
            self.logText.append(f'<span style="color: {renamed_color};">{message}</span>')
        elif "permissions changed" in message.lower():
            self.logText.append(f'<span style="color: {permission_color};">{message}</span>')
        else:
            # Use the default color for other messages
            self.logText.append(f'<span style="color: {default_color};">{message}</span>')

    def clear_logs(self):
        """Clear the log text area."""
        self.logText.clear()

    def update_summary(self):
        """Update the summary section."""
        self.log_queue.put(("summary", None))

    def _update_summary(self):
        """Update the summary label with the latest data."""
        self.cursor.execute("SELECT message FROM logs")
        logs = [row[0] for row in self.cursor.fetchall()]

        event_count = defaultdict(int)
        for log in logs:
            log_lower = log.lower()
            if "file added" in log_lower or "directory added" in log_lower:
                event_count["Added"] += 1
            elif "file deleted" in log_lower or "directory deleted" in log_lower:
                event_count["Deleted"] += 1
            elif "file modified" in log_lower or "directory modified" in log_lower:
                event_count["Modified"] += 1
            elif "file renamed" in log_lower:
                event_count["Renamed"] += 1
            elif "permissions changed" in log_lower:
                event_count["Permissions Changed"] += 1

        summary_text = (
            f"<b>Summary:</b><br>"
            f"Files/Directories Added: {event_count['Added']}<br>"
            f"Files/Directories Deleted: {event_count['Deleted']}<br>"
            f"Files/Directories Modified: {event_count['Modified']}<br>"
            f"Files/Directories Renamed: {event_count['Renamed']}<br>"
            f"Permissions Changed: {event_count['Permissions Changed']}"
        )
        self.summaryLabel.setText(summary_text)

    def update_status(self, message):
        """Update the status bar with a message."""
        self.statusBar.showMessage(f"Status: {message}")

    def launch_dashboard(self):
        """Launch the Plotly Dash dashboard in a new window."""
        if not self.directory_to_watch:
            QMessageBox.warning(self, "No Directory", "Please select a directory first.")
            return

        # Fetch data from the database
        self.cursor.execute("SELECT timestamp, message FROM logs")
        logs = self.cursor.fetchall()

        # Process logs into a DataFrame
        data = self.process_logs_for_dashboard(logs)

        # Check if the Dash app is already running
        if hasattr(self, 'dash_thread') and self.dash_thread.is_alive():
            QMessageBox.information(self, "Dashboard Already Open", "The dashboard is already running.")
            return

        # Start the Dash app in a new thread
        self.dash_thread = threading.Thread(target=self.run_dash_app, args=(data,), daemon=True)
        self.dash_thread.start()

    def process_logs_for_dashboard(self, logs):
        """Process logs into a DataFrame for the dashboard."""
        events = []
        for timestamp, log in logs:
            log_lower = log.lower()
            if "file added" in log_lower or "directory added" in log_lower:
                event_type = "Added"
            elif "file deleted" in log_lower or "directory deleted" in log_lower:
                event_type = "Deleted"
            elif "file modified" in log_lower or "directory modified" in log_lower:
                event_type = "Modified"
            elif "file renamed" in log_lower:
                event_type = "Renamed"
            elif "permissions changed" in log_lower:
                event_type = "Permissions Changed"
            else:
                continue

            # Extract the file/directory name from the log message
            file_name = log.split(': ')[-1]

            # Append the event to the list
            events.append({
                'Event Type': event_type,
                'File': file_name,
                'Timestamp': pd.to_datetime(timestamp),  # Use the timestamp from the database
                'Activity Count': 1  # Each row represents one activity
            })

        # Create a DataFrame from the events list
        data = pd.DataFrame(events)

        # Add a count column for each event type
        event_counts = data['Event Type'].value_counts().reset_index()
        event_counts.columns = ['Event Type', 'Count']

        # Merge the counts back into the main DataFrame
        data = data.merge(event_counts, on='Event Type', how='left')

        return data

    def run_dash_app(self, data):
        """Run the Dash app in a separate thread."""
        app = dash.Dash(__name__)

        app.layout = html.Div([
            html.H1("File Integrity Monitoring Dashboard"),
            html.Div([
                dcc.Dropdown(
                    id='event-type-filter',
                    options=[{'label': event, 'value': event} for event in data['Event Type'].unique()],
                    value=data['Event Type'].unique(),
                    multi=True,
                    placeholder="Select event types..."
                ),
                dcc.Dropdown(
                    id='time-filter',
                    options=[
                        {'label': 'Last 1 Minute', 'value': '1m'},
                        {'label': 'Last 5 Minutes', 'value': '5m'},
                        {'label': 'Last Hour', 'value': '1h'},
                        {'label': 'Last Day', 'value': '1d'},
                        {'label': 'Last Week', 'value': '7d'},
                        {'label': 'All Time', 'value': 'all'}
                    ],
                    value='1m',  # Default to "Last 1 Minute"
                    placeholder="Select time range..."
                )
            ], style={'margin-bottom': '20px'}),
            dcc.Graph(id='timeline-view'),
            dcc.Graph(id='heatmap'),
            dcc.Graph(id='bar-chart'),
            html.Div([
                dcc.Input(id='chat-input', type='text', placeholder='Ask a question...', style={'width': '300px'}),
                html.Button('Submit', id='chat-submit', n_clicks=0)
            ], style={'margin-top': '20px'}),
            html.Div(id='chat-response', style={'margin-top': '10px', 'font-size': '16px'}),
            dcc.Interval(id='interval-component', interval=1000, n_intervals=0)
        ])

        @app.callback(
            [Output('timeline-view', 'figure'),
             Output('heatmap', 'figure'),
             Output('bar-chart', 'figure')],
            [Input('event-type-filter', 'value'),
             Input('time-filter', 'value'),
             Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(selected_events, selected_time, n):
            # Filter data based on the selected time range
            now = pd.Timestamp.now()
            if selected_time == '1m':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(minutes=1)]
            elif selected_time == '5m':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(minutes=5)]
            elif selected_time == '1h':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(hours=1)]
            elif selected_time == '1d':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(days=1)]
            elif selected_time == '7d':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(days=7)]
            else:
                filtered_data = data  # Show all data

            # Further filter by selected event types
            if selected_events:
                filtered_data = filtered_data[filtered_data['Event Type'].isin(selected_events)]

            # Generate the figures
            timeline_fig = px.scatter(
                filtered_data,
                x='Timestamp',
                y='Event Type',
                color='Event Type',
                title="Timeline of Events"
            )

            heatmap_fig = px.density_heatmap(
                filtered_data,
                x='Timestamp',
                y='File',
                z='Activity Count',
                title="File Activity Heatmap"
            )

            bar_fig = px.bar(
                filtered_data,
                x='Event Type',
                y='Activity Count',
                color='Event Type',
                title="Event Count by Type"
            )

            return timeline_fig, heatmap_fig, bar_fig

        @app.callback(
            Output('chat-response', 'children'),
            [Input('chat-submit', 'n_clicks')],
            [dash.dependencies.State('chat-input', 'value')]
        )
        def handle_chat_query(n_clicks, query):
            if not query:
                return "Please enter a question."

            # Convert query to lowercase for easier parsing
            query_lower = query.lower()

            # Parse the query to extract the event type and time range
            event_type = None
            time_range = None

            # Check for event types
            event_types = {
                'added': 'Added',
                'deleted': 'Deleted',
                'modified': 'Modified',
                'renamed': 'Renamed',
                'permissions changed': 'Permissions Changed',
                'removed': 'Deleted'  # Synonym for deleted
            }

            for keyword, event in event_types.items():
                if keyword in query_lower:
                    event_type = event
                    break

            # Check for time ranges
            time_ranges = {
                'last 1 minute': '1m',
                'last 5 minutes': '5m',
                'last hour': '1h',
                'last day': '1d',
                'last week': '7d',
                'all time': 'all'
            }

            for keyword, time_val in time_ranges.items():
                if keyword in query_lower:
                    time_range = time_val
                    break

            # Filter data based on the parsed event type and time range
            now = pd.Timestamp.now()
            if time_range == '1m':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(minutes=1)]
            elif time_range == '5m':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(minutes=5)]
            elif time_range == '1h':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(hours=1)]
            elif time_range == '1d':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(days=1)]
            elif time_range == '7d':
                filtered_data = data[data['Timestamp'] >= now - pd.Timedelta(days=7)]
            else:
                filtered_data = data  # Show all data

            if event_type:
                filtered_data = filtered_data[filtered_data['Event Type'] == event_type]

            # Generate the response
            count = len(filtered_data)
            if event_type and time_range:
                return f"{count} {event_type.lower()} events in the {time_range}."
            elif event_type:
                return f"{count} {event_type.lower()} events in total."
            elif time_range:
                return f"{count} events in the {time_range}."
            else:
                return f"{count} events in total."

        # Run the Dash app on an available port
        port = 8050
        while True:
            try:
                # Open the browser automatically
                webbrowser.open_new(f"http://127.0.0.1:{port}")
                app.run_server(port=port, debug=False)
                break
            except OSError:
                port += 1  # Try the next port if the current one is in use

def process_logs_for_dashboard(self, logs):
        """Process logs into a DataFrame for the dashboard."""
        events = []
        for log in logs:
            log_lower = log.lower()
            if "file added" in log_lower or "directory added" in log_lower:
                event_type = "Added"
            elif "file deleted" in log_lower or "directory deleted" in log_lower:
                event_type = "Deleted"
            elif "file modified" in log_lower or "directory modified" in log_lower:
                event_type = "Modified"
            elif "file renamed" in log_lower:
                event_type = "Renamed"
            elif "permissions changed" in log_lower:
                event_type = "Permissions Changed"
            else:
                continue
        
            # Extract the file/directory name from the log message
            file_name = log.split(': ')[-1]
        
            # Retrieve the timestamp from the database
            self.cursor.execute("SELECT timestamp FROM logs WHERE message = ?", (log,))
            timestamp_str = self.cursor.fetchone()[0]
            timestamp = pd.to_datetime(timestamp_str)  # Convert string back to pandas.Timestamp
        
            events.append({
                'Event Type': event_type,
                'File': file_name,
                'Timestamp': timestamp,  # Use the converted timestamp
                'Activity Count': 1  # Each row represents one activity
            })

        # Create a DataFrame from the events list
        data = pd.DataFrame(events)
    
        # Add a count column for each event type
        event_counts = data['Event Type'].value_counts().reset_index()
        event_counts.columns = ['Event Type', 'Count']
    
        # Merge the counts back into the main DataFrame
        data = data.merge(event_counts, on='Event Type', how='left')
    
        return data

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileIntegrityMonitor()
    window.show()
    sys.exit(app.exec())












   
