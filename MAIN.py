from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QLineEdit, QTextEdit,
    QFileDialog, QMessageBox, QVBoxLayout, QWidget, QComboBox, QInputDialog,
    QAction
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import os
import hashlib
import yara
import logging
from PyPDF2 import PdfReader
from PyPDF2 import PageObject
from PyPDF2 import *
import zipfile
import tarfile
import rarfile
import glob
from winreg import *
from datetime import datetime

# Define paths relative to the script's directory
# Add YARA rules with .yara extension
# I have used YARA rules from this repositories :- https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop
YARA_RULES = [
    # Add full paths for example :- 
    #"D:\\antivirus_pro_1\\reversinglabs-yara-rules-develop\\reversinglabs-yara-rules-develop\\yara\\backdoor\\Win32.Backdoor.Konni.yara",
]

SIGNATURE_FILES = [
     # Add full paths for example :- 
    #"D:\\antivirus_pro_1\\reversinglabs-yara-rules-develop\\reversinglabs-yara-rules-develop\\yara\\MD5 Hahses.txt",
]

class AntivirusGUI(QMainWindow):
    """Main GUI window for the antivirus application."""

    def __init__(self):
        """Initialize the main window and UI components."""
        super().__init__()
        self.antivirus = Antivirus()
        self.setWindowTitle("AntiVirus_Pro")
        self.setGeometry(100, 100, 800, 600)
        self.create_widgets()
        self.browse_button.clicked.connect(self.browse_directory)
        self.scan_button.clicked.connect(self.start_scan)

        # Add export action
        export_action = QAction("Export Report", self)
        export_action.triggered.connect(self.export_report)
        self.addAction(export_action)

    def create_widgets(self):
        """Create and layout UI components."""
        # Define UI components
        self.setStyleSheet("QPushButton {border-radius: 15px; background-color: #4682B4; color: white} QPushButton:hover {background-color: #6495ED}")
        self.directory_label = QLabel("Select directory:", self)
        self.directory_label.setGeometry(50, 50, 300, 30)
        self.directory_entry = QLineEdit(self)
        self.directory_entry.setGeometry(200, 50, 400, 30)
        self.browse_button = QPushButton("Browse", self)
        self.browse_button.setGeometry(620, 50, 100, 30)
        self.scan_button = QPushButton("Scan", self)
        self.scan_button.setGeometry(50, 100, 100, 30)
        self.scan_output = QTextEdit(self)
        self.scan_output.setGeometry(50, 150, 670, 400)
        self.scan_status_label = QLabel("", self)  # Label for scan status
        self.scan_status_label.setGeometry(50, 560, 670, 30)  # Position the label

        # Dropdown list for scan types
        self.scan_types_combo = QComboBox(self)
        self.scan_types_combo.setGeometry(50, 530, 250, 30)
        self.scan_types_combo.addItem("Scan")
        self.scan_types_combo.addItem("Deep system files Scan")
        self.scan_types_combo.addItem("Scan PDF Documents")
        self.scan_types_combo.addItem("Scan Registry")
        self.scan_types_combo.addItem("Scan Archives")

        # Connect dropdown signal to handle_scan_type function
        self.scan_types_combo.currentIndexChanged.connect(self.handle_scan_type)

    def browse_directory(self):
        """Open a dialog to select input based on scan type."""
        scan_type = self.scan_types_combo.currentText()

        if scan_type == "Scan PDF Documents":
            # Select PDF files
            dialog_title = "Select PDF Files"
            options = QFileDialog.Options()
            options |= QFileDialog.ExistingFiles
            file_filter = "PDF Files (*.pdf)"
        elif scan_type == "Scan Archives":
            # Select archives
            dialog_title = "Select Archives"
            options = QFileDialog.Options()
            options |= QFileDialog.ExistingFiles
            file_filter = "Archives (*.zip *.rar *.tar *.gz)"
        else:
            # Select folder
            dialog_title = "Select Directory"
            options = QFileDialog.Options()
            options |= QFileDialog.ShowDirsOnly
            file_filter = None

        selected, _ = QFileDialog.getOpenFileNames(self, dialog_title, "", file_filter, options=options)

        if selected:
            input_paths = selected
            self.directory_entry.setText(", ".join(input_paths))

    def start_scan(self):
        """Start scanning based on the selected scan type."""
        scan_type = self.scan_types_combo.currentText()
        directory = self.directory_entry.text().strip()

        # Check if the scan type requires a directory and if it is valid
        if scan_type not in ["Scan Registry", "Deep system files Scan", "Scan Archives"] \
                and (not directory or not os.path.exists(directory)):
            QMessageBox.warning(self, "Error", "Please select a valid directory to scan.")
            return

        self.scan_output.clear()
        self.scan_status_label.setText("Scan in progress...")  # Update scan status label

        if scan_type not in ["Scan Registry", "Deep system files Scan", "Scan Archives"]:
            self.scan_output.append(f"Scanning directory: {directory} - Scan Type: {scan_type}")
        else:
            self.scan_output.append(f"Scan Type: {scan_type} does not require a directory.")

        try:
            if scan_type == "Scan Archives":
                self.scan_archives()  # Call the method to handle "Scan Archives"
            else:
                self.scanner_thread = ScannerThread(directory if directory and os.path.exists(directory) else None,
                                                scan_type, self.antivirus)
                self.scanner_thread.scan_complete_signal.connect(self.display_scan_results)
                self.scanner_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error starting scan: {e}")

    def scan_archives(self):
        """Handle the Scan Archives functionality."""
        directory = self.directory_entry.text().strip()
        if not directory or not os.path.exists(directory):
            QMessageBox.warning(self, "Error", "Please select a valid directory to scan.")
            return

        try:
            self.scanner_thread = ScannerThread(directory, "Scan Archives", self.antivirus)
            self.scanner_thread.scan_complete_signal.connect(self.display_scan_results)
            self.scanner_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error starting scan: {e}")

    def handle_scan_type(self):
        """Handle changes in the selected scan type."""
        scan_type = self.scan_types_combo.currentText()
        if scan_type == "Scan":
            self.scan_button.setText("Scan")
        else:
            self.scan_button.setText("Start")
        
        if scan_type in ["Scan Registry", "Deep system files Scan"]:
            self.directory_entry.setEnabled(False)
            self.browse_button.setEnabled(False)
        else:
            self.directory_entry.setEnabled(True)
            self.browse_button.setEnabled(True)

    def display_scan_results(self, results):
        """Display the scan results in the text area."""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_output.append(f"Scan started at: {current_time}")  # Add scan start time

        if results:
            self.scan_output.append("Infected files found:")
            for result in results:
                self.scan_output.append(f"{result} - Scanned at: {current_time}")
        else:
            self.scan_output.append("No infected files found.")
        self.scan_status_label.setText("Scan completed.")  # Update scan status label


    def export_report(self):
        """Export the full detailed report with time."""
        report_text = self.scan_output.toPlainText()
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Report", f"Antivirus_Report_{current_time}.txt", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "w") as file:
                file.write(report_text)


class ScannerThread(QThread):
    """Thread for scanning directories without freezing the GUI."""
    scan_complete_signal = pyqtSignal(list)

    def __init__(self, directory, scan_type, antivirus):
        """Initialize the scanner thread."""
        super().__init__()
        self.directory = directory
        self.scan_type = scan_type
        self.antivirus = antivirus
        self.infected_files = []

    def run(self):
        """Run the scan process."""
        self.antivirus.load_signatures()

        try:
            if self.scan_type == "Scan":
                if os.access(self.directory, os.R_OK):
                    self.infected_files = self.antivirus.scan_directory(self.directory)
                else:
                    print(f"Cannot read directory: {self.directory}")
            elif self.scan_type == "Deep system files Scan":
                self.infected_files = self.antivirus.scan_filesystem_deep()
            elif self.scan_type == "Scan PDF Documents":
                if os.access(self.directory, os.R_OK):
                    self.infected_files = self.antivirus.scan_pdf_documents(self.directory)
                else:
                    print(f"Cannot read PDF directory: {self.directory}")
            elif self.scan_type == "Scan Registry":
                self.infected_files = self.antivirus.scan_registry()

            if self.infected_files is None:  # Ensure infected_files is never None
                self.infected_files = []

            self.scan_complete_signal.emit(self.infected_files)

        except PermissionError as e:
            print(f"Permission denied: {e}")
            self.scan_complete_signal.emit([])

        except Exception as e:
            print(f"Error scanning: {e}")
            self.scan_complete_signal.emit([])


class Antivirus:
    """Core antivirus functionality."""

    def __init__(self):
        """Initialize the antivirus."""
        self.signatures = set()
        self.yara_rules = []

    def load_signatures(self):
        """Load malware signatures and YARA rules."""
        self.load_hashes()
        self.load_yara_rules()

    def load_hashes(self):
        """Load hash signatures from specified files."""
        for file_path in SIGNATURE_FILES:
            try:
                with open(file_path, 'r') as file:
                    for line in file:
                        self.signatures.add(line.strip())
            except FileNotFoundError:
                logging.error(f"Signature file not found: {file_path}")
            except Exception as e:
                logging.error(f"Error loading {file_path}: {e}")

    def load_yara_rules(self):
        """Compile and load YARA rules from specified files."""
        for rule_path in YARA_RULES:
            print(f"Loading YARA rule from: {rule_path}")
            try:
                rules = yara.compile(filepath=rule_path)
                self.yara_rules.append(rules)
            except SyntaxError as e:
                logging.error(f"Error in YARA syntax: {e}")
            except Exception as e:
                logging.error(f"Error loading YARA rule {rule_path}: {e}")

    def scan_directory(self, directory):
        """Scan a directory recursively for malware."""
        infected_files = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # File path sanitization
                if not self.is_safe_path(directory, file_path):
                    logging.warning(f"Skipping unsafe path: {file_path}")
                    continue
                try:
                    if self.scan_file(file_path):
                        infected_files.append(file_path)
                except FileNotFoundError:
                    logging.error(f"File not found: {file_path}")
                except PermissionError:
                    logging.error(f"Permission denied: {file_path}")
                except Exception as e:
                    logging.error(f"Error scanning file {file_path}: {e}")

        return infected_files

    def scan_file(self, file_path):
        """Scan a single file for malware signatures."""
        # Hash the file content
        file_hash = self.hash_file(file_path)
        if file_hash in self.signatures:
            return True

        # Check against YARA rules
        for rules in self.yara_rules:
            matches = rules.match(file_path)
            if matches:
                return True
        return False

    def hash_file(self, file_path):
        """Compute the MD5 hash of a file."""
        md5_hash = hashlib.md5()
        try:
            with open(file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
        except Exception as e:
            logging.error(f"Error hashing file {file_path}: {e}")
        return ""

    def is_safe_path(self, base_directory, path, follow_symlinks=False):
        """
        Ensure the path is within the base_directory to prevent directory traversal attacks.
        """
        # Resolve symbolic links
        if follow_symlinks:
            return os.path.realpath(path).startswith(os.path.realpath(base_directory))
        else:
            return os.path.abspath(path).startswith(os.path.abspath(base_directory))

    

    def scan_pdf_documents(self, file_path):
        """Scan PDF documents for potential threats."""
        try:
            infected_files = []
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(file_path, 'rb') as file:
                reader = PdfReader(file)
                for page_number, page in enumerate(reader.pages, start=1):
                    page_text = page.extract_text()
                    if self.is_malicious_content(page_text):
                        infected_files.append(f"Page {page_number} in {file_path} - Scanned at: {current_time}")

            return infected_files

        except Exception as e:
            logging.error(f"Error scanning PDF document {file_path}: {e}")
            return []


    
    def is_malicious_content(self, content):
        """Check if the content contains malicious patterns."""
        # Update the list of suspicious patterns
        suspicious_patterns = [
            "malware", "virus", "trojan", "exploit",
            "ransomware", "spyware", "adware", "rootkit",
            "keylogger", "worm", "backdoor", "botnet",
            "phishing", "drive-by download", "command and control",
            "payload", "zero-day", "remote access trojan", "malicious script"
        ]

        # Convert the content to lowercase for case-insensitive matching
        content_lower = content.lower()

        # Check if any suspicious patterns are present in the content
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                return True

        return False
    
    def scan_registry(self):
        """Scan registry keys using YARA rules."""
        reg_paths = [
            r'SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\Windows\\CurrentVersion\\RunOnce'
        ]

        infected_files = []  # Initialize the list to store infected files

        for reg_path in reg_paths:
            try:
                reg_key = OpenKey(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ | KEY_WOW64_64KEY)  # Specify KEY_READ access
                i = 0
                while True:  # Loop through the registry values
                    try:
                        value_name, value_data, value_type = QueryValueEx(reg_key, str(i))  # Query each value with string index
                        # Check if value_data contains malicious content (you can adjust this condition)
                        if self.scan_file(value_data):
                            infected_files.append(f"Malware detected in registry {reg_path}\\{value_name}")
                    except OSError:
                        break  # Stop the loop if no more values exist
                    i += 1
            except OSError:
                pass

        return infected_files  # Return the list of infected files

    def scan_filesystem_deep(self):
        """Scan the file system more deeply."""
        suspicious_paths = [
            'C:\\System Volume Information\\*',
            'C:\\Windows\\Temp\\*',
            'C:\\Windows\\Prefetch\\*'
        ]
        
        for path in suspicious_paths:
            # Expanding wildcard paths using glob. os.walk doesn't handle wildcards.
            for expanded_path in glob.glob(path, recursive=True):
                for root, dirs, files in os.walk(expanded_path):
                    for name in files + dirs:
                        file_path = os.path.join(root, name)
                        try:
                            # Check archives
                            if os.path.isfile(file_path) and self.is_archive(file_path):
                                self.scan_archive(file_path)
                            
                            # Scan with YARA    
                            matches = self.scan_file(file_path)
                            if matches:
                                print(f"Detected malware: {file_path}")
                        except Exception as e:
                            print(f"Error scanning {file_path}: {e}")

    
    # Scan archive contents
    def is_archive(self, file_path):
        archive_extensions = ['.zip', '.rar', '.tar', '.gz']
        return any(file_path.endswith(ext) for ext in archive_extensions)
    

    def scan_archive(self, archive_path):
        """Scan contents of an archive file."""
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        with archive.open(info.filename) as file:
                            file_content = file.read()
                            if self.scan_content(file_content):
                                print(f"Malware detected in file {info.filename} in archive {archive_path}")
        elif archive_path.endswith('.rar'):
            with rarfile.RarFile(archive_path) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        with archive.open(info) as file:
                            file_content = file.read()
                            if self.scan_content(file_content):
                                print(f"Malware detected in file {info.filename} in archive {archive_path}")
        elif archive_path.endswith('.tar') or archive_path.endswith('.gz'):
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    if not member.isdir():
                        file_content = archive.extractfile(member).read()
                        if self.scan_content(file_content):
                            print(f"Malware detected in file {member.name} in archive {archive_path}")
                            
    def export_report(self):
        """Export the full detailed report with time."""
        report_text = self.scan_output.toPlainText()
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Report", f"Antivirus_Report_{current_time}.txt", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "w") as file:
                file.write(report_text)

    

class CustomError(Exception):
    """Custom exception class for handling errors."""
    pass

if __name__ == "__main__":
    app = QApplication([])
    main_window = AntivirusGUI()
    main_window.show()
    try:
        app.exec_()
    except Exception as e:
        logging.error(f"Application error: {e}")
        QMessageBox.critical(None, "Error", f"Application error: {e}")

