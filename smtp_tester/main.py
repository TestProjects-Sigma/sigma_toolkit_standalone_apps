#!/usr/bin/env python3
"""
SMTP Tester - Standalone Application
A comprehensive SMTP testing tool extracted from SigmaToolkit

Features:
- SMTP server connection testing
- Authentication testing (optional for relay testing)
- Test email sending with/without authentication
- MX record checking
- SMTP port scanning
- Comprehensive SMTP analysis
- Pre-configured settings for popular email providers
"""

import sys
import os
import smtplib
import socket
import ssl
import threading
import time
import subprocess
import platform
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QGroupBox, QLineEdit, QPushButton, QLabel, QGridLayout,
    QCheckBox, QSpinBox, QComboBox, QTextEdit, QFormLayout, 
    QFrame, QSplitter, QMenuBar, QAction, QMessageBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QTimer
from PyQt5.QtGui import QFont


class Logger(QObject):
    """Simple logger for SMTP testing output"""
    message_logged = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.debug_mode = False
        
    def set_debug_mode(self, enabled):
        self.debug_mode = enabled
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        self.message_logged.emit(formatted_message)
        
    def debug(self, message):
        if self.debug_mode:
            self.log(message, "DEBUG")
            
    def info(self, message):
        self.log(message, "INFO")
        
    def warning(self, message):
        self.log(message, "WARNING")
        
    def error(self, message):
        self.log(message, "ERROR")
        
    def success(self, message):
        self.log(message, "SUCCESS")


class SMTPTools(QObject):
    """SMTP testing tools with comprehensive functionality"""
    result_ready = pyqtSignal(str, str)  # result, level
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        
    def test_connection(self, server, port, use_tls=False, use_ssl=False, timeout=10):
        """Test SMTP server connection"""
        def _test_connection():
            try:
                self.logger.debug(f"Testing connection to {server}:{port}")
                self.result_ready.emit(f"Testing connection to {server}:{port}...", "INFO")
                
                if use_ssl:
                    # Direct SSL connection (port 465 typically)
                    self.result_ready.emit("Using SSL/TLS encryption", "INFO")
                    server_obj = smtplib.SMTP_SSL(server, port, timeout=timeout)
                else:
                    # Standard connection
                    server_obj = smtplib.SMTP(server, port, timeout=timeout)
                    
                    if use_tls:
                        # STARTTLS (port 587 typically)
                        self.result_ready.emit("Starting TLS encryption...", "INFO")
                        server_obj.starttls()
                        self.result_ready.emit("TLS encryption enabled", "SUCCESS")
                
                # Get server greeting
                response = server_obj.noop()
                self.result_ready.emit(f"Server response: {response}", "INFO")
                
                # Get server capabilities
                try:
                    capabilities = server_obj.esmtp_features
                    if capabilities:
                        self.result_ready.emit("Server capabilities:", "INFO")
                        for feature, params in capabilities.items():
                            if params:
                                self.result_ready.emit(f"  {feature}: {' '.join(params)}", "INFO")
                            else:
                                self.result_ready.emit(f"  {feature}", "INFO")
                except:
                    pass
                
                server_obj.quit()
                self.result_ready.emit(f"✅ Connection to {server}:{port} successful!", "SUCCESS")
                
            except smtplib.SMTPConnectError as e:
                self.result_ready.emit(f"Connection failed: {str(e)}", "ERROR")
            except smtplib.SMTPServerDisconnected as e:
                self.result_ready.emit(f"Server disconnected: {str(e)}", "ERROR")
            except socket.timeout:
                self.result_ready.emit(f"Connection timed out after {timeout}s", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"Connection error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_test_connection)
        thread.daemon = True
        thread.start()
        
    def test_authentication(self, server, port, username, password, use_tls=False, use_ssl=False, timeout=10):
        """Test SMTP authentication"""
        def _test_auth():
            try:
                self.logger.debug(f"Testing authentication for {username} on {server}:{port}")
                self.result_ready.emit(f"Testing authentication for {username}...", "INFO")
                
                if use_ssl:
                    server_obj = smtplib.SMTP_SSL(server, port, timeout=timeout)
                else:
                    server_obj = smtplib.SMTP(server, port, timeout=timeout)
                    if use_tls:
                        server_obj.starttls()
                
                # Test login
                server_obj.login(username, password)
                self.result_ready.emit(f"✅ Authentication successful for {username}", "SUCCESS")
                
                # Get auth methods supported
                try:
                    if hasattr(server_obj, 'esmtp_features') and 'auth' in server_obj.esmtp_features:
                        auth_methods = server_obj.esmtp_features['auth']
                        self.result_ready.emit(f"Supported auth methods: {' '.join(auth_methods)}", "INFO")
                except:
                    pass
                
                server_obj.quit()
                
            except smtplib.SMTPAuthenticationError as e:
                self.result_ready.emit(f"❌ Authentication failed: {str(e)}", "ERROR")
            except smtplib.SMTPConnectError as e:
                self.result_ready.emit(f"Connection failed: {str(e)}", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"Authentication error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_test_auth)
        thread.daemon = True
        thread.start()
        
    def send_test_email(self, server, port, username, password, from_email, to_email, 
                       subject="SMTP Tester Test Email", use_tls=False, use_ssl=False, timeout=10):
        """Send a test email with optional authentication"""
        def _send_test():
            try:
                self.logger.debug(f"Sending test email from {from_email} to {to_email}")
                self.result_ready.emit(f"Sending test email to {to_email}...", "INFO")
                
                # Create message
                msg = MIMEMultipart()
                msg['From'] = from_email
                msg['To'] = to_email
                msg['Subject'] = subject
                
                # Email body
                auth_status = "with authentication" if username and password else "without authentication (relay)"
                body = f"""This is a test email sent from SMTP Tester.

Server: {server}:{port}
Authentication: {auth_status}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Encryption: {'SSL' if use_ssl else 'TLS' if use_tls else 'None'}

If you received this email, your SMTP configuration is working correctly!

---
SMTP Tester - Standalone SMTP Testing Tool
"""
                msg.attach(MIMEText(body, 'plain'))
                
                # Connect and send
                if use_ssl:
                    server_obj = smtplib.SMTP_SSL(server, port, timeout=timeout)
                else:
                    server_obj = smtplib.SMTP(server, port, timeout=timeout)
                    if use_tls:
                        server_obj.starttls()
                
                # Optional authentication
                if username and password:
                    server_obj.login(username, password)
                    self.result_ready.emit("Authenticated successfully", "SUCCESS")
                else:
                    self.result_ready.emit("Proceeding without authentication (relay test)", "INFO")
                
                # Send email
                text = msg.as_string()
                server_obj.sendmail(from_email, to_email, text)
                server_obj.quit()
                
                success_msg = f"✅ Test email sent successfully to {to_email}!"
                if not username and not password:
                    success_msg += " (via relay)"
                self.result_ready.emit(success_msg, "SUCCESS")
                self.result_ready.emit("Check the recipient's inbox and spam folder", "INFO")
                
            except smtplib.SMTPAuthenticationError as e:
                self.result_ready.emit(f"Authentication failed: {str(e)}", "ERROR")
                self.result_ready.emit("💡 Try without authentication for relay testing", "INFO")
            except smtplib.SMTPRecipientsRefused as e:
                self.result_ready.emit(f"Recipient refused: {str(e)}", "ERROR")
            except smtplib.SMTPSenderRefused as e:
                self.result_ready.emit(f"Sender refused: {str(e)}", "ERROR")
                if not username and not password:
                    self.result_ready.emit("💡 Server may require authentication", "INFO")
            except smtplib.SMTPDataError as e:
                self.result_ready.emit(f"SMTP data error: {str(e)}", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"Email sending error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_send_test)
        thread.daemon = True
        thread.start()
        
    def check_mx_records(self, domain):
        """Check MX records for a domain"""
        def _check_mx():
            try:
                self.logger.debug(f"Checking MX records for {domain}")
                self.result_ready.emit(f"Checking MX records for {domain}...", "INFO")
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=MX", domain]
                else:
                    cmd = ["dig", "MX", domain, "+short"]
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("MX Records found:", "SUCCESS")
                    
                    # Parse and sort MX records by priority
                    mx_records = []
                    lines = process.stdout.strip().split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if line and ('mail exchanger' in line.lower() or 
                                   (not platform.system().lower() == "windows" and line)):
                            mx_records.append(line)
                    
                    for record in mx_records:
                        self.result_ready.emit(f"  {record}", "INFO")
                        
                    if mx_records:
                        self.result_ready.emit("✅ Domain has mail servers configured", "SUCCESS")
                else:
                    self.result_ready.emit(f"❌ No MX records found for {domain}", "WARNING")
                    self.result_ready.emit("This domain cannot receive email", "WARNING")
                    
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"MX lookup timed out for {domain}", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"MX lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_check_mx)
        thread.daemon = True
        thread.start()
        
    def test_port_connectivity(self, server, ports=[25, 465, 587, 2525]):
        """Test connectivity to common SMTP ports"""
        def _test_ports():
            try:
                self.logger.debug(f"Testing SMTP port connectivity to {server}")
                self.result_ready.emit(f"Testing SMTP ports on {server}...", "INFO")
                
                open_ports = []
                closed_ports = []
                
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
                    try:
                        result = sock.connect_ex((server, port))
                        if result == 0:
                            open_ports.append(port)
                            # Get port description
                            port_desc = {
                                25: "SMTP (Plain)",
                                465: "SMTPS (SSL)",
                                587: "SMTP (TLS/STARTTLS)",
                                2525: "SMTP (Alternative)"
                            }
                            desc = port_desc.get(port, "SMTP")
                            self.result_ready.emit(f"✅ Port {port}: OPEN ({desc})", "SUCCESS")
                        else:
                            closed_ports.append(port)
                            self.logger.debug(f"Port {port}: CLOSED")
                    except Exception as e:
                        closed_ports.append(port)
                        self.logger.debug(f"Port {port}: Error - {str(e)}")
                    finally:
                        sock.close()
                
                # Summary
                self.result_ready.emit(f"\nPort scan summary for {server}:", "INFO")
                if open_ports:
                    self.result_ready.emit(f"Open SMTP ports: {open_ports}", "SUCCESS")
                else:
                    self.result_ready.emit("No SMTP ports found open", "WARNING")
                
                if closed_ports:
                    self.result_ready.emit(f"Closed ports: {closed_ports}", "INFO")
                
            except Exception as e:
                self.result_ready.emit(f"Port connectivity test error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_test_ports)
        thread.daemon = True
        thread.start()
        
    def comprehensive_smtp_test(self, server, port, username="", password="", 
                               from_email="", to_email="", use_tls=False, use_ssl=False):
        """Run a comprehensive SMTP test with optional authentication"""
        def _comprehensive_test():
            self.result_ready.emit("=== Comprehensive SMTP Test Started ===", "INFO")
            self.result_ready.emit(f"Target: {server}:{port}", "INFO")
            
            auth_status = "with authentication" if username and password else "without authentication (relay mode)"
            self.result_ready.emit(f"Mode: {auth_status}", "INFO")
            
            # Test 1: Port connectivity
            self.result_ready.emit("\n1. Testing port connectivity...", "INFO")
            time.sleep(0.5)
            self.test_port_connectivity(server, [port])
            
            time.sleep(2)
            
            # Test 2: Basic connection
            self.result_ready.emit("\n2. Testing SMTP connection...", "INFO")
            time.sleep(0.5)
            self.test_connection(server, port, use_tls, use_ssl)
            
            time.sleep(3)
            
            # Test 3: Authentication (if credentials provided)
            if username and password:
                self.result_ready.emit("\n3. Testing authentication...", "INFO")
                time.sleep(0.5)
                self.test_authentication(server, port, username, password, use_tls, use_ssl)
                time.sleep(3)
            else:
                self.result_ready.emit("\n3. Skipping authentication test (relay mode)", "INFO")
            
            # Test 4: Send test email (if email details provided)
            if from_email and to_email:
                relay_note = " (relay mode)" if not username and not password else ""
                self.result_ready.emit(f"\n4. Sending test email{relay_note}...", "INFO")
                time.sleep(0.5)
                self.send_test_email(server, port, username, password, from_email, to_email,
                                   "SMTP Tester Comprehensive Test", use_tls, use_ssl)
            else:
                self.result_ready.emit("\n4. Skipping email test (incomplete email details)", "WARNING")
            
            time.sleep(2)
            self.result_ready.emit("\n=== Comprehensive SMTP Test Completed ===", "INFO")
                
        thread = threading.Thread(target=_comprehensive_test)
        thread.daemon = True
        thread.start()


class SMTPTesterMainWindow(QMainWindow):
    """Main window for standalone SMTP Tester application"""
    
    def __init__(self):
        super().__init__()
        self.logger = Logger()
        self.smtp_tools = SMTPTools(self.logger)
        self.init_ui()
        self.setup_connections()
        
    def init_ui(self):
        self.setWindowTitle("SMTP Tester v1.0 - Standalone SMTP Testing Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout with splitter
        main_layout = QVBoxLayout(central_widget)
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - SMTP configuration and testing
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Server Configuration Section
        server_group = QGroupBox("SMTP Server Configuration")
        server_layout = QGridLayout(server_group)
        
        # Server and port
        server_layout.addWidget(QLabel("Server:"), 0, 0)
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("smtp.gmail.com, mail.company.com, etc.")
        server_layout.addWidget(self.server_edit, 0, 1, 1, 2)
        
        server_layout.addWidget(QLabel("Port:"), 0, 3)
        self.port_combo = QComboBox()
        self.port_combo.setEditable(True)
        self.port_combo.addItems(["587", "465", "25", "2525"])
        server_layout.addWidget(self.port_combo, 0, 4)
        
        # Encryption options
        server_layout.addWidget(QLabel("Encryption:"), 1, 0)
        self.tls_checkbox = QCheckBox("Use TLS (STARTTLS)")
        self.ssl_checkbox = QCheckBox("Use SSL")
        server_layout.addWidget(self.tls_checkbox, 1, 1)
        server_layout.addWidget(self.ssl_checkbox, 1, 2)
        
        # Timeout
        server_layout.addWidget(QLabel("Timeout:"), 1, 3)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setSuffix(" sec")
        server_layout.addWidget(self.timeout_spin, 1, 4)
        
        left_layout.addWidget(server_group)
        
        # Authentication Section
        auth_group = QGroupBox("Authentication (Optional - for Relay Testing)")
        auth_layout = QGridLayout(auth_group)
        
        auth_layout.addWidget(QLabel("Username:"), 0, 0)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Leave empty for relay testing")
        auth_layout.addWidget(self.username_edit, 0, 1)
        
        auth_layout.addWidget(QLabel("Password:"), 0, 2)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Leave empty for relay testing")
        auth_layout.addWidget(self.password_edit, 0, 3)
        
        # Add relay info
        relay_info = QLabel("💡 Leave username/password empty to test mail relay without authentication")
        relay_info.setStyleSheet("color: #0078d4; font-style: italic;")
        auth_layout.addWidget(relay_info, 1, 0, 1, 4)
        
        left_layout.addWidget(auth_group)
        
        # Email Testing Section
        email_group = QGroupBox("Test Email Configuration")
        email_layout = QGridLayout(email_group)
        
        email_layout.addWidget(QLabel("From:"), 0, 0)
        self.from_edit = QLineEdit()
        self.from_edit.setPlaceholderText("sender@domain.com")
        email_layout.addWidget(self.from_edit, 0, 1)
        
        email_layout.addWidget(QLabel("To:"), 0, 2)
        self.to_edit = QLineEdit()
        self.to_edit.setPlaceholderText("recipient@domain.com")
        email_layout.addWidget(self.to_edit, 0, 3)
        
        email_layout.addWidget(QLabel("Subject:"), 1, 0)
        self.subject_edit = QLineEdit()
        self.subject_edit.setText("SMTP Tester Test Email")
        email_layout.addWidget(self.subject_edit, 1, 1, 1, 3)
        
        left_layout.addWidget(email_group)
        
        # Testing Actions Section
        actions_group = QGroupBox("SMTP Testing Actions")
        actions_layout = QGridLayout(actions_group)
        
        # Row 1: Basic tests
        self.connect_btn = QPushButton("Test Connection")
        self.auth_btn = QPushButton("Test Auth")
        self.send_btn = QPushButton("Send Test Email")
        self.mx_btn = QPushButton("Check MX Records")
        
        actions_layout.addWidget(self.connect_btn, 0, 0)
        actions_layout.addWidget(self.auth_btn, 0, 1)
        actions_layout.addWidget(self.send_btn, 0, 2)
        actions_layout.addWidget(self.mx_btn, 0, 3)
        
        # Row 2: Advanced tests
        self.ports_btn = QPushButton("Scan SMTP Ports")
        self.comprehensive_btn = QPushButton("Comprehensive Test")
        
        actions_layout.addWidget(self.ports_btn, 1, 0)
        actions_layout.addWidget(self.comprehensive_btn, 1, 1, 1, 2)
        
        left_layout.addWidget(actions_group)
        
        # Quick Presets Section
        presets_group = QGroupBox("Quick Server Presets")
        presets_layout = QHBoxLayout(presets_group)
        
        self.gmail_btn = QPushButton("Gmail")
        self.outlook_btn = QPushButton("Outlook.com")
        self.office365_btn = QPushButton("Office 365")
        self.yahoo_btn = QPushButton("Yahoo")
        self.custom_btn = QPushButton("Clear All")
        
        presets_layout.addWidget(self.gmail_btn)
        presets_layout.addWidget(self.outlook_btn)
        presets_layout.addWidget(self.office365_btn)
        presets_layout.addWidget(self.yahoo_btn)
        presets_layout.addWidget(self.custom_btn)
        presets_layout.addStretch()
        
        left_layout.addWidget(presets_group)
        
        # SMTP Information Section
        info_group = QGroupBox("SMTP Testing Guide")
        info_layout = QVBoxLayout(info_group)
        
        info_text = QTextEdit()
        info_text.setMaximumHeight(120)
        info_text.setReadOnly(True)
        info_text.setText(
            "SMTP Testing Tips:\n"
            "• Port 587: Modern SMTP with STARTTLS (recommended)\n"
            "• Port 465: SMTP over SSL (legacy but still used)\n"
            "• Port 25: Plain SMTP (often blocked by ISPs)\n"
            "• Leave username/password empty for relay testing\n"
            "• Use 'Comprehensive Test' for complete server analysis\n"
            "• Check MX records first to find the mail server for a domain"
        )
        info_layout.addWidget(info_text)
        
        left_layout.addWidget(info_group)
        left_layout.addStretch()
        
        # Right side - Output and logs
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Output header
        output_header = QLabel("📊 Real-time Results & Logs")
        output_header.setFont(QFont("Arial", 12, QFont.Bold))
        output_header.setStyleSheet("color: #0078d4; padding: 5px;")
        right_layout.addWidget(output_header)
        
        # Output controls
        controls_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Output")
        self.copy_btn = QPushButton("Copy Output")
        self.debug_btn = QPushButton("Toggle Debug")
        self.debug_btn.setCheckable(True)
        
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.copy_btn)
        controls_layout.addWidget(self.debug_btn)
        controls_layout.addStretch()
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Consolas", 10))
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumWidth(500)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #555;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #0078d4;
            }
            QScrollBar:vertical {
                background-color: #2d2d2d;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #555;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666;
            }
        """)
        
        right_layout.addLayout(controls_layout)
        right_layout.addWidget(self.output_text)
        
        # Add to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([700, 700])
        
        main_layout.addWidget(splitter)
        
        # Style the buttons
        self.style_buttons()
        
        # Setup menu
        self.setup_menu()
        
        # Show welcome message
        QTimer.singleShot(1000, self.show_welcome_message)
        
    def style_buttons(self):
        """Apply styling to buttons"""
        # Test action buttons
        test_button_style = """
            QPushButton {
                background-color: #d83b01;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #c23101;
            }
            QPushButton:pressed {
                background-color: #a62d01;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        
        # Preset buttons
        preset_button_style = """
            QPushButton {
                background-color: #107c10;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0e6b0e;
            }
            QPushButton:pressed {
                background-color: #0c5a0c;
            }
        """
        
        # Control buttons
        control_button_style = """
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
            QPushButton:checked {
                background-color: #0078d4;
                color: white;
            }
        """
        
        # Apply styles
        for btn in [self.connect_btn, self.auth_btn, self.send_btn, self.mx_btn, 
                   self.ports_btn, self.comprehensive_btn]:
            btn.setStyleSheet(test_button_style)
            
        for btn in [self.gmail_btn, self.outlook_btn, self.office365_btn, 
                   self.yahoo_btn, self.custom_btn]:
            btn.setStyleSheet(preset_button_style)
            
        for btn in [self.clear_btn, self.copy_btn, self.debug_btn]:
            btn.setStyleSheet(control_button_style)
        
    def setup_connections(self):
        """Setup signal connections"""
        # Test action connections
        self.connect_btn.clicked.connect(self.test_connection)
        self.auth_btn.clicked.connect(self.test_authentication)
        self.send_btn.clicked.connect(self.send_test_email)
        self.mx_btn.clicked.connect(self.check_mx_records)
        self.ports_btn.clicked.connect(self.scan_smtp_ports)
        self.comprehensive_btn.clicked.connect(self.comprehensive_test)
        
        # Preset connections
        self.gmail_btn.clicked.connect(lambda: self.load_preset("gmail"))
        self.outlook_btn.clicked.connect(lambda: self.load_preset("outlook"))
        self.office365_btn.clicked.connect(lambda: self.load_preset("office365"))
        self.yahoo_btn.clicked.connect(lambda: self.load_preset("yahoo"))
        self.custom_btn.clicked.connect(self.clear_all_fields)
        
        # Control connections
        self.clear_btn.clicked.connect(self.clear_output)
        self.copy_btn.clicked.connect(self.copy_output)
        self.debug_btn.toggled.connect(self.toggle_debug)
        
        # SMTP tools connections
        self.smtp_tools.result_ready.connect(self.handle_result)
        
        # Logger connection
        self.logger.message_logged.connect(self.append_output)
        
        # Encryption checkbox logic
        self.tls_checkbox.toggled.connect(self.on_tls_toggled)
        self.ssl_checkbox.toggled.connect(self.on_ssl_toggled)
        
        # Auto-fill from email when username changes
        self.username_edit.textChanged.connect(self.auto_fill_from_email)
        
    def setup_menu(self):
        """Setup application menu"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        help_action = QAction('SMTP Testing Help', self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
    def show_welcome_message(self):
        """Show welcome message"""
        self.logger.info("🎉 Welcome to SMTP Tester v1.0!")
        self.logger.info("📧 Comprehensive SMTP testing tool for email server diagnostics")
        self.logger.info("🔧 Features: Connection testing, Authentication, Email sending, MX records, Port scanning")
        self.logger.info("💡 Ready for SMTP server testing and email configuration validation!")
        
    def on_tls_toggled(self, checked):
        """Handle TLS checkbox toggle"""
        if checked:
            self.ssl_checkbox.setChecked(False)
            if self.port_combo.currentText() == "465":
                self.port_combo.setCurrentText("587")
                
    def on_ssl_toggled(self, checked):
        """Handle SSL checkbox toggle"""
        if checked:
            self.tls_checkbox.setChecked(False)
            if self.port_combo.currentText() == "587":
                self.port_combo.setCurrentText("465")
                
    def auto_fill_from_email(self, text):
        """Auto-fill 'From' email when username changes"""
        if "@" in text and not self.from_edit.text():
            self.from_edit.setText(text)
        
    def load_preset(self, provider):
        """Load predefined SMTP settings"""
        presets = {
            "gmail": {
                "server": "smtp.gmail.com",
                "port": "587",
                "tls": True,
                "ssl": False
            },
            "outlook": {
                "server": "smtp-mail.outlook.com",
                "port": "587", 
                "tls": True,
                "ssl": False
            },
            "office365": {
                "server": "smtp.office365.com",
                "port": "587",
                "tls": True,
                "ssl": False
            },
            "yahoo": {
                "server": "smtp.mail.yahoo.com",
                "port": "587",
                "tls": True,
                "ssl": False
            }
        }
        
        if provider in presets:
            preset = presets[provider]
            self.server_edit.setText(preset["server"])
            self.port_combo.setCurrentText(preset["port"])
            self.tls_checkbox.setChecked(preset["tls"])
            self.ssl_checkbox.setChecked(preset["ssl"])
            self.logger.info(f"Loaded {provider.title()} SMTP settings")
            
    def clear_all_fields(self):
        """Clear all input fields"""
        self.server_edit.clear()
        self.port_combo.setCurrentText("587")
        self.username_edit.clear()
        self.password_edit.clear()
        self.from_edit.clear()
        self.to_edit.clear()
        self.subject_edit.setText("SMTP Tester Test Email")
        self.tls_checkbox.setChecked(False)
        self.ssl_checkbox.setChecked(False)
        self.logger.info("All fields cleared")
        
    def handle_result(self, message, level):
        """Handle results from SMTP tools"""
        if level == "SUCCESS":
            self.logger.success(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def get_server_config(self):
        """Get current server configuration"""
        return {
            'server': self.server_edit.text().strip(),
            'port': int(self.port_combo.currentText()),
            'use_tls': self.tls_checkbox.isChecked(),
            'use_ssl': self.ssl_checkbox.isChecked(),
            'timeout': self.timeout_spin.value(),
            'username': self.username_edit.text().strip(),
            'password': self.password_edit.text(),
            'from_email': self.from_edit.text().strip(),
            'to_email': self.to_edit.text().strip(),
            'subject': self.subject_edit.text().strip()
        }
    
    def test_connection(self):
        """Test SMTP connection"""
        config = self.get_server_config()
        if not config['server']:
            self.logger.error("Please enter SMTP server address")
            return
            
        self.connect_btn.setEnabled(False)
        self.logger.info(f"Testing connection to {config['server']}:{config['port']}...")
        
        self.smtp_tools.test_connection(
            config['server'], config['port'], 
            config['use_tls'], config['use_ssl'], config['timeout']
        )
        
        QTimer.singleShot(5000, lambda: self.connect_btn.setEnabled(True))
    
    def test_authentication(self):
        """Test SMTP authentication"""
        config = self.get_server_config()
        if not config['server']:
            self.logger.error("Please enter SMTP server address")
            return
        if not config['username'] or not config['password']:
            self.logger.warning("No credentials provided - skipping authentication test")
            self.logger.info("Use this test when you have username/password to verify")
            return
            
        self.auth_btn.setEnabled(False)
        self.logger.info(f"Testing authentication for {config['username']}...")
        
        self.smtp_tools.test_authentication(
            config['server'], config['port'], config['username'], config['password'],
            config['use_tls'], config['use_ssl'], config['timeout']
        )
        
        QTimer.singleShot(5000, lambda: self.auth_btn.setEnabled(True))
    
    def send_test_email(self):
        """Send test email"""
        config = self.get_server_config()
        if not config['server']:
            self.logger.error("Please enter SMTP server address")
            return
        if not config['from_email'] or not config['to_email']:
            self.logger.error("Please enter both 'From' and 'To' email addresses")
            return
            
        # Check if this is relay testing
        if not config['username'] and not config['password']:
            self.logger.info("Sending test email via relay (no authentication)")
        else:
            self.logger.info("Sending authenticated test email")
            
        self.send_btn.setEnabled(False)
        self.logger.info(f"Sending test email from {config['from_email']} to {config['to_email']}...")
        
        self.smtp_tools.send_test_email(
            config['server'], config['port'], config['username'], config['password'],
            config['from_email'], config['to_email'], config['subject'],
            config['use_tls'], config['use_ssl'], config['timeout']
        )
        
        QTimer.singleShot(10000, lambda: self.send_btn.setEnabled(True))
    
    def check_mx_records(self):
        """Check MX records"""
        # Extract domain from server or from email
        domain = ""
        if self.from_edit.text() and "@" in self.from_edit.text():
            domain = self.from_edit.text().split("@")[1]
        elif self.to_edit.text() and "@" in self.to_edit.text():
            domain = self.to_edit.text().split("@")[1]
        elif self.server_edit.text():
            # Try to extract domain from server name
            server = self.server_edit.text()
            if server.startswith("smtp."):
                domain = server[5:]  # Remove "smtp." prefix
            elif server.startswith("mail."):
                domain = server[5:]  # Remove "mail." prefix
            else:
                domain = server
        
        if not domain:
            self.logger.error("Please enter an email address or domain to check MX records")
            return
            
        self.mx_btn.setEnabled(False)
        self.logger.info(f"Checking MX records for {domain}...")
        
        self.smtp_tools.check_mx_records(domain)
        
        QTimer.singleShot(5000, lambda: self.mx_btn.setEnabled(True))
    
    def scan_smtp_ports(self):
        """Scan SMTP ports"""
        config = self.get_server_config()
        if not config['server']:
            self.logger.error("Please enter SMTP server address")
            return
            
        self.ports_btn.setEnabled(False)
        self.logger.info(f"Scanning SMTP ports on {config['server']}...")
        
        self.smtp_tools.test_port_connectivity(config['server'])
        
        QTimer.singleShot(8000, lambda: self.ports_btn.setEnabled(True))
    
    def comprehensive_test(self):
        """Run comprehensive SMTP test"""
        config = self.get_server_config()
        if not config['server']:
            self.logger.error("Please enter SMTP server address")
            return
            
        self.comprehensive_btn.setEnabled(False)
        self.logger.info("Starting comprehensive SMTP test...")
        
        self.smtp_tools.comprehensive_smtp_test(
            config['server'], config['port'], config['username'], config['password'],
            config['from_email'], config['to_email'], config['use_tls'], config['use_ssl']
        )
        
        QTimer.singleShot(15000, lambda: self.comprehensive_btn.setEnabled(True))
        
    def append_output(self, message):
        """Append message to output"""
        self.output_text.append(message)
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        self.output_text.setTextCursor(cursor)
        
    def clear_output(self):
        """Clear output text"""
        self.output_text.clear()
        self.logger.log("Output cleared", "INFO")
        
    def copy_output(self):
        """Copy output to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())
        self.logger.log("Output copied to clipboard", "INFO")
        
    def toggle_debug(self, enabled):
        """Toggle debug mode"""
        self.logger.set_debug_mode(enabled)
        status = "enabled" if enabled else "disabled"
        self.logger.log(f"Debug mode {status}", "INFO")
        
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About SMTP Tester", 
                         "SMTP Tester v1.0\n\n"
                         "Standalone SMTP Testing Tool\n"
                         "Extracted from SigmaToolkit\n\n"
                         "Features:\n"
                         "• SMTP server connection testing\n"
                         "• Authentication testing (optional for relay testing)\n"
                         "• Test email sending with/without authentication\n"
                         "• MX record checking\n"
                         "• SMTP port scanning\n"
                         "• Comprehensive SMTP analysis\n"
                         "• Pre-configured settings for popular providers\n\n"
                         "Perfect for email server diagnostics and configuration validation.")
    
    def show_help(self):
        """Show help dialog"""
        help_text = """📧 SMTP TESTER HELP

SMTP Tester provides comprehensive email server testing and diagnostics:

🔧 CONFIGURATION:
• Server: Your SMTP server (smtp.gmail.com, mail.company.com, etc.)
• Port: 587 (TLS), 465 (SSL), 25 (Plain), 2525 (Alternative)
• Encryption: Choose TLS (STARTTLS) or SSL based on your server
• Timeout: Connection timeout in seconds (5-60)

🔐 AUTHENTICATION:
• Username/Password: Required for authenticated SMTP
• Leave empty for relay testing (no authentication)
• Auto-fills 'From' email based on username

📧 EMAIL TESTING:
• From: Sender email address
• To: Recipient email address
• Subject: Email subject line (customizable)

🧪 TESTING FUNCTIONS:
• Test Connection: Basic connectivity and server capabilities
• Test Auth: Verify username/password authentication
• Send Test Email: Send actual test message
• Check MX Records: DNS mail server lookup
• Scan SMTP Ports: Check common SMTP port availability
• Comprehensive Test: All-in-one testing sequence

⚡ QUICK PRESETS:
• Gmail: smtp.gmail.com:587 with TLS
• Outlook.com: smtp-mail.outlook.com:587 with TLS
• Office 365: smtp.office365.com:587 with TLS
• Yahoo: smtp.mail.yahoo.com:587 with TLS
• Clear All: Reset all configuration fields

💡 SMTP PORTS EXPLAINED:
• Port 587: Modern SMTP with STARTTLS (recommended)
• Port 465: SMTP over SSL (legacy but still used)
• Port 25: Plain SMTP (often blocked by ISPs)
• Port 2525: Alternative SMTP port

🔍 TESTING TIPS:
• Use 'Test Connection' first to verify basic connectivity
• Check MX records to find mail servers for a domain
• Leave credentials empty to test mail relay functionality
• Use 'Comprehensive Test' for complete server analysis
• Monitor the real-time log output for detailed diagnostics

🛠️ TROUBLESHOOTING:
• Connection timeouts: Check firewall and network connectivity
• Authentication failures: Verify username/password and account settings
• Email sending failures: Check recipient address and server policies
• MX lookup failures: Verify domain name and DNS connectivity

⚙️ RELAY TESTING:
• Leave username/password empty to test without authentication
• Useful for internal mail servers and relay configurations
• Check if your server accepts emails without credentials
• Verify mail relay policies and restrictions"""
        
        msg = QMessageBox()
        msg.setWindowTitle("SMTP Testing Help")
        msg.setText("SMTP Testing Help")
        msg.setDetailedText(help_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()


class SMTPTesterApp:
    """Main application class"""
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("SMTP Tester")
        self.app.setApplicationVersion("1.0")
        self.main_window = SMTPTesterMainWindow()
        
    def run(self):
        """Run the application"""
        self.main_window.show()
        return self.app.exec_()


if __name__ == "__main__":
    app = SMTPTesterApp()
    sys.exit(app.run())