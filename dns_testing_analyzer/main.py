# dns_testing_app.py - Standalone DNS Testing Application
import sys
import threading
import time
import subprocess
import socket
import re
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QGroupBox, QLineEdit, QPushButton, QLabel, QGridLayout,
    QFrame, QComboBox, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon


class DNSTools(QObject):
    """DNS testing tools and utilities"""
    result_ready = pyqtSignal(str, str)  # result, level
    
    def __init__(self):
        super().__init__()
        self.dns_server = None
        
    def set_dns_server(self, dns_server):
        """Set the DNS server to use for lookups"""
        self.dns_server = dns_server
        
    def forward_lookup(self, domain):
        """Forward DNS lookup (domain to IP)"""
        def _forward_lookup():
            try:
                self.result_ready.emit(f"Forward DNS lookup for {domain}...", "INFO")
                
                # Get IP address
                ip = socket.gethostbyname(domain)
                self.result_ready.emit(f"✅ IP Address: {ip}", "SUCCESS")
                
                # Try to get all IP addresses
                try:
                    result = socket.getaddrinfo(domain, None)
                    ips = list(set([r[4][0] for r in result]))
                    if len(ips) > 1:
                        self.result_ready.emit(f"All IP addresses: {', '.join(ips)}", "INFO")
                except:
                    pass
                    
            except Exception as e:
                self.result_ready.emit(f"❌ Forward DNS lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_forward_lookup, daemon=True)
        thread.start()
        
    def reverse_lookup(self, ip):
        """Reverse DNS lookup (IP to domain)"""
        def _reverse_lookup():
            try:
                self.result_ready.emit(f"Reverse DNS lookup for {ip}...", "INFO")
                
                # Validate IP format
                socket.inet_aton(ip)
                
                # Reverse lookup
                hostname = socket.gethostbyaddr(ip)
                self.result_ready.emit(f"✅ Hostname: {hostname[0]}", "SUCCESS")
                
                if len(hostname[1]) > 0:
                    self.result_ready.emit(f"Aliases: {', '.join(hostname[1])}", "INFO")
                    
            except socket.error as e:
                self.result_ready.emit(f"❌ Reverse DNS lookup error: {str(e)}", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ Reverse DNS lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_reverse_lookup, daemon=True)
        thread.start()
        
    def a_lookup(self, domain):
        """A record lookup (IPv4 addresses)"""
        def _a_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"A record lookup for {domain} {dns_info}...", "INFO")
                
                # Use nslookup/dig for A records
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=A", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "A", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ A Records (IPv4):", "SUCCESS")
                    
                    # Parse the output for clean display
                    if platform.system().lower() == "windows":
                        # Parse nslookup output
                        lines = process.stdout.split('\n')
                        found_addresses = False
                        in_answer_section = False
                        
                        for line in lines:
                            line = line.strip()
                            
                            if line.startswith('Server:') or (line.startswith('Address:') and not in_answer_section):
                                continue
                                
                            if 'Name:' in line and domain in line:
                                in_answer_section = True
                                continue
                                
                            if in_answer_section and 'Address:' in line:
                                ip = line.split('Address:')[1].strip()
                                if ip and '::' not in ip and self._is_valid_ipv4(ip):
                                    self.result_ready.emit(f"  {ip}", "INFO")
                                    found_addresses = True
                        
                        if not found_addresses:
                            try:
                                ip = socket.gethostbyname(domain)
                                self.result_ready.emit(f"  {ip}", "INFO")
                            except:
                                self.result_ready.emit("No A records found", "WARNING")
                    else:
                        # Parse dig output
                        ips = [line.strip() for line in process.stdout.split('\n') if line.strip()]
                        found_addresses = False
                        for ip in ips:
                            if ip and '::' not in ip and self._is_valid_ipv4(ip):
                                self.result_ready.emit(f"  {ip}", "INFO")
                                found_addresses = True
                        
                        if not found_addresses:
                            self.result_ready.emit("No A records found", "WARNING")
                else:
                    # Fallback to socket lookup
                    try:
                        ip = socket.gethostbyname(domain)
                        self.result_ready.emit("A Records (IPv4):", "SUCCESS")
                        self.result_ready.emit(f"  {ip} (via system resolver)", "INFO")
                    except Exception:
                        self.result_ready.emit("❌ No A records found or lookup failed", "WARNING")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ A record lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ A record lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_a_lookup, daemon=True)
        thread.start()
        
    def mx_lookup(self, domain):
        """MX record lookup"""
        def _mx_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"MX record lookup for {domain} {dns_info}...", "INFO")
                
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=MX", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "MX", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ MX Records:", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit("❌ No MX records found", "WARNING")
                    if process.stderr:
                        self.result_ready.emit(process.stderr, "ERROR")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ MX lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ MX lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_mx_lookup, daemon=True)
        thread.start()
        
    def txt_lookup(self, domain):
        """TXT record lookup (includes SPF)"""
        def _txt_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"TXT record lookup for {domain} {dns_info}...", "INFO")
                
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=TXT", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "TXT", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ TXT Records:", "SUCCESS")
                    output = process.stdout
                    
                    # Parse and highlight SPF records
                    lines = output.split('\n')
                    for line in lines:
                        if 'v=spf1' in line.lower():
                            self.result_ready.emit(f"🛡️ SPF Record: {line.strip()}", "SUCCESS")
                        elif line.strip():
                            self.result_ready.emit(line.strip(), "INFO")
                else:
                    self.result_ready.emit("❌ No TXT records found", "WARNING")
                    if process.stderr:
                        self.result_ready.emit(process.stderr, "ERROR")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ TXT lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ TXT lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_txt_lookup, daemon=True)
        thread.start()
        
    def ns_lookup(self, domain):
        """NS record lookup"""
        def _ns_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"NS record lookup for {domain} {dns_info}...", "INFO")
                
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=NS", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "NS", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ Name Servers:", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit("❌ No NS records found", "WARNING")
                    if process.stderr:
                        self.result_ready.emit(process.stderr, "ERROR")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ NS lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ NS lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_ns_lookup, daemon=True)
        thread.start()
        
    def cname_lookup(self, domain):
        """CNAME record lookup"""
        def _cname_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"CNAME record lookup for {domain} {dns_info}...", "INFO")
                
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=CNAME", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "CNAME", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ CNAME Records:", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit("❌ No CNAME records found", "WARNING")
                    if process.stderr:
                        self.result_ready.emit(process.stderr, "ERROR")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ CNAME lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ CNAME lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_cname_lookup, daemon=True)
        thread.start()
        
    def aaaa_lookup(self, domain):
        """AAAA record lookup (IPv6)"""
        def _aaaa_lookup():
            try:
                dns_info = self._get_dns_server_info()
                self.result_ready.emit(f"AAAA record lookup for {domain} {dns_info}...", "INFO")
                
                import platform
                cmd = []
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=AAAA", domain]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.append(dns_ip)
                else:
                    cmd = ["dig", "AAAA", domain, "+short"]
                    if self.dns_server and self.dns_server != "System Default":
                        dns_ip = self._extract_dns_ip(self.dns_server)
                        if dns_ip:
                            cmd.extend(["@" + dns_ip])
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if process.returncode == 0 and process.stdout.strip():
                    self.result_ready.emit("✅ IPv6 Addresses (AAAA):", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit("❌ No AAAA records found", "WARNING")
                    if process.stderr:
                        self.result_ready.emit(process.stderr, "ERROR")
                        
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"❌ AAAA lookup timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"❌ AAAA lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_aaaa_lookup, daemon=True)
        thread.start()
        
    def all_records_lookup(self, domain):
        """Lookup all common DNS records"""
        def _all_records():
            self.result_ready.emit(f"=== Comprehensive DNS lookup for {domain} ===", "INFO")
            
            # Run all lookups with small delays
            self.forward_lookup(domain)
            time.sleep(1)
            self.a_lookup(domain)
            time.sleep(1)
            self.mx_lookup(domain)
            time.sleep(1)
            self.txt_lookup(domain)
            time.sleep(1)
            self.ns_lookup(domain)
            time.sleep(1)
            self.cname_lookup(domain)
            time.sleep(1)
            self.aaaa_lookup(domain)
            
            time.sleep(2)
            self.result_ready.emit(f"=== DNS lookup completed for {domain} ===", "SUCCESS")
                
        thread = threading.Thread(target=_all_records, daemon=True)
        thread.start()
        
    def _extract_dns_ip(self, dns_server_text):
        """Extract IP address from DNS server selection text"""
        match = re.search(r'\(([0-9.]+)\)', dns_server_text)
        if match:
            return match.group(1)
        if re.match(r'^[0-9.]+$', dns_server_text):
            return dns_server_text
        return None

    def _is_valid_ipv4(self, ip):
        """Check if string is a valid IPv4 address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
            
    def _get_dns_server_info(self):
        """Get DNS server info for display"""
        if self.dns_server and self.dns_server != "System Default":
            return f"using {self.dns_server}"
        else:
            return "using system DNS"


class DNSTestingApp(QMainWindow):
    """Main DNS Testing Application Window"""
    
    def __init__(self):
        super().__init__()
        self.dns_tools = DNSTools()
        self.init_ui()
        self.setup_connections()
        
    def init_ui(self):
        self.setWindowTitle("DNS Testing Tool v1.0")
        self.setGeometry(100, 100, 1000, 700)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Header
        header = QLabel("🔍 DNS Testing Tool")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setStyleSheet("color: #0078d4; padding: 10px;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Quick DNS Lookups Section
        quick_group = QGroupBox("Quick DNS Lookups")
        quick_layout = QGridLayout(quick_group)
        
        quick_layout.addWidget(QLabel("Domain/IP:"), 0, 0)
        self.quick_domain_edit = QLineEdit()
        self.quick_domain_edit.setPlaceholderText("Enter domain name or IP address")
        quick_layout.addWidget(self.quick_domain_edit, 0, 1, 1, 2)
        
        # Quick action buttons
        self.forward_btn = QPushButton("Forward Lookup")
        self.reverse_btn = QPushButton("Reverse Lookup")
        self.all_records_btn = QPushButton("All Records")
        
        quick_layout.addWidget(self.forward_btn, 1, 0)
        quick_layout.addWidget(self.reverse_btn, 1, 1)
        quick_layout.addWidget(self.all_records_btn, 1, 2)
        
        layout.addWidget(quick_group)
        
        # Specific Record Types Section
        records_group = QGroupBox("Specific DNS Record Lookups")
        records_layout = QGridLayout(records_group)
        
        records_layout.addWidget(QLabel("Domain:"), 0, 0)
        self.records_domain_edit = QLineEdit()
        self.records_domain_edit.setPlaceholderText("Enter domain name")
        records_layout.addWidget(self.records_domain_edit, 0, 1, 1, 3)
        
        # Record type buttons
        self.a_btn = QPushButton("A Records\n(IPv4)")
        self.mx_btn = QPushButton("MX Records\n(Mail)")
        self.txt_btn = QPushButton("TXT Records\n(SPF/DKIM)")
        self.ns_btn = QPushButton("NS Records\n(Name Servers)")
        self.cname_btn = QPushButton("CNAME Records\n(Aliases)")
        self.aaaa_btn = QPushButton("AAAA Records\n(IPv6)")
        
        records_layout.addWidget(self.a_btn, 1, 0)
        records_layout.addWidget(self.mx_btn, 1, 1)
        records_layout.addWidget(self.txt_btn, 1, 2)
        records_layout.addWidget(self.ns_btn, 2, 0)
        records_layout.addWidget(self.cname_btn, 2, 1)
        records_layout.addWidget(self.aaaa_btn, 2, 2)
        
        layout.addWidget(records_group)
        
        # DNS Server Selection Section
        server_group = QGroupBox("DNS Server Selection")
        server_layout = QHBoxLayout(server_group)
        
        server_layout.addWidget(QLabel("DNS Server:"))
        self.dns_server_combo = QComboBox()
        self.dns_server_combo.addItems([
            "System Default",
            "Google DNS (8.8.8.8)",
            "Cloudflare DNS (1.1.1.1)",
            "Quad9 DNS (9.9.9.9)",
            "OpenDNS (208.67.222.222)",
            "Custom..."
        ])
        server_layout.addWidget(self.dns_server_combo)
        
        self.custom_dns_edit = QLineEdit()
        self.custom_dns_edit.setPlaceholderText("Enter custom DNS server IP")
        self.custom_dns_edit.setEnabled(False)
        server_layout.addWidget(self.custom_dns_edit)
        
        server_layout.addStretch()
        
        layout.addWidget(server_group)
        
        # Quick Test Domains Section
        common_group = QGroupBox("Quick Test Domains")
        common_layout = QHBoxLayout(common_group)
        
        self.test_google_btn = QPushButton("Test google.com")
        self.test_ms_btn = QPushButton("Test microsoft.com")
        self.test_github_btn = QPushButton("Test github.com")
        self.test_local_btn = QPushButton("Test Local Domain")
        
        common_layout.addWidget(self.test_google_btn)
        common_layout.addWidget(self.test_ms_btn)
        common_layout.addWidget(self.test_github_btn)
        common_layout.addWidget(self.test_local_btn)
        common_layout.addStretch()
        
        layout.addWidget(common_group)
        
        # Output Section
        output_group = QGroupBox("DNS Results")
        output_layout = QVBoxLayout(output_group)
        
        # Output controls
        controls_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Output")
        self.copy_btn = QPushButton("Copy Results")
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.copy_btn)
        controls_layout.addStretch()
        
        output_layout.addLayout(controls_layout)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Consolas", 10))
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #555;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
        # Style the buttons
        self.style_buttons()
        
        # Show welcome message
        self.append_output("🔍 DNS Testing Tool v1.0", "INFO")
        self.append_output("Ready to perform DNS lookups and diagnostics", "INFO")
        self.append_output("Enter a domain name and click a lookup button to start", "INFO")
        
    def style_buttons(self):
        """Style all buttons with consistent appearance"""
        main_button_style = """
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        
        record_button_style = """
            QPushButton {
                background-color: #107c10;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #0e6b0e;
            }
            QPushButton:pressed {
                background-color: #0c5a0c;
            }
        """
        
        test_button_style = """
            QPushButton {
                background-color: #8764b8;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7356a1;
            }
            QPushButton:pressed {
                background-color: #5f478a;
            }
        """
        
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
        """
        
        # Apply styles
        for btn in [self.forward_btn, self.reverse_btn, self.all_records_btn]:
            btn.setStyleSheet(main_button_style)
            
        for btn in [self.a_btn, self.mx_btn, self.txt_btn, self.ns_btn, self.cname_btn, self.aaaa_btn]:
            btn.setStyleSheet(record_button_style)
            
        for btn in [self.test_google_btn, self.test_ms_btn, self.test_github_btn, self.test_local_btn]:
            btn.setStyleSheet(test_button_style)
            
        for btn in [self.clear_btn, self.copy_btn]:
            btn.setStyleSheet(control_button_style)
        
    def setup_connections(self):
        """Setup all signal connections"""
        # Quick lookup connections
        self.forward_btn.clicked.connect(self.run_forward_lookup)
        self.reverse_btn.clicked.connect(self.run_reverse_lookup)
        self.all_records_btn.clicked.connect(self.run_all_records)
        
        # Record type connections
        self.a_btn.clicked.connect(self.run_a_lookup)
        self.mx_btn.clicked.connect(self.run_mx_lookup)
        self.txt_btn.clicked.connect(self.run_txt_lookup)
        self.ns_btn.clicked.connect(self.run_ns_lookup)
        self.cname_btn.clicked.connect(self.run_cname_lookup)
        self.aaaa_btn.clicked.connect(self.run_aaaa_lookup)
        
        # Test domain connections
        self.test_google_btn.clicked.connect(lambda: self.test_domain("google.com"))
        self.test_ms_btn.clicked.connect(lambda: self.test_domain("microsoft.com"))
        self.test_github_btn.clicked.connect(lambda: self.test_domain("github.com"))
        self.test_local_btn.clicked.connect(self.test_local_domain)
        
        # Control connections
        self.clear_btn.clicked.connect(self.clear_output)
        self.copy_btn.clicked.connect(self.copy_output)
        
        # DNS tools connections
        self.dns_tools.result_ready.connect(self.handle_result)
        
        # DNS server selection
        self.dns_server_combo.currentTextChanged.connect(self.on_dns_server_changed)
        
        # Enter key connections
        self.quick_domain_edit.returnPressed.connect(self.run_forward_lookup)
        self.records_domain_edit.returnPressed.connect(self.run_all_records)
        
    def on_dns_server_changed(self, text):
        """Handle DNS server selection change"""
        if "Custom" in text:
            self.custom_dns_edit.setEnabled(True)
            self.custom_dns_edit.setFocus()
            self.custom_dns_edit.textChanged.connect(self.on_custom_dns_changed)
        else:
            self.custom_dns_edit.setEnabled(False)
            self.dns_tools.set_dns_server(text)
            self.append_output(f"DNS server set: {text}", "INFO")

    def on_custom_dns_changed(self, text):
        """Handle custom DNS server input"""
        if text.strip():
            self.dns_tools.set_dns_server(text.strip())
            self.append_output(f"Custom DNS server set: {text.strip()}", "INFO")
        
    def handle_result(self, message, level):
        """Handle results from DNS tools"""
        self.append_output(message, level)
    
    def append_output(self, message, level):
        """Append message to output with timestamp and formatting"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        if level == "SUCCESS":
            color = "#00ff00"  # Green
        elif level == "ERROR":
            color = "#ff6666"  # Red
        elif level == "WARNING":
            color = "#ffaa00"  # Orange
        else:
            color = "#ffffff"  # White
            
        formatted_message = f'<span style="color: #888">[{timestamp}]</span> <span style="color: {color}">{message}</span>'
        self.output_text.append(formatted_message)
        
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        self.output_text.setTextCursor(cursor)
    
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.clear()
        self.append_output("Output cleared", "INFO")
        
    def copy_output(self):
        """Copy output to clipboard"""
        from PyQt5.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        # Get plain text version (without HTML formatting)
        plain_text = self.output_text.toPlainText()
        clipboard.setText(plain_text)
        self.append_output("Output copied to clipboard", "INFO")
    
    def run_forward_lookup(self):
        """Run forward DNS lookup"""
        domain = self.quick_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.forward_btn.setEnabled(False)
        self.append_output(f"Starting forward DNS lookup for {domain}...", "INFO")
        
        self.dns_tools.forward_lookup(domain)
        
        # Re-enable button after delay
        QTimer.singleShot(3000, lambda: self.forward_btn.setEnabled(True))
    
    def run_reverse_lookup(self):
        """Run reverse DNS lookup"""
        ip = self.quick_domain_edit.text().strip()
        if not ip:
            self.append_output("Please enter an IP address", "ERROR")
            return
            
        self.reverse_btn.setEnabled(False)
        self.append_output(f"Starting reverse DNS lookup for {ip}...", "INFO")
        
        self.dns_tools.reverse_lookup(ip)
        
        QTimer.singleShot(3000, lambda: self.reverse_btn.setEnabled(True))
    
    def run_all_records(self):
        """Run comprehensive DNS lookup"""
        domain = self.quick_domain_edit.text().strip() or self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.all_records_btn.setEnabled(False)
        self.append_output(f"Starting comprehensive DNS lookup for {domain}...", "INFO")
        
        self.dns_tools.all_records_lookup(domain)
        
        QTimer.singleShot(10000, lambda: self.all_records_btn.setEnabled(True))
    
    def run_a_lookup(self):
        """Run A record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.a_btn.setEnabled(False)
        self.dns_tools.a_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.a_btn.setEnabled(True))
    
    def run_mx_lookup(self):
        """Run MX record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.mx_btn.setEnabled(False)
        self.dns_tools.mx_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.mx_btn.setEnabled(True))
    
    def run_txt_lookup(self):
        """Run TXT record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.txt_btn.setEnabled(False)
        self.dns_tools.txt_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.txt_btn.setEnabled(True))
    
    def run_ns_lookup(self):
        """Run NS record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.ns_btn.setEnabled(False)
        self.dns_tools.ns_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.ns_btn.setEnabled(True))
    
    def run_cname_lookup(self):
        """Run CNAME record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.cname_btn.setEnabled(False)
        self.dns_tools.cname_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.cname_btn.setEnabled(True))
    
    def run_aaaa_lookup(self):
        """Run AAAA record lookup"""
        domain = self.records_domain_edit.text().strip()
        if not domain:
            self.append_output("Please enter a domain name", "ERROR")
            return
            
        self.aaaa_btn.setEnabled(False)
        self.dns_tools.aaaa_lookup(domain)
        
        QTimer.singleShot(3000, lambda: self.aaaa_btn.setEnabled(True))
    
    def test_domain(self, domain):
        """Test a specific domain"""
        self.quick_domain_edit.setText(domain)
        self.records_domain_edit.setText(domain)
        self.run_all_records()
    
    def test_local_domain(self):
        """Test local domain detection"""
        try:
            local_domain = socket.getfqdn()
            self.append_output(f"Detected local domain: {local_domain}", "INFO")
            if '.' in local_domain:
                self.quick_domain_edit.setText(local_domain)
                self.run_forward_lookup()
            else:
                self.append_output("Could not detect a valid local domain", "WARNING")
        except Exception as e:
            self.append_output(f"Error detecting local domain: {str(e)}", "ERROR")


def main():
    """Main function to run the DNS Testing application"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("DNS Testing Tool")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("DNS Tools")
    
    # Create and show the main window
    window = DNSTestingApp()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()