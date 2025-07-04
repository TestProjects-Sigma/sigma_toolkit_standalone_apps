# main.py - Network Toolkit - Single File Version
# A comprehensive standalone network testing and diagnostics tool
# Version: 1.0.0

import sys
import os
import subprocess
import socket
import threading
import time
import re
import platform
import requests
import traceback
from datetime import datetime

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QGroupBox,
                            QWidget, QMenuBar, QAction, QMessageBox, QLineEdit, QPushButton, 
                            QLabel, QSpinBox, QGridLayout, QFrame, QTextEdit, QFileDialog)
from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal, QThread
from PyQt5.QtGui import QFont

# =============================================================================
# LOGGER CLASS
# =============================================================================

class Logger(QObject):
    message_logged = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.debug_mode = False
        self.lock = threading.Lock()
        
    def set_debug_mode(self, enabled):
        with self.lock:
            self.debug_mode = enabled
            
    def log(self, message, level="INFO"):
        with self.lock:
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

# =============================================================================
# NETWORK TOOLS CLASS
# =============================================================================

class NetworkTools(QObject):
    result_ready = pyqtSignal(str, str)  # result, level
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        
    def ping(self, host, count=4):
        """Ping a host"""
        def _ping():
            try:
                self.logger.debug(f"Starting ping to {host} with {count} packets")
                self.result_ready.emit(f"Pinging {host}...", "INFO")
                
                # Build ping command based on OS
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", str(count), host]
                else:
                    cmd = ["ping", "-c", str(count), host]
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if process.returncode == 0:
                    self.result_ready.emit(f"Ping to {host} successful:", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit(f"Ping to {host} failed:", "ERROR")
                    self.result_ready.emit(process.stderr, "ERROR")
                    
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"Ping to {host} timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"Ping error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_ping)
        thread.daemon = True
        thread.start()
        
    def traceroute(self, host):
        """Traceroute to a host"""
        def _traceroute():
            try:
                self.logger.debug(f"Starting traceroute to {host}")
                self.result_ready.emit(f"Tracing route to {host}...", "INFO")
                
                # Build traceroute command based on OS
                if platform.system().lower() == "windows":
                    cmd = ["tracert", host]
                else:
                    cmd = ["traceroute", host]
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if process.returncode == 0:
                    self.result_ready.emit(f"Traceroute to {host} completed:", "SUCCESS")
                    self.result_ready.emit(process.stdout, "INFO")
                else:
                    self.result_ready.emit(f"Traceroute to {host} failed:", "ERROR")
                    self.result_ready.emit(process.stderr, "ERROR")
                    
            except subprocess.TimeoutExpired:
                self.result_ready.emit(f"Traceroute to {host} timed out", "ERROR")
            except Exception as e:
                self.result_ready.emit(f"Traceroute error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_traceroute)
        thread.daemon = True
        thread.start()
        
    def port_scan(self, host, ports):
        """Scan ports on a host"""
        def _port_scan():
            try:
                self.logger.debug(f"Starting port scan on {host} for ports {ports}")
                self.result_ready.emit(f"Scanning ports on {host}...", "INFO")
                
                # Parse port range
                if '-' in ports:
                    start, end = map(int, ports.split('-'))
                    port_list = range(start, end + 1)
                else:
                    port_list = [int(p.strip()) for p in ports.split(',')]
                
                open_ports = []
                closed_ports = []
                
                for port in port_list:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    
                    try:
                        result = sock.connect_ex((host, port))
                        if result == 0:
                            open_ports.append(port)
                            self.result_ready.emit(f"Port {port}: OPEN", "SUCCESS")
                        else:
                            closed_ports.append(port)
                            self.logger.debug(f"Port {port}: CLOSED")
                    except Exception as e:
                        self.logger.debug(f"Port {port}: Error - {str(e)}")
                    finally:
                        sock.close()
                
                # Summary
                self.result_ready.emit(f"\nPort scan completed for {host}", "INFO")
                self.result_ready.emit(f"Open ports: {open_ports if open_ports else 'None'}", "INFO")
                self.result_ready.emit(f"Total ports scanned: {len(port_list)}", "INFO")
                
            except Exception as e:
                self.result_ready.emit(f"Port scan error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_port_scan)
        thread.daemon = True
        thread.start()
        
    def dns_lookup(self, host):
        """Perform DNS lookup"""
        def _dns_lookup():
            try:
                self.logger.debug(f"Starting DNS lookup for {host}")
                self.result_ready.emit(f"DNS lookup for {host}...", "INFO")
                
                # Get IP address
                ip = socket.gethostbyname(host)
                self.result_ready.emit(f"IP Address: {ip}", "SUCCESS")
                
                # Reverse lookup
                try:
                    reverse = socket.gethostbyaddr(ip)
                    self.result_ready.emit(f"Reverse DNS: {reverse[0]}", "INFO")
                except:
                    self.result_ready.emit("Reverse DNS: Not available", "WARNING")
                    
            except Exception as e:
                self.result_ready.emit(f"DNS lookup error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_dns_lookup)
        thread.daemon = True
        thread.start()

# =============================================================================
# SYSTEM INFO WORKER
# =============================================================================

class SystemInfoWorker(QThread):
    """Worker thread to gather system network information"""
    info_ready = pyqtSignal(dict)
    
    def run(self):
        info = {}
        try:
            # Get local IP and subnet
            info.update(self.get_local_network_info())
            # Get external IP
            info['external_ip'] = self.get_external_ip()
            # Get default gateway
            info['gateway'] = self.get_default_gateway()
            # Get DNS servers
            info['dns_servers'] = self.get_dns_servers()
            # Get network interfaces
            info['interfaces'] = self.get_network_interfaces()
        except Exception as e:
            info['error'] = str(e)
        
        self.info_ready.emit(info)
    
    def get_local_network_info(self):
        """Get local IP address and subnet information"""
        try:
            # Connect to a remote address to determine the local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            hostname = socket.gethostname()
            
            return {
                'local_ip': local_ip,
                'hostname': hostname,
                'subnet': self.calculate_subnet(local_ip)
            }
        except Exception as e:
            return {'local_ip': 'Unknown', 'hostname': 'Unknown', 'subnet': 'Unknown'}
    
    def calculate_subnet(self, ip):
        """Calculate likely subnet based on IP class"""
        octets = ip.split('.')
        if octets[0] == '192' and octets[1] == '168':
            return f"192.168.{octets[2]}.0/24"
        elif octets[0] == '10':
            return "10.0.0.0/8"
        elif octets[0] == '172' and 16 <= int(octets[1]) <= 31:
            return f"172.{octets[1]}.0.0/16"
        else:
            return f"{'.'.join(octets[:3])}.0/24"
    
    def get_external_ip(self):
        """Get external/public IP address"""
        try:
            # Try multiple services for reliability
            services = [
                'https://api.ipify.org',
                'https://checkip.amazonaws.com',
                'https://icanhazip.com'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        return response.text.strip()
                except:
                    continue
            
            return "Unable to determine"
        except:
            return "Unable to determine"
    
    def get_default_gateway(self):
        """Get default gateway IP"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != '':
                            return gateway
            else:
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return result.stdout.split()[2]
            
            return "Unknown"
        except:
            return "Unknown"
    
    def get_dns_servers(self):
        """Get DNS server information"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["nslookup", "google.com"], capture_output=True, text=True, timeout=10)
                dns_servers = []
                for line in result.stdout.split('\n'):
                    if 'Server:' in line:
                        dns = line.split(':')[-1].strip()
                        if dns:
                            dns_servers.append(dns)
                return dns_servers[:2] if dns_servers else ["Unknown"]
            else:
                with open('/etc/resolv.conf', 'r') as f:
                    dns_servers = []
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
                    return dns_servers[:2] if dns_servers else ["Unknown"]
        except:
            return ["Unknown"]
    
    def get_network_interfaces(self):
        """Get network interface information"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10)
                # Parse active interfaces
                interfaces = []
                current_interface = None
                for line in result.stdout.split('\n'):
                    if 'adapter' in line.lower() and ':' in line:
                        current_interface = line.split(':')[0].strip()
                    elif 'IPv4 Address' in line and current_interface:
                        interfaces.append(current_interface)
                        current_interface = None
                return interfaces[:3] if interfaces else ["Unknown"]
            else:
                result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=10)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'inet ' in line:
                        interface = line.split(':')[1].strip().split()[0]
                        if interface not in interfaces:
                            interfaces.append(interface)
                return interfaces[:3] if interfaces else ["Unknown"]
        except:
            return ["Unknown"]

# =============================================================================
# NETWORK TAB CLASS
# =============================================================================

class NetworkTab(QWidget):
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.network_tools = NetworkTools(logger)
        self.system_info = {}
        self.init_ui()
        self.setup_connections()
        self.load_system_info()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # System Network Information Section
        system_group = QGroupBox("🖥️ System Network Information")
        system_layout = QVBoxLayout(system_group)
        
        # Create info display area
        self.system_info_text = QTextEdit()
        self.system_info_text.setMaximumHeight(150)
        self.system_info_text.setFont(QFont("Consolas", 10))
        self.system_info_text.setReadOnly(True)
        self.system_info_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                border-radius: 6px;
                padding: 8px;
                color: #495057;
            }
        """)
        self.system_info_text.setText("🔄 Loading system network information...")
        
        # Refresh button
        refresh_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh Network Info")
        self.refresh_btn.setMaximumWidth(200)
        refresh_layout.addWidget(self.refresh_btn)
        refresh_layout.addStretch()
        
        system_layout.addWidget(self.system_info_text)
        system_layout.addLayout(refresh_layout)
        
        layout.addWidget(system_group)
        
        # Ping Section
        ping_group = QGroupBox("Ping Test")
        ping_layout = QGridLayout(ping_group)
        
        ping_layout.addWidget(QLabel("Host:"), 0, 0)
        self.ping_host_edit = QLineEdit()
        self.ping_host_edit.setPlaceholderText("Enter hostname or IP address")
        ping_layout.addWidget(self.ping_host_edit, 0, 1)
        
        ping_layout.addWidget(QLabel("Count:"), 0, 2)
        self.ping_count_spin = QSpinBox()
        self.ping_count_spin.setRange(1, 100)
        self.ping_count_spin.setValue(4)
        ping_layout.addWidget(self.ping_count_spin, 0, 3)
        
        self.ping_btn = QPushButton("Ping")
        self.ping_btn.setMinimumHeight(30)
        ping_layout.addWidget(self.ping_btn, 0, 4)
        
        layout.addWidget(ping_group)
        
        # Traceroute Section
        trace_group = QGroupBox("Traceroute")
        trace_layout = QGridLayout(trace_group)
        
        trace_layout.addWidget(QLabel("Host:"), 0, 0)
        self.trace_host_edit = QLineEdit()
        self.trace_host_edit.setPlaceholderText("Enter hostname or IP address")
        trace_layout.addWidget(self.trace_host_edit, 0, 1)
        
        self.trace_btn = QPushButton("Traceroute")
        self.trace_btn.setMinimumHeight(30)
        trace_layout.addWidget(self.trace_btn, 0, 2)
        
        layout.addWidget(trace_group)
        
        # Port Scan Section
        port_group = QGroupBox("Port Scanner")
        port_layout = QGridLayout(port_group)
        
        port_layout.addWidget(QLabel("Host:"), 0, 0)
        self.port_host_edit = QLineEdit()
        self.port_host_edit.setPlaceholderText("Enter hostname or IP address")
        port_layout.addWidget(self.port_host_edit, 0, 1)
        
        port_layout.addWidget(QLabel("Ports:"), 0, 2)
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("e.g., 80,443,22 or 1-1000")
        port_layout.addWidget(self.ports_edit, 0, 3)
        
        self.port_scan_btn = QPushButton("Scan Ports")
        self.port_scan_btn.setMinimumHeight(30)
        port_layout.addWidget(self.port_scan_btn, 0, 4)
        
        layout.addWidget(port_group)
        
        # DNS Lookup Section
        dns_group = QGroupBox("DNS Lookup")
        dns_layout = QGridLayout(dns_group)
        
        dns_layout.addWidget(QLabel("Host:"), 0, 0)
        self.dns_host_edit = QLineEdit()
        self.dns_host_edit.setPlaceholderText("Enter hostname")
        dns_layout.addWidget(self.dns_host_edit, 0, 1)
        
        self.dns_btn = QPushButton("DNS Lookup")
        self.dns_btn.setMinimumHeight(30)
        dns_layout.addWidget(self.dns_btn, 0, 2)
        
        layout.addWidget(dns_group)
        
        # Quick Actions Section
        quick_group = QGroupBox("Quick Actions")
        quick_layout = QHBoxLayout(quick_group)
        
        self.quick_google_btn = QPushButton("Ping Google DNS")
        self.quick_cloudflare_btn = QPushButton("Ping Cloudflare DNS")
        self.quick_local_btn = QPushButton("Ping Gateway")
        
        quick_layout.addWidget(self.quick_google_btn)
        quick_layout.addWidget(self.quick_cloudflare_btn)
        quick_layout.addWidget(self.quick_local_btn)
        quick_layout.addStretch()
        
        layout.addWidget(quick_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        # Style the buttons
        self.style_buttons()
        
    def style_buttons(self):
        button_style = """
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
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
        
        refresh_style = """
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """
        
        for btn in [self.ping_btn, self.trace_btn, self.port_scan_btn, 
                   self.dns_btn, self.quick_google_btn, self.quick_cloudflare_btn, 
                   self.quick_local_btn]:
            btn.setStyleSheet(button_style)
        
        self.refresh_btn.setStyleSheet(refresh_style)
        
    def setup_connections(self):
        # Button connections
        self.ping_btn.clicked.connect(self.run_ping)
        self.trace_btn.clicked.connect(self.run_traceroute)
        self.port_scan_btn.clicked.connect(self.run_port_scan)
        self.dns_btn.clicked.connect(self.run_dns_lookup)
        
        # Quick action connections
        self.quick_google_btn.clicked.connect(lambda: self.quick_ping("8.8.8.8"))
        self.quick_cloudflare_btn.clicked.connect(lambda: self.quick_ping("1.1.1.1"))
        self.quick_local_btn.clicked.connect(self.ping_gateway)
        
        # Refresh button
        self.refresh_btn.clicked.connect(self.load_system_info)
        
        # Network tools connections
        self.network_tools.result_ready.connect(self.handle_result)
        
        # Enter key connections
        self.ping_host_edit.returnPressed.connect(self.run_ping)
        self.trace_host_edit.returnPressed.connect(self.run_traceroute)
        self.dns_host_edit.returnPressed.connect(self.run_dns_lookup)
        
    def load_system_info(self):
        """Load system network information in background thread"""
        self.system_info_text.setText("🔄 Loading system network information...")
        self.refresh_btn.setEnabled(False)
        
        self.info_worker = SystemInfoWorker()
        self.info_worker.info_ready.connect(self.update_system_info)
        self.info_worker.start()
        
    def update_system_info(self, info):
        """Update the system info display"""
        self.system_info = info
        self.refresh_btn.setEnabled(True)
        
        if 'error' in info:
            self.system_info_text.setText(f"❌ Error loading system information: {info['error']}")
            return
        
        # Format the information nicely
        info_text = f"""💻 Computer: {info.get('hostname', 'Unknown')}
🌐 Local IP: {info.get('local_ip', 'Unknown')}
📡 Subnet: {info.get('subnet', 'Unknown')}
🚪 Gateway: {info.get('gateway', 'Unknown')}
🌍 External IP: {info.get('external_ip', 'Loading...')}
🔍 DNS Servers: {', '.join(info.get('dns_servers', ['Unknown']))}
🔌 Active Interfaces: {', '.join(info.get('interfaces', ['Unknown']))}"""
        
        self.system_info_text.setText(info_text)
        
        # Log the info to the main output as well
        self.logger.info(f"System Network Summary - Local: {info.get('local_ip', 'Unknown')}, External: {info.get('external_ip', 'Unknown')}, Gateway: {info.get('gateway', 'Unknown')}")

    def handle_result(self, message, level):
        if level == "SUCCESS":
            self.logger.success(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def run_ping(self):
        host = self.ping_host_edit.text().strip()
        if not host:
            self.logger.error("Please enter a host to ping")
            return
            
        count = self.ping_count_spin.value()
        self.ping_btn.setEnabled(False)
        self.logger.info(f"Starting ping test to {host}...")
        
        self.network_tools.ping(host, count)
        
        # Re-enable button after a delay
        QTimer.singleShot(5000, lambda: self.ping_btn.setEnabled(True))
    
    def run_traceroute(self):
        host = self.trace_host_edit.text().strip()
        if not host:
            self.logger.error("Please enter a host for traceroute")
            return
            
        self.trace_btn.setEnabled(False)
        self.logger.info(f"Starting traceroute to {host}...")
        
        self.network_tools.traceroute(host)
        
        # Re-enable button after a delay
        QTimer.singleShot(10000, lambda: self.trace_btn.setEnabled(True))
    
    def run_port_scan(self):
        host = self.port_host_edit.text().strip()
        ports = self.ports_edit.text().strip()
        
        if not host:
            self.logger.error("Please enter a host to scan")
            return
        if not ports:
            self.logger.error("Please enter ports to scan")
            return
            
        self.port_scan_btn.setEnabled(False)
        self.logger.info(f"Starting port scan on {host}...")
        
        self.network_tools.port_scan(host, ports)
        
        # Re-enable button after a delay
        QTimer.singleShot(15000, lambda: self.port_scan_btn.setEnabled(True))
    
    def run_dns_lookup(self):
        host = self.dns_host_edit.text().strip()
        if not host:
            self.logger.error("Please enter a host for DNS lookup")
            return
            
        self.dns_btn.setEnabled(False)
        self.logger.info(f"Starting DNS lookup for {host}...")
        
        self.network_tools.dns_lookup(host)
        
        # Re-enable button after a delay
        QTimer.singleShot(3000, lambda: self.dns_btn.setEnabled(True))
    
    def quick_ping(self, ip):
        self.ping_host_edit.setText(ip)
        self.run_ping()
    
    def ping_gateway(self):
        gateway = self.system_info.get('gateway', 'Unknown')
        if gateway and gateway != 'Unknown':
            self.ping_host_edit.setText(gateway)
            self.run_ping()
        else:
            self.logger.error("Gateway not available - try refreshing network info first")

# =============================================================================
# MAIN WINDOW CLASS
# =============================================================================

class NetworkToolkitWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.version = "1.0.0"
        self.logger = Logger()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle(f"Network Toolkit v{self.version}")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout with horizontal split
        main_layout = QHBoxLayout(central_widget)
        
        # Network testing section (left side)
        network_widget = QWidget()
        network_layout = QVBoxLayout(network_widget)
        
        # Add title
        title_label = QLabel("🌐 Network Testing Toolkit")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setStyleSheet("color: #0078d4; padding: 10px;")
        network_layout.addWidget(title_label)
        
        # Add network tab
        self.network_tab = NetworkTab(self.logger)
        network_layout.addWidget(self.network_tab)
        
        # Output section (right side)
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        
        # Output header
        output_header = QLabel("📊 Real-time Results & Logs")
        output_header.setFont(QFont("Arial", 12, QFont.Bold))
        output_header.setStyleSheet("color: #0078d4; padding: 5px;")
        output_layout.addWidget(output_header)
        
        # Output controls
        controls_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Output")
        self.copy_btn = QPushButton("Copy Output")
        self.debug_btn = QPushButton("Toggle Debug")
        self.debug_btn.setCheckable(True)
        self.export_btn = QPushButton("Export Results")
        
        # Style the control buttons
        button_style = """
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
        
        for btn in [self.clear_btn, self.copy_btn, self.debug_btn, self.export_btn]:
            btn.setStyleSheet(button_style)
        
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.copy_btn)
        controls_layout.addWidget(self.debug_btn)
        controls_layout.addWidget(self.export_btn)
        controls_layout.addStretch()
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Consolas", 11))
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumWidth(400)
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
        
        output_layout.addLayout(controls_layout)
        output_layout.addWidget(self.output_text)
        
        # Add widgets to main layout
        main_layout.addWidget(network_widget, 2)  # 2/3 of space
        main_layout.addWidget(output_widget, 1)   # 1/3 of space
        
        # Set minimum sizes
        network_widget.setMinimumWidth(700)
        output_widget.setMinimumWidth(400)
        
        # Setup connections
        self.setup_connections()
        
        # Setup menu
        self.setup_menu()
        
        # Connect logger to output
        self.logger.message_logged.connect(self.append_output)
        
        # Show welcome message
        self.show_welcome_message()
        
    def show_welcome_message(self):
        """Show welcome message"""
        QTimer.singleShot(1000, self._delayed_welcome)
        
    def _delayed_welcome(self):
        """Delayed welcome message"""
        self.logger.info(f"🎉 Welcome to Network Toolkit v{self.version}!")
        self.logger.info("🌐 Comprehensive network testing and diagnostics toolkit")
        self.logger.info("🔍 Features: Ping, Traceroute, Port Scanning, DNS Lookup, System Info")
        self.logger.info("💡 Ready for network troubleshooting and connectivity testing!")
        
    def setup_connections(self):
        self.clear_btn.clicked.connect(self.clear_output)
        self.copy_btn.clicked.connect(self.copy_output)
        self.debug_btn.toggled.connect(self.toggle_debug)
        self.export_btn.clicked.connect(self.export_results)
        
    def setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Results', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        refresh_info_action = QAction('Refresh Network Info', self)
        refresh_info_action.triggered.connect(self.network_tab.load_system_info)
        tools_menu.addAction(refresh_info_action)
        
        quick_tests_menu = tools_menu.addMenu('Quick Tests')
        
        ping_google_action = QAction('Ping Google DNS (8.8.8.8)', self)
        ping_google_action.triggered.connect(lambda: self.network_tab.quick_ping("8.8.8.8"))
        quick_tests_menu.addAction(ping_google_action)
        
        ping_cloudflare_action = QAction('Ping Cloudflare DNS (1.1.1.1)', self)
        ping_cloudflare_action.triggered.connect(lambda: self.network_tab.quick_ping("1.1.1.1"))
        quick_tests_menu.addAction(ping_cloudflare_action)
        
        ping_gateway_action = QAction('Ping Gateway', self)
        ping_gateway_action.triggered.connect(self.network_tab.ping_gateway)
        quick_tests_menu.addAction(ping_gateway_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        help_action = QAction('Network Testing Help', self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
    def append_output(self, message):
        self.output_text.append(message)
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        self.output_text.setTextCursor(cursor)
        
    def clear_output(self):
        self.output_text.clear()
        self.logger.log("Output cleared", "INFO")
        
    def copy_output(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())
        self.logger.log("Output copied to clipboard", "INFO")
        
    def toggle_debug(self, enabled):
        self.logger.set_debug_mode(enabled)
        status = "enabled" if enabled else "disabled"
        self.logger.log(f"Debug mode {status}", "INFO")
        
    def export_results(self):
        """Export all results to file"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Network Test Results", 
                f"network_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Network Toolkit v{self.version} - Test Results Export\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    # Export system network info
                    if hasattr(self.network_tab, 'system_info') and self.network_tab.system_info:
                        f.write("SYSTEM NETWORK INFORMATION:\n")
                        f.write("-" * 30 + "\n")
                        info = self.network_tab.system_info
                        f.write(f"Computer: {info.get('hostname', 'Unknown')}\n")
                        f.write(f"Local IP: {info.get('local_ip', 'Unknown')}\n")
                        f.write(f"Subnet: {info.get('subnet', 'Unknown')}\n")
                        f.write(f"Gateway: {info.get('gateway', 'Unknown')}\n")
                        f.write(f"External IP: {info.get('external_ip', 'Unknown')}\n")
                        f.write(f"DNS Servers: {', '.join(info.get('dns_servers', ['Unknown']))}\n")
                        f.write(f"Active Interfaces: {', '.join(info.get('interfaces', ['Unknown']))}\n\n")
                    
                    # Export console output
                    f.write("TEST RESULTS AND CONSOLE OUTPUT:\n")
                    f.write("-" * 35 + "\n")
                    f.write(self.output_text.toPlainText())
                    f.write("\n\n")
                    
                self.logger.success(f"Results exported to: {file_path}")
                
        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}")
        
    def show_about(self):
        QMessageBox.about(self, "About Network Toolkit", 
                         f"Network Toolkit v{self.version}\n\n"
                         "A comprehensive network testing and diagnostics tool\n"
                         "for system administrators and network engineers.\n\n"
                         "Features:\n"
                         "• System Network Information Display\n"
                         "• Ping Testing with customizable packet count\n"
                         "• Traceroute for network path analysis\n"
                         "• Port Scanner for connectivity testing\n"
                         "• DNS Lookup for domain resolution\n"
                         "• Quick Actions for common network tests\n"
                         "• Real-time output with debug logging\n"
                         "• Export capabilities for documentation\n\n"
                         "Built with PyQt5 for cross-platform compatibility.\n"
                         "Extracted from SigmaToolkit for standalone use.")
    
    def show_help(self):
        help_text = """🌐 NETWORK TOOLKIT HELP

SYSTEM NETWORK INFORMATION:
• Displays current computer name, local/external IP addresses
• Shows subnet information and default gateway
• Lists DNS servers and active network interfaces
• Click 'Refresh Network Info' to update information

PING TEST:
• Test connectivity to any host or IP address
• Customize packet count (1-100)
• Shows round-trip times and packet loss statistics
• Use for basic connectivity troubleshooting

TRACEROUTE:
• Trace the network path to a destination
• Shows all intermediate routers and their response times
• Useful for identifying network bottlenecks or routing issues
• May take longer than ping tests

PORT SCANNER:
• Test connectivity to specific ports on a host
• Supports single ports (80), ranges (1-100), or lists (80,443,22)
• Shows which ports are open or closed
• Useful for service availability testing

DNS LOOKUP:
• Convert domain names to IP addresses
• Includes reverse DNS lookup when possible
• Test DNS resolution issues
• Verify domain configurations

QUICK ACTIONS:
• Ping Google DNS (8.8.8.8): Test internet connectivity
• Ping Cloudflare DNS (1.1.1.1): Alternative connectivity test
• Ping Gateway: Test local network connectivity

TIPS:
• Press Enter in input fields to quickly run tests
• Use debug mode for detailed troubleshooting information
• Export results for documentation and reporting
• Run as administrator for enhanced port scanning capabilities"""
        
        msg = QMessageBox()
        msg.setWindowTitle("Network Toolkit Help")
        msg.setText("Network Toolkit Help")
        msg.setDetailedText(help_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

# =============================================================================
# APPLICATION CLASS
# =============================================================================

class NetworkToolkitApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("Network Toolkit")
        self.app.setApplicationVersion("1.0.0")
        self.main_window = NetworkToolkitWindow()
        
    def run(self):
        self.main_window.show()
        return self.app.exec_()

# =============================================================================
# MAIN FUNCTION
# =============================================================================

def check_requirements():
    """Check if all required modules are available"""
    try:
        import PyQt5
        print("✓ PyQt5 is available")
    except ImportError:
        print("❌ PyQt5 is not installed. Run: pip install PyQt5")
        return False
    
    try:
        import requests
        print("✓ Requests is available")
    except ImportError:
        print("❌ Requests is not installed. Run: pip install requests")
        return False
    
    return True

def main():
    """Main application entry point"""
    print("🌐 Network Toolkit v1.0.0 - Single File Version")
    print("=" * 50)
    
    # Check requirements first
    if not check_requirements():
        print("\n❌ Missing dependencies!")
        print("Please install with: pip install PyQt5 requests")
        input("Press Enter to exit...")
        sys.exit(1)
    
    try:
        print("🚀 Starting Network Toolkit...")
        app = NetworkToolkitApp()
        sys.exit(app.run())
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()