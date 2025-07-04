#!/usr/bin/env python3
"""
Standalone Service Monitor Application
Extracted from SigmaToolkit v1.7.0

A comprehensive service monitoring tool for infrastructure, Microsoft 365, 
cloud services, and custom endpoints with real-time status tracking.
"""

import sys
import threading
import time
import socket
import subprocess
import requests
import json
from datetime import datetime
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QGroupBox, QLineEdit, QPushButton, 
                            QLabel, QGridLayout, QComboBox, QCheckBox, 
                            QTreeWidget, QTreeWidgetItem, QFrame, QTextEdit, 
                            QMessageBox, QFileDialog, QMenu, QAction, QMenuBar)
from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal
from PyQt5.QtGui import QFont, QColor

class Logger(QObject):
    """Simple logger for the standalone application"""
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

class ServiceTools(QObject):
    """Service monitoring tools and functionality"""
    service_checked = pyqtSignal(str, str, float, str)  # name, status, response_time, details
    batch_complete = pyqtSignal()
    result_ready = pyqtSignal(str, str)  # message, level
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.services = {}
        self.last_check_results = {}
        
    def add_service(self, name, url, check_type="http", category="Custom"):
        """Add a service to monitoring"""
        service_id = f"{category}_{name}".replace(" ", "_")
        
        self.services[service_id] = {
            "name": name,
            "url": url,
            "type": check_type,
            "category": category,
            "enabled": True,
            "timeout": 10,
            "added_time": datetime.now().isoformat()
        }
        
        self.logger.debug(f"Added service: {name} ({url}) - Type: {check_type}")
        
    def remove_service(self, name):
        """Remove a service from monitoring"""
        service_to_remove = None
        for service_id, service in self.services.items():
            if service["name"] == name:
                service_to_remove = service_id
                break
                
        if service_to_remove:
            del self.services[service_to_remove]
            if service_to_remove in self.last_check_results:
                del self.last_check_results[service_to_remove]
            self.logger.debug(f"Removed service: {name}")
            
    def get_services_by_category(self):
        """Get services organized by category"""
        categories = {}
        
        for service_id, service in self.services.items():
            category = service["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(service)
            
        return categories
        
    def get_status_summary(self):
        """Get summary of service statuses"""
        summary = {
            "total": len(self.services),
            "healthy": 0,
            "warning": 0,
            "critical": 0
        }
        
        for service_id, result in self.last_check_results.items():
            if result["status"] == "healthy":
                summary["healthy"] += 1
            elif result["status"] == "warning":
                summary["warning"] += 1
            else:
                summary["critical"] += 1
                
        return summary
        
    def check_all_services(self):
        """Check all services"""
        def _check_all():
            self.logger.debug("Starting batch service check")
            
            for service_id, service in self.services.items():
                if service["enabled"]:
                    self._check_single_service(service)
                    time.sleep(0.5)  # Small delay between checks
                    
            self.batch_complete.emit()
            self.result_ready.emit("✅ All services checked", "SUCCESS")
            
        thread = threading.Thread(target=_check_all)
        thread.daemon = True
        thread.start()
        
    def test_single_service(self, name, url, check_type):
        """Test a single service configuration"""
        def _test_service():
            test_service = {
                "name": name,
                "url": url,
                "type": check_type,
                "timeout": 10
            }
            
            self._check_single_service(test_service)
            
        thread = threading.Thread(target=_test_service)
        thread.daemon = True
        thread.start()
        
    def _check_single_service(self, service):
        """Check a single service and emit results"""
        start_time = time.time()
        status = "critical"
        details = ""
        response_time = 0
        
        try:
            if service["type"] == "http":
                status, response_time, details = self._check_http(service["url"], service["timeout"])
            elif service["type"] == "ping":
                status, response_time, details = self._check_ping(service["url"], service["timeout"])
            elif service["type"] == "port":
                status, response_time, details = self._check_port(service["url"], service["timeout"])
            elif service["type"] == "dns":
                status, response_time, details = self._check_dns(service["url"], service["timeout"])
            elif service["type"] == "api":
                status, response_time, details = self._check_api(service["url"], service["timeout"])
                
        except Exception as e:
            status = "critical"
            details = f"Check failed: {str(e)}"
            response_time = 0
            self.logger.error(f"Service check error for {service['name']}: {e}")
            
        # Store result
        service_key = f"{service.get('category', 'Custom')}_{service['name']}".replace(" ", "_")
        
        self.last_check_results[service_key] = {
            "status": status,
            "response_time": response_time,
            "details": details,
            "last_checked": datetime.now().isoformat()
        }
        
        # Emit result
        self.service_checked.emit(service["name"], status, response_time, details)
        
    def _check_http(self, url, timeout):
        """Check HTTP/HTTPS service"""
        try:
            self.logger.debug(f"Checking HTTP: {url}")
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            start_time = time.time()
            response = requests.get(url, timeout=timeout, verify=False, 
                                  headers={'User-Agent': 'ServiceMonitor/1.0'})
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                status = "healthy"
                details = f"HTTP {response.status_code} - OK"
            elif 200 <= response.status_code < 400:
                status = "warning"
                details = f"HTTP {response.status_code} - Redirect/Info"
            else:
                status = "critical"
                details = f"HTTP {response.status_code} - Error"
                
            return status, response_time, details
            
        except requests.exceptions.Timeout:
            return "critical", 0, "Connection timeout"
        except requests.exceptions.ConnectionError:
            return "critical", 0, "Connection failed"
        except requests.exceptions.SSLError:
            return "warning", 0, "SSL certificate issue"
        except Exception as e:
            return "critical", 0, f"HTTP check failed: {str(e)}"
            
    def _check_ping(self, host, timeout):
        """Check ping connectivity"""
        try:
            self.logger.debug(f"Checking ping: {host}")
            
            # Remove protocol if present
            if '://' in host:
                host = urlparse(host).netloc or urlparse(host).path
                
            import platform
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
                
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                # Try to extract actual ping time from output
                output = result.stdout
                if 'time=' in output:
                    try:
                        time_part = output.split('time=')[1].split()[0]
                        if 'ms' in time_part:
                            ping_time = float(time_part.replace('ms', ''))
                            response_time = ping_time
                    except:
                        pass
                        
                if response_time < 100:
                    status = "healthy"
                elif response_time < 500:
                    status = "warning"
                else:
                    status = "critical"
                    
                details = f"Ping successful - {response_time:.1f}ms"
            else:
                status = "critical"
                details = "Ping failed - Host unreachable"
                response_time = 0
                
            return status, response_time, details
            
        except subprocess.TimeoutExpired:
            return "critical", 0, "Ping timeout"
        except Exception as e:
            return "critical", 0, f"Ping check failed: {str(e)}"
            
    def _check_port(self, target, timeout):
        """Check port connectivity"""
        try:
            self.logger.debug(f"Checking port: {target}")
            
            # Parse host:port or URL
            if '://' in target:
                parsed = urlparse(target)
                host = parsed.netloc.split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            elif ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 80  # Default port
                
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000
            sock.close()
            
            if result == 0:
                status = "healthy"
                details = f"Port {port} open on {host}"
            else:
                status = "critical"
                details = f"Port {port} closed on {host}"
                response_time = 0
                
            return status, response_time, details
            
        except socket.timeout:
            return "critical", 0, "Port check timeout"
        except Exception as e:
            return "critical", 0, f"Port check failed: {str(e)}"
            
    def _check_dns(self, domain, timeout):
        """Check DNS resolution"""
        try:
            self.logger.debug(f"Checking DNS: {domain}")
            
            # Remove protocol if present
            if '://' in domain:
                domain = urlparse(domain).netloc or urlparse(domain).path
                
            start_time = time.time()
            ip = socket.gethostbyname(domain)
            response_time = (time.time() - start_time) * 1000
            
            status = "healthy"
            details = f"DNS resolved to {ip}"
            
            return status, response_time, details
            
        except socket.gaierror:
            return "critical", 0, "DNS resolution failed"
        except Exception as e:
            return "critical", 0, f"DNS check failed: {str(e)}"
            
    def _check_api(self, url, timeout):
        """Check API endpoint with custom logic"""
        try:
            self.logger.debug(f"Checking API: {url}")
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            start_time = time.time()
            response = requests.get(url, timeout=timeout, verify=False,
                                  headers={'User-Agent': 'ServiceMonitor/1.0'})
            response_time = (time.time() - start_time) * 1000
            
            # Custom API logic - check for specific response patterns
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for common health check patterns
                if any(keyword in content for keyword in ['ok', 'healthy', 'success', 'up']):
                    status = "healthy"
                    details = f"API healthy - {response.status_code}"
                elif any(keyword in content for keyword in ['error', 'fail', 'down']):
                    status = "critical"
                    details = f"API reports errors - {response.status_code}"
                else:
                    status = "warning"
                    details = f"API responding but status unclear - {response.status_code}"
            else:
                status = "critical"
                details = f"API error - HTTP {response.status_code}"
                
            return status, response_time, details
            
        except requests.exceptions.Timeout:
            return "critical", 0, "API timeout"
        except requests.exceptions.ConnectionError:
            return "critical", 0, "API connection failed"
        except Exception as e:
            return "critical", 0, f"API check failed: {str(e)}"
            
    def export_status_report(self, filepath):
        """Export current status to a report file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("Service Monitor Status Report\n")
                f.write("=" * 40 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                summary = self.get_status_summary()
                f.write("SUMMARY:\n")
                f.write(f"Total Services: {summary['total']}\n")
                f.write(f"Healthy: {summary['healthy']}\n")
                f.write(f"Warning: {summary['warning']}\n")
                f.write(f"Critical: {summary['critical']}\n\n")
                
                categories = self.get_services_by_category()
                
                for category, services in categories.items():
                    f.write(f"\n{category.upper()}:\n")
                    f.write("-" * len(category) + "\n")
                    
                    for service in services:
                        service_key = f"{category}_{service['name']}".replace(" ", "_")
                        result = self.last_check_results.get(service_key, {})
                        
                        status = result.get('status', 'unknown').upper()
                        response_time = result.get('response_time', 0)
                        last_checked = result.get('last_checked', 'Never')
                        
                        f.write(f"  {service['name']}: {status}")
                        if response_time > 0:
                            f.write(f" ({response_time:.0f}ms)")
                        f.write(f" - {service['url']}\n")
                        
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False
            
    def load_services_from_config(self, config_path):
        """Load services from a configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            for service_config in config.get('services', []):
                self.add_service(
                    service_config['name'],
                    service_config['url'],
                    service_config.get('type', 'http'),
                    service_config.get('category', 'Custom')
                )
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return False
            
    def save_services_to_config(self, config_path):
        """Save current services to a configuration file"""
        try:
            config = {
                "services": [
                    {
                        "name": service["name"],
                        "url": service["url"],
                        "type": service["type"],
                        "category": service["category"]
                    }
                    for service in self.services.values()
                ],
                "export_time": datetime.now().isoformat()
            }
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            return False

class ServiceMonitorWindow(QMainWindow):
    """Main window for the service monitor application"""
    
    def __init__(self):
        super().__init__()
        self.logger = Logger()
        self.service_tools = ServiceTools(self.logger)
        self.auto_refresh_timer = QTimer()
        self.config_file_path = "service_config.json"
        self.init_ui()
        self.setup_connections()
        self.load_default_services()
        self.auto_load_config()
        
    def init_ui(self):
        self.setWindowTitle("Service Monitor v1.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Left panel for controls and services
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMinimumWidth(800)
        
        # Service Status Overview Section
        overview_group = QGroupBox("🟢 Service Status Overview")
        overview_layout = QVBoxLayout(overview_group)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("🔄 Refresh All")
        self.test_selected_btn = QPushButton("🧪 Test Selected")
        self.auto_refresh_cb = QCheckBox("Auto-refresh (30s)")
        self.save_config_btn = QPushButton("💾 Save Config")
        self.load_config_btn = QPushButton("📁 Load Config")
        self.add_service_btn = QPushButton("➕ Add Service")
        self.remove_service_btn = QPushButton("🗑️ Remove Service")
        
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.test_selected_btn)
        control_layout.addWidget(self.auto_refresh_cb)
        control_layout.addWidget(self.save_config_btn)
        control_layout.addWidget(self.load_config_btn)
        control_layout.addStretch()
        control_layout.addWidget(self.add_service_btn)
        control_layout.addWidget(self.remove_service_btn)
        
        overview_layout.addLayout(control_layout)
        
        # Service status tree
        self.service_tree = QTreeWidget()
        self.service_tree.setHeaderLabels([
            "Service", "Status", "Response Time", "Last Checked", "Details"
        ])
        self.service_tree.setMinimumHeight(300)
        
        # Enable context menu for individual service actions
        self.service_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.service_tree.customContextMenuRequested.connect(self.show_service_context_menu)
        
        # Style the tree
        self.service_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                border-radius: 6px;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #e9ecef;
            }
            QTreeWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)
        
        overview_layout.addWidget(self.service_tree)
        left_layout.addWidget(overview_group)
        
        # Service Categories Section
        categories_group = QGroupBox("📊 Service Categories")
        categories_layout = QHBoxLayout(categories_group)
        
        # Microsoft 365 Category
        ms365_frame = self.create_category_frame("Microsoft 365", [
            {"name": "Exchange Online", "url": "https://outlook.office365.com"},
            {"name": "SharePoint Online", "url": "https://login.microsoftonline.com"},
            {"name": "Teams", "url": "https://teams.microsoft.com"},
            {"name": "OneDrive", "url": "https://onedrive.live.com"}
        ])
        
        # Infrastructure Category
        infra_frame = self.create_category_frame("Infrastructure", [
            {"name": "Google DNS", "url": "8.8.8.8"},
            {"name": "Cloudflare DNS", "url": "1.1.1.1"},
            {"name": "Quad9 DNS", "url": "9.9.9.9"},
            {"name": "OpenDNS", "url": "208.67.222.222"}
        ])
        
        # Cloud Providers Category
        cloud_frame = self.create_category_frame("Cloud Providers", [
            {"name": "AWS Console", "url": "https://console.aws.amazon.com"},
            {"name": "Azure Portal", "url": "https://portal.azure.com"},
            {"name": "Google Cloud", "url": "https://console.cloud.google.com"},
            {"name": "Cloudflare", "url": "https://dash.cloudflare.com"}
        ])
        
        categories_layout.addWidget(ms365_frame)
        categories_layout.addWidget(infra_frame)
        categories_layout.addWidget(cloud_frame)
        categories_layout.addStretch()
        
        left_layout.addWidget(categories_group)
        
        # Custom Services Section
        custom_group = QGroupBox("🔧 Custom Service Management")
        custom_layout = QGridLayout(custom_group)
        
        custom_layout.addWidget(QLabel("Service Name:"), 0, 0)
        self.service_name_edit = QLineEdit()
        self.service_name_edit.setPlaceholderText("My Custom Service")
        custom_layout.addWidget(self.service_name_edit, 0, 1)
        
        custom_layout.addWidget(QLabel("URL/Endpoint:"), 0, 2)
        self.service_url_edit = QLineEdit()
        self.service_url_edit.setPlaceholderText("https://example.com/api/health")
        custom_layout.addWidget(self.service_url_edit, 0, 3)
        
        custom_layout.addWidget(QLabel("Check Type:"), 1, 0)
        self.check_type_combo = QComboBox()
        self.check_type_combo.addItems([
            "HTTP Status (200 OK)",
            "Ping Test",
            "Port Check",
            "DNS Resolution",
            "Custom API Response"
        ])
        custom_layout.addWidget(self.check_type_combo, 1, 1)
        
        custom_layout.addWidget(QLabel("Category:"), 1, 2)
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.addItems([
            "Custom Services",
            "Internal Tools",
            "External APIs",
            "Infrastructure",
            "Monitoring"
        ])
        custom_layout.addWidget(self.category_combo, 1, 3)
        
        self.add_custom_btn = QPushButton("➕ Add Custom Service")
        self.test_custom_btn = QPushButton("🧪 Test Service")
        
        custom_layout.addWidget(self.add_custom_btn, 2, 0, 1, 2)
        custom_layout.addWidget(self.test_custom_btn, 2, 2, 1, 2)
        
        left_layout.addWidget(custom_group)
        
        # Status Summary Section
        summary_group = QGroupBox("📈 Status Summary")
        summary_layout = QHBoxLayout(summary_group)
        
        # Status indicators
        self.total_services_label = QLabel("Total Services: 0")
        self.healthy_services_label = QLabel("🟢 Healthy: 0")
        self.warning_services_label = QLabel("🟡 Warning: 0")
        self.critical_services_label = QLabel("🔴 Critical: 0")
        
        for label in [self.total_services_label, self.healthy_services_label, 
                     self.warning_services_label, self.critical_services_label]:
            label.setFont(QFont("Arial", 12, QFont.Bold))
            label.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px; margin: 2px;")
        
        self.healthy_services_label.setStyleSheet(
            "padding: 8px; border: 2px solid #28a745; border-radius: 4px; "
            "background-color: #d4edda; color: #155724; font-weight: bold;"
        )
        self.warning_services_label.setStyleSheet(
            "padding: 8px; border: 2px solid #ffc107; border-radius: 4px; "
            "background-color: #fff3cd; color: #856404; font-weight: bold;"
        )
        self.critical_services_label.setStyleSheet(
            "padding: 8px; border: 2px solid #dc3545; border-radius: 4px; "
            "background-color: #f8d7da; color: #721c24; font-weight: bold;"
        )
        
        summary_layout.addWidget(self.total_services_label)
        summary_layout.addWidget(self.healthy_services_label)
        summary_layout.addWidget(self.warning_services_label)
        summary_layout.addWidget(self.critical_services_label)
        summary_layout.addStretch()
        
        left_layout.addWidget(summary_group)
        
        # Right panel for output and logs
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_panel.setMinimumWidth(400)
        
        # Output header
        output_header = QLabel("📊 Real-time Results & Logs")
        output_header.setFont(QFont("Arial", 12, QFont.Bold))
        output_header.setStyleSheet("color: #0078d4; padding: 5px;")
        right_layout.addWidget(output_header)
        
        # Output controls
        output_controls_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Output")
        self.copy_btn = QPushButton("Copy Output")
        self.debug_btn = QPushButton("Toggle Debug")
        self.debug_btn.setCheckable(True)
        self.export_btn = QPushButton("Export Report")
        
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
        
        output_controls_layout.addWidget(self.clear_btn)
        output_controls_layout.addWidget(self.copy_btn)
        output_controls_layout.addWidget(self.debug_btn)
        output_controls_layout.addWidget(self.export_btn)
        output_controls_layout.addStretch()
        
        right_layout.addLayout(output_controls_layout)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Consolas", 11))
        self.output_text.setReadOnly(True)
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
        
        right_layout.addWidget(self.output_text)
        
        # Add panels to main layout
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)
        
        # Setup menu
        self.setup_menu()
        
        # Style the buttons
        self.style_buttons()
        
    def setup_menu(self):
        """Setup application menu"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        load_config_action = QAction('Load Configuration', self)
        load_config_action.triggered.connect(self.load_service_config)
        file_menu.addAction(load_config_action)
        
        save_config_action = QAction('Save Configuration', self)
        save_config_action.triggered.connect(self.save_service_config)
        file_menu.addAction(save_config_action)
        
        file_menu.addSeparator()
        
        export_report_action = QAction('Export Status Report', self)
        export_report_action.triggered.connect(self.export_service_report)
        file_menu.addAction(export_report_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        refresh_all_action = QAction('Refresh All Services', self)
        refresh_all_action.setShortcut('F5')
        refresh_all_action.triggered.connect(self.refresh_all_services)
        tools_menu.addAction(refresh_all_action)
        
        toggle_auto_refresh_action = QAction('Toggle Auto-refresh', self)
        toggle_auto_refresh_action.triggered.connect(self.toggle_auto_refresh_menu)
        tools_menu.addAction(toggle_auto_refresh_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_category_frame(self, category_name, services):
        """Create a frame for a service category"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Box)
        frame.setStyleSheet("""
            QFrame {
                border: 2px solid #dee2e6;
                border-radius: 8px;
                background-color: #f8f9fa;
                margin: 4px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        # Category header
        header = QLabel(f"📁 {category_name}")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        header.setStyleSheet("color: #0078d4; padding: 4px;")
        layout.addWidget(header)
        
        # Service buttons
        for service in services:
            btn = QPushButton(f"🔗 {service['name']}")
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 6px 10px;
                    margin: 2px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    background-color: white;
                }
                QPushButton:hover {
                    background-color: #e3f2fd;
                    border-color: #0078d4;
                }
            """)
            btn.clicked.connect(
                lambda checked, name=service['name'], url=service['url']: 
                self.quick_add_service(name, url, category_name)
            )
            layout.addWidget(btn)
        
        # Quick add all button
        add_all_btn = QPushButton(f"➕ Add All {category_name}")
        add_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 4px;
                font-weight: bold;
                margin-top: 5px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
        """)
        add_all_btn.clicked.connect(
            lambda: self.add_category_services(category_name, services)
        )
        layout.addWidget(add_all_btn)
        
        return frame
        
    def style_buttons(self):
        """Style the main buttons"""
        # Main action buttons
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
        
        # Test selected button style (special orange color)
        self.test_selected_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff8c00;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #e67300;
            }
            QPushButton:pressed {
                background-color: #cc6600;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        # Apply main style to primary buttons
        for btn in [self.refresh_btn, self.add_custom_btn, self.test_custom_btn]:
            btn.setStyleSheet(main_button_style)
            
        # Config buttons style
        for btn in [self.save_config_btn, self.load_config_btn]:
            btn.setStyleSheet("""
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
            """)
            
        # Management buttons style
        for btn in [self.add_service_btn, self.remove_service_btn]:
            btn.setStyleSheet("""
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
                QPushButton:pressed {
                    background-color: #1e7e34;
                }
            """)
        
    def setup_connections(self):
        """Setup signal connections"""
        # Main control connections
        self.refresh_btn.clicked.connect(self.refresh_all_services)
        self.test_selected_btn.clicked.connect(self.test_selected_service)
        self.auto_refresh_cb.toggled.connect(self.toggle_auto_refresh)
        self.save_config_btn.clicked.connect(self.save_service_config)
        self.load_config_btn.clicked.connect(self.load_service_config)
        self.add_service_btn.clicked.connect(self.add_service_dialog)
        self.remove_service_btn.clicked.connect(self.remove_service)
        
        # Custom service connections
        self.add_custom_btn.clicked.connect(self.add_custom_service)
        self.test_custom_btn.clicked.connect(self.test_custom_service)
        
        # Output controls
        self.clear_btn.clicked.connect(self.clear_output)
        self.copy_btn.clicked.connect(self.copy_output)
        self.debug_btn.toggled.connect(self.toggle_debug)
        self.export_btn.clicked.connect(self.export_service_report)
        
        # Service tools connections
        self.service_tools.service_checked.connect(self.update_service_status)
        self.service_tools.batch_complete.connect(self.update_summary)
        
        # Auto-refresh timer
        self.auto_refresh_timer.timeout.connect(self.refresh_all_services)
        
        # Tree selection
        self.service_tree.itemSelectionChanged.connect(self.on_service_selected)
        
        # Logger connection
        self.logger.message_logged.connect(self.append_output)
        
        # Show welcome message
        QTimer.singleShot(1000, self.show_welcome_message)
        
    def show_welcome_message(self):
        """Show welcome message"""
        self.logger.info("🎉 Welcome to Service Monitor v1.0!")
        self.logger.info("🟢 Real-time monitoring for Microsoft 365, cloud services, and custom endpoints")
        self.logger.info("💡 Ready for comprehensive infrastructure monitoring!")
        
    def load_default_services(self):
        """Load some default services for demonstration"""
        default_services = [
            {
                "name": "Google DNS",
                "url": "8.8.8.8",
                "type": "ping",
                "category": "Infrastructure"
            },
            {
                "name": "Cloudflare DNS",
                "url": "1.1.1.1", 
                "type": "ping",
                "category": "Infrastructure"
            }
        ]
        
        for service in default_services:
            self.service_tools.add_service(
                service["name"], service["url"], 
                service["type"], service["category"]
            )
        
        self.update_service_tree()
        
    def quick_add_service(self, name, url, category):
        """Quick add a service from category buttons"""
        self.logger.info(f"Adding {name} to monitoring...")
        self.service_tools.add_service(name, url, "http", category)
        self.update_service_tree()
        self.auto_save_config()
        self.logger.success(f"✅ {name} added to service monitoring")
        
    def add_category_services(self, category_name, services):
        """Add all services from a category"""
        self.logger.info(f"Adding all {category_name} services...")
        
        for service in services:
            self.service_tools.add_service(
                service["name"], service["url"], "http", category_name
            )
        
        self.update_service_tree()
        self.auto_save_config()
        self.logger.success(f"✅ Added all {category_name} services ({len(services)} total)")
        
    def add_custom_service(self):
        """Add custom service from the form"""
        name = self.service_name_edit.text().strip()
        url = self.service_url_edit.text().strip()
        check_type = self.check_type_combo.currentText().lower()
        category = self.category_combo.currentText()
        
        if not name or not url:
            self.logger.error("Please enter both service name and URL")
            return
            
        # Convert check type to internal format
        type_mapping = {
            "http status (200 ok)": "http",
            "ping test": "ping",
            "port check": "port",
            "dns resolution": "dns",
            "custom api response": "api"
        }
        
        check_type_key = type_mapping.get(check_type, "http")
        
        self.logger.info(f"Adding custom service: {name}")
        self.service_tools.add_service(name, url, check_type_key, category)
        
        # Clear form
        self.service_name_edit.clear()
        self.service_url_edit.clear()
        
        self.update_service_tree()
        self.auto_save_config()
        self.logger.success(f"✅ Custom service '{name}' added successfully")
        
    def test_custom_service(self):
        """Test the custom service configuration"""
        name = self.service_name_edit.text().strip() or "Test Service"
        url = self.service_url_edit.text().strip()
        check_type = self.check_type_combo.currentText().lower()
        
        if not url:
            self.logger.error("Please enter a URL to test")
            return
            
        self.logger.info(f"Testing service configuration: {url}")
        
        # Convert check type
        type_mapping = {
            "http status (200 ok)": "http",
            "ping test": "ping", 
            "port check": "port",
            "dns resolution": "dns",
            "custom api response": "api"
        }
        
        check_type_key = type_mapping.get(check_type, "http")
        self.service_tools.test_single_service(name, url, check_type_key)
        
    def update_service_tree(self):
        """Update the service tree display"""
        self.service_tree.clear()
        
        services_by_category = self.service_tools.get_services_by_category()
        
        for category, services in services_by_category.items():
            category_item = QTreeWidgetItem([f"📁 {category}", "", "", "", ""])
            category_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            
            for service in services:
                service_item = QTreeWidgetItem([
                    service["name"],
                    "🔄 Checking...",
                    "N/A",
                    "Never",
                    service["url"]
                ])
                category_item.addChild(service_item)
            
            self.service_tree.addTopLevelItem(category_item)
            category_item.setExpanded(True)
        
        self.update_summary()
        
    def update_service_status(self, service_name, status, response_time, details):
        """Update individual service status in the tree"""
        # Find the service item in the tree
        root = self.service_tree.invisibleRootItem()
        
        for i in range(root.childCount()):
            category_item = root.child(i)
            
            for j in range(category_item.childCount()):
                service_item = category_item.child(j)
                
                if service_item.text(0) == service_name:
                    # Update status with icon
                    if status == "healthy":
                        status_text = "🟢 Online"
                        service_item.setBackground(1, QColor(212, 237, 218))
                    elif status == "warning":
                        status_text = "🟡 Warning"
                        service_item.setBackground(1, QColor(255, 243, 205))
                    else:
                        status_text = "🔴 Offline"
                        service_item.setBackground(1, QColor(248, 215, 218))
                    
                    service_item.setText(1, status_text)
                    service_item.setText(2, f"{response_time:.0f}ms" if response_time > 0 else "N/A")
                    service_item.setText(3, self.get_current_time())
                    
                    if details:
                        service_item.setToolTip(4, details)
                    
                    break
        
        self.update_summary()
        
    def get_current_time(self):
        """Get current time string"""
        return datetime.now().strftime("%H:%M:%S")
        
    def update_summary(self):
        """Update the status summary labels"""
        summary = self.service_tools.get_status_summary()
        
        self.total_services_label.setText(f"Total Services: {summary['total']}")
        self.healthy_services_label.setText(f"🟢 Healthy: {summary['healthy']}")
        self.warning_services_label.setText(f"🟡 Warning: {summary['warning']}")
        self.critical_services_label.setText(f"🔴 Critical: {summary['critical']}")
        
    def refresh_all_services(self):
        """Refresh all services"""
        self.logger.info("🔄 Refreshing all service statuses...")
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("🔄 Refreshing...")
        
        self.service_tools.check_all_services()
        
        # Re-enable button after delay
        QTimer.singleShot(5000, self.restore_refresh_button)
        
    def restore_refresh_button(self):
        """Restore refresh button state"""
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("🔄 Refresh All")
        
    def toggle_auto_refresh(self, enabled):
        """Toggle auto-refresh functionality"""
        if enabled:
            self.auto_refresh_timer.start(30000)  # 30 seconds
            self.logger.info("🔄 Auto-refresh enabled (30 seconds)")
        else:
            self.auto_refresh_timer.stop()
            self.logger.info("⏹️ Auto-refresh disabled")
            
    def toggle_auto_refresh_menu(self):
        """Toggle auto-refresh from menu"""
        current_state = self.auto_refresh_cb.isChecked()
        self.auto_refresh_cb.setChecked(not current_state)
        
    def add_service_dialog(self):
        """Show dialog to add a new service"""
        self.logger.info("💡 Use the Custom Service Management section to add services")
        
    def remove_service(self):
        """Remove selected service"""
        selected_items = self.service_tree.selectedItems()
        if not selected_items:
            self.logger.warning("Please select a service to remove")
            return
            
        item = selected_items[0]
        if item.parent():  # Make sure it's a service, not a category
            service_name = item.text(0)
            
            reply = QMessageBox.question(
                self, 
                "Remove Service",
                f"Are you sure you want to remove '{service_name}' from monitoring?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.service_tools.remove_service(service_name)
                self.update_service_tree()
                self.auto_save_config()
                self.logger.success(f"✅ Service '{service_name}' removed from monitoring")
        else:
            self.logger.warning("Please select a service (not a category)")
            
    def on_service_selected(self):
        """Handle service selection in tree"""
        selected_items = self.service_tree.selectedItems()
        has_service_selected = selected_items and selected_items[0].parent() is not None
        
        # Enable/disable Test Selected button based on selection
        self.test_selected_btn.setEnabled(has_service_selected)
        
        if has_service_selected:
            service_name = selected_items[0].text(0)
            self.logger.info(f"Selected service: {service_name}")
            
    def test_selected_service(self):
        """Test only the selected service"""
        selected_items = self.service_tree.selectedItems()
        if not selected_items:
            self.logger.warning("Please select a service to test")
            return
            
        item = selected_items[0]
        if not item.parent():  # Make sure it's a service, not a category
            self.logger.warning("Please select a service (not a category)")
            return
            
        service_name = item.text(0)
        self.logger.info(f"🧪 Testing selected service: {service_name}")
        
        # Find the service in our services dictionary
        service_to_test = None
        for service_id, service in self.service_tools.services.items():
            if service["name"] == service_name:
                service_to_test = service
                break
                
        if service_to_test:
            self.test_selected_btn.setEnabled(False)
            self.test_selected_btn.setText("🧪 Testing...")
            
            # Update the service status to show it's being tested
            item.setText(1, "🔄 Testing...")
            item.setBackground(1, QColor(255, 255, 224))  # Light yellow background
            
            # Test the single service
            def _test_single():
                self.service_tools._check_single_service(service_to_test)
                
            import threading
            thread = threading.Thread(target=_test_single)
            thread.daemon = True
            thread.start()
            
            # Re-enable button after delay
            QTimer.singleShot(5000, self.restore_test_selected_button)
        else:
            self.logger.error(f"Could not find service configuration for: {service_name}")
            
    def restore_test_selected_button(self):
        """Restore test selected button state"""
        self.test_selected_btn.setEnabled(True)
        self.test_selected_btn.setText("🧪 Test Selected")
        
    def show_service_context_menu(self, position):
        """Show context menu for service tree items"""
        item = self.service_tree.itemAt(position)
        if not item:
            return
            
        menu = QMenu()
        
        if item.parent():  # It's a service item
            service_name = item.text(0)
            
            # Test service action
            test_action = QAction("🧪 Test This Service", self)
            test_action.triggered.connect(lambda: self.test_single_service_by_name(service_name))
            menu.addAction(test_action)
            
            menu.addSeparator()
            
            # Copy service info action
            copy_action = QAction("📋 Copy Service Info", self)
            copy_action.triggered.connect(lambda: self.copy_service_info(service_name))
            menu.addAction(copy_action)
            
            menu.addSeparator()
            
            # Remove service action
            remove_action = QAction("🗑️ Remove Service", self)
            remove_action.triggered.connect(lambda: self.remove_specific_service(service_name))
            menu.addAction(remove_action)
            
        else:  # It's a category item
            category_name = item.text(0).replace("📁 ", "")
            
            # Test all services in category
            test_category_action = QAction(f"🧪 Test All {category_name}", self)
            test_category_action.triggered.connect(lambda: self.test_category_services(category_name))
            menu.addAction(test_category_action)
            
            # Expand/collapse category
            if item.isExpanded():
                collapse_action = QAction("📁 Collapse Category", self)
                collapse_action.triggered.connect(lambda: item.setExpanded(False))
                menu.addAction(collapse_action)
            else:
                expand_action = QAction("📂 Expand Category", self)
                expand_action.triggered.connect(lambda: item.setExpanded(True))
                menu.addAction(expand_action)
        
        # Show the context menu
        menu.exec_(self.service_tree.mapToGlobal(position))
        
    def test_single_service_by_name(self, service_name):
        """Test a single service by name (used by context menu)"""
        # Find and select the service in the tree first
        root = self.service_tree.invisibleRootItem()
        for i in range(root.childCount()):
            category_item = root.child(i)
            for j in range(category_item.childCount()):
                service_item = category_item.child(j)
                if service_item.text(0) == service_name:
                    self.service_tree.setCurrentItem(service_item)
                    self.test_selected_service()
                    return
        
        self.logger.error(f"Could not find service: {service_name}")
        
    def copy_service_info(self, service_name):
        """Copy service information to clipboard"""
        # Find the service configuration
        service_config = None
        for service_id, service in self.service_tools.services.items():
            if service["name"] == service_name:
                service_config = service
                break
                
        if service_config:
            clipboard = QApplication.clipboard()
            
            # Get the latest status
            service_key = f"{service_config['category']}_{service_name}".replace(" ", "_")
            result = self.service_tools.last_check_results.get(service_key, {})
            
            service_info = f"""Service: {service_name}
URL: {service_config['url']}
Type: {service_config['type']}
Category: {service_config['category']}
Status: {result.get('status', 'Unknown')}
Response Time: {result.get('response_time', 0):.0f}ms
Last Checked: {result.get('last_checked', 'Never')}
Details: {result.get('details', 'N/A')}"""
            
            clipboard.setText(service_info)
            self.logger.success(f"📋 Service info copied for: {service_name}")
        else:
            self.logger.error(f"Could not find service configuration for: {service_name}")
            
    def remove_specific_service(self, service_name):
        """Remove a specific service"""
        reply = QMessageBox.question(
            self, 
            "Remove Service",
            f"Are you sure you want to remove '{service_name}' from monitoring?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.service_tools.remove_service(service_name)
            self.update_service_tree()
            self.auto_save_config()
            self.logger.success(f"✅ Service '{service_name}' removed from monitoring")
            
    def test_category_services(self, category_name):
        """Test all services in a specific category"""
        self.logger.info(f"🧪 Testing all services in category: {category_name}")
        
        # Find all services in the category
        services_to_test = []
        for service_id, service in self.service_tools.services.items():
            if service["category"] == category_name and service["enabled"]:
                services_to_test.append(service)
        
        if not services_to_test:
            self.logger.warning(f"No enabled services found in category: {category_name}")
            return
            
        self.logger.info(f"Testing {len(services_to_test)} services in {category_name}...")
        
        # Test each service in the category
        def _test_category():
            for service in services_to_test:
                self.service_tools._check_single_service(service)
                import time
                time.sleep(0.5)  # Small delay between tests
                
        import threading
        thread = threading.Thread(target=_test_category)
        thread.daemon = True
        thread.start()
        
    def auto_save_config(self):
        """Automatically save the current configuration"""
        try:
            success = self.service_tools.save_services_to_config(self.config_file_path)
            if success:
                self.logger.debug(f"Configuration auto-saved to {self.config_file_path}")
            else:
                self.logger.debug("Auto-save failed")
        except Exception as e:
            self.logger.debug(f"Auto-save error: {str(e)}")
            
    def auto_load_config(self):
        """Automatically load configuration if it exists"""
        try:
            import os
            if os.path.exists(self.config_file_path):
                success = self.service_tools.load_services_from_config(self.config_file_path)
                if success:
                    self.update_service_tree()
                    self.logger.info(f"📁 Loaded previous configuration ({len(self.service_tools.services)} services)")
                else:
                    self.logger.debug("Auto-load failed")
            else:
                self.logger.debug("No previous configuration found")
        except Exception as e:
            self.logger.debug(f"Auto-load error: {str(e)}")
            
    def save_service_config(self):
        """Save service configuration to file with dialog"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Service Configuration",
                f"service_config_{self.get_current_time().replace(':', '-')}.json",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                success = self.service_tools.save_services_to_config(file_path)
                if success:
                    self.logger.success(f"💾 Configuration saved to: {file_path}")
                    # Also update the default config file
                    self.service_tools.save_services_to_config(self.config_file_path)
                else:
                    self.logger.error("Failed to save configuration")
                    
        except Exception as e:
            self.logger.error(f"Save configuration failed: {str(e)}")
            
    def load_service_config(self):
        """Load service configuration from file with dialog"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Load Service Configuration",
                "",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                # Ask if user wants to replace current services or add to them
                reply = QMessageBox.question(
                    self,
                    "Load Configuration",
                    "Do you want to replace current services with the loaded configuration?\n\n"
                    "Choose 'Yes' to replace all services\n"
                    "Choose 'No' to add to existing services",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Cancel:
                    return
                    
                if reply == QMessageBox.Yes:
                    # Clear existing services
                    self.service_tools.services.clear()
                    self.service_tools.last_check_results.clear()
                    
                success = self.service_tools.load_services_from_config(file_path)
                if success:
                    self.update_service_tree()
                    self.auto_save_config()  # Save to default config
                    action = "replaced" if reply == QMessageBox.Yes else "added to"
                    self.logger.success(f"📁 Configuration loaded and {action} current services")
                else:
                    self.logger.error("Failed to load configuration")
                    
        except Exception as e:
            self.logger.error(f"Load configuration failed: {str(e)}")
            
    def export_service_report(self):
        """Export service monitoring report"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Service Report", 
                f"service_status_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                success = self.service_tools.export_status_report(file_path)
                if success:
                    self.logger.success(f"Service report exported to: {file_path}")
                else:
                    self.logger.error("Failed to export service report")
                    
        except Exception as e:
            self.logger.error(f"Export service report failed: {str(e)}")
            
    def append_output(self, message):
        """Append message to output text area"""
        self.output_text.append(message)
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        self.output_text.setTextCursor(cursor)
        
    def clear_output(self):
        """Clear output text area"""
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
        QMessageBox.about(self, "About Service Monitor", 
                         "Service Monitor v1.0\n\n"
                         "Real-time infrastructure monitoring tool\n"
                         "Extracted from SigmaToolkit v1.7.0\n\n"
                         "Features:\n"
                         "• Microsoft 365 service monitoring\n"
                         "• Cloud provider status checking\n"
                         "• Custom service endpoint monitoring\n"
                         "• Real-time status tracking with visual indicators\n"
                         "• Auto-refresh capability for continuous monitoring\n"
                         "• Export status reports for documentation\n"
                         "• Configuration save/load for backup and sharing\n\n"
                         "Created for efficient infrastructure monitoring workflows.")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Service Monitor")
    app.setApplicationVersion("1.0")
    
    # Apply application-wide styles
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f5f5f5;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #cccccc;
            border-radius: 8px;
            margin-top: 1ex;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QLineEdit {
            padding: 8px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 12px;
        }
        QLineEdit:focus {
            border-color: #0078d4;
        }
        QComboBox {
            padding: 8px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 12px;
        }
        QComboBox:focus {
            border-color: #0078d4;
        }
        QCheckBox {
            font-size: 12px;
            font-weight: bold;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
        }
        QCheckBox::indicator:unchecked {
            border: 2px solid #ddd;
            border-radius: 3px;
            background-color: white;
        }
        QCheckBox::indicator:checked {
            border: 2px solid #0078d4;
            border-radius: 3px;
            background-color: #0078d4;
            image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEwIDNMNC41IDguNUwyIDYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=);
        }
    """)
    
    # Create and show main window
    window = ServiceMonitorWindow()
    window.show()
    
    # Run application
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())