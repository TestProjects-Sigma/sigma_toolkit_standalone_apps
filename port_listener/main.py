#!/usr/bin/env python3
"""
Sigma Port Listener - Standalone Network Testing Tool
A standalone PyQt5-based port listener for firewall testing and connection monitoring.

Author: Sigma
Version: 1.0.0
License: MIT
"""

import sys
import socket
import threading
import time
import ctypes
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QGroupBox, 
                            QFrame, QMessageBox, QCheckBox, QSpinBox, QComboBox,
                            QWidget)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, QObject, Qt
from PyQt5.QtGui import QFont, QIcon


class PortListenerTools(QObject):
    """Core port listener functionality"""
    connection_received = pyqtSignal(str, str)  # client_ip, timestamp
    error_occurred = pyqtSignal(str)
    status_changed = pyqtSignal(str)  # uptime
    
    def __init__(self):
        super().__init__()
        self.listening = False
        self.socket = None
        self.listen_thread = None
        self.start_time = None
        self.connection_count = 0
        self.last_client_ip = None
        
        # Timer for uptime updates
        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        
    def start_listening(self, ip, port, response_type="HTTP OK"):
        """Start listening on the specified IP and port"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(1.0)  # Allow checking for stop condition
            
            bind_ip = "" if ip == "0.0.0.0" else ip
            self.socket.bind((bind_ip, port))
            self.socket.listen(5)
            
            self.listening = True
            self.start_time = datetime.now()
            self.connection_count = 0
            self.response_type = response_type
            
            # Start listening thread
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()
            
            # Start uptime timer
            self.uptime_timer.start(1000)  # Update every second
            
            print(f"Port listener started on {ip}:{port}")
            return True
            
        except Exception as e:
            self.error_occurred.emit(str(e))
            print(f"Failed to start port listener: {str(e)}")
            return False
            
    def stop_listening(self):
        """Stop the port listener"""
        try:
            self.listening = False
            self.uptime_timer.stop()
            
            if self.socket:
                self.socket.close()
                self.socket = None
                
            if self.listen_thread and self.listen_thread.is_alive():
                self.listen_thread.join(timeout=3)
                
            print("Port listener stopped")
            
        except Exception as e:
            self.error_occurred.emit(str(e))
            print(f"Error stopping port listener: {str(e)}")
            
    def _listen_loop(self):
        """Main listening loop"""
        while self.listening and self.socket:
            try:
                conn, addr = self.socket.accept()
                self.connection_count += 1
                self.last_client_ip = addr[0]
                
                # Handle the connection
                self._handle_connection(conn, addr)
                
                # Emit signal
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.connection_received.emit(addr[0], timestamp)
                
            except socket.timeout:
                continue  # Check if we should keep listening
            except Exception as e:
                if self.listening:  # Only log if we're supposed to be listening
                    self.error_occurred.emit(f"Connection handling error: {str(e)}")
                break
                
    def _handle_connection(self, conn, addr):
        """Handle an individual connection"""
        try:
            # Receive any data (optional)
            try:
                data = conn.recv(1024)
                if data:
                    print(f"Received data from {addr[0]}: {data[:100]}")
            except:
                pass
                
            # Send response based on type
            if self.response_type == "HTTP OK":
                response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n\r\nPort test successful!"
                conn.send(response)
            elif self.response_type == "Echo":
                if data:
                    conn.send(b"ECHO: " + data)
                else:
                    conn.send(b"ECHO: No data received")
            # Silent mode sends no response
            
        except Exception as e:
            print(f"Error handling connection from {addr[0]}: {str(e)}")
        finally:
            try:
                conn.close()
            except:
                pass
                
    def test_connection(self, ip, port):
        """Test connection to the specified IP and port"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            
            result = test_socket.connect_ex((ip, port))
            test_socket.close()
            
            return result == 0
            
        except Exception as e:
            print(f"Test connection error: {str(e)}")
            return False
            
    def get_statistics(self):
        """Get current statistics"""
        return {
            'connections': self.connection_count,
            'last_client': self.last_client_ip,
            'uptime': self._get_uptime_string(),
            'listening': self.listening
        }
        
    def update_uptime(self):
        """Update uptime display"""
        if self.listening and self.start_time:
            uptime = self._get_uptime_string()
            self.status_changed.emit(uptime)
            
    def _get_uptime_string(self):
        """Get formatted uptime string"""
        if not self.start_time:
            return "00:00:00"
            
        uptime = datetime.now() - self.start_time
        hours = int(uptime.total_seconds() // 3600)
        minutes = int((uptime.total_seconds() % 3600) // 60)
        seconds = int(uptime.total_seconds() % 60)
        
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class PortListenerApp(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.port_tools = PortListenerTools()
        self.is_listening = False
        self.init_ui()
        self.setup_connections()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Sigma Port Listener v1.0.0")
        self.setGeometry(100, 100, 800, 700)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Title
        title_label = QLabel("🔌 Sigma Port Listener")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setStyleSheet("color: #0078d4; padding: 15px; text-align: center;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel("Professional network testing tool for firewall validation and connection monitoring")
        desc_label.setFont(QFont("Arial", 11))
        desc_label.setStyleSheet("color: #666; padding: 5px; text-align: center;")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # Firewall Warning Panel
        self.create_warning_panel(layout)
        
        # Configuration Panel
        self.create_config_panel(layout)
        
        # Control Panel
        self.create_control_panel(layout)
        
        # Status Panel
        self.create_status_panel(layout)
        
        # Connection Log Panel
        self.create_log_panel(layout)
        
        layout.addStretch()
        central_widget.setLayout(layout)
        
    def create_warning_panel(self, layout):
        """Create firewall warning panel"""
        warning_group = QGroupBox("⚠️ Important Information")
        warning_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ffc107;
                border-radius: 5px;
                margin: 5px 0px;
                background-color: #fff3cd;
                color: #856404;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        warning_layout = QVBoxLayout()
        
        warning_text = QLabel(
            "• Ensure Windows Firewall allows inbound connections on the specified port\n"
            "• Ports below 1024 require Administrator privileges\n" 
            "• You may need to create a firewall rule or run as administrator\n"
            "• Test with: telnet your-server-ip port-number or curl http://your-server-ip:port"
        )
        warning_text.setStyleSheet("color: #856404; font-weight: normal; padding: 5px;")
        warning_text.setWordWrap(True)
        
        warning_layout.addWidget(warning_text)
        warning_group.setLayout(warning_layout)
        layout.addWidget(warning_group)
        
    def create_config_panel(self, layout):
        """Create configuration panel"""
        config_group = QGroupBox("🔧 Configuration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #007bff;
                border-radius: 5px;
                margin: 5px 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        config_layout = QVBoxLayout()
        
        # IP Address Configuration
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setToolTip("Use 0.0.0.0 to listen on all interfaces, or specify a specific IP")
        self.ip_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        ip_layout.addWidget(self.ip_input)
        config_layout.addLayout(ip_layout)
        
        # Port Configuration
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("8080")
        self.port_input.setToolTip("Port to listen on (1-65535). Ports below 1024 require admin privileges")
        self.port_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        port_layout.addWidget(self.port_input)
        port_layout.addStretch()
        config_layout.addLayout(port_layout)
        
        # Response Type
        response_layout = QHBoxLayout()
        response_layout.addWidget(QLabel("Response Type:"))
        self.response_combo = QComboBox()
        self.response_combo.addItems(["HTTP OK", "Echo", "Silent"])
        self.response_combo.setToolTip("Type of response to send to connecting clients")
        self.response_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        response_layout.addWidget(self.response_combo)
        response_layout.addStretch()
        config_layout.addLayout(response_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
    def create_control_panel(self, layout):
        """Create control panel"""
        control_group = QGroupBox("🎮 Controls")
        control_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #28a745;
                border-radius: 5px;
                margin: 5px 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        control_layout = QVBoxLayout()
        
        # Button and status layout
        button_layout = QHBoxLayout()
        
        # Start/Stop button
        self.start_stop_btn = QPushButton("🚀 Start Listening")
        self.start_stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)
        
        # Test button
        self.test_btn = QPushButton("🧪 Test Connection")
        self.test_btn.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
            QPushButton:pressed {
                background-color: #117a8b;
            }
        """)
        
        button_layout.addWidget(self.start_stop_btn)
        button_layout.addWidget(self.test_btn)
        button_layout.addStretch()
        
        control_layout.addLayout(button_layout)
        
        # Status display
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Ready to start")
        self.status_label.setStyleSheet("color: #007bff; font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        control_layout.addLayout(status_layout)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
    def create_status_panel(self, layout):
        """Create status information panel"""
        status_group = QGroupBox("📊 Connection Statistics")
        status_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #6f42c1;
                border-radius: 5px;
                margin: 5px 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        stats_layout = QHBoxLayout()
        
        # Connection count
        self.connection_count_label = QLabel("Connections: 0")
        self.connection_count_label.setStyleSheet("font-weight: bold; color: #6f42c1; font-size: 12px;")
        
        # Last connection
        self.last_connection_label = QLabel("Last: None")
        self.last_connection_label.setStyleSheet("font-weight: bold; color: #6f42c1; font-size: 12px;")
        
        # Uptime
        self.uptime_label = QLabel("Uptime: 00:00:00")
        self.uptime_label.setStyleSheet("font-weight: bold; color: #6f42c1; font-size: 12px;")
        
        stats_layout.addWidget(self.connection_count_label)
        stats_layout.addWidget(self.last_connection_label)
        stats_layout.addWidget(self.uptime_label)
        stats_layout.addStretch()
        
        status_group.setLayout(stats_layout)
        layout.addWidget(status_group)
        
    def create_log_panel(self, layout):
        """Create connection log panel"""
        log_group = QGroupBox("📝 Connection Log")
        log_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #fd7e14;
                border-radius: 5px;
                margin: 5px 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        log_layout = QVBoxLayout()
        
        # Log controls
        log_controls_layout = QHBoxLayout()
        
        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.setToolTip("Automatically scroll to newest entries")
        
        self.show_timestamps_cb = QCheckBox("Show timestamps")
        self.show_timestamps_cb.setChecked(True)
        self.show_timestamps_cb.setToolTip("Include timestamps in log entries")
        
        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        
        log_controls_layout.addWidget(self.auto_scroll_cb)
        log_controls_layout.addWidget(self.show_timestamps_cb)
        log_controls_layout.addStretch()
        log_controls_layout.addWidget(self.clear_log_btn)
        
        # Connection log text area
        self.connection_log = QTextEdit()
        self.connection_log.setMaximumHeight(200)
        self.connection_log.setReadOnly(True)
        self.connection_log.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: 1px solid #555;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        
        log_layout.addLayout(log_controls_layout)
        log_layout.addWidget(self.connection_log)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
    def setup_connections(self):
        """Setup signal connections"""
        self.start_stop_btn.clicked.connect(self.toggle_listening)
        self.test_btn.clicked.connect(self.test_connection)
        self.clear_log_btn.clicked.connect(self.clear_connection_log)
        
        # Connect port tools signals
        self.port_tools.connection_received.connect(self.on_connection_received)
        self.port_tools.error_occurred.connect(self.on_error_occurred)
        self.port_tools.status_changed.connect(self.on_status_changed)
        
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
            
    def validate_inputs(self):
        """Validate IP and port inputs"""
        ip = self.ip_input.text().strip()
        port_text = self.port_input.text().strip()
        
        # Validate IP
        if ip and ip != "0.0.0.0":
            try:
                socket.inet_aton(ip)
            except socket.error:
                raise ValueError("Invalid IP address format")
                
        # Validate port
        try:
            port = int(port_text)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            if "invalid literal" in str(e):
                raise ValueError("Port must be a number")
            raise
            
        # Check for privileged ports
        if port < 1024 and not self.check_admin_privileges():
            raise ValueError(f"Port {port} requires administrator privileges")
            
        return ip, port
        
    def toggle_listening(self):
        """Toggle listening state"""
        if self.is_listening:
            self.stop_listening()
        else:
            self.start_listening()
            
    def start_listening(self):
        """Start the port listener"""
        try:
            ip, port = self.validate_inputs()
            response_type = self.response_combo.currentText()
            
            success = self.port_tools.start_listening(ip, port, response_type)
            
            if success:
                self.is_listening = True
                self.start_stop_btn.setText("🛑 Stop Listening")
                self.start_stop_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #dc3545;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 5px;
                        font-weight: bold;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: #c82333;
                    }
                    QPushButton:pressed {
                        background-color: #bd2130;
                    }
                """)
                
                self.status_label.setText(f"🟢 Listening on {ip}:{port}")
                self.status_label.setStyleSheet("color: #28a745; font-weight: bold; font-size: 14px;")
                
                # Disable inputs
                self.ip_input.setEnabled(False)
                self.port_input.setEnabled(False)
                self.response_combo.setEnabled(False)
                
                self.add_connection_log(f"Started listening on {ip}:{port} with {response_type} response")
                
            else:
                QMessageBox.critical(self, "Error", "Failed to start port listener")
                
        except ValueError as e:
            QMessageBox.warning(self, "Input Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start listener: {str(e)}")
            
    def stop_listening(self):
        """Stop the port listener"""
        try:
            self.port_tools.stop_listening()
            
            self.is_listening = False
            self.start_stop_btn.setText("🚀 Start Listening")
            self.start_stop_btn.setStyleSheet("""
                QPushButton {
                    background-color: #28a745;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 5px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #218838;
                }
                QPushButton:pressed {
                    background-color: #1e7e34;
                }
            """)
            
            self.status_label.setText("🔴 Stopped")
            self.status_label.setStyleSheet("color: #dc3545; font-weight: bold; font-size: 14px;")
            
            # Re-enable inputs
            self.ip_input.setEnabled(True)
            self.port_input.setEnabled(True)
            self.response_combo.setEnabled(True)
            
            self.add_connection_log("Stopped listening")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error stopping listener: {str(e)}")
            
    def test_connection(self):
        """Test connection to the listening port"""
        if not self.is_listening:
            QMessageBox.warning(self, "Not Listening", "Port listener is not currently running.")
            return
            
        try:
            ip = self.ip_input.text().strip()
            port = int(self.port_input.text().strip())
            
            # Use localhost if listening on all interfaces
            test_ip = "127.0.0.1" if ip == "0.0.0.0" else ip
            
            success = self.port_tools.test_connection(test_ip, port)
            
            if success:
                QMessageBox.information(self, "Test Successful", f"Test connection to {test_ip}:{port} successful!")
                self.add_connection_log(f"Test connection to {test_ip}:{port} successful")
            else:
                QMessageBox.warning(self, "Test Failed", f"Test connection to {test_ip}:{port} failed")
                
        except Exception as e:
            QMessageBox.critical(self, "Test Error", f"Test connection failed: {str(e)}")
            
    def clear_connection_log(self):
        """Clear the connection log"""
        self.connection_log.clear()
        
    def add_connection_log(self, message):
        """Add entry to connection log"""
        if self.show_timestamps_cb.isChecked():
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}"
        else:
            log_entry = message
            
        self.connection_log.append(log_entry)
        
        # Auto-scroll if enabled
        if self.auto_scroll_cb.isChecked():
            scrollbar = self.connection_log.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            
    def on_connection_received(self, client_ip, timestamp):
        """Handle incoming connection"""
        self.add_connection_log(f"Connection from: {client_ip}")
        
        # Update statistics
        stats = self.port_tools.get_statistics()
        self.connection_count_label.setText(f"Connections: {stats['connections']}")
        self.last_connection_label.setText(f"Last: {client_ip}")
        
    def on_error_occurred(self, error_msg):
        """Handle errors from port tools"""
        self.add_connection_log(f"ERROR: {error_msg}")
        
    def on_status_changed(self, uptime):
        """Handle status updates"""
        self.uptime_label.setText(f"Uptime: {uptime}")


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Sigma Port Listener")
    app.setApplicationVersion("1.0.0")
    
    # Set application icon (if available)
    # app.setWindowIcon(QIcon("icon.ico"))
    
    window = PortListenerApp()
    window.show()
    
    # Show welcome message
    QTimer.singleShot(1000, lambda: window.add_connection_log(
        "🎉 Welcome to Sigma Port Listener v1.0.0! Configure your settings and click 'Start Listening' to begin monitoring."
    ))
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
