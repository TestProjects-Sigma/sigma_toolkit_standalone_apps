import sys
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QGroupBox, QFormLayout, QCheckBox, QSpinBox, QTextEdit,
    QMessageBox, QProgressBar, QStatusBar, QSplitter, QHeaderView,
    QDialog, QScrollArea, QFrame
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtGui import QFont, QIcon

from ldap3 import Server, Connection, ALL, NTLM, Tls
from ldap3.core.exceptions import LDAPException
import ssl
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Enable MD4 for NTLM if available (required for newer Python versions)
try:
    import hashlib
    hashlib.new('md4')
except ValueError:
    # MD4 not available, try to enable it
    try:
        from Crypto.Hash import MD4
        # Monkey patch MD4 into hashlib for NTLM compatibility
        def _md4_new(data=b''):
            h = MD4.new()
            if data:
                h.update(data)
            return h
        hashlib.md4 = _md4_new
        hashlib.new('md4', b'test')  # Test if it works
    except (ImportError, Exception):
        # If all else fails, we'll handle this in the connection
        pass


@dataclass
class UserPasswordInfo:
    """Data class to hold user password information."""
    username: str
    display_name: str
    email: str
    password_last_set: datetime
    password_expires: datetime
    days_until_expiry: int
    account_disabled: bool
    password_never_expires: bool


class ADConfig:
    """Configuration management for Active Directory connection."""
    
    def __init__(self, config_file: str = "ad_config.json"):
        self.config_file = Path(config_file)
        self.default_config = {
            "server": "server1.contoso.com",
            "port": 636,
            "use_ssl": True,
            "domain": "contoso",
            "base_dn": "ou=test,dc=contoso,dc=com",
            "username": "user1",
            "auto_refresh": False,
            "refresh_interval": 60,
            "warning_days": 14
        }
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults to handle new keys
                merged_config = self.default_config.copy()
                merged_config.update(config)
                return merged_config
            except (json.JSONDecodeError, IOError):
                return self.default_config.copy()
        return self.default_config.copy()
    
    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                # Don't save sensitive data like passwords
                safe_config = {k: v for k, v in self.config.items() if k != 'password'}
                json.dump(safe_config, f, indent=2)
            return True
        except IOError:
            return False


class ADConnectionTestWorker(QThread):
    """Worker thread for testing AD connection."""
    
    success = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, server: str, port: int, use_ssl: bool, domain: str,
                 username: str, password: str, base_dn: str):
        super().__init__()
        self.server = server
        self.port = port
        self.use_ssl = use_ssl
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = base_dn
    
    def run(self):
        """Test the connection."""
        try:
            # Setup TLS configuration for secure connection
            tls_config = None
            if self.use_ssl:
                tls_config = Tls(
                    validate=ssl.CERT_NONE,  # More lenient for testing
                    version=ssl.PROTOCOL_TLS,
                    ciphers='HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
                )
            
            # Create server connection
            server = Server(
                self.server,
                port=self.port,
                use_ssl=self.use_ssl,
                tls=tls_config,
                get_info=ALL
            )
            
            # Try different authentication methods
            conn = None
            auth_methods = [
                ("NTLM", lambda: Connection(server, user=f"{self.domain}\\{self.username}", 
                                          password=self.password, authentication=NTLM)),
                ("Simple", lambda: Connection(server, user=f"{self.username}@{self.domain}", 
                                            password=self.password, authentication='SIMPLE')),
                ("Simple DN", lambda: Connection(server, user=f"cn={self.username},{self.base_dn}", 
                                               password=self.password, authentication='SIMPLE'))
            ]
            
            last_error = None
            for auth_name, conn_func in auth_methods:
                try:
                    conn = conn_func()
                    if conn.bind():
                        # Test a simple search to verify permissions
                        conn.search(
                            search_base=self.base_dn,
                            search_filter="(objectClass=*)",
                            search_scope='BASE',
                            attributes=['objectClass']
                        )
                        
                        conn.unbind()
                        self.success.emit(f"Connected successfully using {auth_name} authentication.")
                        return
                    else:
                        last_error = f"{auth_name}: Bind failed - {conn.result}"
                except Exception as e:
                    last_error = f"{auth_name}: {str(e)}"
                    if conn:
                        try:
                            conn.unbind()
                        except:
                            pass
            
            # If we get here, all methods failed
            self.error.emit(f"All authentication methods failed. Last error: {last_error}")
            
        except Exception as e:
            self.error.emit(f"Connection test failed: {str(e)}")


class ADPasswordWorker(QThread):
    """Worker thread for Active Directory operations."""
    
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    
    def __init__(self, server: str, port: int, use_ssl: bool, domain: str,
                 username: str, password: str, base_dn: str):
        super().__init__()
        self.server = server
        self.port = port
        self.use_ssl = use_ssl
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self._is_running = True
    
    def stop(self):
        """Stop the worker thread."""
        self._is_running = False
    
    def run(self):
        """Main worker thread execution."""
        try:
            self.progress.emit(10)
            
            # Setup TLS configuration for secure connection
            tls_config = None
            if self.use_ssl:
                tls_config = Tls(
                    validate=ssl.CERT_NONE,  # More lenient for corporate environments
                    version=ssl.PROTOCOL_TLS,
                    ciphers='HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
                )
            
            # Create server connection
            server = Server(
                self.server,
                port=self.port,
                use_ssl=self.use_ssl,
                tls=tls_config,
                get_info=ALL
            )
            
            self.progress.emit(30)
            
            # Try different authentication methods
            conn = None
            auth_methods = [
                ("NTLM", lambda: Connection(server, user=f"{self.domain}\\{self.username}", 
                                          password=self.password, authentication=NTLM)),
                ("Simple", lambda: Connection(server, user=f"{self.username}@{self.domain}", 
                                            password=self.password, authentication='SIMPLE'))
            ]
            
            connected = False
            for auth_name, conn_func in auth_methods:
                try:
                    conn = conn_func()
                    if conn.bind():
                        connected = True
                        break
                except Exception as e:
                    if "MD4" in str(e):
                        # Try with alternative NTLM handling
                        try:
                            conn = Connection(
                                server, 
                                user=f"{self.username}@{self.domain}", 
                                password=self.password, 
                                authentication='SIMPLE'
                            )
                            if conn.bind():
                                connected = True
                                break
                        except:
                            pass
                    continue
            
            if not connected:
                raise Exception("Failed to authenticate with any method. Check credentials and server settings.")
            
            self.progress.emit(50)
            
            if not self._is_running:
                return
            
            # Search for users with password information
            search_filter = "(&(objectClass=user)(objectCategory=person))"
            attributes = [
                'sAMAccountName', 'displayName', 'mail',
                'pwdLastSet', 'userAccountControl'
            ]
            
            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            self.progress.emit(70)
            
            users_info = []
            total_entries = len(conn.entries)
            
            for i, entry in enumerate(conn.entries):
                if not self._is_running:
                    break
                
                try:
                    user_info = self._process_user_entry(entry, conn.server.info)
                    if user_info:
                        users_info.append(user_info)
                except Exception as e:
                    # Log individual user processing errors but continue
                    print(f"Error processing user {entry.sAMAccountName}: {e}")
                
                # Update progress
                progress = 70 + int((i / total_entries) * 25)
                self.progress.emit(progress)
            
            conn.unbind()
            self.progress.emit(100)
            self.finished.emit(users_info)
            
        except LDAPException as e:
            self.error.emit(f"LDAP Error: {str(e)}")
        except Exception as e:
            self.error.emit(f"Connection Error: {str(e)}")
    
    def _process_user_entry(self, entry, server_info) -> Optional[UserPasswordInfo]:
        """Process individual user entry to extract password information."""
        try:
            username = str(entry.sAMAccountName.value) if entry.sAMAccountName else "unknown"
            display_name = str(entry.displayName.value) if entry.displayName and entry.displayName.value else username
            email = str(entry.mail.value) if entry.mail and entry.mail.value else ""
            
            # Get password last set time
            if not entry.pwdLastSet or not entry.pwdLastSet.value:
                return None
            
            # Check if pwdLastSet is already a datetime or needs conversion
            pwd_last_set_raw = entry.pwdLastSet.value
            
            if isinstance(pwd_last_set_raw, datetime):
                # Already converted by ldap3
                pwd_last_set_dt = pwd_last_set_raw
                # Remove timezone info if present for easier calculation
                if pwd_last_set_dt.tzinfo:
                    pwd_last_set_dt = pwd_last_set_dt.replace(tzinfo=None)
            elif isinstance(pwd_last_set_raw, int):
                # Raw Windows FILETIME - convert it
                if pwd_last_set_raw == 0:
                    return None
                pwd_last_set_dt = datetime(1601, 1, 1) + timedelta(microseconds=pwd_last_set_raw/10)
            else:
                print(f"Unexpected pwdLastSet type for {username}: {type(pwd_last_set_raw)}")
                return None
            
            # Get user account control flags - handle Attribute objects
            uac = 0
            if entry.userAccountControl and entry.userAccountControl.value:
                try:
                    uac = int(entry.userAccountControl.value)
                except (ValueError, TypeError):
                    print(f"Could not convert userAccountControl for {username}: {entry.userAccountControl.value}")
                    uac = 0
            
            account_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
            password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWD flag
            
            # Calculate password expiration
            if password_never_expires:
                password_expires = datetime.max
                days_until_expiry = 999999
            else:
                # Use standard 90-day password policy
                max_age_days = 90
                password_expires = pwd_last_set_dt + timedelta(days=max_age_days)
                days_until_expiry = (password_expires - datetime.now()).days
            
            return UserPasswordInfo(
                username=username,
                display_name=display_name,
                email=email,
                password_last_set=pwd_last_set_dt,
                password_expires=password_expires,
                days_until_expiry=days_until_expiry,
                account_disabled=account_disabled,
                password_never_expires=password_never_expires
            )
            
        except Exception as e:
            print(f"Error processing user {username if 'username' in locals() else 'unknown'}: {e}")
            # Print more debugging info
            if 'entry' in locals():
                if hasattr(entry, 'userAccountControl'):
                    print(f"userAccountControl type: {type(entry.userAccountControl)}, value: {entry.userAccountControl}")
                    if hasattr(entry.userAccountControl, 'value'):
                        print(f"userAccountControl.value type: {type(entry.userAccountControl.value)}, value: {entry.userAccountControl.value}")
            return None


class NumericTableWidgetItem(QTableWidgetItem):
    """Custom table widget item for proper numerical sorting."""
    
    def __init__(self, text, numeric_value):
        super().__init__(text)
        self.numeric_value = numeric_value
    
    def __lt__(self, other):
        """Custom comparison for sorting."""
        if isinstance(other, NumericTableWidgetItem):
            return self.numeric_value < other.numeric_value
        return super().__lt__(other)


class PasswordExpiryTable(QTableWidget):
    """Custom table widget for displaying password expiry information."""
    
    def __init__(self):
        super().__init__()
        self.setup_table()
    
    def setup_table(self):
        """Setup table headers and properties."""
        headers = [
            "Username", "Display Name", "Email", "Days Until Expiry",
            "Password Last Set", "Password Expires", "Status"
        ]
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Set table properties
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSortingEnabled(True)
        
        # Set column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Username
        header.setSectionResizeMode(1, QHeaderView.Stretch)          # Display Name
        header.setSectionResizeMode(2, QHeaderView.Stretch)          # Email
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents) # Days
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents) # Last Set
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents) # Expires
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents) # Status
    
    def populate_data(self, users_data: List[UserPasswordInfo]):
        """Populate table with user password data."""
        # Disable sorting while populating to avoid issues
        self.setSortingEnabled(False)
        self.setRowCount(len(users_data))
        
        for row, user in enumerate(users_data):
            # Username
            self.setItem(row, 0, QTableWidgetItem(user.username))
            
            # Display Name
            self.setItem(row, 1, QTableWidgetItem(user.display_name))
            
            # Email
            self.setItem(row, 2, QTableWidgetItem(user.email))
            
            # Days until expiry - use custom numeric item for proper sorting
            if user.password_never_expires:
                days_item = NumericTableWidgetItem("Never", 999999)
            else:
                days_item = NumericTableWidgetItem(str(user.days_until_expiry), user.days_until_expiry)
                
                # Apply color coding
                if user.days_until_expiry < 0:
                    days_item.setBackground(Qt.red)
                elif user.days_until_expiry <= 7:
                    days_item.setBackground(Qt.yellow)
                    
            self.setItem(row, 3, days_item)
            
            # Password last set
            last_set_str = user.password_last_set.strftime("%Y-%m-%d %H:%M")
            self.setItem(row, 4, QTableWidgetItem(last_set_str))
            
            # Password expires
            if user.password_never_expires:
                expires_str = "Never"
            else:
                expires_str = user.password_expires.strftime("%Y-%m-%d %H:%M")
            self.setItem(row, 5, QTableWidgetItem(expires_str))
            
            # Status
            if user.account_disabled:
                status = "Disabled"
            elif user.password_never_expires:
                status = "Never Expires"
            elif user.days_until_expiry < 0:
                status = "Expired"
            elif user.days_until_expiry <= 7:
                status = "Expiring Soon"
            else:
                status = "Active"
            self.setItem(row, 6, QTableWidgetItem(status))
        
        # Re-enable sorting after populating
        self.setSortingEnabled(True)


class ConfigurationHelpDialog(QDialog):
    """Dialog showing configuration help and examples."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuration Help")
        self.setModal(True)
        self.resize(800, 600)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the help dialog UI."""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Active Directory Configuration Guide")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Scroll area for content
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout()
        
        # Required Settings Section
        required_group = QGroupBox("Required Settings")
        required_layout = QVBoxLayout()
        
        required_text = QLabel("""Fill in the configuration panel with your Active Directory details:""")
        required_text.setWordWrap(True)
        required_layout.addWidget(required_text)
        
        # Configuration table
        config_examples = [
            ("Server", "dc01.company.com", "Your AD domain controller FQDN or IP"),
            ("Port", "636 (SSL) or 389", "LDAP port (636 recommended for security)"),
            ("Use SSL/TLS", "✅ Checked", "Enable secure connection (recommended)"),
            ("Domain", "COMPANY", "Your Windows domain name (short format)"),
            ("Base DN", "DC=company,DC=com", "LDAP search base for users"),
            ("Username", "serviceaccount", "AD account with read permissions"),
            ("Password", "your_password", "Account password (not saved)")
        ]
        
        for field, example, description in config_examples:
            example_frame = QFrame()
            example_frame.setFrameStyle(QFrame.Box)
            example_layout = QVBoxLayout()
            
            field_label = QLabel(f"<b>{field}:</b>")
            example_label = QLabel(f"Example: <code>{example}</code>")
            desc_label = QLabel(description)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #666; font-style: italic;")
            
            example_layout.addWidget(field_label)
            example_layout.addWidget(example_label)
            example_layout.addWidget(desc_label)
            example_frame.setLayout(example_layout)
            
            required_layout.addWidget(example_frame)
        
        required_group.setLayout(required_layout)
        scroll_layout.addWidget(required_group)
        
        # Common Scenarios Section
        scenarios_group = QGroupBox("Common Configuration Scenarios")
        scenarios_layout = QVBoxLayout()
        
        scenario1 = QLabel("""
<b>Scenario 1: Standard Corporate Domain</b><br>
• Server: <code>dc01.company.local</code><br>
• Port: <code>636</code><br>
• Domain: <code>COMPANY</code><br>
• Base DN: <code>DC=company,DC=local</code><br>
• Username: <code>svc-ldap</code> (service account)
        """)
        scenario1.setWordWrap(True)
        scenarios_layout.addWidget(scenario1)
        
        scenario2 = QLabel("""
<b>Scenario 2: Cloud/Hybrid Environment</b><br>
• Server: <code>dc.company.com</code><br>
• Port: <code>636</code><br>
• Domain: <code>company.com</code><br>
• Base DN: <code>DC=company,DC=com</code><br>
• Username: <code>admin@company.com</code>
        """)
        scenario2.setWordWrap(True)
        scenarios_layout.addWidget(scenario2)
        
        scenario3 = QLabel("""
<b>Scenario 3: Development/Testing</b><br>
• Server: <code>192.168.1.10</code> (IP address)<br>
• Port: <code>389</code> (non-SSL for testing)<br>
• Domain: <code>TESTDOMAIN</code><br>
• Base DN: <code>DC=testdomain,DC=local</code><br>
• Username: <code>testuser</code>
        """)
        scenario3.setWordWrap(True)
        scenarios_layout.addWidget(scenario3)
        
        scenarios_group.setLayout(scenarios_layout)
        scroll_layout.addWidget(scenarios_group)
        
        # Troubleshooting Section
        troubleshoot_group = QGroupBox("Quick Troubleshooting")
        troubleshoot_layout = QVBoxLayout()
        
        troubleshoot_text = QLabel("""
<b>Connection Issues:</b><br>
• Use "Test Connection" button to verify settings<br>
• Try both server name and IP address<br>
• Check if port 636/389 is accessible<br>
• Verify service account is not locked<br><br>

<b>No Results:</b><br>
• Verify Base DN matches your domain structure<br>
• Check service account has read permissions<br>
• Ensure users exist in the specified organizational unit<br><br>

<b>Authentication Errors:</b><br>
• Try short domain name (COMPANY) vs FQDN (company.com)<br>
• Verify username format (with or without domain prefix)<br>
• Check account password and expiration
        """)
        troubleshoot_text.setWordWrap(True)
        troubleshoot_layout.addWidget(troubleshoot_text)
        
        troubleshoot_group.setLayout(troubleshoot_layout)
        scroll_layout.addWidget(troubleshoot_group)
        
        # Security Notes Section
        security_group = QGroupBox("Security Recommendations")
        security_layout = QVBoxLayout()
        
        security_text = QLabel("""
<b>Best Practices:</b><br>
• Always use SSL/TLS (port 636) in production<br>
• Create dedicated service account with minimal permissions<br>
• Use strong passwords for service accounts<br>
• Monitor LDAP access logs regularly<br>
• Test configuration in development environment first<br><br>

<b>Required Permissions:</b><br>
• Read access to user objects in Active Directory<br>
• Permission to query: sAMAccountName, displayName, mail, pwdLastSet, userAccountControl<br>
• No administrator privileges required
        """)
        security_text.setWordWrap(True)
        security_layout.addWidget(security_text)
        
        security_group.setLayout(security_layout)
        scroll_layout.addWidget(security_group)
        
        # Set scroll widget
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)


class ConfigurationWidget(QWidget):
    """Widget for AD connection configuration."""
    
    def __init__(self, config: ADConfig):
        super().__init__()
        self.config = config
        self.setup_ui()
        self.load_config_values()
    
    def setup_ui(self):
        """Setup the configuration UI."""
        layout = QVBoxLayout()
        
        # Connection settings
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QFormLayout()
        
        self.server_edit = QLineEdit()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(636)
        
        self.use_ssl_check = QCheckBox("Use SSL/TLS")
        self.use_ssl_check.setChecked(True)
        
        self.domain_edit = QLineEdit()
        self.base_dn_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        
        conn_layout.addRow("Server:", self.server_edit)
        conn_layout.addRow("Port:", self.port_spin)
        conn_layout.addRow("", self.use_ssl_check)
        conn_layout.addRow("Domain:", self.domain_edit)
        conn_layout.addRow("Base DN:", self.base_dn_edit)
        conn_layout.addRow("Username:", self.username_edit)
        conn_layout.addRow("Password:", self.password_edit)
        
        conn_group.setLayout(conn_layout)
        
        # Application settings
        app_group = QGroupBox("Application Settings")
        app_layout = QFormLayout()
        
        self.auto_refresh_check = QCheckBox("Auto Refresh")
        self.refresh_interval_spin = QSpinBox()
        self.refresh_interval_spin.setRange(30, 3600)
        self.refresh_interval_spin.setValue(60)
        self.refresh_interval_spin.setSuffix(" seconds")
        
        self.warning_days_spin = QSpinBox()
        self.warning_days_spin.setRange(1, 365)
        self.warning_days_spin.setValue(14)
        self.warning_days_spin.setSuffix(" days")
        
        app_layout.addRow("", self.auto_refresh_check)
        app_layout.addRow("Refresh Interval:", self.refresh_interval_spin)
        app_layout.addRow("Warning Days:", self.warning_days_spin)
        
        app_group.setLayout(app_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save Configuration")
        self.test_button = QPushButton("Test Connection")
        self.help_button = QPushButton("Configuration Help")
        
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.help_button)
        button_layout.addStretch()
        
        # Main layout
        layout.addWidget(conn_group)
        layout.addWidget(app_group)
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
        
        # Connect signals
        self.save_button.clicked.connect(self.save_configuration)
        self.test_button.clicked.connect(self.test_connection)
        self.help_button.clicked.connect(self.show_configuration_help)
    
    def load_config_values(self):
        """Load configuration values into UI controls."""
        self.server_edit.setText(self.config.config.get("server", "test"))
        self.port_spin.setValue(self.config.config.get("port", 636))
        self.use_ssl_check.setChecked(self.config.config.get("use_ssl", True))
        self.domain_edit.setText(self.config.config.get("domain", ""))
        self.base_dn_edit.setText(self.config.config.get("base_dn", ""))
        self.username_edit.setText(self.config.config.get("username", ""))
        self.auto_refresh_check.setChecked(self.config.config.get("auto_refresh", False))
        self.refresh_interval_spin.setValue(self.config.config.get("refresh_interval", 60))
        self.warning_days_spin.setValue(self.config.config.get("warning_days", 14))
    
    def save_configuration(self):
        """Save configuration from UI controls."""
        self.config.config.update({
            "server": self.server_edit.text(),
            "port": self.port_spin.value(),
            "use_ssl": self.use_ssl_check.isChecked(),
            "domain": self.domain_edit.text(),
            "base_dn": self.base_dn_edit.text(),
            "username": self.username_edit.text(),
            "auto_refresh": self.auto_refresh_check.isChecked(),
            "refresh_interval": self.refresh_interval_spin.value(),
            "warning_days": self.warning_days_spin.value()
        })
        
        if self.config.save_config():
            QMessageBox.information(self, "Success", "Configuration saved successfully!")
        else:
            QMessageBox.warning(self, "Error", "Failed to save configuration!")
    
    def test_connection(self):
        """Test the AD connection with current settings."""
        if not self.password_edit.text():
            QMessageBox.warning(self, "Warning", "Please enter a password to test connection.")
            return
        
        params = self.get_connection_params()
        required_fields = ["server", "domain", "username", "password", "base_dn"]
        for field in required_fields:
            if not params.get(field):
                QMessageBox.warning(
                    self, "Configuration Error", 
                    f"Please fill in the {field.replace('_', ' ').title()} field."
                )
                return
        
        # Create test worker
        self.test_worker = ADConnectionTestWorker(
            params["server"], params["port"], params["use_ssl"],
            params["domain"], params["username"], params["password"],
            params["base_dn"]
        )
        
        self.test_worker.success.connect(self.on_test_success)
        self.test_worker.error.connect(self.on_test_error)
        
        self.test_button.setEnabled(False)
        self.test_button.setText("Testing...")
        self.test_worker.start()
    
    def on_test_success(self, message):
        """Handle successful connection test."""
        QMessageBox.information(self, "Connection Test", f"Success! {message}")
        self.test_button.setEnabled(True)
        self.test_button.setText("Test Connection")
    
    def on_test_error(self, error_message):
        """Handle connection test error."""
        QMessageBox.critical(self, "Connection Test Failed", error_message)
        self.test_button.setEnabled(True)
        self.test_button.setText("Test Connection")
    
    def show_configuration_help(self):
        """Show configuration help dialog with examples."""
        help_dialog = ConfigurationHelpDialog(self)
        help_dialog.exec_()
    
    def get_connection_params(self) -> Dict[str, Any]:
        """Get current connection parameters."""
        return {
            "server": self.server_edit.text(),
            "port": self.port_spin.value(),
            "use_ssl": self.use_ssl_check.isChecked(),
            "domain": self.domain_edit.text(),
            "username": self.username_edit.text(),
            "password": self.password_edit.text(),
            "base_dn": self.base_dn_edit.text()
        }


class ADPasswordExpiryApp(QMainWindow):
    """Main application window for AD Password Expiry Checker."""
    
    def __init__(self):
        super().__init__()
        self.config = ADConfig()
        self.worker = None
        self.refresh_timer = QTimer()
        self.users_data = []
        
        self.setup_ui()
        self.setup_connections()
        self.setup_refresh_timer()
    
    def setup_ui(self):
        """Setup the main user interface."""
        self.setWindowTitle("Active Directory Password Expiry Checker")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget with splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh Data")
        self.config_button = QPushButton("Configuration")
        self.help_button = QPushButton("Help")
        self.export_button = QPushButton("Export Data")
        
        toolbar_layout.addWidget(self.refresh_button)
        toolbar_layout.addWidget(self.config_button)
        toolbar_layout.addWidget(self.help_button)
        toolbar_layout.addWidget(self.export_button)
        toolbar_layout.addStretch()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Configuration
        self.config_widget = ConfigurationWidget(self.config)
        splitter.addWidget(self.config_widget)
        
        # Right panel - Data table
        table_widget = QWidget()
        table_layout = QVBoxLayout()
        
        # Summary info
        self.summary_label = QLabel("No data loaded")
        self.summary_label.setFont(QFont("Arial", 10, QFont.Bold))
        
        # Data table
        self.table = PasswordExpiryTable()
        
        table_layout.addWidget(self.summary_label)
        table_layout.addWidget(self.table)
        table_widget.setLayout(table_layout)
        
        splitter.addWidget(table_widget)
        splitter.setSizes([400, 800])  # Give more space to table
        
        # Add to main layout
        layout.addLayout(toolbar_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def setup_connections(self):
        """Setup signal connections."""
        self.refresh_button.clicked.connect(self.refresh_data)
        self.config_button.clicked.connect(self.show_configuration)
        self.help_button.clicked.connect(self.show_help)
        self.export_button.clicked.connect(self.export_data)
        self.refresh_timer.timeout.connect(self.refresh_data)
    
    def setup_refresh_timer(self):
        """Setup automatic refresh timer."""
        if self.config.config.get("auto_refresh", False):
            interval = self.config.config.get("refresh_interval", 60) * 1000
            self.refresh_timer.start(interval)
    
    def show_help(self):
        """Show configuration help dialog."""
        help_dialog = ConfigurationHelpDialog(self)
        help_dialog.exec_()
    
    def show_configuration(self):
        """Show/hide configuration panel."""
        # This could be expanded to show config in a dialog
        pass
    
    def refresh_data(self):
        """Refresh AD password data."""
        if self.worker and self.worker.isRunning():
            return
        
        params = self.config_widget.get_connection_params()
        
        # Validate required parameters
        required_fields = ["server", "domain", "username", "password", "base_dn"]
        for field in required_fields:
            if not params.get(field):
                QMessageBox.warning(
                    self, "Configuration Error", 
                    f"Please configure the {field.replace('_', ' ').title()} field."
                )
                return
        
        # Start worker thread
        self.worker = ADPasswordWorker(
            params["server"], params["port"], params["use_ssl"],
            params["domain"], params["username"], params["password"],
            params["base_dn"]
        )
        
        self.worker.finished.connect(self.on_data_received)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.on_progress)
        
        self.progress_bar.setVisible(True)
        self.refresh_button.setEnabled(False)
        self.status_bar.showMessage("Connecting to Active Directory...")
        
        self.worker.start()
    
    def on_data_received(self, users_data: List[UserPasswordInfo]):
        """Handle received user data."""
        self.users_data = users_data
        self.table.populate_data(users_data)
        
        # Update summary
        total_users = len(users_data)
        expired_count = len([u for u in users_data if u.days_until_expiry < 0])
        expiring_soon = len([u for u in users_data if 0 <= u.days_until_expiry <= 7])
        
        summary_text = (
            f"Total Users: {total_users} | "
            f"Expired: {expired_count} | "
            f"Expiring Soon (≤7 days): {expiring_soon}"
        )
        self.summary_label.setText(summary_text)
        
        self.progress_bar.setVisible(False)
        self.refresh_button.setEnabled(True)
        self.status_bar.showMessage(f"Data refreshed - {total_users} users loaded")
    
    def on_error(self, error_message: str):
        """Handle worker errors."""
        QMessageBox.critical(self, "Connection Error", error_message)
        self.progress_bar.setVisible(False)
        self.refresh_button.setEnabled(True)
        self.status_bar.showMessage("Error occurred during refresh")
    
    def on_progress(self, value: int):
        """Update progress bar."""
        self.progress_bar.setValue(value)
    
    def export_data(self):
        """Export current data to CSV."""
        if not self.users_data:
            QMessageBox.information(self, "No Data", "No data to export. Please refresh data first.")
            return
        
        # Simple CSV export (you could use QFileDialog for file selection)
        try:
            with open("password_expiry_report.csv", "w") as f:
                f.write("Username,Display Name,Email,Days Until Expiry,Password Last Set,Password Expires,Status\n")
                for user in self.users_data:
                    status = "Active"
                    if user.account_disabled:
                        status = "Disabled"
                    elif user.password_never_expires:
                        status = "Never Expires"
                    elif user.days_until_expiry < 0:
                        status = "Expired"
                    elif user.days_until_expiry <= 7:
                        status = "Expiring Soon"
                    
                    f.write(f'"{user.username}","{user.display_name}","{user.email}",'
                           f'{user.days_until_expiry},'
                           f'"{user.password_last_set.strftime("%Y-%m-%d %H:%M")}",'
                           f'"{user.password_expires.strftime("%Y-%m-%d %H:%M") if not user.password_never_expires else "Never"}",'
                           f'"{status}"\n')
            
            QMessageBox.information(self, "Export Complete", "Data exported to password_expiry_report.csv")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export data: {str(e)}")
    
    def closeEvent(self, event):
        """Handle application close event."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()


class ADPasswordAPI:
    """API class for integration with other applications."""
    
    def __init__(self, config_file: str = "ad_config.json"):
        self.config = ADConfig(config_file)
    
    def get_password_expiry_data(self, server: str, port: int, use_ssl: bool,
                               domain: str, username: str, password: str,
                               base_dn: str) -> List[Dict[str, Any]]:
        """
        Get password expiry data programmatically.
        Returns list of dictionaries with user password information.
        """
        try:
            # Setup TLS configuration
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS,
                ciphers='HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
            )
            
            # Create server connection
            server_obj = Server(
                server, port=port, use_ssl=use_ssl,
                tls=tls_config, get_info=ALL
            )
            
            # Establish connection
            user_dn = f"{domain}\\{username}"
            conn = Connection(
                server_obj, user=user_dn, password=password,
                authentication=NTLM, auto_bind=True
            )
            
            # Search for users
            search_filter = "(&(objectClass=user)(objectCategory=person))"
            attributes = [
                'sAMAccountName', 'displayName', 'mail',
                'pwdLastSet', 'userAccountControl'
            ]
            
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            users_data = []
            for entry in conn.entries:
                user_info = self._process_entry_to_dict(entry)
                if user_info:
                    users_data.append(user_info)
            
            conn.unbind()
            return users_data
            
        except Exception as e:
            raise Exception(f"Failed to retrieve AD data: {str(e)}")
    
    def _process_entry_to_dict(self, entry) -> Optional[Dict[str, Any]]:
        """Process LDAP entry to dictionary format."""
        try:
            username = str(entry.sAMAccountName)
            pwd_last_set = entry.pwdLastSet.value if entry.pwdLastSet else None
            
            if not pwd_last_set:
                return None
            
            pwd_last_set_dt = datetime(1601, 1, 1) + timedelta(microseconds=pwd_last_set/10)
            
            # Default 42 days password age
            password_expires = pwd_last_set_dt + timedelta(days=42)
            days_until_expiry = (password_expires - datetime.now()).days
            
            uac = int(entry.userAccountControl) if entry.userAccountControl else 0
            account_disabled = bool(uac & 0x2)
            password_never_expires = bool(uac & 0x10000)
            
            if password_never_expires:
                days_until_expiry = 999999
            
            return {
                "username": username,
                "display_name": str(entry.displayName) if entry.displayName else username,
                "email": str(entry.mail) if entry.mail else "",
                "password_last_set": pwd_last_set_dt.isoformat(),
                "password_expires": password_expires.isoformat(),
                "days_until_expiry": days_until_expiry,
                "account_disabled": account_disabled,
                "password_never_expires": password_never_expires
            }
            
        except Exception:
            return None


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("AD Password Expiry Checker")
    app.setApplicationVersion("1.0")
    
    # Create and show main window
    window = ADPasswordExpiryApp()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()