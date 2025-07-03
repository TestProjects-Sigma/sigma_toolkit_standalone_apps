#!/usr/bin/env python3
"""
Active Directory Folder Permissions Analyzer
A PyQt5 application to analyze AD permissions on network/local folders
"""

import sys
import os
import csv
import json
import subprocess
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QProgressBar, QLabel, QGroupBox,
    QSplitter, QHeaderView, QCheckBox, QComboBox, QTabWidget
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QIcon
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class PermissionEntry:
    """Data class to represent a permission entry"""
    
    def __init__(self, path: str, identity: str, permission: str, 
                 access_type: str, inherited: bool = False):
        self.path = path
        self.identity = identity
        self.permission = permission
        self.access_type = access_type  # Allow/Deny
        self.inherited = inherited
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'Path': self.path,
            'Identity': self.identity,
            'Permission': self.permission,
            'Access Type': self.access_type,
            'Inherited': self.inherited,
            'Scan Time': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }


class PermissionScanner:
    """Core class for scanning folder permissions using Windows tools"""
    
    @staticmethod
    def scan_folder_permissions(folder_path: str, include_subfolders: bool = False) -> List[PermissionEntry]:
        """Scan permissions for folders only using icacls command"""
        permissions = []
        
        try:
            # Normalize the path to use Windows backslashes
            normalized_path = os.path.normpath(folder_path)
            
            if include_subfolders:
                # First get all subdirectories
                subdirs = [normalized_path]
                try:
                    for root, dirs, files in os.walk(normalized_path):
                        for dir_name in dirs:
                            subdir_path = os.path.normpath(os.path.join(root, dir_name))
                            subdirs.append(subdir_path)
                except PermissionError:
                    print(f"Limited access during directory traversal")
                
                # Scan each directory individually
                for directory in subdirs:
                    dir_permissions = PermissionScanner._scan_single_folder(directory)
                    permissions.extend(dir_permissions)
            else:
                # Scan only the specified folder
                permissions = PermissionScanner._scan_single_folder(normalized_path)
        
        except Exception as e:
            print(f"Error scanning {folder_path}: {str(e)}")
            # Try alternative method
            return PermissionScanner._scan_with_powershell(folder_path, include_subfolders)
        
        print(f"Found {len(permissions)} total permission entries for folders")
        return permissions
    
    @staticmethod
    def _scan_single_folder(folder_path: str) -> List[PermissionEntry]:
        """Scan permissions for a single folder"""
        permissions = []
        
        try:
            # Normalize the path to use Windows backslashes
            normalized_path = os.path.normpath(folder_path)
            
            # Check if path exists first
            if not os.path.exists(normalized_path):
                print(f"Path does not exist: {normalized_path}")
                return permissions
            
            # Use icacls without quotes and without shell=True for better compatibility
            cmd = ['icacls', normalized_path]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  encoding='cp1252', errors='replace')
            
            print(f"Scanning: {normalized_path}")
            print(f"Return code: {result.returncode}")
            
            if result.returncode != 0:
                print(f"icacls failed for {normalized_path}: {result.stderr}")
                # Try with PowerShell as fallback
                return PermissionScanner._scan_single_folder_powershell(normalized_path)
            
            # Parse icacls output
            lines = result.stdout.split('\n')
            
            for i, line in enumerate(lines):
                original_line = line
                line = line.strip()
                
                # Skip empty lines, status messages
                if not line or 'Successfully processed' in line or 'files processed' in line:
                    continue
                
                # Skip the first line (path line) or lines that start with the path
                if i == 0 or line.startswith(normalized_path):
                    continue
                
                # Look for permission entries - they should contain :( pattern
                if ':(' in line:
                    # Split by the first :( to get identity and permissions
                    colon_paren_pos = line.find(':(')
                    if colon_paren_pos > 0:
                        identity = line[:colon_paren_pos].strip()
                        permission_part = line[colon_paren_pos + 2:]  # Skip ':('
                        
                        print(f"Processing: Identity='{identity}', Permission part='{permission_part}'")
                        
                        # Extract all permission flags from the parentheses
                        # Format is typically: (I)(OI)(CI)(F) or (I)(M) etc.
                        # We need to find the last parentheses content which contains the actual permission
                        import re
                        
                        # Find all parentheses content
                        paren_matches = re.findall(r'\(([^)]+)\)', permission_part)
                        print(f"Found parentheses content: {paren_matches}")
                        
                        if paren_matches:
                            # The actual permission is usually the last meaningful code
                            # Look for permission codes (not inheritance flags)
                            permission_codes = []
                            inherited = False
                            access_type = 'Allow'
                            
                            for match in paren_matches:
                                if match == 'I':
                                    inherited = True
                                elif match == 'DENY':
                                    access_type = 'Deny'
                                elif match in ['F', 'M', 'RX', 'R', 'W', 'D', 'C', 'RC', 'WD', 'AD', 'WEA', 'REA', 'X', 'DC']:
                                    # These are actual permission codes
                                    permission_codes.append(match)
                                # Skip inheritance flags like OI, CI, IO
                            
                            print(f"Permission codes found: {permission_codes}")
                            print(f"Inherited: {inherited}, Access type: {access_type}")
                            
                            if permission_codes:
                                # Use the permission codes to determine readable permissions
                                permission_code_str = ','.join(permission_codes)
                                readable_permissions = PermissionScanner._convert_to_readable_permissions(permission_code_str)
                                print(f"Readable permissions: '{readable_permissions}'")
                                
                                if identity and readable_permissions:
                                    permissions.append(PermissionEntry(
                                        path=normalized_path,
                                        identity=identity,
                                        permission=readable_permissions,
                                        access_type=access_type,
                                        inherited=inherited
                                    ))
                                    print(f"Added permission entry for {identity}")
            
            print(f"Total permissions found for {normalized_path}: {len(permissions)}")
        
        except Exception as e:
            print(f"Error scanning single folder {normalized_path}: {str(e)}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            # Fallback to PowerShell
            return PermissionScanner._scan_single_folder_powershell(normalized_path)
        
        return permissions
    
    @staticmethod
    def _scan_single_folder_powershell(folder_path: str) -> List[PermissionEntry]:
        """Scan a single folder using PowerShell as fallback"""
        permissions = []
        
        try:
            normalized_path = os.path.normpath(folder_path)
            print(f"Trying PowerShell fallback for: {normalized_path}")
            
            # PowerShell command for single folder
            ps_script = f"""
try {{
    $acl = Get-Acl -Path '{normalized_path}' -ErrorAction Stop
    foreach ($access in $acl.Access) {{
        $permissions = [System.Collections.Generic.List[string]]::new()
        
        # Check for specific permissions
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) {{ $permissions.Add("Read") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {{ $permissions.Add("Write") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) {{ $permissions.Add("Change") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) {{ $permissions.Add("Delete") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) {{ $permissions.Add("List") }}
        
        if ($permissions.Count -gt 0) {{
            $permString = $permissions -join ", "
            Write-Output "{normalized_path}|$($access.IdentityReference)|$permString|$($access.AccessControlType)|$($access.IsInherited)"
        }}
    }}
}} catch {{
    Write-Error "Failed to get ACL for {normalized_path}: $($_.Exception.Message)"
}}
"""
            
            cmd = ['powershell', '-Command', ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  encoding='cp1252', errors='replace')
            
            print(f"PowerShell return code: {result.returncode}")
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if '|' in line and line:
                        parts = line.split('|')
                        if len(parts) >= 5:
                            path = parts[0].strip()
                            identity = parts[1].strip()
                            permission = parts[2].strip()
                            access_type = parts[3].strip()
                            inherited = parts[4].strip().lower() == 'true'
                            
                            if permission:  # Only add if we have readable permissions
                                permissions.append(PermissionEntry(
                                    path=path,
                                    identity=identity,
                                    permission=permission,
                                    access_type=access_type,
                                    inherited=inherited
                                ))
            else:
                if result.stderr:
                    print(f"PowerShell error: {result.stderr}")
        
        except Exception as e:
            print(f"PowerShell fallback error for {folder_path}: {str(e)}")
        
        return permissions
    
    @staticmethod
    def _scan_with_powershell(folder_path: str, include_subfolders: bool = False) -> List[PermissionEntry]:
        """Alternative scanning method using PowerShell - folders only"""
        permissions = []
        
        try:
            if include_subfolders:
                # PowerShell command to get ACL information for directories only
                ps_script = f"""
# Get all subdirectories
$folders = Get-ChildItem -Path '{folder_path}' -Recurse -Directory -ErrorAction SilentlyContinue
$folders += Get-Item -Path '{folder_path}' -ErrorAction SilentlyContinue

foreach ($folder in $folders) {{
    $path = $folder.FullName
    try {{
        $acl = Get-Acl -Path $path -ErrorAction Stop
        foreach ($access in $acl.Access) {{
            $permissions = [System.Collections.Generic.List[string]]::new()
            
            # Check for specific permissions
            if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) {{ $permissions.Add("Read") }}
            if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {{ $permissions.Add("Write") }}
            if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) {{ $permissions.Add("Change") }}
            if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) {{ $permissions.Add("Delete") }}
            if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) {{ $permissions.Add("List") }}
            
            if ($permissions.Count -gt 0) {{
                $permString = $permissions -join ", "
                Write-Output "$path|$($access.IdentityReference)|$permString|$($access.AccessControlType)|$($access.IsInherited)"
            }}
        }}
    }} catch {{
        # Skip inaccessible folders
    }}
}}
"""
            else:
                # PowerShell command for single folder
                ps_script = f"""
try {{
    $acl = Get-Acl -Path '{folder_path}' -ErrorAction Stop
    foreach ($access in $acl.Access) {{
        $permissions = [System.Collections.Generic.List[string]]::new()
        
        # Check for specific permissions
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) {{ $permissions.Add("Read") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {{ $permissions.Add("Write") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) {{ $permissions.Add("Change") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) {{ $permissions.Add("Delete") }}
        if ($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) {{ $permissions.Add("List") }}
        
        if ($permissions.Count -gt 0) {{
            $permString = $permissions -join ", "
            Write-Output "{folder_path}|$($access.IdentityReference)|$permString|$($access.AccessControlType)|$($access.IsInherited)"
        }}
    }}
}} catch {{
    # Skip if inaccessible
}}
"""
            
            cmd = ['powershell', '-Command', ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  encoding='cp1252', errors='replace')
            
            print(f"PowerShell command executed, return code: {result.returncode}")
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if '|' in line and line:
                        parts = line.split('|')
                        if len(parts) >= 5:
                            path = parts[0].strip()
                            identity = parts[1].strip()
                            permission = parts[2].strip()
                            access_type = parts[3].strip()
                            inherited = parts[4].strip().lower() == 'true'
                            
                            if permission:  # Only add if we have readable permissions
                                permissions.append(PermissionEntry(
                                    path=path,
                                    identity=identity,
                                    permission=permission,
                                    access_type=access_type,
                                    inherited=inherited
                                ))
        
        except Exception as e:
            print(f"PowerShell scan error: {str(e)}")
        
        return permissions
    
    @staticmethod
    def _convert_to_readable_permissions(permission_code: str) -> str:
        """Convert icacls permission codes to readable permission types"""
        readable_permissions = []
        
        # Handle comma-separated codes
        codes = [code.strip().upper() for code in permission_code.split(',')]
        
        print(f"Converting permission codes: {codes}")
        
        # Check for Full Control first
        if any(code in ['F', 'FC', 'FULLCONTROL'] for code in codes):
            return "Read, Write, Change, Delete, List"
        
        # Check for Modify
        if any(code in ['M', 'MODIFY'] for code in codes):
            return "Read, Write, Change, Delete, List"
        
        # Check individual permissions
        has_read = any(code in ['R', 'RX', 'RC', 'GR', 'RD'] for code in codes)
        has_write = any(code in ['W', 'WD', 'AD', 'WEA', 'GW'] for code in codes)
        has_execute = any(code in ['RX', 'X', 'GE'] for code in codes)
        has_delete = any(code in ['D', 'DC', 'DA'] for code in codes)
        
        # RX typically means Read & Execute (which includes List)
        if any(code in ['RX'] for code in codes):
            has_read = True
            has_execute = True
        
        # Build readable permissions
        if has_read:
            readable_permissions.append("Read")
        if has_write:
            readable_permissions.append("Write")
        if has_write or any(code in ['M', 'MODIFY'] for code in codes):  # Modify implies Change
            if "Change" not in readable_permissions:
                readable_permissions.append("Change")
        if has_delete:
            readable_permissions.append("Delete")
        if has_execute or has_read:  # Execute or Read typically includes List
            if "List" not in readable_permissions:
                readable_permissions.append("List")
        
        result = ', '.join(readable_permissions) if readable_permissions else ""
        print(f"Converted '{permission_code}' to '{result}'")
        return result
    
    @staticmethod
    def is_ad_group(identity: str) -> bool:
        """Check if identity is likely an AD group (basic heuristic)"""
        ad_indicators = ['DOMAIN\\', 'BUILTIN\\', '\\Domain', '\\']
        return any(indicator in identity.upper() for indicator in ad_indicators)


class ScanWorker(QThread):
    """Worker thread for scanning permissions"""
    
    progress = pyqtSignal(str)  # Status message
    finished = pyqtSignal(list)  # List of PermissionEntry objects
    error = pyqtSignal(str)  # Error message
    
    def __init__(self, paths: List[str], include_subfolders: bool = True):
        super().__init__()
        self.paths = paths
        self.include_subfolders = include_subfolders
        self.scanner = PermissionScanner()
    
    def run(self):
        """Run the scanning process"""
        all_permissions = []
        
        try:
            for path in self.paths:
                self.progress.emit(f"Scanning: {path}")
                
                # Check if path exists
                if not os.path.exists(path):
                    self.error.emit(f"Path not found: {path}")
                    continue
                
                # Check if we can access the path
                try:
                    os.listdir(path) if os.path.isdir(path) else os.path.exists(path)
                    self.progress.emit(f"Path accessible, scanning permissions...")
                except PermissionError:
                    self.progress.emit(f"Limited access to path, attempting permission scan anyway...")
                
                permissions = self.scanner.scan_folder_permissions(path, self.include_subfolders)
                all_permissions.extend(permissions)
                
                self.progress.emit(f"Found {len(permissions)} permission entries in {path}")
            
            self.finished.emit(all_permissions)
        
        except Exception as e:
            self.error.emit(f"Scanning error: {str(e)}")
            import traceback
            print(f"Full error trace: {traceback.format_exc()}")


class PermissionsTableWidget(QTableWidget):
    """Custom table widget for displaying permissions"""
    
    def __init__(self):
        super().__init__()
        self.init_table()
    
    def init_table(self):
        """Initialize table structure"""
        headers = ['Path', 'Identity', 'Permission', 'Access Type', 'Inherited', 'Scan Time']
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Configure table appearance and column resizing
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Path - user resizable
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Identity - user resizable  
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Permission - user resizable
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Access Type - auto size
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Inherited - auto size
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Scan Time - auto size
        
        # Set minimum column widths
        self.setColumnWidth(0, 200)  # Path
        self.setColumnWidth(1, 150)  # Identity
        self.setColumnWidth(2, 120)  # Permission
        
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSortingEnabled(True)
        
        # Enable word wrap for better text visibility
        self.setWordWrap(True)
        
        # Set default row height to accommodate wrapped text
        self.verticalHeader().setDefaultSectionSize(25)
    
    def populate_data(self, permissions: List[PermissionEntry], filter_text: str = ""):
        """Populate table with permission data"""
        # Filter data if needed
        if filter_text:
            filtered_permissions = [
                p for p in permissions 
                if filter_text.lower() in p.identity.lower() or 
                   filter_text.lower() in p.path.lower() or
                   filter_text.lower() in p.permission.lower()
            ]
        else:
            filtered_permissions = permissions
        
        self.setRowCount(len(filtered_permissions))
        
        for row, perm in enumerate(filtered_permissions):
            # Create items with proper text wrapping
            path_item = QTableWidgetItem(perm.path)
            path_item.setToolTip(perm.path)  # Show full path in tooltip
            
            identity_item = QTableWidgetItem(perm.identity)
            identity_item.setToolTip(perm.identity)
            
            permission_item = QTableWidgetItem(perm.permission)
            permission_item.setToolTip(perm.permission)
            
            access_item = QTableWidgetItem(perm.access_type)
            inherited_item = QTableWidgetItem("Yes" if perm.inherited else "No")
            time_item = QTableWidgetItem(perm.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            
            self.setItem(row, 0, path_item)
            self.setItem(row, 1, identity_item)
            self.setItem(row, 2, permission_item)
            self.setItem(row, 3, access_item)
            self.setItem(row, 4, inherited_item)
            self.setItem(row, 5, time_item)
        
        # Auto-resize rows to fit content
        self.resizeRowsToContents()


class ADPermissionsAnalyzer(QMainWindow):
    """Main application class"""
    
    def __init__(self):
        super().__init__()
        self.permissions_data = []
        self.init_ui()
        self.init_connections()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Active Directory Folder Permissions Analyzer")
        self.setGeometry(100, 100, 1400, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create UI components
        self.create_path_input_section(main_layout)
        self.create_filter_section(main_layout)
        self.create_results_section(main_layout)
        self.create_status_section(main_layout)
        
        # Apply styling
        self.apply_styling()
    
    def create_path_input_section(self, parent_layout):
        """Create the path input section"""
        path_group = QGroupBox("Folder Selection")
        path_layout = QVBoxLayout(path_group)
        
        # Path input row
        input_row = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter UNC path or local folder path...")
        input_row.addWidget(QLabel("Path:"))
        input_row.addWidget(self.path_input)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_folder)
        input_row.addWidget(self.browse_btn)
        
        path_layout.addLayout(input_row)
        
        # Options row
        options_row = QHBoxLayout()
        
        self.include_subfolders_cb = QCheckBox("Include subfolders")
        self.include_subfolders_cb.setChecked(True)
        options_row.addWidget(self.include_subfolders_cb)
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        options_row.addWidget(self.scan_btn)
        
        options_row.addStretch()
        path_layout.addLayout(options_row)
        
        parent_layout.addWidget(path_group)
    
    def create_filter_section(self, parent_layout):
        """Create the filter section"""
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)
        
        filter_layout.addWidget(QLabel("Search:"))
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by identity, path, or permission...")
        self.filter_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)
        
        self.show_groups_only_cb = QCheckBox("Show AD Groups Only")
        self.show_groups_only_cb.stateChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.show_groups_only_cb)
        
        parent_layout.addWidget(filter_group)
    
    def create_results_section(self, parent_layout):
        """Create the results section"""
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Results toolbar
        toolbar_layout = QHBoxLayout()
        
        self.export_csv_btn = QPushButton("Export All to CSV")
        self.export_csv_btn.clicked.connect(self.export_to_csv)
        self.export_csv_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_csv_btn)
        
        self.export_selected_csv_btn = QPushButton("Export Selected to CSV")
        self.export_selected_csv_btn.clicked.connect(self.export_selected_to_csv)
        self.export_selected_csv_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_selected_csv_btn)
        
        self.export_json_btn = QPushButton("Export to JSON")
        self.export_json_btn.clicked.connect(self.export_to_json)
        self.export_json_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_json_btn)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        self.clear_btn.setEnabled(False)
        toolbar_layout.addWidget(self.clear_btn)
        
        toolbar_layout.addStretch()
        
        self.results_count_label = QLabel("0 entries")
        toolbar_layout.addWidget(self.results_count_label)
        
        results_layout.addLayout(toolbar_layout)
        
        # Results table
        self.results_table = PermissionsTableWidget()
        # Connect selection change to update export button state
        self.results_table.itemSelectionChanged.connect(self.update_export_buttons)
        results_layout.addWidget(self.results_table)
        
        parent_layout.addWidget(results_group)
    
    def create_status_section(self, parent_layout):
        """Create the status section"""
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        status_layout.addWidget(self.progress_bar)
        
        parent_layout.addLayout(status_layout)
    
    def init_connections(self):
        """Initialize signal connections"""
        self.path_input.returnPressed.connect(self.start_scan)
    
    def apply_styling(self):
        """Apply custom styling to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin: 5px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
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
            QLineEdit {
                border: 2px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QTableWidget {
                gridline-color: #d0d0d0;
                background-color: white;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)
    
    def browse_folder(self):
        """Open folder browser dialog"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder", "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        if folder:
            # Normalize the path for Windows
            normalized_folder = os.path.normpath(folder)
            self.path_input.setText(normalized_folder)
    
    def start_scan(self):
        """Start the permission scanning process"""
        path = self.path_input.text().strip()
        
        if not path:
            QMessageBox.warning(self, "Warning", "Please enter a folder path.")
            return
        
        # Normalize the path to ensure Windows compatibility
        normalized_path = os.path.normpath(path)
        
        # Prepare UI for scanning
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Starting scan...")
        
        # Start worker thread with normalized path
        self.scan_worker = ScanWorker([normalized_path], self.include_subfolders_cb.isChecked())
        self.scan_worker.progress.connect(self.update_scan_progress)
        self.scan_worker.finished.connect(self.scan_completed)
        self.scan_worker.error.connect(self.scan_error)
        self.scan_worker.start()
    
    def update_scan_progress(self, message: str):
        """Update scan progress"""
        self.status_label.setText(message)
    
    def scan_completed(self, permissions: List[PermissionEntry]):
        """Handle scan completion"""
        self.permissions_data = permissions
        self.apply_filter()  # This will populate the table
        
        # Update UI
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.export_csv_btn.setEnabled(len(permissions) > 0)
        self.export_selected_csv_btn.setEnabled(False)  # No selection yet
        self.export_json_btn.setEnabled(len(permissions) > 0)
        self.clear_btn.setEnabled(len(permissions) > 0)
        
        if len(permissions) > 0:
            self.status_label.setText(f"Scan completed. Found {len(permissions)} permission entries.")
        else:
            self.status_label.setText("Scan completed. No permissions found - check path accessibility and permissions.")
            
            # Show more detailed message for troubleshooting
            path = self.path_input.text().strip()
            if os.path.exists(path):
                QMessageBox.information(self, "No Permissions Found", 
                                      f"The path exists but no permissions were found.\n\n"
                                      f"This could happen if:\n"
                                      f"• You don't have sufficient privileges to read ACLs\n"
                                      f"• The path has no explicit permissions set\n"
                                      f"• There's an issue with the icacls command\n\n"
                                      f"Try running the application as Administrator or check the path: {path}")
            else:
                QMessageBox.warning(self, "Path Not Found", 
                                  f"The specified path does not exist or is not accessible:\n{path}")

    
    def scan_error(self, error_message: str):
        """Handle scan error"""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Scan failed")
        
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{error_message}")
    
    def apply_filter(self):
        """Apply current filters to the results table"""
        if not self.permissions_data:
            return
        
        filtered_data = self.permissions_data
        
        # Apply AD groups filter
        if self.show_groups_only_cb.isChecked():
            filtered_data = [p for p in filtered_data 
                           if PermissionScanner.is_ad_group(p.identity)]
        
        # Apply search filter
        filter_text = self.filter_input.text().strip()
        
        # Populate table with filtered data
        self.results_table.populate_data(filtered_data, filter_text)
        
        # Update count
        display_count = self.results_table.rowCount()
        total_count = len(self.permissions_data)
        
        if display_count != total_count:
            self.results_count_label.setText(f"{display_count} of {total_count} entries")
        else:
            self.results_count_label.setText(f"{total_count} entries")
    
    def update_export_buttons(self):
        """Update export button states based on selection"""
        selected_rows = len(self.results_table.selectionModel().selectedRows())
        self.export_selected_csv_btn.setEnabled(selected_rows > 0)
    
    def get_selected_permissions(self) -> List[PermissionEntry]:
        """Get permission entries for currently selected rows"""
        selected_permissions = []
        selected_rows = self.results_table.selectionModel().selectedRows()
        
        for index in selected_rows:
            row = index.row()
            if row < len(self.permissions_data):
                # Find the corresponding permission entry by matching table data
                path = self.results_table.item(row, 0).text()
                identity = self.results_table.item(row, 1).text()
                permission = self.results_table.item(row, 2).text()
                
                # Find matching permission entry in our data
                for perm in self.permissions_data:
                    if (perm.path == path and 
                        perm.identity == identity and 
                        perm.permission == permission):
                        selected_permissions.append(perm)
                        break
        
        return selected_permissions
    
    def export_selected_to_csv(self):
        """Export selected results to CSV file"""
        selected_permissions = self.get_selected_permissions()
        
        if not selected_permissions:
            QMessageBox.information(self, "No Selection", "Please select one or more rows to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Selected to CSV", 
            f"permissions_selected_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV files (*.csv)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['Path', 'Identity', 'Permission', 'Access Type', 'Inherited', 'Scan Time']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for perm in selected_permissions:
                        writer.writerow(perm.to_dict())
                
                QMessageBox.information(self, "Export Complete", 
                                      f"Exported {len(selected_permissions)} selected entries to {filename}")
                self.status_label.setText(f"Exported {len(selected_permissions)} selected entries to CSV")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data:\n{str(e)}")
    
    def export_to_csv(self):
        """Export all results to CSV file"""
        if not self.permissions_data:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export All to CSV", f"permissions_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV files (*.csv)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['Path', 'Identity', 'Permission', 'Access Type', 'Inherited', 'Scan Time']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for perm in self.permissions_data:
                        writer.writerow(perm.to_dict())
                
                QMessageBox.information(self, "Export Complete", f"Data exported to {filename}")
                self.status_label.setText(f"Exported {len(self.permissions_data)} entries to CSV")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data:\n{str(e)}")
    
    def export_to_json(self):
        """Export results to JSON file"""
        if not self.permissions_data:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export to JSON", f"permissions_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON files (*.json)"
        )
        
        if filename:
            try:
                data = {
                    'scan_info': {
                        'scan_date': datetime.now().isoformat(),
                        'total_entries': len(self.permissions_data)
                    },
                    'permissions': [perm.to_dict() for perm in self.permissions_data]
                }
                
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(data, jsonfile, indent=2, ensure_ascii=False)
                
                QMessageBox.information(self, "Export Complete", f"Data exported to {filename}")
                self.status_label.setText(f"Exported {len(self.permissions_data)} entries to JSON")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data:\n{str(e)}")
    
    def clear_results(self):
        """Clear all results"""
        reply = QMessageBox.question(self, "Clear Results", 
                                   "Are you sure you want to clear all results?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.permissions_data = []
            self.results_table.setRowCount(0)
            self.results_count_label.setText("0 entries")
            self.export_csv_btn.setEnabled(False)
            self.export_selected_csv_btn.setEnabled(False)
            self.export_json_btn.setEnabled(False)
            self.clear_btn.setEnabled(False)
            self.status_label.setText("Results cleared")


class ADPermissionsApp:
    """Main application wrapper for easy integration"""
    
    def __init__(self):
        self.app = None
        self.main_window = None
    
    def create_application(self, args=None):
        """Create QApplication instance"""
        if args is None:
            args = []
        
        self.app = QApplication(args)
        self.app.setApplicationName("AD Permissions Analyzer")
        self.app.setOrganizationName("Your Organization")
        
        return self.app
    
    def create_main_window(self):
        """Create main window instance"""
        self.main_window = ADPermissionsAnalyzer()
        return self.main_window
    
    def run_standalone(self):
        """Run as standalone application"""
        if not self.app:
            self.create_application(sys.argv)
        
        if not self.main_window:
            self.create_main_window()
        
        self.main_window.show()
        return self.app.exec_()
    
    def get_main_window(self):
        """Get main window for integration with other apps"""
        if not self.main_window:
            self.create_main_window()
        return self.main_window


def main():
    """Main entry point"""
    app_wrapper = ADPermissionsApp()
    sys.exit(app_wrapper.run_standalone())


if __name__ == "__main__":
    main()
