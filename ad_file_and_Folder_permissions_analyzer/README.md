# Active Directory Folder Permissions Analyzer

A PyQt5-based Windows application for analyzing and reporting NTFS permissions on network and local folders. This tool helps system administrators quickly identify which Active Directory groups and users have access to specific directories.

## Features

### 🔍 **Permission Scanning**
- Scan local folders and UNC network paths
- Recursive subfolder scanning option
- Focus on directory permissions only (excludes files)
- Support for both standard and complex folder structures

### 👥 **Active Directory Integration**
- Automatically identifies AD groups vs local users
- Filter to show only AD groups
- Displays user-friendly permission types

### 📊 **Clean Permission Display**
- Shows only relevant permission types: **Read**, **Write**, **Change**, **Delete**, **List**
- Indicates inheritance status
- Shows Allow/Deny access types
- Real-time filtering and search capabilities

### 📤 **Flexible Export Options**
- **Export All to CSV** - Export complete scan results
- **Export Selected to CSV** - Export only selected table rows
- **Export to JSON** - Machine-readable format for automation
- Timestamped filenames for easy organization

### 🎨 **Professional Interface**
- Clean, modern PyQt5 interface
- Resizable columns with tooltips
- Progress indication during scans
- Status updates and error handling

## Requirements

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.7 or higher
- **Permissions**: Standard user (Administrator recommended for full access)

### Python Dependencies
```bash
pip install PyQt5
```

## Installation

### Option 1: Direct Usage
1. Download the `ad_permissions_app.py` file
2. Install PyQt5: `pip install PyQt5`
3. Run: `python ad_permissions_app.py`

### Option 2: Integration with Existing Applications
```python
from ad_permissions_app import ADPermissionsApp

# Create and integrate
permissions_app = ADPermissionsApp()
permissions_window = permissions_app.get_main_window()
permissions_window.show()
```

## Usage Guide

### 1. **Starting a Scan**

#### Manual Path Entry
- Enter the folder path in the text field:
  - Local: `C:\Users\Public\Documents`
  - UNC: `\\server\share\folder`

#### Browse for Folder
- Click **Browse** to select a folder using the file dialog

#### Scan Options
- ☑️ **Include subfolders** - Recursively scan all subdirectories
- Click **Start Scan** to begin

### 2. **Viewing Results**

The results table displays:
- **Path** - Directory path
- **Identity** - User or group name (e.g., `DOMAIN\GroupName`)
- **Permission** - Specific permissions (Read, Write, Change, Delete, List)
- **Access Type** - Allow or Deny
- **Inherited** - Whether permission is inherited from parent
- **Scan Time** - When the scan was performed

### 3. **Filtering Results**

#### Search Filter
- Use the search box to filter by:
  - Identity name
  - Path
  - Permission type

#### AD Groups Filter
- ☑️ **Show AD Groups Only** - Hide local users and show only domain groups

### 4. **Exporting Data**

#### Export All Results
1. Click **Export All to CSV**
2. Choose filename and location
3. All scan results are exported

#### Export Selected Results
1. Select specific rows in the table:
   - Single click on row number for single selection
   - Ctrl+Click for multiple individual rows
   - Shift+Click for range selection
   - Ctrl+A to select all visible rows
2. Click **Export Selected to CSV**
3. Choose filename and location
4. Only selected rows are exported

#### JSON Export
- Click **Export to JSON** for machine-readable format
- Includes metadata and structured permission data

## Understanding Permission Types

| Permission | Description |
|------------|-------------|
| **Read** | View folder contents and file properties |
| **Write** | Create new files and folders |
| **Change** | Modify existing files and folders |
| **Delete** | Remove files and folders |
| **List** | Browse folder contents |

### Special Combinations
- **Full Control** → Displays as: "Read, Write, Change, Delete, List"
- **Modify** → Displays as: "Read, Write, Change, Delete, List"
- **Read & Execute** → Displays as: "Read, List"

## Troubleshooting

### "No Permissions Found"
**Possible causes:**
- Insufficient privileges to read ACLs
- Path doesn't exist or is inaccessible
- No explicit permissions set (only inherited)

**Solutions:**
- Run application as Administrator
- Verify path exists and is accessible
- Check network connectivity for UNC paths

### "Path Syntax Error"
**Possible causes:**
- Mixed forward/backward slashes
- Invalid UNC path format
- Special characters in path

**Solutions:**
- Use proper Windows path format: `C:\folder` or `\\server\share`
- Avoid special characters when possible
- Try browsing to folder instead of typing path

### Slow Scanning
**Possible causes:**
- Large directory structures
- Network latency for UNC paths
- Many nested folders

**Solutions:**
- Disable "Include subfolders" for faster scanning
- Scan specific subdirectories instead of root
- Use during off-peak hours for network shares

## Technical Details

### Architecture
- **Object-Oriented Design** - Clean separation of concerns
- **Threading** - Non-blocking UI during scans
- **Error Handling** - Graceful fallback mechanisms
- **Cross-compatible** - Works with local and network paths

### Permission Detection Methods
1. **Primary**: Windows `icacls` command
2. **Fallback**: PowerShell `Get-Acl` cmdlet
3. **Path Normalization** - Automatic Windows path format correction

### File Formats

#### CSV Export Format
```csv
Path,Identity,Permission,Access Type,Inherited,Scan Time
C:\folder,DOMAIN\Users,"Read, List",Allow,Yes,2025-07-01 13:22:37
```

#### JSON Export Format
```json
{
  "scan_info": {
    "scan_date": "2025-07-01T13:22:37",
    "total_entries": 25
  },
  "permissions": [
    {
      "Path": "C:\\folder",
      "Identity": "DOMAIN\\Users",
      "Permission": "Read, List",
      "Access Type": "Allow",
      "Inherited": true,
      "Scan Time": "2025-07-01 13:22:37"
    }
  ]
}
```

## Security Considerations

- Application requires read access to folder ACLs
- No modifications are made to any permissions
- Network credentials use current user context
- Export files contain sensitive permission information

## Integration Examples

### Standalone Application
```python
python ad_permissions_app.py
```

### Embedded in Existing Application
```python
from ad_permissions_app import ADPermissionsApp

class MyMainApp:
    def __init__(self):
        self.permissions_app = ADPermissionsApp()
        
    def show_permissions_analyzer(self):
        window = self.permissions_app.get_main_window()
        window.show()
```

### Automation Integration
```python
# Access the core scanning functionality
from ad_permissions_app import PermissionScanner

scanner = PermissionScanner()
permissions = scanner.scan_folder_permissions("C:\\data", include_subfolders=True)

for perm in permissions:
    print(f"{perm.path}: {perm.identity} -> {perm.permission}")
```

## Contributing

This application is designed with modularity in mind. Key extension points:

- **PermissionScanner** - Add new scanning methods
- **PermissionEntry** - Extend data model
- **Export functions** - Add new output formats
- **UI components** - Customize interface elements

## License

This project is provided as-is for educational and administrative purposes. Please ensure compliance with your organization's software policies.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify system requirements are met
3. Test with simple folder structures first
4. Run as Administrator if permission issues occur

---

*Built with Python and PyQt5 for Windows system administration*