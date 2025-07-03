# Active Directory Password Expiry Checker

A secure PyQt5-based desktop application for monitoring Windows Active Directory password expiration dates. This tool provides a clean GUI interface to track when user passwords will expire or have already expired, with color-coded visual indicators and export capabilities.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![PyQt5](https://img.shields.io/badge/PyQt5-5.15.9-green.svg)

## 🚀 Features

### 🔒 Security Features
- **LDAP over SSL/TLS (LDAPS)** with strong cipher suites
- **NTLM authentication** for Windows Active Directory
- **Certificate validation** for secure connections
- **No sensitive data storage** - passwords never saved to config files
- **Multiple authentication methods** with automatic fallback

### 📊 Password Monitoring
- **Real-time password expiration tracking** with exact day counts
- **Visual indicators**: 
  - 🔴 **Red highlighting** for expired passwords (negative days like -5)
  - 🟡 **Yellow highlighting** for passwords expiring soon (≤7 days)
  - ✅ **Normal display** for active passwords
- **Handles special cases**: "Password never expires" and disabled accounts
- **Sortable data table** with comprehensive user information

### 🖥️ User Interface
- **Clean PyQt5 GUI** with split-panel design
- **Configuration panel** for easy setup and testing
- **Auto-refresh capability** with configurable intervals
- **Progress indicators** for long-running operations
- **Export functionality** to CSV format
- **Summary statistics** showing total/expired/expiring counts

### 🏗️ Integration Ready
- **Standalone application** that runs independently
- **API class included** for easy integration with existing applications
- **Clean OOP structure** for maintainability and extension
- **Threaded operations** to prevent UI blocking

## 📋 Requirements

- **Python 3.7+**
- **Windows environment** (for Active Directory access)
- **Network access** to your Active Directory server
- **Service account** with read permissions on AD user objects

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd ad-password-checker
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Linux/Mac
```

### 3. Install Dependencies
```bash
pip install PyQt5==5.15.9 ldap3==2.9.1 cryptography==41.0.7 pycryptodome==3.19.0
```

### 4. Run the Application
```bash
python ad_password_checker.py
```

## ⚙️ Configuration

### Required Settings

Fill in the configuration panel with your Active Directory details:

| Field | Example | Description |
|-------|---------|-------------|
| **Server** | `dc01.company.com` | Your AD domain controller |
| **Port** | `636` (SSL) or `389` | LDAP port (636 recommended for security) |
| **Use SSL/TLS** | ✅ Checked | Enable secure connection (recommended) |
| **Domain** | `COMPANY` | Your Windows domain name |
| **Base DN** | `DC=company,DC=com` | LDAP search base for users |
| **Username** | `serviceaccount` | AD account with read permissions |
| **Password** | `your_password` | Account password (not saved) |

### Optional Settings

| Setting | Default | Description |
|---------|---------|-------------|
| **Auto Refresh** | Disabled | Automatically refresh data |
| **Refresh Interval** | 60 seconds | How often to refresh (if enabled) |
| **Warning Days** | 14 days | Days threshold for warnings |

## 🎯 Usage

### 1. Initial Setup
1. **Launch the application**
2. **Fill in the configuration** in the left panel
3. **Click "Test Connection"** to verify settings
4. **Click "Save Configuration"** to store settings

### 2. Monitor Passwords
1. **Click "Refresh Data"** to load user information
2. **Review the results** in the main table:
   - Users with expired passwords show **negative numbers** (e.g., -5 days)
   - Users with passwords expiring soon show **positive numbers** (e.g., 11 days)
   - Color coding helps identify critical accounts
3. **Check the summary** for quick statistics

### 3. Export Data
1. **Click "Export Data"** to save results as CSV
2. **File saved** as `password_expiry_report.csv` in the current directory

## 📊 Understanding the Results

### Password Status Indicators

| Display | Meaning | Color |
|---------|---------|-------|
| `11` | Password expires in 11 days | Normal |
| `3` | Password expires in 3 days | 🟡 Yellow |
| `-5` | Password expired 5 days ago | 🔴 Red |
| `Never` | Password never expires | Normal |
| `Disabled` | Account is disabled | Normal |

### Table Columns

- **Username**: Active Directory login name
- **Display Name**: User's full name
- **Email**: Email address (if available)
- **Days Until Expiry**: Countdown to password expiration
- **Password Last Set**: When password was last changed
- **Password Expires**: Calculated expiration date
- **Status**: Account status summary

## 🔧 Integration with Existing Applications

### Using the API Class

```python
from ad_password_checker import ADPasswordAPI

# Initialize the API
ad_api = ADPasswordAPI("config.json")

# Get password data programmatically
users = ad_api.get_password_expiry_data(
    server="dc.company.com",
    port=636,
    use_ssl=True,
    domain="COMPANY",
    username="serviceaccount",
    password="password",
    base_dn="DC=company,DC=com"
)

# Process results
for user in users:
    if user['days_until_expiry'] < 0:
        print(f"EXPIRED: {user['username']} ({user['days_until_expiry']} days)")
    elif user['days_until_expiry'] <= 11:
        print(f"EXPIRING: {user['username']} ({user['days_until_expiry']} days)")
```

### Return Data Format

Each user record contains:
```python
{
    "username": "john.doe",
    "display_name": "John Doe",
    "email": "john.doe@company.com",
    "password_last_set": "2025-06-13T08:02:31",
    "password_expires": "2025-09-11T08:02:31",
    "days_until_expiry": 77,
    "account_disabled": False,
    "password_never_expires": False
}
```

## 🛡️ Security Best Practices

### Connection Security
- **Always use SSL/TLS** (port 636) in production
- **Validate certificates** in secure environments
- **Use service accounts** with minimal required permissions
- **Never store passwords** in configuration files

### Account Permissions
The service account needs:
- **Read access** to user objects in Active Directory
- **Permission to query** user attributes: `sAMAccountName`, `displayName`, `mail`, `pwdLastSet`, `userAccountControl`
- **No elevated privileges** required

### Network Security
- **Firewall rules** allowing LDAP/LDAPS traffic
- **VPN or secure network** when accessing from remote locations
- **Monitor connections** in your LDAP server logs

## 🔍 Troubleshooting

### Common Issues

#### "Connection Error: unsupported hash type MD4"
- **Solution**: Install `pycryptodome`: `pip install pycryptodome==3.19.0`
- **Cause**: Newer Python versions disable MD4 needed for NTLM

#### "Test connection failed"
- **Check server name**: Try both short name and FQDN
- **Verify port**: 636 for SSL, 389 for non-SSL
- **Check credentials**: Ensure username/password are correct
- **Network access**: Verify firewall allows LDAP connections

#### "No results returned"
- **Verify Base DN**: Should match your domain structure
- **Check permissions**: Service account needs read access
- **Review search scope**: Ensure users exist in the specified OU

#### "Authentication failed"
- **Try different formats**: App tries multiple automatically
- **Domain format**: Use short domain name (e.g., "COMPANY" not "company.com")
- **Account status**: Ensure service account is not locked/disabled

### Debug Mode

Enable debug output by adding to the beginning of the script:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Getting Help

1. **Check the console output** for detailed error messages
2. **Verify configuration** with "Test Connection" first
3. **Review Active Directory logs** for authentication issues
4. **Test with different service accounts** if available

## 📁 File Structure

```
ad-password-checker/
├── ad_password_checker.py    # Main application file
├── ad_config.json           # Configuration file (auto-created)
├── password_expiry_report.csv # Export file (auto-created)
├── README.md               # This documentation
└── requirements.txt        # Python dependencies
```

## 🔄 Password Policy Notes

- **Default assumption**: 90-day password expiration policy
- **Domain policy detection**: Attempts to read actual domain policy
- **Fallback behavior**: Uses 90-day default if policy cannot be determined
- **Never expires**: Properly handles accounts with password never expires flag
- **Disabled accounts**: Identifies and marks disabled user accounts

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- **Additional authentication methods** (Kerberos, etc.)
- **Enhanced password policy detection**
- **Email notifications** for expiring passwords
- **Advanced filtering and search**
- **Multiple domain support**
- **REST API interface**

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for password monitoring purposes. Always:
- **Test thoroughly** in non-production environments first
- **Follow your organization's security policies**
- **Keep service account credentials secure**
- **Monitor and audit** tool usage appropriately

## 📞 Support

For issues and questions:
1. **Check troubleshooting section** above
2. **Review error messages** in console output
3. **Verify configuration** with test connection feature
4. **Test with minimal setup** first before complex configurations