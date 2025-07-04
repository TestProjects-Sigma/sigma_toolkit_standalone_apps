# SMTP Tester

**Version: 1.0**

A comprehensive standalone SMTP testing tool extracted from SigmaToolkit. Perfect for email server diagnostics, configuration validation, and troubleshooting SMTP connectivity issues.

## 🚀 Features

### 📧 Comprehensive SMTP Testing
- **Connection Testing**: Verify SMTP server connectivity and capabilities with detailed server information
- **Authentication Testing**: Test username/password authentication with support for various auth methods
- **Email Sending**: Send actual test emails with delivery confirmation and detailed logging
- **Relay Testing**: Test mail servers without authentication for internal relay configurations
- **Port Scanning**: Test connectivity to common SMTP ports (25, 465, 587, 2525) with descriptions

### 🔐 Security & Encryption Support
- **TLS Support**: STARTTLS encryption for secure connections (port 587)
- **SSL Support**: Direct SSL connections for legacy servers (port 465)
- **Flexible Authentication**: Optional authentication for relay testing scenarios
- **Multiple Auth Methods**: Support for various SMTP authentication mechanisms

### 🌐 DNS & Network Analysis
- **MX Record Checking**: Lookup and validate mail server DNS records for domains
- **Domain Analysis**: Extract domains from email addresses for automated MX lookups
- **Network Connectivity**: Comprehensive port availability testing and diagnostics
- **Server Capabilities**: Display supported SMTP features and extensions

### ⚡ Quick Configuration Presets
- **Gmail**: Pre-configured for smtp.gmail.com with optimal settings
- **Outlook.com**: Ready-to-use settings for Microsoft Outlook.com
- **Office 365**: Enterprise Office 365 SMTP configuration
- **Yahoo**: Yahoo Mail SMTP server settings
- **Custom Servers**: Full flexibility for any SMTP server configuration

### 🧪 Advanced Testing Features
- **Comprehensive Test Mode**: All-in-one testing sequence for complete server analysis
- **Real-time Logging**: Detailed output with timestamps and color-coded status indicators
- **Smart Auto-fill**: Automatic population of related fields for efficient configuration
- **Timeout Control**: Configurable connection timeouts for different network conditions
- **Error Handling**: Detailed error messages with troubleshooting suggestions

### 🎨 Professional Interface
- **Modern UI**: Clean, intuitive interface designed for efficiency and clarity
- **Split Layout**: Configuration panel and real-time output for optimal workflow
- **Responsive Design**: Resizable panels and comfortable spacing for different screen sizes
- **Dark Theme Output**: High-contrast console output for easy reading during extended use
- **Status Indicators**: Visual feedback for connection states and test progress

## 📋 Requirements

- **Python 3.7+**
- **PyQt5** for the graphical interface
- **Network access** to SMTP servers you want to test
- **DNS resolution** for MX record lookups
- **Firewall permissions** for outbound SMTP connections

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd smtp-tester
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
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python main.py
```

## ⚙️ Configuration

### Basic SMTP Configuration

| Setting | Example | Description |
|---------|---------|-------------|
| **Server** | `smtp.gmail.com` | SMTP server hostname or IP address |
| **Port** | `587` | SMTP port (587 for TLS, 465 for SSL, 25 for plain) |
| **Encryption** | ✅ TLS | Choose TLS (STARTTLS) or SSL based on server support |
| **Timeout** | `10 seconds` | Connection timeout for slower networks |

### Authentication (Optional)

| Setting | Example | Description |
|---------|---------|-------------|
| **Username** | `user@domain.com` | SMTP authentication username |
| **Password** | `your_password` | SMTP authentication password |
| **Relay Mode** | Leave empty | Test without authentication for relay servers |

### Email Testing Configuration

| Setting | Example | Description |
|---------|---------|-------------|
| **From** | `sender@domain.com` | Sender email address |
| **To** | `recipient@domain.com` | Recipient email address for test emails |
| **Subject** | `SMTP Test` | Customizable email subject line |

## 🎯 Usage

### 1. Quick Start with Presets
1. **Select Provider**: Click Gmail, Outlook, Office 365, or Yahoo for instant configuration
2. **Add Credentials**: Enter your username and password (if required)
3. **Test Connection**: Click "Test Connection" to verify server accessibility
4. **Send Test Email**: Configure email addresses and send a test message

### 2. Custom SMTP Server Testing
1. **Enter Server Details**: Input your SMTP server hostname and port
2. **Choose Encryption**: Select TLS or SSL based on your server requirements
3. **Configure Authentication**: Add credentials or leave empty for relay testing
4. **Run Tests**: Use individual tests or "Comprehensive Test" for complete analysis

### 3. Relay Testing (No Authentication)
1. **Configure Server**: Enter internal mail server details
2. **Leave Credentials Empty**: Skip username/password for relay testing
3. **Test Relay**: Verify if the server accepts emails without authentication
4. **Check Policies**: Ensure relay is properly configured and secured

### 4. Troubleshooting Workflow
1. **Check MX Records**: Verify domain has properly configured mail servers
2. **Scan Ports**: Confirm SMTP ports are accessible through firewalls
3. **Test Connection**: Verify basic connectivity and server capabilities
4. **Test Authentication**: Validate credentials and authentication methods
5. **Send Test Email**: Confirm end-to-end email delivery functionality

## 📊 Understanding Results

### Connection Test Results

| Status | Meaning | Next Steps |
|--------|---------|------------|
| ✅ **Connection Successful** | Server is accessible and responding | Proceed with authentication or email testing |
| ❌ **Connection Failed** | Cannot reach server | Check hostname, port, firewall, network connectivity |
| ⏱️ **Connection Timeout** | Server not responding within timeout | Increase timeout, check network latency |

### Authentication Test Results

| Status | Meaning | Troubleshooting |
|--------|---------|-----------------|
| ✅ **Authentication Successful** | Credentials verified | Ready for email sending |
| ❌ **Authentication Failed** | Invalid credentials | Check username/password, account status, 2FA settings |
| ⚠️ **No Credentials** | Testing in relay mode | Normal for internal servers, ensure proper relay configuration |

### Email Sending Results

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| ✅ **Email Sent Successfully** | Message delivered to server | Check recipient inbox and spam folder |
| ❌ **Recipient Refused** | Server rejected recipient | Verify email address, check server policies |
| ❌ **Sender Refused** | Server rejected sender | Check sender address, authentication requirements |
| ❌ **Authentication Required** | Server requires credentials | Add username/password or enable relay |

### Port Scan Results

| Port | Description | Usage |
|------|-------------|-------|
| **25** | SMTP (Plain) | Traditional SMTP, often blocked by ISPs |
| **465** | SMTPS (SSL) | Legacy SSL SMTP, direct encryption |
| **587** | SMTP (TLS) | Modern SMTP with STARTTLS, recommended |
| **2525** | SMTP (Alternative) | Alternative port when others are blocked |

## 🔍 SMTP Testing Guide

### Common SMTP Ports Explained

- **Port 587 (TLS/STARTTLS)**: Modern standard for secure SMTP submission
- **Port 465 (SSL)**: Legacy but still widely used for SSL-encrypted SMTP
- **Port 25 (Plain)**: Traditional SMTP port, often blocked by ISPs for security
- **Port 2525 (Alternative)**: Used when standard ports are blocked or restricted

### Authentication Methods

- **LOGIN**: Basic username/password authentication
- **PLAIN**: Plain text authentication (over encrypted connection)
- **CRAM-MD5**: Challenge-response authentication
- **OAUTH2**: Modern token-based authentication (for cloud services)

### Encryption Types

- **TLS (STARTTLS)**: Upgrades plain connection to encrypted (recommended)
- **SSL**: Direct encrypted connection from start
- **Plain**: Unencrypted connection (not recommended for production)

## 🛡️ Security Best Practices

### Email Server Testing Security
- **Use test accounts** when possible to avoid exposing production credentials
- **Verify SSL certificates** when testing with encryption enabled
- **Monitor test emails** to ensure they don't contain sensitive information
- **Test during maintenance windows** to avoid impacting production systems

### Network Security
- **Firewall rules** allowing outbound SMTP connections to test servers
- **VPN or secure network** when testing from remote locations
- **Monitor connections** in server logs for security and compliance
- **Document test procedures** for audit and compliance requirements

### Credential Management
- **Never store credentials** in configuration files or logs
- **Use application passwords** instead of main account passwords when available
- **Rotate test credentials** regularly following security policies
- **Limit permissions** on test accounts to minimum required for testing

## 🔄 Troubleshooting

### Connection Issues

#### "Connection timed out"
- **Solution**: Increase timeout value or check network connectivity
- **Cause**: Network latency, firewall blocking, or server overload
- **Alternative**: Try different SMTP port or server

#### "Connection refused"
- **Check port**: Verify SMTP port is correct and accessible
- **Verify hostname**: Ensure server address is correct
- **Firewall**: Check if outbound SMTP connections are allowed
- **Server status**: Confirm SMTP service is running on target server

### Authentication Problems

#### "Authentication failed"
- **Verify credentials**: Double-check username and password
- **Account status**: Ensure account is active and not locked
- **2FA/App passwords**: Use application-specific passwords if 2FA is enabled
- **Server settings**: Confirm authentication method is supported

#### "Authentication not supported"
- **Check server capabilities**: Server may not require authentication
- **Relay configuration**: Test without credentials for internal servers
- **Protocol version**: Ensure server supports modern authentication methods

### Email Sending Issues

#### "Recipient refused"
- **Valid address**: Verify recipient email address format and domain
- **Server policies**: Check if server accepts emails to external domains
- **Relay restrictions**: Confirm relay permissions for target recipient

#### "Sender refused"
- **Authentication**: Server may require valid credentials
- **Valid sender**: Use a properly formatted sender address
- **Domain verification**: Ensure sender domain is authorized

### DNS and Network Issues

#### "MX lookup failed"
- **DNS connectivity**: Verify DNS resolution is working
- **Domain validity**: Confirm domain name is spelled correctly
- **DNS servers**: Try using different DNS servers for lookup

#### "No SMTP ports open"
- **Firewall**: Check firewall rules on both client and server
- **ISP blocking**: Some ISPs block outbound SMTP ports
- **Server configuration**: Verify SMTP service is running and listening

## 📁 File Structure

```
smtp-tester/
├── main.py                     # Complete standalone application
├── requirements.txt            # Python dependencies
└── README.md                  # This documentation
```

## 🤝 Contributing

Contributions are welcome! Priority areas for improvement:

### High Priority
- **OAuth2 authentication** support for modern cloud services
- **Configuration profiles** for saving and loading server settings
- **Batch testing** for multiple servers or configurations
- **Email template customization** for test messages

### Medium Priority
- **Certificate validation** and SSL/TLS diagnostics
- **Performance metrics** and connection timing analysis
- **Export functionality** for test results and reports
- **Advanced logging** with different output formats

### Low Priority
- **Plugin architecture** for custom testing modules
- **Automated testing scripts** for CI/CD integration
- **Mobile-responsive interface** for tablet and phone use
- **Internationalization** for multiple language support

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for SMTP server testing and email configuration validation purposes. Always:

### Testing Responsibilities
- **Test in non-production environments** first when possible
- **Use test accounts** to avoid exposing production credentials
- **Monitor test emails** to ensure they don't impact production systems
- **Follow your organization's testing policies** and procedures

### Security Responsibilities
- **Keep credentials secure** and never store them in configuration files
- **Use encrypted connections** (TLS/SSL) when testing production servers
- **Monitor access logs** for security and compliance requirements
- **Document testing activities** for audit and compliance purposes

### Operational Responsibilities
- **Verify server settings** before running comprehensive tests
- **Limit test frequency** to avoid overwhelming target servers
- **Clean up test data** and emails after testing is complete
- **Report issues** found during testing through proper channels

## 📞 Support

For issues and questions:

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Review error messages** in the real-time output panel
3. **Test with known working servers** to verify tool functionality
4. **Verify network connectivity** and firewall settings

### Community Support
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples included
- **Best Practices**: Security and operational guidelines provided

### Enterprise Support
For enterprise deployments requiring:
- **Custom SMTP testing** workflows and automation
- **Integration** with existing monitoring and alerting systems
- **Advanced security** requirements and compliance frameworks
- **Training and support** for IT teams and administrators

---

**SMTP Tester v1.0** - Your comprehensive standalone tool for SMTP server testing, email configuration validation, and mail system diagnostics. Built for system administrators and IT professionals who need reliable email server testing capabilities.