# Mail Header Analyzer

**Version: 2.0**

A comprehensive standalone PyQt5-based GUI application designed for email administrators, security analysts, and IT professionals to perform detailed email header analysis, authentication verification, and spam detection. Your dedicated tool for email security compliance and troubleshooting.

## 🚀 Features

### 📧 Comprehensive Header Analysis
- **Complete Email Header Parsing**: Analyze all email headers with detailed inspection and visualization
- **Visual Header Tree Display**: Clean, organized view of all header fields and values
- **Authentication Status Checking**: Real-time SPF, DKIM, and DMARC validation from headers
- **Security Issue Detection**: Identify suspicious patterns, missing headers, and potential threats
- **Professional Analysis Reports**: Generate comprehensive analysis with security recommendations
- **Sample Headers**: Built-in sample data for testing and learning email analysis

### 🔐 Email Authentication Verification
- **SPF Record Analysis**: Validate sender IP against DNS policies with detailed mechanism breakdown
- **DKIM Signature Verification**: Check cryptographic signatures, key strength, and selector validation
- **DMARC Policy Assessment**: Analyze domain policies, alignment settings, and enforcement levels
- **Auto-Domain Extraction**: Automatically extract domain and IP information from email headers
- **Comprehensive Authentication Reports**: Combined analysis with security recommendations and compliance status
- **Real-time DNS Queries**: Live lookup of authentication records with detailed parsing

### 🛤️ Delivery Path Visualization
- **Email Route Tracking**: Trace message path through all mail servers with detailed hop analysis
- **Timestamp Analysis**: Calculate delivery delays and identify bottlenecks in the mail flow
- **Server Identification**: Extract and analyze all intermediate mail servers and their roles
- **Loop Detection**: Identify potential mail routing loops and configuration issues
- **Customizable Display**: Toggle timestamps, delays, server info, and display order
- **Performance Analytics**: Assess delivery speed and identify slow mail infrastructure

### 🛡️ Spam & Security Analysis
- **IP Reputation Checking**: Verify sender IP against reputation databases and reverse DNS
- **Blacklist Verification**: Recommendations for checking against common spam blacklists
- **Content Pattern Analysis**: Identify suspicious content indicators and phishing patterns
- **Risk Assessment**: Generate overall security and spam probability scores
- **Security Compliance**: Support for email security auditing and compliance requirements
- **Threat Intelligence**: Integration-ready analysis for security information systems

### 💾 File Support & Data Management
- **Multiple File Formats**: Support for .eml (standard), .msg (Outlook), and .txt files
- **Drag & Drop Upload**: Easy file loading with validation and format detection
- **Export Capabilities**: Save complete analysis results to text files for documentation
- **Copy/Paste Integration**: Easy clipboard operations for headers and results
- **Sample Data Library**: Built-in examples for testing different email scenarios
- **Auto-Save Results**: Persistent analysis results for review and comparison

### 🎨 Professional User Interface
- **Modern Tabbed Interface**: Organized analysis sections with clean navigation
- **Real-time Output Logging**: Live results with timestamp and color-coded log levels
- **Resizable Panels**: Optimized workspace with customizable layout
- **Debug Mode**: Detailed logging for advanced troubleshooting and analysis
- **Status Bar**: Real-time operation feedback and progress indicators
- **Keyboard Shortcuts**: Efficient workflow with menu shortcuts and hotkeys

## 📋 Requirements

- **Python 3.7+**
- **PyQt5** for the graphical user interface
- **Network access** for DNS queries and authentication record lookups
- **Email client access** for copying headers or exporting .eml files
- **Modern operating system** (Windows 10+, macOS 10.14+, Linux with GUI)

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd mail-header-analyzer
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
python mail_analyzer.py
```

## ⚙️ Quick Start Guide

### Getting Email Headers

#### From Gmail:
1. Open the email in Gmail
2. Click the three dots menu (⋮) next to Reply
3. Select "Show original"
4. Copy the headers from the text that appears

#### From Outlook:
1. Open the email in Outlook
2. Go to File → Properties
3. Copy the text from the "Internet headers" box

#### From Thunderbird:
1. Select the email
2. Go to View → Message Source (Ctrl+U)
3. Copy the header portion (everything before the blank line)

#### From .eml Files:
1. Save email as .eml file from your email client
2. Use "Upload .eml File" option in the application

### Basic Usage Workflow

1. **Load Headers**: Paste headers or upload .eml file
2. **Analyze**: Click "Analyze Headers" for comprehensive analysis
3. **Authentication**: Use authentication tab for SPF/DKIM/DMARC checking
4. **Delivery Path**: Review routing and timing in delivery path tab
5. **Security**: Check IP reputation and spam indicators
6. **Export**: Save results for documentation and reports

## 📊 Understanding Results

### Header Analysis Results

#### Authentication Status Indicators
- **✅ PASS**: Authentication check passed successfully
- **❌ FAIL**: Authentication check failed (potential security issue)
- **⚠️ SOFTFAIL**: Authentication check returned soft failure (warning)
- **❓ UNKNOWN**: Authentication status could not be determined

#### Delivery Path Analysis
- **Hop Count**: Number of mail servers the email passed through
- **Total Delay**: Time taken for complete email delivery
- **Server Analysis**: Identification of each mail server in the path
- **Timing Issues**: Detection of unusual delays or time regressions

#### Security Assessment
- **🟢 Low Risk**: Email appears legitimate with proper authentication
- **🟡 Medium Risk**: Some security concerns but not necessarily malicious
- **🔴 High Risk**: Multiple security issues indicating potential threats

### Authentication Records Explained

#### SPF (Sender Policy Framework)
- **Purpose**: Validates that sending IP is authorized by domain owner
- **Mechanisms**: Include, A, MX, IP4, IP6 records that authorize senders
- **Policies**: All, ~all (SoftFail), -all (Fail), ?all (Neutral)
- **Result**: Pass/Fail indication for sender IP authorization

#### DKIM (DomainKeys Identified Mail)
- **Purpose**: Cryptographic signature verification for message integrity
- **Components**: Public key, signature algorithm, signed headers
- **Validation**: Signature verification against DNS-published public key
- **Security**: Ensures message hasn't been tampered with in transit

#### DMARC (Domain Message Authentication)
- **Purpose**: Policy for handling SPF and DKIM authentication failures
- **Policies**: None (monitor), Quarantine (suspicious), Reject (block)
- **Alignment**: How strictly SPF and DKIM must align with From domain
- **Reporting**: Aggregate and forensic reporting for domain owners

## 🔧 Advanced Configuration

### DNS Server Selection
The application uses system default DNS servers for authentication record lookups. For testing with specific DNS servers, you can:

1. Configure system DNS settings
2. Use VPN or network tools to route DNS queries
3. Test from different network locations for comparison

### Debug Mode
Enable debug mode for detailed logging:
1. Click the "Debug" button in the output section
2. Review detailed logs for troubleshooting
3. Copy debug output for technical support

### Custom Analysis Options
- **Delivery Path Display**: Customize timestamp, delay, and server information display
- **Authentication Testing**: Test individual components or run comprehensive analysis
- **Export Formats**: Save results in detailed text format for external analysis

## 🛡️ Security Best Practices

### Email Header Analysis Security
- **Never trust headers alone** - headers can be spoofed or manipulated
- **Verify authentication results** with multiple checks and cross-references
- **Check for consistency** between different header fields and authentication results
- **Monitor for anomalies** in delivery paths and unusual routing patterns

### Authentication Record Security
- **Regular monitoring** of SPF, DKIM, and DMARC records for unauthorized changes
- **Proper DMARC policies** - move from p=none to p=quarantine/reject when ready
- **Key rotation** for DKIM signatures according to security best practices
- **Monitor DMARC reports** for authentication failures and potential abuse

### Privacy and Data Protection
- **Sensitive information** in headers should be handled according to privacy policies
- **Email content** may contain confidential information - handle appropriately
- **Exported results** contain detailed email routing information - store securely
- **IP addresses** in headers may reveal internal network information

## 🔍 Troubleshooting

### Common Issues

#### "Unable to resolve DNS records"
- **Check network connectivity** to ensure internet access
- **Verify DNS settings** and try different DNS servers
- **Firewall rules** may be blocking DNS queries
- **Try different domains** to isolate the issue

#### "Invalid email format detected"
- **Ensure complete headers** are copied, including all Received headers
- **Check file encoding** when uploading .eml files
- **Verify header format** matches standard email header structure
- **Try sample headers** to test application functionality

#### "Authentication check timeout"
- **Network latency** may cause DNS lookup delays
- **Firewall restrictions** may block outbound DNS queries
- **DNS server issues** may cause query failures
- **Retry the check** after a brief delay

#### "No delivery path found"
- **Missing Received headers** in the email - some may have been stripped
- **Incomplete headers** copied from email client
- **Internal emails** may have minimal routing information
- **Check different email sources** for comparison

### Performance Optimization
- **Close other applications** for better system performance during analysis
- **Use local DNS cache** for faster repeated queries
- **Process smaller header sets** for testing before full analysis
- **Monitor system resources** during large-scale analysis operations

### Getting Help
1. **Enable debug mode** for detailed error information
2. **Check system requirements** and dependency versions
3. **Test with sample data** to isolate configuration issues
4. **Review network configuration** for DNS and connectivity issues

## 📁 File Structure

```
mail-header-analyzer/
├── mail_analyzer.py           # Main application file
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── LICENSE                   # License information
└── examples/
    ├── sample_headers.txt    # Sample email headers for testing
    ├── sample_phishing.eml   # Example phishing email (safe)
    └── sample_legitimate.eml # Example legitimate email
```

## 🔄 Version History

- **v2.0** - Complete standalone application with all mail analysis features
- **v1.4** - Original mail analysis module in SigmaToolkit
- **v1.3** - Added comprehensive authentication checking
- **v1.2** - Enhanced delivery path analysis
- **v1.1** - Added spam detection capabilities
- **v1.0** - Initial header parsing and basic analysis

## 🤝 Contributing

Contributions are welcome! Priority areas for improvement:

### High Priority
- **Additional file format support** (.msg, .mbox, .pst integration)
- **Enhanced threat detection** with machine learning-based analysis
- **Bulk analysis capabilities** for processing multiple emails
- **Integration APIs** for SIEM and security platform connectivity
- **Advanced reporting** with charts, graphs, and executive summaries

### Medium Priority
- **Email client plugins** for direct integration with popular email clients
- **Command-line interface** for automation and scripting
- **Cloud service integration** for reputation and threat intelligence
- **Custom rule engine** for organization-specific analysis rules
- **Historical analysis** and trending capabilities

### Low Priority
- **Additional export formats** (PDF, JSON, XML, CSV)
- **Custom themes** and UI personalization
- **Internationalization** and multi-language support
- **Mobile companion app** for basic analysis capabilities

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for email security analysis and troubleshooting purposes. Always:

### Security Responsibilities
- **Verify results** with multiple analysis methods and tools
- **Follow security policies** of your organization
- **Handle sensitive data** according to privacy regulations
- **Keep software updated** for latest security features
- **Use in compliance** with applicable laws and regulations

### Analysis Limitations
- **Headers can be spoofed** - use results as part of broader security analysis
- **DNS results depend** on network configuration and timing
- **Authentication results** should be correlated with email content analysis
- **False positives/negatives** are possible with any automated analysis tool

### Operational Responsibilities
- **Test thoroughly** in non-production environments first
- **Document findings** and maintain analysis records
- **Regular updates** to maintain compatibility and security
- **Professional judgment** required for interpreting results
- **Backup important data** before making security decisions based on analysis

---

**Mail Header Analyzer v2.0** - Your dedicated tool for comprehensive email security analysis, authentication verification, and spam detection. Perfect for email administrators, security analysts, and IT professionals who need detailed email forensics and security compliance capabilities.