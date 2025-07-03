# DNS Tester

**Version: 1.0.0**

A comprehensive standalone DNS testing and analysis tool extracted from SigmaToolkit. Perfect for network administrators, IT professionals, and anyone needing reliable DNS diagnostics.

## 🚀 Features

### 🔍 DNS Testing (v1.0.0)
- **Forward/Reverse Lookup**: Domain ↔ IP address resolution with detailed analysis
- **MX Records**: Mail server configuration analysis for email troubleshooting
- **TXT Records**: SPF, DKIM, and other text records for email authentication
- **NS Records**: Name server information and delegation analysis
- **CNAME Records**: Domain aliases and canonical names
- **AAAA Records**: IPv6 address resolution with full support
- **A Records**: IPv4 address resolution with detailed analysis
- **DNS Server Selection**: Test with Google, Cloudflare, Quad9, OpenDNS, or custom DNS servers
- **Comprehensive Analysis**: All-in-one DNS record lookup with intelligent parsing

### 🛠️ General Features
- **Professional UI**: Modern interface designed for efficiency and DNS troubleshooting
- **Real-time Output**: Live results with timestamp and color-coded log levels
- **Debug Mode**: Toggle detailed logging for advanced troubleshooting
- **Copy Results**: One-click copying of output to clipboard
- **Export Functionality**: Save DNS analysis results for documentation
- **Cross-Platform**: Works seamlessly on Windows, Linux, and macOS
- **Quick Test Domains**: Pre-configured buttons for testing common domains
- **Custom DNS Server Support**: Test with any DNS server for comparison

## 📋 Requirements

- **Python 3.7+**
- **PyQt5 GUI framework**
- **Network access** for DNS queries
- **nslookup** (Windows) or **dig** (Linux/macOS) for advanced DNS queries

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd dns-tester
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

## 🎯 Usage

### 1. Quick DNS Lookups
1. **Enter Domain/IP**: Input domain name (google.com) or IP address (8.8.8.8)
2. **Choose Lookup Type**: 
   - Forward Lookup: Domain → IP address
   - Reverse Lookup: IP → Domain name
   - All Records: Comprehensive DNS analysis
3. **View Results**: Real-time results appear in the output panel

### 2. Specific Record Types
1. **Enter Domain**: Input domain name in the specific records section
2. **Select Record Type**: Choose from A, MX, TXT, NS, CNAME, or AAAA
3. **Analyze Results**: Detailed record information with explanations

### 3. DNS Server Testing
1. **Select DNS Server**: Choose from popular DNS providers or enter custom
2. **Compare Results**: Test the same domain with different DNS servers
3. **Identify Issues**: Compare responses to identify DNS propagation problems

### 4. Quick Domain Tests
1. **Use Pre-configured Tests**: Test google.com, microsoft.com, github.com
2. **Local Domain Detection**: Automatically detect and test your local domain
3. **Comprehensive Analysis**: Each test runs a full DNS analysis

## 📊 Understanding Results

### DNS Record Types Explained

| Record Type | Purpose | Example Use Case |
|-------------|---------|------------------|
| **A Record** | IPv4 address mapping | Website hosting, basic connectivity |
| **AAAA Record** | IPv6 address mapping | Modern IPv6 connectivity |
| **MX Record** | Mail server configuration | Email delivery troubleshooting |
| **TXT Record** | Text information (SPF, DKIM) | Email authentication, domain verification |
| **NS Record** | Name server delegation | DNS infrastructure analysis |
| **CNAME Record** | Domain aliases | CDN configuration, subdomain management |

### Common DNS Issues

- **No A Records**: Domain not resolving - check domain registration
- **MX Records Missing**: Email delivery issues - verify mail server configuration  
- **SPF Records**: Look for "v=spf1" in TXT records for email authentication
- **Timeouts**: Network connectivity or DNS server issues
- **Different Results**: DNS propagation delays or server-specific issues

## 🔧 Advanced Features

### DNS Server Comparison
Test the same domain with multiple DNS servers to identify:
- **Propagation Issues**: New DNS changes not yet propagated
- **DNS Filtering**: Corporate or ISP DNS filtering
- **Performance Differences**: Response time variations
- **Reliability Issues**: Server-specific failures

### Troubleshooting Workflow
1. **Start with Forward Lookup**: Verify basic domain resolution
2. **Check A Records**: Ensure IPv4 addresses are correct
3. **Verify MX Records**: For email-related issues
4. **Analyze TXT Records**: For email authentication problems
5. **Compare DNS Servers**: Rule out DNS server issues

## ⚙️ Configuration

### DNS Server Options

| Server | IP Address | Description |
|--------|------------|-------------|
| **System Default** | Auto-detected | Uses your system's configured DNS |
| **Google DNS** | 8.8.8.8 | Fast, reliable public DNS |
| **Cloudflare DNS** | 1.1.1.1 | Privacy-focused public DNS |
| **Quad9 DNS** | 9.9.9.9 | Security-focused with malware blocking |
| **OpenDNS** | 208.67.222.222 | Content filtering and security |
| **Custom** | Your choice | Any DNS server IP address |

### Application Settings

| Setting | Default | Description |
|---------|---------|-------------|
| **Debug Mode** | Disabled | Enable detailed logging for troubleshooting |
| **Auto-scroll** | Enabled | Automatically scroll to latest results |
| **Export Format** | Text | Default format for exporting results |

## 🔍 Troubleshooting

### Common Issues

#### "Command not found" errors
- **Windows**: Ensure nslookup is available (usually built-in)
- **Linux/macOS**: Install dig utility: `sudo apt-get install dnsutils` (Ubuntu) or `brew install bind` (macOS)

#### "No records found"
- **Check domain spelling**: Verify domain name is correct
- **Try different DNS server**: Some servers may have different data
- **Check network connectivity**: Verify internet connection

#### Slow responses
- **Network latency**: High latency to DNS servers
- **DNS server issues**: Try different DNS server
- **Firewall blocking**: Check firewall rules for DNS queries

#### Timeout errors
- **Increase timeout**: Use debug mode for more detailed error information
- **Check DNS server**: Verify DNS server is responding
- **Network issues**: Test basic connectivity first

### Debug Mode
Enable debug output for detailed troubleshooting:
1. **Click "Toggle Debug"** to enable detailed logging
2. **Review debug output** for detailed error messages
3. **Check DNS commands** being executed
4. **Verify DNS server communication**

## 📁 File Structure

```
dns-tester/
├── main.py                    # Main application entry point
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── dns_tab.py               # DNS testing interface
├── dns_tools.py             # DNS operations and tools
└── logger.py                # Logging functionality
```

## 💡 Best Practices

### DNS Testing Workflow
1. **Start Simple**: Begin with forward lookup for basic connectivity
2. **Use Multiple DNS Servers**: Compare results to identify issues
3. **Document Results**: Export results for troubleshooting documentation
4. **Test Regularly**: Monitor important domains regularly
5. **Compare Changes**: Test before and after DNS changes

### Performance Optimization
- **Use appropriate DNS server**: Choose geographically close servers
- **Cache considerations**: Remember DNS caching affects results
- **Timing**: Allow time for DNS propagation after changes
- **Batch testing**: Test multiple related domains together

### Security Considerations
- **Use trusted DNS servers**: Stick to reputable public DNS providers
- **Verify DNSSEC**: Check for DNS security extensions where applicable
- **Monitor changes**: Regular testing can detect unauthorized changes
- **Document baselines**: Keep records of normal DNS configurations

## 🤝 Contributing

Contributions are welcome! Priority areas for improvement:

### High Priority
- **DNSSEC validation** support for enhanced security
- **Bulk domain testing** for multiple domains at once
- **DNS monitoring** with scheduled checks and alerts
- **Visual DNS tree** display for complex DNS hierarchies

### Medium Priority
- **Historical tracking** of DNS changes over time
- **Performance metrics** and response time analysis
- **Custom report generation** with charts and graphs
- **Integration with monitoring systems** via API

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for DNS testing and troubleshooting purposes. Always:

### Usage Responsibilities
- **Respect DNS servers**: Don't abuse public DNS services with excessive queries
- **Follow policies**: Respect terms of service for DNS providers
- **Test responsibly**: Use appropriate intervals for monitoring
- **Document changes**: Keep records of DNS modifications

### Operational Notes
- **DNS propagation**: Changes may take 24-48 hours to fully propagate
- **Cache effects**: Local DNS caching may affect immediate results
- **Network dependencies**: Results depend on network connectivity and configuration
- **Tool limitations**: Some advanced DNS features may require specialized tools

## 📞 Support

For issues and questions:

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Enable debug mode** for detailed error information
3. **Verify network connectivity** and DNS server accessibility
4. **Test with different DNS servers** to isolate issues

### Community Support
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Best Practices**: DNS testing and troubleshooting guidelines

### Enterprise Support
For enterprise deployments requiring:
- **Custom integration** with existing monitoring systems
- **Advanced DNS monitoring** and alerting capabilities
- **Dedicated support** and training for IT teams
- **Custom feature development** for specific organizational needs

---

**DNS Tester v1.0.0** - Your comprehensive DNS analysis toolkit for network troubleshooting, domain validation, and DNS infrastructure monitoring. Built for IT professionals who demand reliable, accurate, and efficient DNS diagnostics.

## 🎯 Use Cases

### Network Troubleshooting
- **Connectivity Issues**: Verify DNS resolution when websites won't load
- **Email Problems**: Check MX records for mail delivery issues
- **Performance Issues**: Compare DNS server response times
- **Configuration Validation**: Verify DNS changes have propagated

### Security Analysis
- **SPF Record Validation**: Verify email authentication setup
- **Domain Verification**: Confirm domain ownership via TXT records
- **DNS Hijacking Detection**: Monitor for unauthorized DNS changes
- **Phishing Investigation**: Analyze suspicious domain configurations

### Infrastructure Monitoring
- **DNS Health Checks**: Regular monitoring of critical domains
- **Propagation Verification**: Confirm DNS changes have spread globally
- **Redundancy Testing**: Verify backup DNS servers are working
- **Performance Baseline**: Establish normal DNS response times

### Development & DevOps
- **Pre-deployment Testing**: Verify DNS configuration before going live
- **CDN Configuration**: Validate CNAME records for content delivery
- **API Endpoint Validation**: Confirm DNS resolution for API services
- **Multi-environment Testing**: Compare DNS across dev/staging/production

## 🔬 Technical Details

### Supported Platforms
- **Windows**: Uses nslookup for detailed DNS queries
- **Linux**: Uses dig command for comprehensive analysis
- **macOS**: Uses dig command with full feature support
- **Cross-platform**: Socket-based fallbacks for basic operations

### DNS Query Methods
1. **Socket-based**: Fast, direct DNS queries using Python's socket library
2. **Command-line**: Detailed queries using nslookup (Windows) or dig (Unix)
3. **Fallback**: Automatic fallback to alternative methods if primary fails
4. **Custom DNS**: Ability to query any DNS server directly

### Performance Characteristics
- **Threaded Operations**: Non-blocking UI during DNS queries
- **Timeout Handling**: Configurable timeouts prevent hanging
- **Error Recovery**: Graceful handling of network and DNS errors
- **Resource Efficient**: Minimal system resource usage

## 🎨 Interface Design

### User Experience
- **Intuitive Layout**: Logical grouping of related DNS functions
- **Color-coded Results**: Visual indicators for success, warning, and error states
- **Real-time Feedback**: Immediate response to user actions
- **Professional Appearance**: Clean, modern interface suitable for business use

### Accessibility Features
- **Keyboard Navigation**: Full keyboard support for all functions
- **Clear Typography**: Readable fonts and appropriate sizing
- **Status Indicators**: Clear visual and textual status information
- **Export Capabilities**: Multiple formats for result sharing

## 🔄 Integration Possibilities

### Command Line Usage
The DNS tools can be used programmatically:

```python
from dns_tools import DNSTools
from logger import Logger

# Create logger and DNS tools
logger = Logger()
dns_tools = DNSTools(logger)

# Set custom DNS server
dns_tools.set_dns_server("8.8.8.8")

# Perform DNS lookup (results via signals)
dns_tools.forward_lookup("example.com")
```

### API Integration
The modular design allows easy integration into larger systems:
- **Monitoring Systems**: Integrate DNS checks into existing monitoring
- **Automation Scripts**: Use DNS tools in deployment and testing scripts
- **Custom Applications**: Embed DNS functionality in custom tools
- **Reporting Systems**: Generate DNS reports for compliance and documentation

## 📈 Future Enhancements

### Planned Features
- **DNS-over-HTTPS (DoH)**: Support for modern encrypted DNS protocols
- **DNS-over-TLS (DoT)**: Secure DNS query support
- **Batch Processing**: Process multiple domains from file input
- **Historical Data**: Track DNS changes over time
- **Alert System**: Notifications for DNS issues or changes
- **Custom Plugins**: Extensible architecture for custom DNS tests

### Advanced Capabilities
- **DNSSEC Validation**: Full DNSSEC chain validation
- **Geographic DNS**: Test DNS resolution from different geographic locations
- **Load Testing**: High-volume DNS query testing
- **Compliance Reporting**: Generate reports for security and compliance audits

---

*Built with ❤️ for the IT community. DNS Tester: Making DNS troubleshooting simple, reliable, and efficient.*