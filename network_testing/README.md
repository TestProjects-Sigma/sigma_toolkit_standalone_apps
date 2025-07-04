# Network Toolkit

**Version: 1.0.0**

A comprehensive standalone network testing and diagnostics tool designed for system administrators, network engineers, and IT professionals. This toolkit provides essential network troubleshooting capabilities in a clean, modern PyQt5-based GUI application.

## 🚀 Features

### 🖥️ System Network Information
- **Comprehensive Network Overview**: Displays computer name, local/external IP addresses, subnet information
- **Gateway Detection**: Automatically identifies default gateway for connectivity testing
- **DNS Server Discovery**: Shows configured DNS servers for troubleshooting resolution issues
- **Active Interface Listing**: Displays all active network interfaces on the system
- **Real-time Refresh**: One-click refresh to update network information dynamically

### 📡 Ping Testing
- **Customizable Ping Tests**: Test connectivity to any host or IP address with configurable packet count (1-100)
- **Detailed Statistics**: Shows round-trip times, packet loss, and connectivity statistics
- **Quick Actions**: One-click ping tests for Google DNS (8.8.8.8), Cloudflare DNS (1.1.1.1), and local gateway
- **Real-time Results**: Live output with detailed ping statistics and analysis

### 🛤️ Traceroute Analysis
- **Network Path Tracing**: Trace the complete network path to any destination
- **Hop-by-hop Analysis**: Shows all intermediate routers and their response times
- **Bottleneck Identification**: Identify network delays and routing issues
- **Cross-platform Support**: Works on Windows (tracert) and Linux/macOS (traceroute)

### 🔌 Port Scanner
- **Flexible Port Scanning**: Test single ports (80), port ranges (1-1000), or comma-separated lists (80,443,22)
- **Connection Testing**: Verify service availability and firewall configurations
- **Real-time Results**: Live display of open/closed ports with immediate feedback
- **Performance Optimized**: Fast scanning with configurable timeouts

### 🔍 DNS Lookup
- **Forward DNS Resolution**: Convert domain names to IP addresses
- **Reverse DNS Lookup**: Convert IP addresses back to domain names when available
- **DNS Troubleshooting**: Verify domain configurations and resolution issues
- **Multiple DNS Testing**: Test with different DNS servers for comparison

### 🎛️ User Interface Features
- **Modern Professional Design**: Clean, intuitive interface designed for efficiency
- **Real-time Output**: Live results with timestamp logging and color-coded status levels
- **Debug Mode**: Toggle detailed logging for advanced troubleshooting
- **Export Capabilities**: Export all test results and system information to text files
- **Copy to Clipboard**: One-click copying of all output for documentation
- **Keyboard Shortcuts**: Press Enter in input fields to quickly execute tests

## 📋 Requirements

- **Python 3.7+**
- **Operating System**: Windows, Linux, or macOS
- **Network Access**: Internet connectivity for external IP detection and DNS testing
- **Privileges**: Administrator/root privileges recommended for enhanced port scanning capabilities

## 🛠️ Installation

### 1. Clone or Download
```bash
git clone <repository-url>
cd network-toolkit
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

### 1. System Network Information
1. **Automatic Loading**: Network information loads automatically on startup
2. **Manual Refresh**: Click "🔄 Refresh Network Info" to update information
3. **Information Display**: View computer name, IP addresses, gateway, DNS servers, and active interfaces

### 2. Ping Testing
1. **Enter Target**: Type hostname or IP address in the Host field
2. **Set Packet Count**: Choose number of ping packets (1-100, default: 4)
3. **Execute Test**: Click "Ping" or press Enter in the host field
4. **View Results**: Real-time ping statistics appear in the output panel

### 3. Traceroute Analysis
1. **Enter Destination**: Type the target hostname or IP address
2. **Start Trace**: Click "Traceroute" button to begin path analysis
3. **Monitor Progress**: Watch real-time hop-by-hop results
4. **Analyze Path**: Review the complete network path and identify issues

### 4. Port Scanning
1. **Target Host**: Enter the hostname or IP address to scan
2. **Specify Ports**: Enter ports in various formats:
   - Single port: `80`
   - Port range: `1-1000`
   - Multiple ports: `80,443,22,25`
3. **Execute Scan**: Click "Scan Ports" to start testing
4. **Review Results**: Open ports appear immediately, with summary at completion

### 5. DNS Lookup
1. **Enter Domain**: Type the domain name or hostname
2. **Perform Lookup**: Click "DNS Lookup" or press Enter
3. **View Resolution**: See IP address and reverse DNS information

### 6. Quick Actions
- **Ping Google DNS**: Test internet connectivity via 8.8.8.8
- **Ping Cloudflare DNS**: Alternative connectivity test via 1.1.1.1
- **Ping Gateway**: Test local network connectivity to default gateway

## 📊 Understanding Results

### System Information Display
- **Computer**: Local machine hostname
- **Local IP**: Internal network IP address
- **Subnet**: Calculated network subnet (e.g., 192.168.1.0/24)
- **Gateway**: Default gateway IP address
- **External IP**: Public internet IP address
- **DNS Servers**: Configured DNS server addresses
- **Active Interfaces**: Network adapters currently active

### Ping Results
- **Round-trip times**: Response times in milliseconds
- **Packet loss**: Percentage of lost packets
- **Statistics**: Minimum, maximum, and average response times
- **Status indicators**: Success (green) or failure (red) messages

### Port Scan Results
- **Open Ports**: Services accepting connections
- **Closed Ports**: Ports not accepting connections (logged in debug mode)
- **Summary**: Total ports scanned and results overview

### DNS Lookup Results
- **IP Address**: Resolved IP address for the domain
- **Reverse DNS**: Domain name associated with the IP (if available)
- **Error Messages**: Details about resolution failures

## 🔧 Advanced Features

### Debug Mode
- **Activation**: Click "Toggle Debug" button to enable detailed logging
- **Enhanced Output**: Shows additional diagnostic information
- **Troubleshooting**: Helps identify issues with network commands and connectivity

### Export Functionality
- **Complete Results**: Export all test results and system information
- **Timestamped Files**: Automatic filename generation with date/time stamps
- **Documentation**: Perfect for creating network diagnostic reports

### Menu Options
- **File Menu**: Export results, exit application
- **Tools Menu**: Quick access to network info refresh and quick tests
- **Help Menu**: Comprehensive help documentation and about information

## 🛡️ Security Considerations

### Network Security
- **Read-only Operations**: Application only performs diagnostic tests, never modifies network settings
- **Port Scanning Ethics**: Use port scanning responsibly and only on networks you own or have permission to test
- **Firewall Interaction**: Some tests may trigger firewall alerts or logging

### Privileges
- **Standard User**: Most functions work with standard user privileges
- **Administrator Mode**: Enhanced port scanning capabilities with elevated privileges
- **Network Access**: Requires outbound internet access for external IP detection

## 🔍 Troubleshooting

### Common Issues

#### "Command not found" errors
- **Windows**: Ensure Windows is up to date (ping, tracert commands)
- **Linux/macOS**: Install network utilities if missing: `sudo apt-get install iputils-ping traceroute`

#### Port scanning limitations
- **Firewall blocking**: Local firewall may block outbound connections
- **Timeout issues**: Increase timeout or reduce port range for slow networks
- **Permission errors**: Run as administrator for enhanced scanning capabilities

#### External IP detection fails
- **Internet connectivity**: Verify internet access is available
- **Firewall restrictions**: Ensure outbound HTTPS traffic is allowed
- **Proxy settings**: Configure proxy if required for internet access

#### DNS lookup failures
- **DNS server issues**: Try alternative DNS servers (8.8.8.8, 1.1.1.1)
- **Network connectivity**: Verify basic network connectivity first
- **Domain validity**: Ensure the domain name is spelled correctly

### Performance Optimization
- **Large port scans**: Use smaller ranges or scan during off-peak hours
- **Network latency**: Expect slower results on high-latency connections
- **Resource usage**: Close other network-intensive applications during testing

## 📁 File Structure

```
network-toolkit/
├── main.py                     # Main application entry point
├── network_tab.py              # Network testing interface
├── network_tools.py            # Network operations and tools
├── logger.py                   # Logging functionality
├── requirements.txt            # Python dependencies
├── README.md                   # This documentation
└── screenshots/                # Application screenshots (optional)
```

## 🤝 Contributing

Contributions are welcome! Priority areas for improvement:

### High Priority
- **Enhanced port scanning** with service detection and banner grabbing
- **Network discovery** features for subnet scanning
- **Performance monitoring** with continuous ping and latency tracking
- **Advanced DNS testing** with record type queries (MX, TXT, NS)

### Medium Priority
- **Network speed testing** integration
- **SNMP monitoring** capabilities
- **Custom profiles** for different network environments
- **Scheduled testing** and alerting functionality

### Low Priority
- **Additional export formats** (CSV, JSON, XML)
- **Custom themes** and UI improvements
- **Plugin architecture** for extensibility
- **Mobile-responsive** interface considerations

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for network testing and diagnostic purposes. Always:

### Responsible Usage
- **Test ethically** - only scan networks you own or have explicit permission to test
- **Respect resources** - avoid excessive testing that could impact network performance
- **Follow policies** - comply with organizational and legal network usage policies
- **Document properly** - maintain records of testing activities for audit purposes

### Limitations
- **Accuracy**: Results depend on network conditions and may vary over time
- **Scope**: Tool provides basic network diagnostics, not comprehensive security assessment
- **Compatibility**: Some features may behave differently across operating systems
- **Dependencies**: Requires underlying system network utilities to function properly

## 📞 Support

For issues and questions:

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Enable debug mode** for detailed diagnostic information
3. **Verify network connectivity** before reporting issues
4. **Test with minimal configuration** to isolate problems

### Community Support
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Best Practices**: Network testing guidelines and recommendations

---

**Network Toolkit v1.0.0** - Your comprehensive standalone network diagnostics solution. Built for system administrators who demand reliable, efficient, and professional network testing tools with a clean, modern interface.

*Extracted from SigmaToolkit for focused network testing capabilities.*