# Standalone Speed Test Application

**Version: 1.0**

A comprehensive PyQt5-based speed testing application with official Speedtest.net CLI integration, real-time LCD displays, and LAN testing capabilities. Perfect for network administrators, IT professionals, and anyone who needs accurate speed testing with a professional interface.

## 🚀 Features

### ⚡ Official Speedtest Integration
- **Speedtest.net CLI Support**: Uses genuine speedtest.net CLI for maximum accuracy and gigabit testing
- **Automatic Detection**: Detects both official Ookla CLI and Python speedtest-cli versions
- **Real-time Progress**: Live progress tracking with detailed status updates
- **Performance Assessment**: Intelligent analysis with recommendations (Excellent/Good/Fair/Poor)
- **Server Selection**: Choose from auto-select, Cloudflare, Google, or Microsoft servers
- **JSON Parsing**: Accurate result parsing from both CLI versions

### 📟 Professional LCD Displays
- **Download Speed Display**: Real-time green LCD showing current download speeds
- **Upload Speed Display**: Real-time orange LCD showing current upload speeds  
- **Latency Display**: Real-time blue LCD showing ping latency in milliseconds
- **LCD-style Visual**: Professional appearance with flat segment styling
- **Live Updates**: Displays update in real-time during testing

### 🔧 Built-in Fallback Tests
- **Download Testing**: Built-in download speed simulation when CLI unavailable
- **Upload Testing**: Built-in upload speed simulation with realistic variations
- **Latency Testing**: Comprehensive ping testing with quality assessment
- **Cross-platform Ping**: Works on Windows, Linux, and macOS
- **Realistic Simulation**: Speed variations and timing to simulate real conditions

### 🏠 LAN Speed Testing
- **Local Network Testing**: Test speed to devices on your local network
- **IP Validation**: Automatic validation of target IP addresses
- **Port Connectivity**: Tests port accessibility before speed testing
- **Connection Analysis**: Multiple connection attempts for accurate estimation
- **Network Information**: Provides network type and hostname resolution
- **Speed Estimation**: Latency-based speed estimation with quality ratings

### 🎨 Professional User Interface
- **Modern Design**: Clean, professional interface with grouped controls
- **Progress Tracking**: Real-time progress bar with detailed status messages
- **Color-coded Output**: Success (green), warnings (orange), errors (red)
- **Responsive Layout**: Organized sections for different testing types
- **Status Updates**: Live console output with timestamps
- **Easy Controls**: Intuitive button layout and clear navigation

### 🛠️ Advanced Capabilities
- **Multi-platform Support**: Works on Windows, Linux, and macOS
- **Installation Guidance**: Built-in installation instructions for all platforms
- **Error Handling**: Comprehensive error handling with helpful messages
- **Test Controls**: Start, stop, and clear functionality
- **CLI Detection**: Automatic detection and guidance for optimal setup

## 📋 Requirements

- **Python 3.7+**
- **PyQt5** (GUI framework)
- **speedtest-cli** (optional but recommended for accurate results)
- **Network connectivity** for internet speed testing
- **Local network access** for LAN testing

## 🛠️ Installation

### 1. Download the Application
Save the `main.py` file to your desired directory.

### 2. Install Python Dependencies
```bash
pip install PyQt5
```

### 3. Install Speedtest CLI (Recommended)
For most accurate results, install the speedtest CLI:

#### Windows:
```bash
# Option 1: Python version (easiest)
pip install speedtest-cli

# Option 2: Official CLI
# Download from: https://www.speedtest.net/apps/cli
# Extract and add to PATH

# Option 3: Package managers
choco install speedtest        # Chocolatey
scoop install speedtest        # Scoop
```

#### Linux:
```bash
# Option 1: Python version
sudo apt install speedtest-cli
pip install speedtest-cli

# Option 2: Official CLI (Ubuntu/Debian)
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest

# Option 3: Other distributions
sudo dnf install speedtest-cli    # Fedora
sudo pacman -S speedtest-cli      # Arch
```

#### macOS:
```bash
# Option 1: Homebrew (recommended)
brew install speedtest-cli

# Option 2: Python version
pip install speedtest-cli
```

### 4. Run the Application
```bash
python main.py
```

## 🎯 Usage Guide

### Internet Speed Testing

1. **Official Speedtest** (Recommended):
   - Click "🚀 Official Speedtest" for most accurate results
   - Uses the same engine as speedtest.net website
   - Best for gigabit connections and professional testing

2. **Server Selection**:
   - Choose "Auto-select Best Server" for optimal performance
   - Select specific servers (Cloudflare, Google, Microsoft) for consistency
   - Server affects latency and routing paths

3. **Built-in Tests** (Fallback):
   - Use "Test Download" and "Test Upload" when CLI unavailable
   - Provides basic speed estimation
   - Shows realistic speed variations

### Latency Testing

1. **Ping Tests**:
   - Click "Test Latency" to ping selected server
   - Shows average, minimum, and maximum ping times
   - Quality assessment: Excellent (<20ms), Good (<50ms), Fair (<100ms), Poor (>100ms)

### LAN Speed Testing

1. **Setup**:
   - Enter target device IP address (e.g., 192.168.1.100)
   - Specify port number (default: 12345)
   - Ensure target device has a service running on that port

2. **Common Ports to Try**:
   - Port 22: SSH service
   - Port 80: HTTP web server
   - Port 443: HTTPS web server
   - Port 445: SMB file sharing
   - Port 21: FTP service

3. **Results**:
   - Shows connection latency and estimated speed
   - Provides network type information
   - Quality ratings based on performance

### Understanding Results

#### Speed Displays
- **Download Speed**: How fast you can download data from the internet
- **Upload Speed**: How fast you can upload data to the internet
- **Latency**: Round-trip time for data packets (lower is better)

#### Performance Ratings
- **🚀 Excellent**: >700 Mbps download (gigabit performance)
- **✅ Good**: 500-700 Mbps (high-speed broadband)
- **⚡ Decent**: 100-500 Mbps (standard broadband)
- **⚠️ Below Expected**: <100 Mbps (may indicate issues)

#### LAN Quality Ratings
- **⚡ Excellent**: <1ms latency (very fast local network)
- **✅ Good**: 1-5ms latency (fast local network)
- **⚠️ Average**: 5-20ms latency (standard network)
- **🐌 Slow**: >20ms latency (slow connection or network issues)

## 🔧 Configuration

### Server Selection
- **Auto-select**: Automatically chooses the best server based on location and latency
- **Cloudflare**: Global CDN with excellent performance worldwide
- **Google**: Reliable global infrastructure with consistent results
- **Microsoft**: Good for testing Microsoft 365 and Azure connectivity

### LAN Testing Setup
For accurate LAN testing, ensure the target device has a service running:

```bash
# Example: Start a simple HTTP server on target device
python -m http.server 8000  # Python 3
python -m SimpleHTTPServer 8000  # Python 2

# Then test from this app using port 8000
```

## 🛡️ Troubleshooting

### Speedtest CLI Issues

#### "CLI not found"
- **Solution**: Install speedtest-cli: `pip install speedtest-cli`
- **Alternative**: Click "📥 Install CLI" for platform-specific instructions
- **Fallback**: Use built-in tests for basic speed estimation

#### "Connection failed"
- **Check internet connection**: Verify basic connectivity
- **Firewall issues**: Ensure speedtest traffic is allowed
- **Server problems**: Try different server selection
- **Network restrictions**: Some corporate networks block speedtest

#### "JSON parsing error"
- **Update CLI**: `pip install --upgrade speedtest-cli`
- **Try different server**: Some servers may have compatibility issues
- **Check CLI version**: Run `speedtest-cli --version` in terminal

### LAN Testing Issues

#### "Port closed" or "Connection refused"
- **Start service**: Ensure target device has service running on specified port
- **Try common ports**: 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB)
- **Check firewall**: Target device firewall may be blocking connections
- **Verify IP**: Ensure target IP address is correct and reachable

#### "Invalid IP address"
- **Format check**: Use proper IPv4 format (e.g., 192.168.1.100)
- **Network range**: Ensure IP is in your local network range
- **Connectivity**: Try pinging the IP first: `ping 192.168.1.100`

### General Issues

#### Application won't start
- **Python version**: Ensure Python 3.7+ is installed
- **PyQt5 missing**: Install with `pip install PyQt5`
- **Permission issues**: Try running as administrator/sudo

#### Slow performance
- **Close other apps**: Stop bandwidth-heavy applications during testing
- **Network congestion**: Test during off-peak hours
- **Multiple tests**: Run several tests for average results
- **CLI preferred**: Use official CLI for best performance

## 📊 Technical Details

### Speed Test Methods
1. **Official CLI**: Uses Speedtest.net's official testing infrastructure
2. **Built-in Tests**: Simulated tests for fallback functionality
3. **LAN Tests**: Latency-based estimation for local network performance

### Supported Platforms
- **Windows**: Full functionality with all CLI options
- **Linux**: Complete support with package manager installation
- **macOS**: Full compatibility with Homebrew installation

### Network Requirements
- **Internet connection**: For speed testing and CLI downloads
- **Local network**: For LAN testing capabilities
- **Firewall access**: May need to allow speedtest traffic

## 🔄 Version History

**v1.0.0** - Initial standalone release
- Official Speedtest.net CLI integration
- Real-time LCD displays with professional styling
- Built-in fallback tests for when CLI unavailable
- Comprehensive LAN speed testing capabilities
- Cross-platform support (Windows, Linux, macOS)
- Modern PyQt5 interface with progress tracking
- Color-coded results and comprehensive error handling
- Installation guidance and troubleshooting documentation

## 📞 Support

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Verify installation** of Python dependencies and CLI tools
3. **Test basic connectivity** before using the application
4. **Review console output** for detailed error messages

### Installation Verification
```bash
# Verify Python and PyQt5
python --version
python -c "import PyQt5; print('PyQt5 installed successfully')"

# Verify speedtest CLI (optional)
speedtest-cli --version
# or
speedtest --version
```

### Getting Help
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Community**: Share experiences and solutions

---

**Standalone Speed Test Application v1.0** - Professional network speed testing with real-time displays and comprehensive analysis. Perfect for network administrators, IT professionals, and anyone who needs accurate speed testing with a clean, modern interface.