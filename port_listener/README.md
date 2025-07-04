# Sigma Port Listener

**Version: 1.0.0**

A standalone PyQt5-based port listener application designed for network administrators to perform firewall testing and connection monitoring. This professional tool helps validate network connectivity, test firewall rules, and monitor incoming connections in real-time.

## 🚀 Features

### 🔌 Port Listener Capabilities
- **Firewall Testing**: Test port accessibility and firewall rules with real-time monitoring
- **Connection Monitoring**: Monitor incoming connections with detailed logging and statistics
- **Multiple Response Types**: HTTP OK, Echo, or Silent response modes for different testing scenarios
- **Real-time Statistics**: Connection counting, uptime tracking, and client IP monitoring
- **Network Validation**: Verify connectivity through corporate firewalls and load balancers
- **Professional Interface**: Clean, modern interface designed for network professionals

### 🛠️ Core Features
- **Flexible Configuration**: Listen on specific IP addresses or all interfaces (0.0.0.0)
- **Port Range Support**: Support for any port 1-65535 with privilege checking for system ports
- **Response Modes**:
  - **HTTP OK**: Sends proper HTTP 200 response (web browser compatible)
  - **Echo**: Returns received data back to client (useful for testing data transmission)
  - **Silent**: Accepts connections but sends no response (stealth monitoring)
- **Real-time Monitoring**: Live connection log with timestamps and auto-scroll capability
- **Connection Statistics**: Track total connections, last client IP, and uptime
- **Test Connection**: Built-in connectivity testing to verify your own listener

### 🎮 User Interface
- **Modern Design**: Professional dark-themed interface with color-coded status indicators
- **Real-time Updates**: Live connection statistics and uptime monitoring
- **Connection Log**: Detailed logging with optional timestamps and auto-scroll
- **Status Indicators**: Clear visual feedback for listening status and connection health
- **Intuitive Controls**: Easy-to-use start/stop controls with configuration validation

## 📋 Requirements

- **Python 3.7+**
- **PyQt5** for the graphical interface
- **Windows/Linux/macOS** (cross-platform compatible)
- **Administrator privileges** (recommended for ports below 1024)
- **Network access** for testing connectivity

## 🛠️ Installation

### 1. Download or Clone
```bash
# Download the main.py file or clone the repository
wget https://raw.githubusercontent.com/your-repo/sigma-port-listener/main/main.py
# or
git clone https://github.com/your-repo/sigma-port-listener.git
cd sigma-port-listener
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python main.py
```

## ⚙️ Configuration

### Basic Settings

| Setting | Example | Description |
|---------|---------|-------------|
| **IP Address** | `127.0.0.1` | Local interface only |
| **IP Address** | `0.0.0.0` | Listen on all network interfaces |
| **Port** | `8080` | Port to listen on (1-65535) |
| **Response Type** | `HTTP OK` | Type of response to send to clients |

### Response Types Explained

| Type | Description | Use Case |
|------|-------------|----------|
| **HTTP OK** | Sends HTTP 200 response with success message | Web browser testing, HTTP health checks |
| **Echo** | Returns received data back to the client | Data transmission testing, protocol validation |
| **Silent** | Accepts connection but sends no response | Stealth monitoring, basic connectivity testing |

## 🎯 Usage

### 1. Basic Firewall Testing
1. **Configure Settings**: Enter IP address (use `0.0.0.0` for all interfaces) and port
2. **Select Response Type**: Choose `HTTP OK` for web-based testing
3. **Start Listening**: Click "🚀 Start Listening" to begin monitoring
4. **Test Externally**: Use tools like `telnet`, `curl`, or web browser to test connectivity
5. **Monitor Results**: Watch the connection log for incoming connections

### 2. Network Connectivity Validation
1. **Set Specific Port**: Choose the port you need to test (e.g., 443 for HTTPS, 80 for HTTP)
2. **Configure Response**: Use `Echo` mode to test data transmission
3. **Monitor Connections**: Track which clients are connecting and when
4. **Validate Firewall Rules**: Confirm that your firewall allows the expected traffic

### 3. Connection Monitoring
1. **Enable Auto-scroll**: Keep the latest connections visible
2. **Show Timestamps**: Track exactly when connections occur
3. **Monitor Statistics**: Watch connection counts and client IPs
4. **Log Analysis**: Review connection patterns for security or troubleshooting

## 🧪 Testing Your Listener

### Command Line Testing
```bash
# Test with telnet
telnet your-server-ip 8080

# Test with curl (for HTTP OK response)
curl http://your-server-ip:8080

# Test with netcat
nc your-server-ip 8080
```

### Web Browser Testing
- For HTTP OK response type, simply navigate to: `http://your-server-ip:port`
- You should see "Port test successful!" message

### Network Scanner Testing
```bash
# Test with nmap
nmap -p 8080 your-server-ip

# Test specific port range
nmap -p 8080-8090 your-server-ip
```

## 🔍 Troubleshooting

### Common Issues

#### "Failed to start port listener"
- **Solution**: Check if the port is already in use by another application
- **Check**: Use `netstat -an | grep :8080` to see if port is occupied
- **Alternative**: Try a different port number

#### "Port requires administrator privileges"
- **Solution**: Run the application as Administrator (Windows) or with sudo (Linux/Mac)
- **Cause**: Ports below 1024 are restricted to privileged users
- **Alternative**: Use a port above 1024 (e.g., 8080, 9000)

#### "No connections appearing"
- **Check Firewall**: Ensure Windows Firewall or iptables allows inbound connections
- **Verify IP**: Use `0.0.0.0` to listen on all interfaces
- **Test Locally**: Try connecting from the same machine first
- **Network Access**: Verify external clients can reach your machine

#### "Connection refused" when testing
- **Listener Status**: Ensure the listener is actually running (green status)
- **Correct IP/Port**: Verify you're connecting to the right address and port
- **Network Path**: Check routing and firewall rules between client and server

### Firewall Configuration

#### Windows Firewall
```cmd
# Allow inbound on specific port
netsh advfirewall firewall add rule name="Port Listener Test" dir=in action=allow protocol=TCP localport=8080

# Remove rule when done
netsh advfirewall firewall delete rule name="Port Listener Test"
```

#### Linux iptables
```bash
# Allow inbound on specific port
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Remove rule when done
sudo iptables -D INPUT -p tcp --dport 8080 -j ACCEPT
```

## 💡 Use Cases

### Network Infrastructure Testing
- **Firewall Rule Validation**: Verify that firewall rules allow expected traffic
- **Load Balancer Testing**: Confirm load balancers are forwarding traffic correctly
- **Network Segmentation**: Test connectivity between network segments
- **VPN Connectivity**: Validate VPN tunnel functionality

### Security and Monitoring
- **Port Scanning Detection**: Monitor for unauthorized connection attempts
- **Network Reconnaissance**: Identify which systems are attempting connections
- **Security Testing**: Validate that only authorized systems can connect
- **Incident Response**: Monitor specific ports during security investigations

### Development and Testing
- **Application Testing**: Test how applications connect to specific ports
- **Protocol Development**: Test custom network protocols
- **Integration Testing**: Verify system-to-system connectivity
- **Performance Testing**: Monitor connection patterns under load

## 🛡️ Security Considerations

### Safe Usage
- **Temporary Testing**: Only run the listener when actively testing
- **Specific IP Binding**: Use specific IP addresses rather than 0.0.0.0 when possible
- **Port Selection**: Use non-standard ports to avoid conflicts
- **Monitor Logs**: Review connection logs for unexpected or suspicious activity

### Network Security
- **Firewall Rules**: Create specific firewall rules rather than disabling firewalls
- **Access Control**: Restrict access to the listening port to authorized networks
- **Logging**: Monitor all connections for security purposes
- **Time Limits**: Limit how long the listener runs to minimize exposure

## 📊 Understanding Results

### Connection Statistics
- **Connections**: Total number of connection attempts since starting
- **Last**: IP address of the most recent connection
- **Uptime**: How long the listener has been running

### Log Entries
- **Timestamp**: When the connection occurred (if enabled)
- **Client IP**: Source IP address of the connecting client
- **Status Messages**: Startup, shutdown, and error messages

### Response Verification
- **HTTP OK**: Client should receive "Port test successful!" message
- **Echo**: Client should receive back whatever data they sent
- **Silent**: Client connection succeeds but receives no data

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for network testing and validation purposes. Always:

### Security Responsibilities
- **Test in controlled environments** before production use
- **Follow your organization's security policies** and procedures
- **Monitor and audit** tool usage appropriately
- **Limit exposure time** - only run when actively testing
- **Use appropriate firewall rules** rather than disabling security

### Operational Responsibilities
- **Verify network policies** before opening ports
- **Document testing activities** for audit purposes
- **Coordinate with network teams** before testing
- **Clean up firewall rules** after testing
- **Monitor for unauthorized connections** during and after testing

## 📞 Support

For issues and questions:

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Verify firewall configuration** and network connectivity
3. **Test with local connections first** before external testing
4. **Check system logs** for additional error information

### Best Practices
- **Start with high-numbered ports** (8080, 9000) to avoid privilege issues
- **Test locally first** before testing across networks
- **Use specific IP addresses** when possible for better security
- **Monitor connection logs** for unexpected activity
- **Document your testing** for future reference

---

**Sigma Port Listener v1.0.0** - Professional network testing tool for firewall validation and connection monitoring. Built for network administrators who need reliable, easy-to-use port listening capabilities for infrastructure testing and validation.