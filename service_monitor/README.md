# Service Monitor

**Version: 1.0**

A standalone real-time infrastructure monitoring application extracted from SigmaToolkit v1.7.0. Monitor Microsoft 365 services, cloud providers, and custom endpoints with professional visual status tracking and comprehensive reporting capabilities.

## 🚀 Features

### 🟢 Real-time Service Monitoring
- **Comprehensive Status Tracking**: Monitor HTTP/HTTPS endpoints, ping connectivity, port availability, and DNS resolution
- **Visual Status Indicators**: Color-coded displays with 🟢 Healthy, 🟡 Warning, 🔴 Critical status
- **Response Time Tracking**: Monitor service performance with millisecond precision
- **Auto-refresh Capability**: Continuous monitoring with configurable 30-second intervals
- **Professional UI**: Modern interface with real-time updates and dark console output

### ☁️ Pre-configured Service Categories
- **Microsoft 365**: Exchange Online, SharePoint Online, Teams, OneDrive with one-click addition
- **Infrastructure Services**: Google DNS, Cloudflare DNS, Quad9 DNS, OpenDNS monitoring
- **Cloud Providers**: AWS Console, Azure Portal, Google Cloud Console, Cloudflare Dashboard
- **Quick Deployment**: Add entire service categories with single button clicks

### 🔧 Custom Service Management
- **Flexible Configuration**: Add any HTTP endpoint, server, or service with custom settings
- **Multiple Check Types**: HTTP status (200 OK), Ping tests, Port checks, DNS resolution, Custom API endpoints
- **Category Organization**: Organize services into custom categories for better management
- **Test Before Adding**: Validate service configurations before adding to monitoring

### 📊 Advanced Monitoring Features
- **Service Tree View**: Hierarchical display organized by categories with expandable sections
- **Context Menus**: Right-click services for individual testing, copying info, and management
- **Batch Operations**: Test all services in a category or refresh entire monitoring setup
- **Real-time Updates**: Live status changes with timestamp tracking and detailed logging

### 💾 Configuration Management
- **Save/Load Configurations**: Export and import service configurations for backup and sharing
- **Auto-save Functionality**: Automatic configuration persistence between sessions
- **JSON Export Format**: Standard format for easy integration and version control
- **Bulk Configuration**: Replace or merge service configurations from files

### 📈 Status Summary Dashboard
- **Live Statistics**: Real-time overview of total, healthy, warning, and critical services
- **Performance Metrics**: Response time tracking and service availability statistics
- **Visual Indicators**: Color-coded summary labels for quick status assessment
- **Monitoring History**: Track service status changes and performance trends

### 📄 Comprehensive Reporting
- **Status Reports**: Generate detailed text reports with service status and performance data
- **Export Capabilities**: Save reports for documentation, incident management, and compliance
- **Service Information**: Copy individual service details to clipboard for sharing
- **Audit Trail**: Comprehensive logging of all monitoring activities and status changes

### 🛠️ Professional Tools
- **Debug Mode**: Toggle detailed logging for troubleshooting and analysis
- **Keyboard Shortcuts**: F5 for refresh, Ctrl+Q for exit, and other productivity shortcuts
- **Copy Functionality**: Copy console output and service information to clipboard
- **Menu System**: Professional menu bar with File, Tools, and Help sections

## 📋 Requirements

- **Python 3.7+**
- **Network access** to monitored services
- **Internet connection** for cloud service monitoring
- **Firewall permissions** for outbound connections

## 🛠️ Installation

### 1. Download or Clone
```bash
# Download the main.py file or clone repository
wget [your-repository-url]/main.py
# or
git clone [your-repository-url]
cd service-monitor
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

### Quick Start with Pre-configured Services

1. **Microsoft 365 Monitoring**:
   - Click "Add All Microsoft 365" button
   - Automatically adds Exchange, SharePoint, Teams, and OneDrive monitoring
   - Perfect for Office 365 infrastructure monitoring

2. **Infrastructure Monitoring**:
   - Click "Add All Infrastructure" for DNS server monitoring
   - Includes Google DNS, Cloudflare, Quad9, and OpenDNS
   - Essential for network connectivity validation

3. **Cloud Provider Monitoring**:
   - Click "Add All Cloud Providers" for major cloud consoles
   - Monitors AWS, Azure, Google Cloud, and Cloudflare dashboards
   - Critical for multi-cloud environment monitoring

### Custom Service Configuration

| Field | Example | Description |
|-------|---------|-------------|
| **Service Name** | `Production API` | Descriptive name for identification |
| **URL/Endpoint** | `https://api.company.com/health` | Full URL or IP address for monitoring |
| **Check Type** | `HTTP Status (200 OK)` | Monitoring method selection |
| **Category** | `Internal APIs` | Organizational category |

### Check Types Explained

| Type | Use Case | Description |
|------|----------|-------------|
| **HTTP Status (200 OK)** | Web services, APIs | Checks for successful HTTP response |
| **Ping Test** | Server connectivity | Basic network reachability test |
| **Port Check** | Database, mail servers | Verifies specific port availability |
| **DNS Resolution** | Domain validation | Confirms DNS name resolution |
| **Custom API Response** | Health check APIs | Advanced API endpoint validation |

## 🎯 Usage

### 1. Quick Service Addition
1. **Browse Categories**: Use the Service Categories section for common services
2. **One-Click Addition**: Click individual service buttons or "Add All" for categories
3. **Instant Monitoring**: Services are immediately added to the monitoring tree
4. **Auto-Configuration**: Appropriate check types are automatically selected

### 2. Custom Service Monitoring
1. **Service Configuration**: Fill in the Custom Service Management form
2. **Test Configuration**: Use "Test Service" to validate settings before adding
3. **Add to Monitoring**: Click "Add Custom Service" to include in monitoring
4. **Organize Services**: Use custom categories for logical grouping

### 3. Real-time Monitoring
1. **Enable Auto-refresh**: Check the "Auto-refresh (30s)" checkbox for continuous monitoring
2. **Manual Refresh**: Use "Refresh All" button for immediate status updates
3. **Individual Testing**: Select services and use "Test Selected" for focused testing
4. **Monitor Status**: Watch the Status Summary for overall infrastructure health

### 4. Advanced Operations
1. **Context Menus**: Right-click services for individual actions and information
2. **Category Testing**: Right-click categories to test all services in that group
3. **Configuration Management**: Use File menu to save and load monitoring configurations
4. **Report Generation**: Export status reports for documentation and analysis

## 📊 Understanding Results

### Status Indicators

| Status | Color | Response Time | Meaning |
|--------|-------|---------------|---------|
| **🟢 Healthy** | Green | < 200ms | Service responding normally |
| **🟡 Warning** | Yellow | 200-1000ms | Service slow or minor issues |
| **🔴 Critical** | Red | > 1000ms or failed | Service down or major problems |

### Service Tree Display

- **📁 Categories**: Expandable groups for service organization
- **Service Name**: Descriptive identifier for each monitored endpoint
- **Status**: Current health status with visual indicators
- **Response Time**: Latest response time in milliseconds
- **Last Checked**: Timestamp of most recent monitoring check
- **Details**: Additional information about service status or errors

### Console Output

- **Real-time Logging**: Live feed of all monitoring activities
- **Timestamp**: Precise timing for all logged events
- **Log Levels**: INFO, SUCCESS, WARNING, ERROR, and DEBUG messages
- **Debug Mode**: Toggle for detailed troubleshooting information

## 🔧 Configuration Management

### Saving Configurations

```bash
File → Save Configuration
# Creates timestamped JSON file with all service definitions
# Format: service_config_YYYYMMDD_HHMMSS.json
```

### Loading Configurations

```bash
File → Load Configuration
# Options to replace existing services or merge with current setup
# Supports standard JSON configuration format
```

### Auto-save Functionality

- **Automatic Persistence**: Configurations automatically saved to `service_config.json`
- **Session Recovery**: Previous monitoring setup restored on application startup
- **Change Tracking**: Configuration updates saved when services are added or removed

## 🛡️ Best Practices

### Service Monitoring Strategy
- **Start with Critical Services**: Add your most important infrastructure first
- **Use Categories**: Organize services logically for easier management
- **Enable Auto-refresh**: Set up continuous monitoring for proactive issue detection
- **Regular Testing**: Manually test services periodically to validate monitoring accuracy

### Performance Optimization
- **Reasonable Service Count**: Monitor essential services to avoid overwhelming the system
- **Network Considerations**: Account for network latency in response time expectations
- **Timeout Settings**: Default 10-second timeout balances accuracy with responsiveness
- **Monitoring Intervals**: 30-second auto-refresh provides good balance of timeliness and system load

### Operational Guidelines
- **Document Configurations**: Export and version control your monitoring configurations
- **Share Configurations**: Use save/load functionality to distribute monitoring setups
- **Monitor Monitoring**: Watch console output for monitoring system health
- **Regular Reports**: Export status reports for trend analysis and documentation

## 🔍 Troubleshooting

### Common Issues

#### "Connection Failed" or "Timeout" Errors
- **Network Connectivity**: Verify network access to monitored services
- **Firewall Rules**: Ensure outbound connections are allowed
- **Service Availability**: Confirm target services are actually running
- **URL Format**: Verify correct URL format (include http:// or https://)

#### Services Show as Critical When They're Working
- **Response Time**: Service may be responding slowly (> 1000ms)
- **SSL Issues**: Try HTTP instead of HTTPS for internal services
- **Authentication**: Some services may require authentication
- **Endpoint Validity**: Verify the monitored endpoint actually provides status information

#### Auto-refresh Not Working
- **Checkbox Status**: Ensure "Auto-refresh (30s)" is checked
- **Application Focus**: Auto-refresh continues even when application is in background
- **System Resources**: Very high system load may affect timer precision

### Debug Mode

Enable debug mode for detailed troubleshooting:
1. Click "Toggle Debug" button or use Tools → Toggle Debug Mode
2. Review detailed logging in console output
3. Check network requests, response details, and timing information
4. Export console output for analysis or support requests

### Performance Issues

- **Reduce Service Count**: Monitor fewer services if experiencing slowdowns
- **Disable Auto-refresh**: Turn off auto-refresh during troubleshooting
- **Check Network**: Verify network connectivity and DNS resolution
- **System Resources**: Monitor CPU and memory usage during large-scale monitoring

## 📁 File Structure

```
service-monitor/
├── main.py                     # Complete standalone application
├── requirements.txt            # Python dependencies
├── README.md                  # This documentation
├── service_config.json        # Auto-saved configuration (created on first run)
└── exports/                   # Directory for exported reports (optional)
    ├── service_status_report_YYYYMMDD_HHMMSS.txt
    └── service_config_YYYYMMDD_HHMMSS.json
```

## 🔄 Integration Capabilities

### API Usage (Programmatic Access)

The ServiceTools class can be used programmatically:

```python
from main import ServiceTools, Logger

# Initialize monitoring
logger = Logger()
service_tools = ServiceTools(logger)

# Add services programmatically
service_tools.add_service("Production API", "https://api.company.com/health", "http", "APIs")
service_tools.add_service("Database Server", "db.company.com:5432", "port", "Infrastructure")

# Check all services
service_tools.check_all_services()

# Get status summary
summary = service_tools.get_status_summary()
print(f"Healthy: {summary['healthy']}, Critical: {summary['critical']}")
```

### Configuration File Format

```json
{
  "services": [
    {
      "name": "Production API",
      "url": "https://api.company.com/health",
      "type": "http",
      "category": "APIs"
    },
    {
      "name": "Database Server", 
      "url": "db.company.com:5432",
      "type": "port",
      "category": "Infrastructure"
    }
  ],
  "export_time": "2024-01-15T10:30:00.000000"
}
```

## 🤝 Contributing

Contributions and improvements are welcome! Priority areas:

### High Priority
- **Additional Check Types**: Database connectivity, SMTP testing, SSL certificate validation
- **Alerting System**: Email notifications and webhook integration for status changes
- **Historical Data**: Trend analysis and performance tracking over time
- **Threshold Configuration**: Custom response time thresholds per service

### Medium Priority
- **Dashboard Enhancements**: Graphical status displays and performance charts
- **Mobile Interface**: Responsive design for mobile monitoring
- **Multi-threading**: Parallel service checking for improved performance
- **Plugin Architecture**: Extensible monitoring types and custom integrations

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Disclaimer

This tool is provided as-is for infrastructure monitoring and troubleshooting purposes. Always:

### Operational Responsibilities
- **Test thoroughly** in non-production environments first
- **Verify network access** and firewall configurations
- **Monitor system resources** during large-scale monitoring operations
- **Validate service endpoints** before adding to monitoring
- **Document configurations** and maintain backup copies

### Security Considerations
- **Network Security**: Ensure monitoring traffic complies with security policies
- **Credential Management**: No credentials are stored; uses network-level authentication
- **Data Sensitivity**: Exported reports may contain sensitive infrastructure information
- **Access Control**: Restrict access to monitoring configurations and reports

## 📞 Support

For issues and questions:

### Self-Help Resources
1. **Check troubleshooting section** above for common issues
2. **Enable debug mode** for detailed error information
3. **Verify network connectivity** to monitored services
4. **Test with simple services** first (like Google DNS) before complex endpoints

### Documentation
- **Configuration Examples**: See usage section for detailed setup instructions
- **Best Practices**: Follow operational guidelines for optimal performance
- **Troubleshooting Guide**: Comprehensive error resolution steps

---

**Service Monitor v1.0** - Professional infrastructure monitoring for system administrators who demand real-time visibility, reliability, and comprehensive service health tracking. Perfect for monitoring Microsoft 365, cloud services, and custom infrastructure endpoints.