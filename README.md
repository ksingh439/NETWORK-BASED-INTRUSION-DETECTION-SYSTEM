# Network Based Intrusion Detection System (NIDS)

A comprehensive Network Intrusion Detection System built with Python that provides real-time network monitoring, threat detection, and analysis capabilities.

## Features

### 🔍 **Detection Capabilities**
- **Rule-based Detection**: Configurable detection rules for common attack patterns
- **Anomaly Detection**: Machine learning-based detection using Isolation Forest
- **Real-time Monitoring**: Live packet capture and analysis
- **Protocol Analysis**: Support for TCP, UDP, ICMP, and other protocols
- **Port Scan Detection**: Identifies potential port scanning activities
- **DDoS Detection**: Detects various DDoS attack patterns

### 📊 **Monitoring & Visualization**
- **Web Dashboard**: Real-time monitoring dashboard with charts and statistics
- **Live Statistics**: Packet rates, protocol distribution, and alert trends
- **Alert Management**: Comprehensive alert logging and management
- **System Monitoring**: CPU, memory, and network usage tracking

### ⚙️ **Configuration & Management**
- **YAML Configuration**: Easy-to-configure system settings
- **Custom Rules**: Define custom detection rules
- **Multiple Interfaces**: Monitor multiple network interfaces
- **Logging System**: Comprehensive logging with rotation
- **Performance Monitoring**: Built-in performance tracking

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrative/root privileges (for packet capture)
- Network interface access

### Setup

1. **Clone or download the project**
   ```bash
   # If using git
   git clone <repository-url>
   cd network-based-intrusion-detection-system
   
   # Or download and extract the files
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify system requirements**
   ```bash
   python main.py --check
   ```

4. **List available network interfaces**
   ```bash
   python main.py --list-interfaces
   ```

## Quick Start

### 1. Basic Usage

Start the full system (NIDS + Dashboard):
```bash
python main.py --full
```

Start only the NIDS core:
```bash
python main.py --nids
```

Start only the web dashboard:
```bash
python main.py --dashboard
```

### 2. Specify Network Interface

```bash
python main.py --nids --interface eth0
```

### 3. Access the Dashboard

Open your web browser and navigate to:
```
http://127.0.0.1:8080
```

## Configuration

### Main Configuration (config.yaml)

```yaml
# Network Interface Configuration
network:
  interface: "eth0"  # Change to your network interface
  promiscuous_mode: true
  buffer_size: 65535

# Detection Settings
detection:
  rules_enabled: true
  rules_file: "rules/detection_rules.yaml"
  anomaly_enabled: true
  model_file: "models/anomaly_model.pkl"
  threshold: 0.8

# Logging Configuration
logging:
  level: "INFO"
  log_file: "logs/nids.log"
  console_output: true

# Web Dashboard
dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 8080
```

### Detection Rules (rules/detection_rules.yaml)

The system includes pre-configured detection rules for common threats:

- **Port Scan Detection**: Identifies scanning across multiple ports
- **Suspicious Port Access**: Monitors access to sensitive ports
- **DDoS Attacks**: Detects ICMP floods, SYN floods, etc.
- **Brute Force Attacks**: Identifies HTTP and SSH brute force attempts
- **Malicious Communication**: Detects C2 communication and malicious domains

## Command Line Options

```bash
# Check system requirements
python main.py --check

# List network interfaces
python main.py --list-interfaces

# Start NIDS core
python main.py --nids [--interface INTERFACE]

# Start dashboard only
python main.py --dashboard

# Start full system
python main.py --full [--interface INTERFACE]

# Use custom configuration
python main.py --config custom.yaml --full

# Show version
python main.py --version
```

## Architecture

### Core Components

1. **PacketCapture** (`nids_core.py`)
   - Handles network packet capture using Scapy
   - Supports multiple network interfaces
   - Configurable buffer sizes and promiscuous mode

2. **RuleEngine** (`nids_core.py`)
   - Processes packets against detection rules
   - Supports custom rule definitions
   - Real-time rule evaluation

3. **AnomalyDetector** (`nids_core.py`)
   - Machine learning-based anomaly detection
   - Uses Isolation Forest algorithm
   - Automatic model training and updates

4. **Web Dashboard** (`dashboard.py`)
   - Real-time monitoring interface
   - Interactive charts and statistics
   - WebSocket-based live updates

5. **Utilities** (`utils.py`)
   - Helper functions and utilities
   - System monitoring tools
   - Performance tracking

### Data Flow

```
Network Packets → PacketCapture → RuleEngine → Alerts
                     ↓              ↓
               AnomalyDetector → Dashboard
                     ↓
                 Logging System
```

## Detection Rules

### Rule Structure

Each detection rule follows this structure:

```yaml
- name: "Rule Name"
  description: "Description of what the rule detects"
  condition: "detection_condition"
  threshold: 10
  time_window: 60
  severity: "medium"
  enabled: true
```

### Available Conditions

- `port_scan`: Detects port scanning activities
- `suspicious_port`: Monitors access to specific ports
- `large_packet`: Detects unusually large packets
- `icmp_flood`: Identifies ICMP flood attacks
- `syn_flood`: Detects SYN flood attacks
- `dns_amplification`: Identifies DNS amplification attacks
- `http_brute_force`: Detects HTTP brute force attempts
- `ssh_brute_force`: Detects SSH brute force attempts
- `suspicious_user_agent`: Identifies suspicious user agents
- `tor_exit_node`: Detects TOR exit node access
- `malicious_domain`: Identifies access to malicious domains

## Web Dashboard Features

### Real-time Monitoring
- Live packet capture statistics
- Protocol distribution charts
- Alert timeline visualization
- System resource monitoring

### Alert Management
- Real-time alert notifications
- Alert severity classification
- Historical alert data
- Alert filtering and search

### Statistics and Analytics
- Packet rate monitoring
- Protocol usage analysis
- Geographic distribution (if configured)
- Performance metrics

## Logging and Alerts

### Log Files
- **Main Log**: `logs/nids.log`
- **Alert Log**: Integrated in main log with severity levels
- **System Log**: Performance and system events

### Alert Levels
- **HIGH**: Critical security threats
- **MEDIUM**: Suspicious activities
- **LOW**: Informational alerts

### Alert Formats
```
[HIGH] Port Scan Detection: Potential port scanning activity detected
[MEDIUM] Suspicious Port Access: Access to sensitive port 22 detected
[LOW] Large Data Transfer: Unusually large packet detected
```

## Performance Considerations

### System Requirements
- **Minimum**: 2GB RAM, 2 CPU cores
- **Recommended**: 4GB RAM, 4+ CPU cores
- **Storage**: 1GB+ for logs and models

### Optimization Tips
1. **Interface Selection**: Monitor specific interfaces rather than all
2. **Rule Filtering**: Disable unnecessary rules
3. **Buffer Sizes**: Adjust buffer sizes based on traffic volume
4. **Log Rotation**: Configure appropriate log rotation

### Monitoring Performance
```bash
# Monitor system resources
python main.py --check

# Check performance statistics in dashboard
# Navigate to http://127.0.0.1:8080
```

## Security Considerations

### Permissions
- **Required**: Administrative/root privileges for packet capture
- **Network**: Access to network interfaces
- **File System**: Write access for logs and models

### Data Privacy
- **Packet Data**: Packets are processed in memory only
- **Logs**: No packet content stored in logs by default
- **Models**: Anomaly detection models contain traffic patterns only

### Recommendations
1. **Network Isolation**: Run in dedicated network segment
2. **Access Control**: Limit dashboard access to authorized users
3. **Log Protection**: Secure log files with appropriate permissions
4. **Regular Updates**: Keep detection rules updated

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Solution: Run with administrative privileges
   sudo python main.py --full  # Linux/macOS
   # Run as Administrator on Windows
   ```

2. **Interface Not Found**
   ```bash
   # List available interfaces
   python main.py --list-interfaces
   
   # Update config.yaml with correct interface
   ```

3. **Port Already in Use**
   ```bash
   # Change dashboard port in config.yaml
   dashboard:
     port: 8081  # Use different port
   ```

4. **Missing Dependencies**
   ```bash
   # Reinstall dependencies
   pip install -r requirements.txt --upgrade
   ```

### Debug Mode

Enable debug logging in `config.yaml`:
```yaml
logging:
  level: "DEBUG"
  
dashboard:
  debug: true
```

### Log Analysis

```bash
# View recent logs
tail -f logs/nids.log

# Search for errors
grep "ERROR" logs/nids.log

# View alerts only
grep "HIGH\|MEDIUM" logs/nids.log
```

## Advanced Usage

### Custom Detection Rules

Create custom rules in `rules/detection_rules.yaml`:

```yaml
- name: "Custom Rule"
  description: "Custom detection logic"
  condition: "custom_condition"
  threshold: 50
  time_window: 120
  severity: "high"
  enabled: true
```

### Integration with SIEM

Export alerts for SIEM integration:

```python
from utils import export_alerts

# Export alerts to JSON
export_alerts(alerts, format='json', filename='siem_export.json')

# Export to CSV
export_alerts(alerts, format='csv', filename='siem_export.csv')
```

### API Integration

The dashboard provides REST API endpoints:

```bash
# Get current statistics
curl http://127.0.0.1:8080/api/stats

# Get recent alerts
curl http://127.0.0.1:8080/api/alerts

# Get system statistics
curl http://127.0.0.1:8080/api/system
```

## Contributing

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Check code style
flake8 *.py
```

### Adding New Features
1. Create feature branch
2. Implement changes
3. Add tests
4. Update documentation
5. Submit pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for error messages
3. Verify system requirements
4. Check network interface configuration

## Changelog

### Version 1.0.0
- Initial release
- Core NIDS functionality
- Web dashboard
- Rule-based detection
- Anomaly detection
- Comprehensive documentation

---

**Note**: This NIDS is for educational and research purposes. For production environments, consider additional security measures and professional security solutions.
