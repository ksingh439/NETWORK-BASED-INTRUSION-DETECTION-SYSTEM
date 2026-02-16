# NIDS Usage Examples

This document provides practical examples of using the Network Intrusion Detection System in various scenarios.

## Table of Contents

1. [Basic Setup and Configuration](#basic-setup-and-configuration)
2. [Monitoring Specific Network Traffic](#monitoring-specific-network-traffic)
3. [Custom Detection Rules](#custom-detection-rules)
4. [Integration with Other Tools](#integration-with-other-tools)
5. [Performance Tuning](#performance-tuning)
6. [Real-World Scenarios](#real-world-scenarios)

## Basic Setup and Configuration

### Example 1: First-Time Setup

```bash
# 1. Check system requirements
python main.py --check

# 2. List available interfaces
python main.py --list-interfaces

# 3. Start with default configuration
python main.py --full

# 4. Access dashboard at http://127.0.0.1:8080
```

### Example 2: Custom Interface Configuration

Edit `config.yaml`:
```yaml
network:
  interface: "wlan0"  # Use wireless interface
  promiscuous_mode: true
  buffer_size: 32768
```

Start the system:
```bash
python main.py --nids --interface wlan0
```

### Example 3: Development Environment Setup

```bash
# Create virtual environment
python -m venv nids_env
source nids_env/bin/activate  # Linux/macOS
# or
nids_env\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Start in debug mode
python main.py --config config_dev.yaml --full
```

## Monitoring Specific Network Traffic

### Example 4: Monitoring Web Server Traffic

Configuration for web server monitoring:
```yaml
# config_webserver.yaml
network:
  interface: "eth0"
  
detection:
  rules_enabled: true
  anomaly_enabled: true
  
logging:
  level: "INFO"
  log_file: "logs/webserver_nids.log"

dashboard:
  port: 8081
```

Custom rules for web server:
```yaml
# rules/webserver_rules.yaml
rules:
  - name: "Web Server Port Scan"
    description: "Detect port scanning on web ports"
    condition: "port_scan"
    threshold: 5
    time_window: 30
    severity: "high"
    enabled: true
    
  - name: "HTTP Method Anomaly"
    description: "Detect unusual HTTP methods"
    condition: "http_method_anomaly"
    methods: ["GET", "POST", "PUT", "DELETE"]
    severity: "medium"
    enabled: true
```

Start monitoring:
```bash
python main.py --config config_webserver.yaml --full
```

### Example 5: Monitoring Internal Network

```yaml
# config_internal.yaml
network:
  interface: "eth1"
  
detection:
  rules_enabled: true
  anomaly_enabled: true
  
logging:
  level: "DEBUG"
  log_file: "logs/internal_nids.log"
```

Start internal network monitoring:
```bash
sudo python main.py --config config_internal.yaml --nids --interface eth1
```

## Custom Detection Rules

### Example 6: Creating Custom Port Scan Rule

Add to `rules/detection_rules.yaml`:
```yaml
- name: "Aggressive Port Scan"
    description: "Detect rapid port scanning"
    condition: "port_scan"
    threshold: 50
    time_window: 10
    severity: "high"
    enabled: true
    
  - name: "Slow Port Scan"
    description: "Detect slow and stealthy port scanning"
    condition: "port_scan"
    threshold: 20
    time_window: 300
    severity: "medium"
    enabled: true
```

### Example 7: Custom Application Detection

```yaml
- name: "Database Access Anomaly"
  description: "Detect unusual database access patterns"
  condition: "database_access"
  ports: [3306, 5432, 1433, 1521]
  threshold: 100
  time_window: 60
  severity: "high"
  enabled: true
  
- name: "SSH Brute Force"
  description: "Detect SSH brute force attempts"
  condition: "ssh_brute_force"
  threshold: 10
  time_window: 60
  severity: "high"
  enabled: true
```

### Example 8: Time-Based Rules

```yaml
- name: "After Hours Activity"
  description: "Detect network activity during off-hours"
  condition: "time_based"
  start_hour: 22
  end_hour: 6
  severity: "medium"
  enabled: true
  
- name: "Weekend Activity"
  description: "Detect unusual weekend network activity"
  condition: "weekend_activity"
  threshold: 1000
  severity: "low"
  enabled: true
```

## Integration with Other Tools

### Example 9: SIEM Integration Script

```python
# siem_integration.py
import json
import requests
from utils import export_alerts
from datetime import datetime

def send_to_siem(alerts, siem_url, api_key):
    """Send alerts to SIEM system"""
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    for alert in alerts:
        payload = {
            'timestamp': alert['timestamp'],
            'source': 'NIDS',
            'severity': alert['severity'],
            'rule_name': alert['rule_name'],
            'description': alert['description'],
            'source_ip': alert.get('packet_info', {}).get('src_ip'),
            'destination_ip': alert.get('packet_info', {}).get('dst_ip')
        }
        
        try:
            response = requests.post(siem_url, json=payload, headers=headers)
            if response.status_code == 200:
                print(f"Alert sent to SIEM: {alert['rule_name']}")
            else:
                print(f"Failed to send alert: {response.status_code}")
        except Exception as e:
            print(f"Error sending to SIEM: {e}")

# Usage
if __name__ == "__main__":
    # Export recent alerts
    alerts = []  # Load alerts from NIDS
    
    # Send to SIEM
    send_to_siem(alerts, "https://your-siem.com/api/alerts", "your-api-key")
```

### Example 10: Email Alert Integration

```python
# email_alerts.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(alert, smtp_config):
    """Send email alert for critical incidents"""
    msg = MIMEMultipart()
    msg['From'] = smtp_config['from_email']
    msg['To'] = smtp_config['to_email']
    msg['Subject'] = f"NIDS Alert: {alert['rule_name']}"
    
    body = f"""
    Network Intrusion Detection System Alert
    
    Rule: {alert['rule_name']}
    Severity: {alert['severity']}
    Time: {alert['timestamp']}
    Description: {alert['description']}
    
    Packet Information:
    {alert.get('packet_info', 'N/A')}
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
        server.starttls()
        server.login(smtp_config['username'], smtp_config['password'])
        server.send_message(msg)
        server.quit()
        print("Email alert sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

# SMTP Configuration
smtp_config = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'username': 'your-email@gmail.com',
    'password': 'your-password',
    'from_email': 'nids@yourcompany.com',
    'to_email': 'security@yourcompany.com'
}
```

### Example 11: Slack Integration

```python
# slack_integration.py
import requests
import json

def send_slack_alert(alert, webhook_url):
    """Send alert to Slack channel"""
    color = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'good'
    }.get(alert['severity'], 'warning')
    
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"NIDS Alert: {alert['rule_name']}",
                "text": alert['description'],
                "fields": [
                    {
                        "title": "Severity",
                        "value": alert['severity'].upper(),
                        "short": True
                    },
                    {
                        "title": "Time",
                        "value": alert['timestamp'],
                        "short": True
                    }
                ],
                "footer": "Network Intrusion Detection System",
                "ts": int(alert.get('timestamp', 0))
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print("Slack notification sent")
        else:
            print(f"Failed to send Slack notification: {response.status_code}")
    except Exception as e:
        print(f"Error sending to Slack: {e}")
```

## Performance Tuning

### Example 12: High-Traffic Environment Configuration

```yaml
# config_high_traffic.yaml
network:
  interface: "eth0"
  buffer_size: 131072  # Larger buffer for high traffic
  
performance:
  packet_buffer_size: 2000
  processing_threads: 8
  statistics_interval: 10

detection:
  rules_enabled: true
  anomaly_enabled: false  # Disable ML for high performance
  
logging:
  level: "WARNING"  # Reduce log verbosity
  console_output: false
```

### Example 13: Resource-Limited Environment

```yaml
# config_low_resource.yaml
network:
  interface: "eth0"
  buffer_size: 8192  # Smaller buffer
  
performance:
  packet_buffer_size: 500
  processing_threads: 2
  statistics_interval: 60

detection:
  rules_enabled: true
  anomaly_enabled: false
  
logging:
  level: "ERROR"
  max_file_size: "5MB"
  backup_count: 2
```

### Example 14: Performance Monitoring Script

```python
# performance_monitor.py
import time
import psutil
import requests
from datetime import datetime

def monitor_nids_performance(dashboard_url="http://127.0.0.1:8080"):
    """Monitor NIDS performance metrics"""
    
    while True:
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            # Get NIDS metrics
            response = requests.get(f"{dashboard_url}/api/stats")
            nids_stats = response.json() if response.status_code == 200 else {}
            
            # Print performance report
            print(f"\n=== NIDS Performance Report - {datetime.now()} ===")
            print(f"CPU Usage: {cpu_percent}%")
            print(f"Memory Usage: {memory.percent}%")
            print(f"Network Sent: {network.bytes_sent:,} bytes")
            print(f"Network Recv: {network.bytes_recv:,} bytes")
            print(f"Total Packets: {nids_stats.get('total_packets', 0):,}")
            print(f"Total Alerts: {nids_stats.get('total_alerts', 0):,}")
            
            # Alert if performance issues
            if cpu_percent > 80:
                print("⚠️  WARNING: High CPU usage!")
            if memory.percent > 80:
                print("⚠️  WARNING: High memory usage!")
                
        except Exception as e:
            print(f"Error monitoring performance: {e}")
        
        time.sleep(30)  # Check every 30 seconds

if __name__ == "__main__":
    monitor_nids_performance()
```

## Real-World Scenarios

### Example 15: Home Network Security

Setup for home network monitoring:
```yaml
# config_home.yaml
network:
  interface: "wlan0"  # WiFi interface
  
detection:
  rules_enabled: true
  anomaly_enabled: true
  suspicious_ports: [22, 23, 80, 443, 3389]
  
logging:
  level: "INFO"
  log_file: "logs/home_network.log"
  
dashboard:
  port: 8080
  host: "0.0.0.0"  # Allow access from other devices
```

Start home monitoring:
```bash
python main.py --config config_home.yaml --full
```

### Example 16: Small Office Network

```yaml
# config_office.yaml
network:
  interface: "eth0"
  
detection:
  rules_enabled: true
  anomaly_enabled: true
  
alerts:
  email_alerts: true
  webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
  
logging:
  level: "INFO"
  log_file: "logs/office_network.log"
```

### Example 17: Development Environment

```yaml
# config_dev.yaml
network:
  interface: "lo"  # Loopback for testing
  
detection:
  rules_enabled: true
  anomaly_enabled: false
  
logging:
  level: "DEBUG"
  console_output: true
  
dashboard:
  debug: true
  port: 8081
```

### Example 18: Testing with Sample Traffic

```python
# traffic_generator.py
from scapy.all import IP, TCP, UDP, ICMP, send
import random
import time

def generate_normal_traffic():
    """Generate normal network traffic for testing"""
    for i in range(100):
        # Normal web traffic
        packet = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(dport=80, sport=random.randint(1024, 65535))
        send(packet, verbose=False)
        time.sleep(0.1)

def generate_port_scan():
    """Generate port scanning traffic for testing"""
    src_ip = "192.168.1.200"
    dst_ip = "192.168.1.1"
    
    for port in range(1, 1024):
        packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
        time.sleep(0.01)

def generate_ddos():
    """Generate DDoS traffic for testing"""
    src_ips = [f"192.168.1.{i}" for i in range(200, 250)]
    dst_ip = "192.168.1.1"
    
    for _ in range(1000):
        src_ip = random.choice(src_ips)
        packet = IP(src=src_ip, dst=dst_ip)/ICMP()
        send(packet, verbose=False)

if __name__ == "__main__":
    print("Generating test traffic...")
    
    # Generate normal traffic
    print("Generating normal traffic...")
    generate_normal_traffic()
    
    # Generate port scan
    print("Generating port scan...")
    generate_port_scan()
    
    # Generate DDoS
    print("Generating DDoS traffic...")
    generate_ddos()
    
    print("Test traffic generation complete")
```

### Example 19: Automated Response Script

```python
# automated_response.py
import subprocess
import time
from utils import get_network_interfaces

def block_ip(ip_address):
    """Block IP address using firewall"""
    try:
        # Linux iptables
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        print(f"Blocked IP: {ip_address}")
        return True
    except subprocess.CalledProcessError:
        try:
            # Windows firewall
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                           f'name="Block {ip_address}"', 'dir=in', 'action=block', 
                           f'remoteip={ip_address}'], check=True)
            print(f"Blocked IP: {ip_address}")
            return True
        except subprocess.CalledProcessError:
            print(f"Failed to block IP: {ip_address}")
            return False

def automated_response(alert):
    """Automated response to security alerts"""
    if alert['severity'] == 'high':
        src_ip = alert.get('packet_info', {}).get('src_ip')
        if src_ip and src_ip != 'unknown':
            print(f"High severity alert detected: {alert['rule_name']}")
            print(f"Source IP: {src_ip}")
            
            # Block the IP
            if block_ip(src_ip):
                print("Automated response: IP blocked")
            else:
                print("Automated response: Failed to block IP")
```

### Example 20: Log Analysis Script

```python
# log_analyzer.py
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta

def analyze_nids_logs(log_file='logs/nids.log', days=7):
    """Analyze NIDS logs for patterns and trends"""
    
    # Read recent logs
    cutoff_date = datetime.now() - timedelta(days=days)
    alerts = []
    
    with open(log_file, 'r') as f:
        for line in f:
            try:
                # Parse log entry
                timestamp_str = line.split(' - ')[0]
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                
                if timestamp >= cutoff_date:
                    alerts.append(line)
            except:
                continue
    
    # Analyze patterns
    severity_counts = Counter()
    rule_counts = Counter()
    source_ips = Counter()
    
    alert_pattern = re.compile(r'\[(HIGH|MEDIUM|LOW)\] (.*?):')
    
    for alert in alerts:
        # Extract severity and rule
        match = alert_pattern.search(alert)
        if match:
            severity = match.group(1)
            rule = match.group(2)
            
            severity_counts[severity] += 1
            rule_counts[rule] += 1
        
        # Extract source IP (simplified)
        ip_match = re.search(r'src_ip": "(\d+\.\d+\.\d+\.\d+)"', alert)
        if ip_match:
            source_ips[ip_match.group(1)] += 1
    
    # Generate report
    print(f"\n=== NIDS Log Analysis - Last {days} Days ===")
    print(f"Total Alerts: {len(alerts)}")
    
    print("\nAlert Severity Distribution:")
    for severity, count in severity_counts.most_common():
        print(f"  {severity}: {count}")
    
    print("\nTop 10 Alert Rules:")
    for rule, count in rule_counts.most_common(10):
        print(f"  {rule}: {count}")
    
    print("\nTop 10 Source IPs:")
    for ip, count in source_ips.most_common(10):
        print(f"  {ip}: {count}")

if __name__ == "__main__":
    analyze_nids_logs()
```

These examples demonstrate various ways to configure and use the NIDS in different environments and scenarios. Adjust the configurations based on your specific requirements and network environment.
