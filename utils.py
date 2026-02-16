#!/usr/bin/env python3
"""
NIDS Utility Functions
Helper functions and utilities for the Network Intrusion Detection System
"""

import os
import sys
import time
import json
import socket
import struct
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import subprocess
import platform

def get_network_interfaces() -> List[Dict[str, str]]:
    """Get list of available network interfaces with details"""
    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
        
        interfaces = []
        for iface in get_if_list():
            try:
                interfaces.append({
                    'name': iface,
                    'ip': get_if_addr(iface),
                    'mac': get_if_hwaddr(iface)
                })
            except:
                interfaces.append({
                    'name': iface,
                    'ip': 'N/A',
                    'mac': 'N/A'
                })
        
        return interfaces
    except ImportError:
        logging.error("Scapy not available for interface detection")
        return []

def check_admin_privileges() -> bool:
    """Check if the script is running with administrative privileges"""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def validate_ip(ip: str) -> bool:
    """Validate if a string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_ip_from_domain(domain: str) -> Optional[str]:
    """Resolve domain name to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def calculate_packet_hash(packet_data: bytes) -> str:
    """Calculate SHA256 hash of packet data"""
    return hashlib.sha256(packet_data).hexdigest()

def format_bytes(bytes_count: int) -> str:
    """Format bytes into human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"

def format_time(timestamp: float) -> str:
    """Format Unix timestamp to readable string"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def get_protocol_name(protocol_number: int) -> str:
    """Get protocol name from protocol number"""
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        50: 'ESP',
        51: 'AH',
        58: 'IPv6-ICMP',
        60: 'IPv6-NoNxt',
        89: 'OSPF',
        103: 'PIM',
        108: 'PCP',
        111: 'VXLAN',
        115: 'L2TP',
        118: 'STP',
        121: 'SMP',
        127: 'L2TPv3'
    }
    return protocol_map.get(protocol_number, f'Protocol-{protocol_number}')

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    try:
        ip_parts = list(map(int, ip.split('.')))
        
        # 10.0.0.0/8
        if ip_parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if ip_parts[0] == 192 and ip_parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (localhost)
        if ip_parts[0] == 127:
            return True
            
        return False
    except:
        return False

def get_geolocation(ip: str) -> Optional[Dict[str, str]]:
    """Get geolocation information for IP address (placeholder)"""
    # In a real implementation, this would use a geolocation API
    # like ipinfo.io, maxmind geoip2, etc.
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'latitude': '0',
        'longitude': '0'
    }

def is_tor_exit_node(ip: str) -> bool:
    """Check if IP is a known TOR exit node (placeholder)"""
    # In a real implementation, this would check against TOR exit node lists
    # from services like torproject.org or third-party APIs
    return False

def load_malicious_domains() -> List[str]:
    """Load list of known malicious domains (placeholder)"""
    # In a real implementation, this would load from threat intelligence feeds
    # like PhishTank, MalwareDomainList, etc.
    return [
        'malicious-example.com',
        'phishing-site.net',
        'malware-distribution.org'
    ]

def create_log_directory(log_dir: str = "logs") -> bool:
    """Create log directory if it doesn't exist"""
    try:
        os.makedirs(log_dir, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Failed to create log directory {log_dir}: {e}")
        return False

def rotate_logs(log_file: str, max_size: int = 10*1024*1024, backup_count: int = 5):
    """Rotate log files when they exceed maximum size"""
    try:
        if os.path.exists(log_file) and os.path.getsize(log_file) > max_size:
            for i in range(backup_count - 1, 0, -1):
                old_file = f"{log_file}.{i}"
                new_file = f"{log_file}.{i + 1}"
                if os.path.exists(old_file):
                    if os.path.exists(new_file):
                        os.remove(new_file)
                    os.rename(old_file, new_file)
            
            if os.path.exists(f"{log_file}.1"):
                os.remove(f"{log_file}.1")
            os.rename(log_file, f"{log_file}.1")
            
            logging.info(f"Rotated log file: {log_file}")
    except Exception as e:
        logging.error(f"Error rotating logs: {e}")

def send_email_alert(subject: str, message: str, to_email: str, smtp_config: Dict = None):
    """Send email alert (placeholder implementation)"""
    # In a real implementation, this would use SMTP to send emails
    logging.info(f"Email Alert - Subject: {subject}, To: {to_email}")
    logging.info(f"Message: {message}")

def send_webhook_alert(webhook_url: str, alert_data: Dict):
    """Send webhook alert (placeholder implementation)"""
    # In a real implementation, this would send HTTP POST to webhook URL
    logging.info(f"Webhook Alert - URL: {webhook_url}")
    logging.info(f"Data: {json.dumps(alert_data, indent=2)}")

def get_system_info() -> Dict[str, Any]:
    """Get system information for monitoring"""
    try:
        import psutil
        
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent
        }
    except ImportError:
        logging.warning("psutil not available for system monitoring")
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor()
        }

def validate_config(config: Dict) -> Tuple[bool, List[str]]:
    """Validate configuration dictionary"""
    errors = []
    
    # Check required sections
    required_sections = ['network', 'detection', 'logging']
    for section in required_sections:
        if section not in config:
            errors.append(f"Missing required section: {section}")
    
    # Validate network configuration
    if 'network' in config:
        network_config = config['network']
        if 'interface' not in network_config:
            errors.append("Missing network interface configuration")
    
    # Validate detection configuration
    if 'detection' in config:
        detection_config = config['detection']
        if 'rules_file' not in detection_config:
            errors.append("Missing rules file configuration")
    
    # Validate logging configuration
    if 'logging' in config:
        logging_config = config['logging']
        if 'level' not in logging_config:
            errors.append("Missing logging level configuration")
        elif logging_config['level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            errors.append(f"Invalid logging level: {logging_config['level']}")
    
    return len(errors) == 0, errors

def backup_file(file_path: str, backup_dir: str = "backups") -> bool:
    """Create backup of a file"""
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.basename(file_path)
        backup_path = os.path.join(backup_dir, f"{filename}.{timestamp}.bak")
        
        with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
            dst.write(src.read())
        
        logging.info(f"Created backup: {backup_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to backup file {file_path}: {e}")
        return False

def cleanup_old_files(directory: str, days: int = 30, pattern: str = "*"):
    """Clean up old files in directory"""
    try:
        import glob
        
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        pattern_path = os.path.join(directory, pattern)
        
        for file_path in glob.glob(pattern_path):
            if os.path.getmtime(file_path) < cutoff_time:
                os.remove(file_path)
                logging.info(f"Removed old file: {file_path}")
                
    except Exception as e:
        logging.error(f"Error cleaning up old files: {e}")

def get_port_service(port: int, protocol: str = 'tcp') -> str:
    """Get service name for port number"""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return f"Port-{port}"

def analyze_packet_frequency(packets: List[Dict], time_window: int = 60) -> Dict[str, int]:
    """Analyze packet frequency by source IP within time window"""
    current_time = time.time()
    frequency = {}
    
    for packet in packets:
        packet_time = packet.get('timestamp', 0)
        if current_time - packet_time <= time_window:
            src_ip = packet.get('src_ip', 'unknown')
            frequency[src_ip] = frequency.get(src_ip, 0) + 1
    
    return frequency

def detect_port_scan_pattern(port_access: Dict[str, set], threshold: int = 10) -> List[str]:
    """Detect IPs that are scanning multiple ports"""
    suspicious_ips = []
    
    for ip, ports in port_access.items():
        if len(ports) >= threshold:
            suspicious_ips.append(ip)
    
    return suspicious_ips

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def is_encrypted_traffic(packet_data: bytes) -> bool:
    """Simple heuristic to detect encrypted traffic"""
    if len(packet_data) < 20:
        return False
    
    # Calculate entropy of first 100 bytes
    sample_size = min(100, len(packet_data))
    entropy = calculate_entropy(packet_data[:sample_size])
    
    # Encrypted traffic typically has high entropy (> 7.0)
    return entropy > 7.0

def create_rule_template() -> Dict:
    """Create a template for new detection rules"""
    return {
        'name': 'New Detection Rule',
        'description': 'Description of what this rule detects',
        'condition': 'rule_condition',
        'threshold': 10,
        'time_window': 60,
        'severity': 'medium',
        'enabled': True,
        'parameters': {}
    }

def export_alerts(alerts: List[Dict], format: str = 'json', filename: str = None) -> str:
    """Export alerts to file"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"alerts_export_{timestamp}.{format}"
    
    try:
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
        elif format.lower() == 'csv':
            import pandas as pd
            df = pd.DataFrame(alerts)
            df.to_csv(filename, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logging.info(f"Exported {len(alerts)} alerts to {filename}")
        return filename
    except Exception as e:
        logging.error(f"Error exporting alerts: {e}")
        return None

class PerformanceMonitor:
    """Monitor system performance during NIDS operation"""
    
    def __init__(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.alert_count = 0
        self.cpu_samples = []
        self.memory_samples = []
        
    def update(self, packet_count: int = 0, alert_count: int = 0):
        """Update performance metrics"""
        self.packet_count += packet_count
        self.alert_count += alert_count
        
        try:
            import psutil
            self.cpu_samples.append(psutil.cpu_percent())
            self.memory_samples.append(psutil.virtual_memory().percent)
            
            # Keep only last 100 samples
            if len(self.cpu_samples) > 100:
                self.cpu_samples = self.cpu_samples[-100:]
            if len(self.memory_samples) > 100:
                self.memory_samples = self.memory_samples[-100:]
        except ImportError:
            pass
    
    def get_stats(self) -> Dict:
        """Get current performance statistics"""
        runtime = time.time() - self.start_time
        
        return {
            'runtime_seconds': runtime,
            'packet_count': self.packet_count,
            'alert_count': self.alert_count,
            'packets_per_second': self.packet_count / runtime if runtime > 0 else 0,
            'alerts_per_minute': (self.alert_count / runtime * 60) if runtime > 0 else 0,
            'avg_cpu_usage': sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0,
            'avg_memory_usage': sum(self.memory_samples) / len(self.memory_samples) if self.memory_samples else 0,
            'max_cpu_usage': max(self.cpu_samples) if self.cpu_samples else 0,
            'max_memory_usage': max(self.memory_samples) if self.memory_samples else 0
        }
