#!/usr/bin/env python3
"""
Network Based Intrusion Detection System - Core Module
Main NIDS engine with packet capture and detection capabilities
"""

import os
import sys
import time
import logging
import threading
import signal
import yaml
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    import psutil
    from colorama import init, Fore, Style
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for colored output
init(autoreset=True)

class PacketCapture:
    """Handles network packet capture using Scapy"""
    
    def __init__(self, interface: str, promiscuous: bool = True, buffer_size: int = 65535):
        self.interface = interface
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        self.capture_active = False
        self.packet_queue = deque(maxlen=1000)
        self.capture_thread = None
        
    def start_capture(self, packet_callback):
        """Start packet capture in a separate thread"""
        self.capture_active = True
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(packet_callback,),
            daemon=True
        )
        self.capture_thread.start()
        
    def _capture_packets(self, packet_callback):
        """Internal packet capture method"""
        try:
            sniff(
                iface=self.interface,
                prn=packet_callback,
                store=0,
                stop_filter=lambda x: not self.capture_active
            )
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
            
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)

class RuleEngine:
    """Rule-based detection engine"""
    
    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules = []
        self.load_rules()
        
    def load_rules(self):
        """Load detection rules from YAML file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    rules_data = yaml.safe_load(f)
                    self.rules = rules_data.get('rules', [])
                logging.info(f"Loaded {len(self.rules)} detection rules")
            else:
                logging.warning(f"Rules file {self.rules_file} not found")
                self.create_default_rules()
        except Exception as e:
            logging.error(f"Error loading rules: {e}")
            self.create_default_rules()
            
    def create_default_rules(self):
        """Create default detection rules"""
        self.rules = [
            {
                'name': 'Port Scan Detection',
                'description': 'Detect potential port scanning activity',
                'condition': 'port_scan',
                'threshold': 10,
                'time_window': 60
            },
            {
                'name': 'Suspicious Port Access',
                'description': 'Detect access to suspicious ports',
                'condition': 'suspicious_port',
                'ports': [22, 23, 80, 443, 3389, 1433, 3306]
            },
            {
                'name': 'Large Data Transfer',
                'description': 'Detect unusually large data transfers',
                'condition': 'large_packet',
                'threshold': 8000  # bytes
            },
            {
                'name': 'ICMP Flood',
                'description': 'Detect potential ICMP flood attacks',
                'condition': 'icmp_flood',
                'threshold': 100,
                'time_window': 10
            }
        ]
        
    def analyze_packet(self, packet, traffic_stats: Dict) -> Optional[Dict]:
        """Analyze packet against rules"""
        alerts = []
        
        for rule in self.rules:
            if self._evaluate_rule(rule, packet, traffic_stats):
                alerts.append({
                    'rule_name': rule['name'],
                    'description': rule['description'],
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'medium',
                    'packet_info': self._extract_packet_info(packet)
                })
                
        return alerts if alerts else None
        
    def _evaluate_rule(self, rule: Dict, packet, traffic_stats: Dict) -> bool:
        """Evaluate a single rule against packet"""
        condition = rule['condition']
        
        if condition == 'port_scan':
            return self._check_port_scan(rule, traffic_stats)
        elif condition == 'suspicious_port':
            return self._check_suspicious_port(rule, packet)
        elif condition == 'large_packet':
            return self._check_large_packet(rule, packet)
        elif condition == 'icmp_flood':
            return self._check_icmp_flood(rule, traffic_stats)
            
        return False
        
    def _check_port_scan(self, rule: Dict, traffic_stats: Dict) -> bool:
        """Check for port scanning activity"""
        src_ip = traffic_stats.get('current_src_ip')
        if not src_ip:
            return False
            
        port_access = traffic_stats.get('port_access', {}).get(src_ip, set())
        threshold = rule.get('threshold', 10)
        
        return len(port_access) >= threshold
        
    def _check_suspicious_port(self, rule: Dict, packet) -> bool:
        """Check for access to suspicious ports"""
        if TCP in packet or UDP in packet:
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            suspicious_ports = rule.get('ports', [])
            return dport in suspicious_ports
        return False
        
    def _check_large_packet(self, rule: Dict, packet) -> bool:
        """Check for unusually large packets"""
        threshold = rule.get('threshold', 8000)
        return len(packet) > threshold
        
    def _check_icmp_flood(self, rule: Dict, traffic_stats: Dict) -> bool:
        """Check for ICMP flood attacks"""
        icmp_count = traffic_stats.get('protocol_counts', {}).get('ICMP', 0)
        threshold = rule.get('threshold', 100)
        return icmp_count > threshold
        
    def _extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        info = {
            'size': len(packet),
            'protocol': 'Unknown'
        }
        
        if IP in packet:
            info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto
            })
            
        if TCP in packet:
            info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': str(packet[TCP].flags)
            })
        elif UDP in packet:
            info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif ICMP in packet:
            info['icmp_type'] = packet[ICMP].type
            
        return info

class AnomalyDetector:
    """Machine learning-based anomaly detection"""
    
    def __init__(self, model_file: str = None):
        self.model_file = model_file
        self.model = None
        self.scaler = StandardScaler()
        self.feature_buffer = deque(maxlen=1000)
        self.is_trained = False
        
        if model_file and os.path.exists(model_file):
            self.load_model()
        else:
            self.initialize_model()
            
    def initialize_model(self):
        """Initialize the anomaly detection model"""
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        logging.info("Initialized new anomaly detection model")
        
    def load_model(self):
        """Load pre-trained model"""
        try:
            self.model = joblib.load(self.model_file)
            self.is_trained = True
            logging.info(f"Loaded model from {self.model_file}")
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            self.initialize_model()
            
    def save_model(self):
        """Save trained model"""
        if self.model_file and self.model:
            try:
                os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
                joblib.dump(self.model, self.model_file)
                logging.info(f"Model saved to {self.model_file}")
            except Exception as e:
                logging.error(f"Error saving model: {e}")
                
    def extract_features(self, packet, traffic_stats: Dict) -> List[float]:
        """Extract features from packet for anomaly detection"""
        features = []
        
        # Basic packet features
        features.append(len(packet))  # Packet size
        features.append(traffic_stats.get('packet_rate', 0))  # Packet rate
        features.append(traffic_stats.get('byte_rate', 0))  # Byte rate
        
        # Protocol features
        protocol_counts = traffic_stats.get('protocol_counts', {})
        features.append(protocol_counts.get('TCP', 0))
        features.append(protocol_counts.get('UDP', 0))
        features.append(protocol_counts.get('ICMP', 0))
        
        # Port features
        if TCP in packet or UDP in packet:
            features.append(packet[TCP].dport if TCP in packet else packet[UDP].dport)
            features.append(packet[TCP].sport if TCP in packet else packet[UDP].sport)
        else:
            features.extend([0, 0])
            
        # IP features
        if IP in packet:
            features.append(int(packet[IP].ttl))
            features.append(packet[IP].tos)
        else:
            features.extend([0, 0])
            
        return features
        
    def train(self, features: List[List[float]]):
        """Train the anomaly detection model"""
        if len(features) < 100:
            logging.warning("Insufficient data for training (need at least 100 samples)")
            return
            
        try:
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train model
            self.model.fit(scaled_features)
            self.is_trained = True
            
            logging.info(f"Model trained with {len(features)} samples")
            self.save_model()
            
        except Exception as e:
            logging.error(f"Error training model: {e}")
            
    def detect_anomaly(self, features: List[float]) -> Tuple[bool, float]:
        """Detect if features are anomalous"""
        if not self.is_trained:
            return False, 0.0
            
        try:
            # Scale features
            scaled_features = self.scaler.transform([features])
            
            # Predict anomaly
            anomaly_score = self.model.decision_function(scaled_features)[0]
            is_anomaly = self.model.predict(scaled_features)[0] == -1
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            logging.error(f"Error detecting anomaly: {e}")
            return False, 0.0

class NIDS:
    """Main Network Intrusion Detection System class"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config = self.load_config(config_file)
        self.setup_logging()
        
        # Initialize components
        self.packet_capture = PacketCapture(
            interface=self.config['network']['interface'],
            promiscuous=self.config['network']['promiscuous_mode'],
            buffer_size=self.config['network']['buffer_size']
        )
        
        self.rule_engine = RuleEngine(self.config['detection']['rules_file'])
        self.anomaly_detector = AnomalyDetector(self.config['detection']['model_file'])
        
        # Traffic statistics
        self.traffic_stats = defaultdict(int)
        self.port_access = defaultdict(set)
        self.protocol_counts = defaultdict(int)
        self.packet_times = deque(maxlen=1000)
        
        # Alert management
        self.alerts = deque(maxlen=1000)
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self.get_default_config()
            
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'network': {'interface': 'eth0', 'promiscuous_mode': True},
            'detection': {'rules_enabled': True, 'anomaly_enabled': True},
            'logging': {'level': 'INFO', 'console_output': True}
        }
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        
        # Create logs directory
        log_file = log_config.get('log_file', 'logs/nids.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_config.get('level', 'INFO')),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if log_config.get('console_output', True) else logging.NullHandler()
            ]
        )
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info("Received shutdown signal, stopping NIDS...")
        self.stop()
        
    def packet_handler(self, packet):
        """Main packet processing handler"""
        try:
            # Update traffic statistics
            self.update_traffic_stats(packet)
            
            # Rule-based detection
            if self.config['detection']['rules_enabled']:
                alerts = self.rule_engine.analyze_packet(packet, dict(self.traffic_stats))
                if alerts:
                    for alert in alerts:
                        self.handle_alert(alert)
                        
            # Anomaly detection
            if self.config['detection']['anomaly_enabled']:
                features = self.anomaly_detector.extract_features(packet, dict(self.traffic_stats))
                self.anomaly_detector.feature_buffer.append(features)
                
                # Train model periodically
                if len(self.anomaly_detector.feature_buffer) >= 500 and not self.anomaly_detector.is_trained:
                    self.anomaly_detector.train(list(self.anomaly_detector.feature_buffer))
                    
                # Detect anomalies
                if self.anomaly_detector.is_trained:
                    is_anomaly, score = self.anomaly_detector.detect_anomaly(features)
                    if is_anomaly:
                        alert = {
                            'rule_name': 'Anomaly Detection',
                            'description': f'Anomalous traffic detected (score: {score:.3f})',
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'high',
                            'packet_info': self.rule_engine._extract_packet_info(packet)
                        }
                        self.handle_alert(alert)
                        
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            
    def update_traffic_stats(self, packet):
        """Update traffic statistics"""
        current_time = time.time()
        self.packet_times.append(current_time)
        
        # Update packet and byte rates
        if len(self.packet_times) > 1:
            time_diff = self.packet_times[-1] - self.packet_times[0]
            if time_diff > 0:
                self.traffic_stats['packet_rate'] = len(self.packet_times) / time_diff
                self.traffic_stats['byte_rate'] = sum(len(p) for p in self.packet_times) / time_diff
                
        # Update protocol counts
        if TCP in packet:
            self.protocol_counts['TCP'] += 1
        elif UDP in packet:
            self.protocol_counts['UDP'] += 1
        elif ICMP in packet:
            self.protocol_counts['ICMP'] += 1
            
        self.traffic_stats['protocol_counts'] = dict(self.protocol_counts)
        
        # Update port access tracking
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            self.port_access[src_ip].add(dport)
            self.traffic_stats['port_access'] = dict(self.port_access)
            self.traffic_stats['current_src_ip'] = src_ip
            
    def handle_alert(self, alert: Dict):
        """Handle detected alerts"""
        self.alerts.append(alert)
        
        # Log alert
        severity = alert.get('severity', 'medium').upper()
        message = f"[{severity}] {alert['rule_name']}: {alert['description']}"
        
        if severity == 'HIGH':
            logging.error(f"{Fore.RED}{message}{Style.RESET_ALL}")
        elif severity == 'MEDIUM':
            logging.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")
        else:
            logging.info(f"{Fore.CYAN}{message}{Style.RESET_ALL}")
            
        # Additional alert handling can be added here (email, webhook, etc.)
        
    def start(self):
        """Start the NIDS"""
        logging.info("Starting Network Intrusion Detection System...")
        
        # Check network interface
        available_interfaces = get_if_list()
        if self.config['network']['interface'] not in available_interfaces:
            logging.error(f"Network interface {self.config['network']['interface']} not found")
            logging.info(f"Available interfaces: {', '.join(available_interfaces)}")
            return
            
        self.running = True
        
        # Start packet capture
        self.packet_capture.start_capture(self.packet_handler)
        
        logging.info(f"NIDS started on interface {self.config['network']['interface']}")
        logging.info("Monitoring network traffic... (Press Ctrl+C to stop)")
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
                
                # Print statistics periodically
                if int(time.time()) % self.config['performance']['statistics_interval'] == 0:
                    self.print_statistics()
                    
        except KeyboardInterrupt:
            self.stop()
            
    def stop(self):
        """Stop the NIDS"""
        logging.info("Stopping NIDS...")
        self.running = False
        self.packet_capture.stop_capture()
        
        # Save model if trained
        if self.anomaly_detector.is_trained:
            self.anomaly_detector.save_model()
            
        logging.info("NIDS stopped")
        
    def print_statistics(self):
        """Print traffic statistics"""
        stats = {
            'Total Packets': sum(self.protocol_counts.values()),
            'TCP': self.protocol_counts['TCP'],
            'UDP': self.protocol_counts['UDP'],
            'ICMP': self.protocol_counts['ICMP'],
            'Alerts': len(self.alerts),
            'Packet Rate': f"{self.traffic_stats.get('packet_rate', 0):.2f} pps",
            'Byte Rate': f"{self.traffic_stats.get('byte_rate', 0):.2f} Bps"
        }
        
        logging.info(f"Statistics: {stats}")

def main():
    """Main entry point"""
    print(f"{Fore.CYAN}Network Based Intrusion Detection System{Style.RESET_ALL}")
    print("=" * 50)
    
    # Initialize and start NIDS
    nids = NIDS()
    nids.start()

if __name__ == "__main__":
    main()
