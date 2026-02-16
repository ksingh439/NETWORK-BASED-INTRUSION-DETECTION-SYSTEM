#!/usr/bin/env python3
"""
NIDS Web Dashboard
Real-time monitoring dashboard for Network Intrusion Detection System
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any

try:
    from flask import Flask, render_template, jsonify, request
    from flask_socketio import SocketIO, emit
    import yaml
    import psutil
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Please install requirements: pip install -r requirements.txt")
    exit(1)

class NIDSDashboard:
    """Web dashboard for NIDS monitoring"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config = self.load_config(config_file)
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'nids_dashboard_secret_key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Dashboard data
        self.traffic_data = {
            'timestamps': [],
            'packet_counts': [],
            'alert_counts': [],
            'protocol_distribution': {'TCP': 0, 'UDP': 0, 'ICMP': 0},
            'recent_alerts': [],
            'system_stats': {}
        }
        
        # Setup routes
        self.setup_routes()
        self.setup_socketio_events()
        
        # Start background data collection
        self.running = False
        self.data_thread = None
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {'dashboard': {'host': '127.0.0.1', 'port': 8080}}
            
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('dashboard.html')
            
        @self.app.route('/api/stats')
        def get_stats():
            """API endpoint for current statistics"""
            return jsonify(self.get_current_stats())
            
        @self.app.route('/api/alerts')
        def get_alerts():
            """API endpoint for recent alerts"""
            return jsonify({
                'alerts': self.traffic_data['recent_alerts'][-50:],  # Last 50 alerts
                'total': len(self.traffic_data['recent_alerts'])
            })
            
        @self.app.route('/api/system')
        def get_system_stats():
            """API endpoint for system statistics"""
            return jsonify(self.get_system_statistics())
            
    def setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            print('Client connected to dashboard')
            emit('initial_data', self.get_current_stats())
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            print('Client disconnected from dashboard')
            
    def get_current_stats(self) -> Dict:
        """Get current traffic and alert statistics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'packet_counts': self.traffic_data['packet_counts'][-60:],  # Last 60 data points
            'alert_counts': self.traffic_data['alert_counts'][-60:],
            'timestamps': self.traffic_data['timestamps'][-60:],
            'protocol_distribution': self.traffic_data['protocol_distribution'],
            'total_packets': sum(self.traffic_data['packet_counts']),
            'total_alerts': len(self.traffic_data['recent_alerts']),
            'recent_alerts': self.traffic_data['recent_alerts'][-10:]  # Last 10 alerts
        }
        
    def get_system_statistics(self) -> Dict:
        """Get system resource statistics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Network statistics
            network = psutil.net_io_counters()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'network_bytes_sent': network.bytes_sent,
                'network_bytes_recv': network.bytes_recv,
                'disk_percent': disk.percent,
                'disk_used': disk.used,
                'disk_total': disk.total
            }
        except Exception as e:
            print(f"Error getting system stats: {e}")
            return {}
            
    def update_data(self):
        """Background thread to update dashboard data"""
        while self.running:
            try:
                current_time = datetime.now()
                
                # Simulate traffic data (in real implementation, this would come from NIDS core)
                import random
                packet_count = random.randint(50, 200)
                alert_count = random.randint(0, 5)
                
                # Update time series data
                self.traffic_data['timestamps'].append(current_time.strftime('%H:%M:%S'))
                self.traffic_data['packet_counts'].append(packet_count)
                self.traffic_data['alert_counts'].append(alert_count)
                
                # Keep only last 100 data points
                if len(self.traffic_data['timestamps']) > 100:
                    self.traffic_data['timestamps'] = self.traffic_data['timestamps'][-100:]
                    self.traffic_data['packet_counts'] = self.traffic_data['packet_counts'][-100:]
                    self.traffic_data['alert_counts'] = self.traffic_data['alert_counts'][-100:]
                
                # Update protocol distribution
                self.traffic_data['protocol_distribution']['TCP'] += random.randint(30, 80)
                self.traffic_data['protocol_distribution']['UDP'] += random.randint(10, 40)
                self.traffic_data['protocol_distribution']['ICMP'] += random.randint(0, 10)
                
                # Generate sample alerts
                if alert_count > 0:
                    alert_types = [
                        'Port Scan Detected',
                        'Suspicious Port Access',
                        'Large Data Transfer',
                        'ICMP Flood Attack',
                        'Anomalous Traffic Pattern'
                    ]
                    
                    for i in range(alert_count):
                        alert = {
                            'id': len(self.traffic_data['recent_alerts']) + 1,
                            'timestamp': current_time.isoformat(),
                            'type': random.choice(alert_types),
                            'severity': random.choice(['low', 'medium', 'high']),
                            'source_ip': f"192.168.1.{random.randint(1, 254)}",
                            'description': f"Suspicious activity detected from source IP"
                        }
                        self.traffic_data['recent_alerts'].append(alert)
                
                # Keep only last 200 alerts
                if len(self.traffic_data['recent_alerts']) > 200:
                    self.traffic_data['recent_alerts'] = self.traffic_data['recent_alerts'][-200:]
                
                # Emit real-time updates to connected clients
                self.socketio.emit('data_update', self.get_current_stats())
                
            except Exception as e:
                print(f"Error updating dashboard data: {e}")
                
            time.sleep(5)  # Update every 5 seconds
            
    def start(self):
        """Start the dashboard server"""
        self.running = True
        
        # Start background data collection
        self.data_thread = threading.Thread(target=self.update_data, daemon=True)
        self.data_thread.start()
        
        # Start Flask server
        host = self.config.get('dashboard', {}).get('host', '127.0.0.1')
        port = self.config.get('dashboard', {}).get('port', 8080)
        debug = self.config.get('dashboard', {}).get('debug', False)
        
        print(f"Starting NIDS Dashboard on http://{host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)
        
    def stop(self):
        """Stop the dashboard server"""
        self.running = False
        if self.data_thread:
            self.data_thread.join(timeout=5)

def create_templates():
    """Create HTML templates for the dashboard"""
    templates_dir = "templates"
    os.makedirs(templates_dir, exist_ok=True)
    
    # Dashboard HTML template
    dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            font-size: 1.8rem;
            font-weight: 300;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4CAF50;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .charts-container {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .chart-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .chart-title {
            font-size: 1.2rem;
            margin-bottom: 1rem;
            font-weight: 300;
        }
        
        .alerts-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
            max-height: 400px;
            overflow-y: auto;
        }
        
        .alert-item {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 0.8rem;
            border-left: 4px solid;
            transition: transform 0.2s ease;
        }
        
        .alert-item:hover {
            transform: translateX(5px);
        }
        
        .alert-high {
            border-left-color: #f44336;
        }
        
        .alert-medium {
            border-left-color: #ff9800;
        }
        
        .alert-low {
            border-left-color: #4CAF50;
        }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .alert-type {
            font-weight: bold;
        }
        
        .alert-time {
            font-size: 0.8rem;
            opacity: 0.7;
        }
        
        .alert-details {
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .connection-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.7);
            padding: 0.8rem 1.2rem;
            border-radius: 25px;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .connection-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #4CAF50;
        }
        
        .connection-dot.disconnected {
            background: #f44336;
        }
        
        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.3);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.5);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Network Intrusion Detection System</h1>
        <div class="status-indicator">
            <div class="status-dot"></div>
            <span>System Active</span>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="totalPackets">0</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalAlerts">0</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="packetRate">0</div>
                <div class="stat-label">Packet Rate (pps)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="alertRate">0</div>
                <div class="stat-label">Alert Rate (/min)</div>
            </div>
        </div>
        
        <div class="charts-container">
            <div class="chart-card">
                <h3 class="chart-title">Traffic Overview</h3>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">Protocol Distribution</h3>
                <canvas id="protocolChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-container">
            <h3 class="chart-title">Recent Alerts</h3>
            <div id="alertsList"></div>
        </div>
    </div>
    
    <div class="connection-status">
        <div class="connection-dot" id="connectionDot"></div>
        <span id="connectionStatus">Connected</span>
    </div>
    
    <script>
        // Initialize Socket.IO connection
        const socket = io();
        
        // Chart configurations
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        const protocolCtx = document.getElementById('protocolChart').getContext('2d');
        
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    borderColor: '#4CAF50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Alerts',
                    data: [],
                    borderColor: '#f44336',
                    backgroundColor: 'rgba(244, 67, 54, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#fff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    y: {
                        ticks: { color: '#fff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                }
            }
        });
        
        const protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#2196F3', '#FF9800', '#9C27B0']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                }
            }
        });
        
        // Socket.IO event handlers
        socket.on('connect', () => {
            updateConnectionStatus(true);
        });
        
        socket.on('disconnect', () => {
            updateConnectionStatus(false);
        });
        
        socket.on('initial_data', (data) => {
            updateDashboard(data);
        });
        
        socket.on('data_update', (data) => {
            updateDashboard(data);
        });
        
        function updateDashboard(data) {
            // Update statistics
            document.getElementById('totalPackets').textContent = data.total_packets || 0;
            document.getElementById('totalAlerts').textContent = data.total_alerts || 0;
            
            // Calculate rates
            const packetRate = data.packet_counts.length > 0 ? 
                data.packet_counts.reduce((a, b) => a + b, 0) / data.packet_counts.length : 0;
            const alertRate = data.alert_counts.length > 0 ? 
                data.alert_counts.reduce((a, b) => a + b, 0) : 0;
            
            document.getElementById('packetRate').textContent = Math.round(packetRate);
            document.getElementById('alertRate').textContent = alertRate;
            
            // Update traffic chart
            trafficChart.data.labels = data.timestamps || [];
            trafficChart.data.datasets[0].data = data.packet_counts || [];
            trafficChart.data.datasets[1].data = data.alert_counts || [];
            trafficChart.update();
            
            // Update protocol chart
            if (data.protocol_distribution) {
                protocolChart.data.datasets[0].data = [
                    data.protocol_distribution.TCP || 0,
                    data.protocol_distribution.UDP || 0,
                    data.protocol_distribution.ICMP || 0
                ];
                protocolChart.update();
            }
            
            // Update alerts list
            updateAlertsList(data.recent_alerts || []);
        }
        
        function updateAlertsList(alerts) {
            const alertsList = document.getElementById('alertsList');
            alertsList.innerHTML = '';
            
            alerts.slice().reverse().forEach(alert => {
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item alert-${alert.severity}`;
                
                const time = new Date(alert.timestamp).toLocaleTimeString();
                
                alertDiv.innerHTML = `
                    <div class="alert-header">
                        <span class="alert-type">${alert.type}</span>
                        <span class="alert-time">${time}</span>
                    </div>
                    <div class="alert-details">
                        ${alert.description} - Source: ${alert.source_ip}
                    </div>
                `;
                
                alertsList.appendChild(alertDiv);
            });
        }
        
        function updateConnectionStatus(connected) {
            const dot = document.getElementById('connectionDot');
            const status = document.getElementById('connectionStatus');
            
            if (connected) {
                dot.classList.remove('disconnected');
                status.textContent = 'Connected';
            } else {
                dot.classList.add('disconnected');
                status.textContent = 'Disconnected';
            }
        }
        
        // Fetch initial data
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => updateDashboard(data))
            .catch(error => console.error('Error fetching initial data:', error));
    </script>
</body>
</html>"""
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
        f.write(dashboard_html)
    
    print(f"Created dashboard template in {templates_dir}/")

def main():
    """Main entry point for dashboard"""
    # Create templates directory and HTML file
    create_templates()
    
    # Initialize and start dashboard
    dashboard = NIDSDashboard()
    
    try:
        dashboard.start()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        dashboard.stop()

if __name__ == "__main__":
    main()
