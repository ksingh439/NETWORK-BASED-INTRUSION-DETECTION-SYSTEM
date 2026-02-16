# Installation Guide

This guide provides detailed installation instructions for the Network Intrusion Detection System (NIDS).

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+, CentOS 7+)
- **Python**: 3.7 or higher
- **RAM**: 2GB minimum
- **Storage**: 1GB free space
- **Network**: Administrative/root privileges for packet capture

### Recommended Requirements
- **Operating System**: Linux (Ubuntu 20.04+ or CentOS 8+)
- **Python**: 3.9 or higher
- **RAM**: 4GB or more
- **Storage**: 5GB free space
- **CPU**: 4+ cores for optimal performance
- **Network**: Dedicated network interface for monitoring

## Prerequisites Installation

### Windows

#### 1. Install Python
```powershell
# Download Python from https://www.python.org/downloads/
# or use Chocolatey
choco install python3

# Verify installation
python --version
pip --version
```

#### 2. Install Microsoft Visual C++ Build Tools
```powershell
# Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
# or use Chocolatey
choco install visualstudio2019buildtools
```

#### 3. Install Npcap (for packet capture)
```powershell
# Download from https://npcap.com/
# Install with "Install Npcap in WinPcap API-compatible Mode"
```

#### 4. Install Git (optional)
```powershell
# Download from https://git-scm.com/
# or use Chocolatey
choco install git
```

### macOS

#### 1. Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Install Python
```bash
# Install Python 3
brew install python3

# Verify installation
python3 --version
pip3 --version
```

#### 3. Install Xcode Command Line Tools
```bash
xcode-select --install
```

#### 4. Install libpcap
```bash
brew install libpcap
```

### Linux (Ubuntu/Debian)

#### 1. Update System Packages
```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Install Python and Development Tools
```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip python3-dev -y

# Install build tools
sudo apt install build-essential -y

# Install libpcap development headers
sudo apt install libpcap-dev -y

# Verify installation
python3 --version
pip3 --version
```

#### 3. Install Additional Dependencies
```bash
# Install system dependencies
sudo apt install tcpdump wireshark-common -y

# Add user to wireshark group for packet capture permissions
sudo usermod -a -G wireshark $USER
newgrp wireshark
```

### Linux (CentOS/RHEL/Fedora)

#### 1. Update System Packages
```bash
# For CentOS/RHEL
sudo yum update -y

# For Fedora
sudo dnf update -y
```

#### 2. Install Python and Development Tools
```bash
# For CentOS/RHEL
sudo yum install python3 python3-pip python3-devel -y
sudo yum groupinstall "Development Tools" -y

# For Fedora
sudo dnf install python3 python3-pip python3-devel -y
sudo dnf groupinstall "Development Tools" -y
```

#### 3. Install libpcap
```bash
# For CentOS/RHEL
sudo yum install libpcap-devel -y

# For Fedora
sudo dnf install libpcap-devel -y
```

## NIDS Installation

### Method 1: Direct Download

1. **Download the NIDS files**
   ```bash
   # Create installation directory
   mkdir ~/nids
   cd ~/nids
   
   # Download and extract (replace with actual download method)
   # If you have the files, copy them to this directory
   ```

2. **Install Python Dependencies**
   ```bash
   # Install requirements
   pip install -r requirements.txt
   
   # Or install with user permissions
   pip install --user -r requirements.txt
   ```

### Method 2: Git Clone (if available)

```bash
# Clone the repository
git clone <repository-url> nids
cd nids

# Install dependencies
pip install -r requirements.txt
```

### Method 3: Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv nids_env

# Activate virtual environment
# On Linux/macOS:
source nids_env/bin/activate
# On Windows:
nids_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

## Post-Installation Configuration

### 1. Create Required Directories

```bash
# Create logs directory
mkdir -p logs

# Create models directory for ML models
mkdir -p models

# Create backups directory
mkdir -p backups

# Set appropriate permissions
chmod 755 logs models backups
```

### 2. Verify Installation

```bash
# Check system requirements
python main.py --check

# List available network interfaces
python main.py --list-interfaces
```

### 3. Configuration Setup

```bash
# Copy default configuration if needed
cp config.yaml config_backup.yaml

# Edit configuration for your environment
nano config.yaml  # or use your preferred editor
```

### 4. Test Installation

```bash
# Start NIDS in test mode
python main.py --nids

# In another terminal, test dashboard
python main.py --dashboard
```

## Platform-Specific Notes

### Windows

#### Running as Administrator
```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Navigate to NIDS directory
cd C:\path\to\nids

# Run with elevated privileges
python main.py --full
```

#### Firewall Configuration
```powershell
# Allow Python through Windows Firewall
New-NetFirewallRule -DisplayName "NIDS" -Direction Inbound -Program "python.exe" -Action Allow
```

### macOS

#### Granting Permissions
1. **Security & Privacy**: Allow terminal/applications to monitor network
2. **Full Disk Access**: Add terminal or Python to Full Disk Access list
3. **Network Monitoring**: Grant permission for packet capture

#### Using sudo
```bash
# Run with sudo for packet capture
sudo python main.py --full
```

### Linux

#### Permissions Setup
```bash
# Method 1: Run with sudo
sudo python main.py --full

# Method 2: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Method 3: Add user to specific groups
sudo usermod -a -G wireshark $USER
```

#### systemd Service (Optional)
```bash
# Create service file
sudo nano /etc/systemd/system/nids.service
```

Service file content:
```ini
[Unit]
Description=Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=nids
WorkingDirectory=/opt/nids
ExecStart=/opt/nids/nids_env/bin/python main.py --full
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nids
sudo systemctl start nids
sudo systemctl status nids
```

## Troubleshooting Installation

### Common Issues

#### 1. Permission Denied Errors
```bash
# Linux/macOS
sudo python main.py --check

# Windows
# Run PowerShell/CMD as Administrator
```

#### 2. Missing Dependencies
```bash
# Reinstall all dependencies
pip install -r requirements.txt --upgrade --force-reinstall

# Install specific packages
pip install scapy numpy pandas scikit-learn flask flask-socketio
```

#### 3. Network Interface Issues
```bash
# Check available interfaces
python main.py --list-interfaces

# Update config.yaml with correct interface
nano config.yaml
```

#### 4. Port Already in Use
```bash
# Find process using port 8080
# Linux/macOS
lsof -i :8080
# Windows
netstat -ano | findstr :8080

# Kill process or change port in config.yaml
```

#### 5. Python Path Issues
```bash
# Check Python path
which python3
python3 -c "import sys; print(sys.path)"

# Use full path to Python
/usr/bin/python3 main.py --check
```

### Verification Steps

1. **Check Python Installation**
   ```bash
   python --version
   pip --version
   ```

2. **Verify Dependencies**
   ```bash
   pip list | grep -E "(scapy|numpy|pandas|flask)"
   ```

3. **Test Packet Capture**
   ```bash
   python -c "from scapy.all import sniff; print('Scapy working')"
   ```

4. **Test Configuration**
   ```bash
   python main.py --check
   ```

5. **Test Dashboard**
   ```bash
   python main.py --dashboard
   # Then open http://127.0.0.1:8080 in browser
   ```

## Performance Optimization

### System-Level Optimizations

#### Linux
```bash
# Increase network buffer sizes
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

#### Windows
```powershell
# Set power plan to High Performance
powercfg /setactive SCHEME_MIN

# Disable Windows Defender real-time protection (temporary)
Set-MpPreference -DisableRealtimeMonitoring $true
```

### NIDS Configuration Optimizations

Edit `config.yaml`:
```yaml
# For high-traffic environments
network:
  buffer_size: 131072
  
performance:
  packet_buffer_size: 2000
  processing_threads: 8
  
logging:
  level: "WARNING"  # Reduce log overhead
```

## Security Considerations

### 1. File Permissions
```bash
# Secure NIDS files
chmod 750 main.py nids_core.py dashboard.py utils.py
chmod 640 config.yaml
chmod 755 logs models backups
```

### 2. Network Isolation
- Run NIDS on dedicated monitoring interface
- Use firewall rules to restrict dashboard access
- Consider running in container or VM

### 3. Log Security
```bash
# Encrypt log files
openssl enc -aes-256-cbc -salt -in logs/nids.log -out logs/nids.log.enc

# Set log rotation
logrotate -f /etc/logrotate.d/nids
```

## Next Steps

After successful installation:

1. **Read the User Guide**: Check `USAGE_EXAMPLES.md` for practical examples
2. **Configure Rules**: Customize detection rules in `rules/detection_rules.yaml`
3. **Set Up Monitoring**: Configure the dashboard for your needs
4. **Test Detection**: Use test traffic to verify detection capabilities
5. **Deploy**: Deploy in your production environment

## Support

If you encounter issues during installation:

1. Check the troubleshooting section above
2. Review system logs for error messages
3. Verify all prerequisites are installed
4. Ensure you have proper permissions
5. Consult the main README.md for additional information

---

**Note**: This NIDS is designed for educational and research purposes. For production environments, consider additional security measures and professional security solutions.
