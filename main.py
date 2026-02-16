#!/usr/bin/env python3
"""
Network Based Intrusion Detection System - Main Entry Point
Main launcher for the NIDS with command-line interface
"""

import os
import sys
import argparse
import signal
import threading
import time
from typing import Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nids_core import NIDS
from dashboard import NIDSDashboard
from utils import (
    get_network_interfaces, check_admin_privileges, validate_config,
    create_log_directory, get_system_info, format_bytes
)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal, stopping NIDS...")
    if 'nids_instance' in globals():
        nids_instance.stop()
    if 'dashboard_instance' in globals():
        dashboard_instance.stop()
    sys.exit(0)

def list_interfaces():
    """List available network interfaces"""
    print("Available Network Interfaces:")
    print("=" * 50)
    
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No interfaces found. Make sure you have the necessary permissions.")
        return
    
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface['name']}")
        print(f"   IP Address: {iface['ip']}")
        print(f"   MAC Address: {iface['mac']}")
        print()

def check_requirements():
    """Check if system meets requirements"""
    print("System Requirements Check:")
    print("=" * 30)
    
    # Check admin privileges
    if check_admin_privileges():
        print("[OK] Running with administrative privileges")
    else:
        print("[WARNING] Not running with administrative privileges")
        print("  Some features may not work correctly.")
        print("  Consider running with sudo/administrator privileges.")
    
    # Check network interfaces
    interfaces = get_network_interfaces()
    if interfaces:
        print(f"[OK] Found {len(interfaces)} network interface(s)")
    else:
        print("[ERROR] No network interfaces found")
    
    # Check required directories
    if create_log_directory():
        print("[OK] Log directory accessible")
    else:
        print("[ERROR] Cannot create log directory")
    
    # Display system info
    sys_info = get_system_info()
    print(f"[OK] System: {sys_info['platform']} {sys_info['platform_release']}")
    print(f"[OK] CPU: {sys_info['cpu_count']} cores")
    if 'memory_total' in sys_info:
        print(f"[OK] Memory: {format_bytes(sys_info['memory_total'])}")
    
    print()

def validate_configuration(config_file: str) -> bool:
    """Validate NIDS configuration"""
    try:
        import yaml
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        is_valid, errors = validate_config(config)
        
        if is_valid:
            print("[OK] Configuration is valid")
            return True
        else:
            print("[ERROR] Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False
    except FileNotFoundError:
        print(f"[ERROR] Configuration file not found: {config_file}")
        return False
    except Exception as e:
        print(f"[ERROR] Error reading configuration: {e}")
        return False

def start_nids(config_file: str, interface: Optional[str] = None):
    """Start the NIDS core engine"""
    global nids_instance
    
    print("Starting Network Intrusion Detection System...")
    print("=" * 50)
    
    # Load and validate configuration
    if not validate_configuration(config_file):
        return
    
    try:
        # Initialize NIDS
        nids_instance = NIDS(config_file)
        
        # Override interface if specified
        if interface:
            nids_instance.config['network']['interface'] = interface
        
        # Start NIDS
        nids_instance.start()
        
    except KeyboardInterrupt:
        print("\nStopping NIDS...")
        if 'nids_instance' in globals():
            nids_instance.stop()
    except Exception as e:
        print(f"Error starting NIDS: {e}")
        sys.exit(1)

def start_dashboard(config_file: str):
    """Start the web dashboard"""
    global dashboard_instance
    
    print("Starting NIDS Dashboard...")
    print("=" * 30)
    
    try:
        # Initialize dashboard
        dashboard_instance = NIDSDashboard(config_file)
        
        # Start dashboard
        dashboard_instance.start()
        
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        if 'dashboard_instance' in globals():
            dashboard_instance.stop()
    except Exception as e:
        print(f"Error starting dashboard: {e}")
        sys.exit(1)

def start_full_system(config_file: str, interface: Optional[str] = None):
    """Start both NIDS core and dashboard"""
    global nids_instance, dashboard_instance
    
    print("Starting Full NIDS System...")
    print("=" * 40)
    
    # Validate configuration
    if not validate_configuration(config_file):
        return
    
    try:
        # Start NIDS in background thread
        nids_instance = NIDS(config_file)
        if interface:
            nids_instance.config['network']['interface'] = interface
        
        nids_thread = threading.Thread(target=nids_instance.start, daemon=True)
        nids_thread.start()
        
        # Give NIDS time to initialize
        time.sleep(2)
        
        # Start dashboard in main thread
        dashboard_instance = NIDSDashboard(config_file)
        dashboard_instance.start()
        
    except KeyboardInterrupt:
        print("\nStopping full system...")
        if 'nids_instance' in globals():
            nids_instance.stop()
        if 'dashboard_instance' in globals():
            dashboard_instance.stop()
    except Exception as e:
        print(f"Error starting system: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Based Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --check                    # Check system requirements
  %(prog)s --list-interfaces          # List network interfaces
  %(prog)s --nids                     # Start NIDS core only
  %(prog)s --dashboard                # Start web dashboard only
  %(prog)s --full                     # Start full system (NIDS + dashboard)
  %(prog)s --nids --interface eth0    # Start NIDS on specific interface
  %(prog)s --config custom.yaml       # Use custom configuration
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--interface', '-i',
        help='Network interface to monitor'
    )
    
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check system requirements and permissions'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces'
    )
    
    parser.add_argument(
        '--nids',
        action='store_true',
        help='Start NIDS core engine only'
    )
    
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Start web dashboard only'
    )
    
    parser.add_argument(
        '--full',
        action='store_true',
        help='Start full system (NIDS + dashboard)'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='NIDS v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Print banner
    print("=" * 60)
    print("      Network Based Intrusion Detection System")
    print("                     Version 1.0.0")
    print("=" * 60)
    print()
    
    # Handle commands
    if args.check:
        check_requirements()
    elif args.list_interfaces:
        list_interfaces()
    elif args.nids:
        start_nids(args.config, args.interface)
    elif args.dashboard:
        start_dashboard(args.config)
    elif args.full:
        start_full_system(args.config, args.interface)
    else:
        # Show help if no action specified
        parser.print_help()
        print("\nQuick Start:")
        print("  python main.py --check          # Check system requirements")
        print("  python main.py --list-interfaces # List network interfaces")
        print("  python main.py --full            # Start full system")
        print("  python main.py --nids --interface eth0  # Start NIDS on eth0")

if __name__ == "__main__":
    main()
