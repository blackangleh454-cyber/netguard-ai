#!/usr/bin/env python3
"""
NetGuardAI CLI - Command-line interface for NetGuardAI
"""

import sys
import argparse
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from netguard import NetGuardAI


class CLI:
    def __init__(self):
        self.guard = NetGuardAI()
    
    def status(self, args):
        """Show NetGuardAI status"""
        status = self.guard.get_status()
        
        print(f"""
╔════════════════════════════════════════════╗
║         NetGuardAI STATUS                  ║
╠════════════════════════════════════════════╣
║  Status:        {status['status']:<22}║
║  Uptime:        {status['uptime']:<22}║
║  Firewall:      {status['firewall']:<22}║
║  IDS:           {status['ids']:<22}║
║  Autonomous:    {status['autonomous']:<22}║
╠════════════════════════════════════════════╣
║  Blocked IPs:   {status['blocked_ips']:<22}║
║  Threats:       {status['threats_detected']:<22}║
║  Blocked:       {status['threats_blocked']:<22}║
║  Alerts:        {status['alerts']:<22}║
║  Rules:         {status['rules']:<22}║
╚════════════════════════════════════════════╝
        """)
    
    def block(self, args):
        """Block an IP address"""
        ip = args.ip
        
        if self.guard.block_ip(ip):
            print(f"✓ IP {ip} has been blocked")
        else:
            print(f"✗ Failed to block {ip}")
    
    def unblock(self, args):
        """Unblock an IP address"""
        ip = args.ip
        
        if self.guard.unblock_ip(ip):
            print(f"✓ IP {ip} has been unblocked")
        else:
            print(f"✗ Failed to unblock {ip}")
    
    def blocked_list(self, args):
        """List blocked IPs"""
        ips = self.guard.get_blocked_ips()
        
        if not ips:
            print("No blocked IPs")
            return
        
        print(f"\n{'='*50}")
        print(f"Blocked IPs ({len(ips)} total)")
        print(f"{'='*50}")
        
        for ip in ips:
            print(f"  • {ip}")
        
        print(f"{'='*50}\n")
    
    def logs(self, args):
        """Show recent logs"""
        logs = self.guard.get_logs(args.limit)
        
        if not logs:
            print("No recent logs")
            return
        
        print(f"\n{'='*60}")
        print(f"Recent Events (last {len(logs)})")
        print(f"{'='*60}")
        
        for log in logs[-args.limit:]:
            timestamp = log.get("timestamp", "")[:19]
            msg_type = log.get("type", "UNKNOWN")
            message = log.get("message", "")
            print(f"[{timestamp}] [{msg_type}] {message}")
        
        print(f"{'='*60}\n")
    
    def threats(self, args):
        """Show recent threats"""
        threats = self.guard.get_threats(args.limit)
        
        if not threats:
            print("No recent threats detected")
            return
        
        print(f"\n{'='*70}")
        print(f"Recent Threats (last {len(threats)})")
        print(f"{'='*70}")
        
        for threat in threats[-args.limit:]:
            ts = threat.get("timestamp", "")[:19]
            sev = threat.get("severity", "?")
            t_type = threat.get("type", "unknown")
            src = threat.get("source_ip", "?")
            
            sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            icon = sev_icons.get(sev, "⚪")
            
            print(f"{icon} [{ts}] {sev:8} | {t_type:20} | {src}")
        
        print(f"{'='*70}\n")
    
    def scan(self, args):
        """Scan network"""
        print("Scanning network...")
        devices = self.guard.scan_network()
        
        if not devices:
            print("No devices found")
            return
        
        print(f"\n{'='*60}")
        print(f"Network Devices ({len(devices)} found)")
        print(f"{'='*60}")
        
        for device in devices:
            print(f"  IP: {device.get('ip', 'unknown'):<20} MAC: {device.get('mac', 'N/A')}")
        
        print(f"{'='*60}\n")
    
    def start(self, args):
        """Start NetGuardAI"""
        print("Starting NetGuardAI...")
        if self.guard.initialize():
            print("✓ NetGuardAI started successfully")
            self.guard.start()
        else:
            print("✗ Failed to start NetGuardAI")
    
    def stop(self, args):
        """Stop NetGuardAI"""
        print("Stopping NetGuardAI...")
        self.guard.shutdown()
        print("✓ NetGuardAI stopped")


def main():
    cli = CLI()
    parser = argparse.ArgumentParser(
        description="NetGuardAI - Autonomous Firewall & IDS Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    parser_status = subparsers.add_parser("status", help="Show NetGuardAI status")
    
    parser_block = subparsers.add_parser("block", help="Block an IP address")
    parser_block.add_argument("ip", help="IP address to block")
    
    parser_unblock = subparsers.add_parser("unblock", help="Unblock an IP address")
    parser_unblock.add_argument("ip", help="IP address to unblock")
    
    parser_blocked = subparsers.add_parser("blocked", help="List blocked IPs")
    
    parser_logs = subparsers.add_parser("logs", help="Show recent logs")
    parser_logs.add_argument("-n", "--limit", type=int, default=50, help="Number of logs to show")
    
    parser_threats = subparsers.add_parser("threats", help="Show recent threats")
    parser_threats.add_argument("-n", "--limit", type=int, default=20, help="Number of threats to show")
    
    parser_scan = subparsers.add_parser("scan", help="Scan network for devices")
    
    parser_start = subparsers.add_parser("start", help="Start NetGuardAI")
    
    parser_stop = subparsers.add_parser("stop", help="Stop NetGuardAI")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    commands = {
        "status": cli.status,
        "block": cli.block,
        "unblock": cli.unblock,
        "blocked": cli.blocked_list,
        "logs": cli.logs,
        "threats": cli.threats,
        "scan": cli.scan,
        "start": cli.start,
        "stop": cli.stop
    }
    
    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
