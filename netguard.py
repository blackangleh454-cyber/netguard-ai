#!/usr/bin/env python3
"""
NetGuardAI - Autonomous Firewall & IDS Manager
Author: Mirza Muhammad Usman
Description: AI-powered network security manager using Snort IDS and iptables/nftables
"""

import os
import sys
import json
import time
import threading
import subprocess
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.firewall_manager import FirewallManager
from core.snort_controller import SnortController
from core.threat_detector import ThreatDetector
from core.autonomous_engine import AutonomousEngine
from core.rule_generator import RuleGenerator
from core.logger import SecurityLogger
from utils.config import Config
from utils.network_scanner import NetworkScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetGuardAI:
    def __init__(self):
        self.config = Config()
        self.firewall = FirewallManager()
        self.snort = SnortController()
        self.threat_detector = ThreatDetector()
        self.autonomous_engine = AutonomousEngine()
        self.rule_generator = RuleGenerator()
        self.security_logger = SecurityLogger()
        self.network_scanner = NetworkScanner()
        
        self.running = False
        self.threat_count = 0
        self.blocked_ips = set()
        self.stats = {
            "start_time": None,
            "threats_detected": 0,
            "threats_blocked": 0,
            "alerts_generated": 0,
            "rules_created": 0
        }
        
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check if required tools are installed"""
        required = ["iptables", "snort", "tcpdump"]
        missing = []
        
        for tool in required:
            try:
                subprocess.run(["which", tool], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                missing.append(tool)
        
        if missing:
            logger.warning(f"Missing tools: {', '.join(missing)}")
            logger.info("Install with: sudo apt install iptables snort tcpdump")
    
    def _check_permissions(self):
        """Verify root/sudo privileges"""
        if os.geteuid() != 0:
            logger.error("NetGuardAI requires root privileges!")
            logger.info("Run with: sudo python3 netguard.py")
            return False
        return True
    
    def initialize(self):
        """Initialize all NetGuardAI systems"""
        if not self._check_permissions():
            return False
        
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗             ║
║     ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝             ║
║     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗             ║
║     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║             ║
║     ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║             ║
║     ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝             ║
║                                                              ║
║     🔒 Autonomous Firewall & IDS Manager                      ║
║     🛡️ Powered by Snort + AI Threat Detection               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        logger.info("Initializing NetGuardAI...")
        
        try:
            self.firewall.initialize()
            logger.info("✓ Firewall Manager initialized")
            
            self.snort.initialize()
            logger.info("✓ Snort IDS initialized")
            
            self.autonomous_engine.initialize()
            logger.info("✓ Autonomous Engine initialized")
            
            self.stats["start_time"] = datetime.now().isoformat()
            self.security_logger.log_event("SYSTEM", "NetGuardAI started")
            
            logger.info("\n✅ All systems online!")
            logger.info(f"   • Firewall: ACTIVE")
            logger.info(f"   • IDS: ACTIVE")
            logger.info(f"   • Autonomous Mode: ENABLED")
            
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    def start(self):
        """Start NetGuardAI main loop"""
        if not self.initialize():
            return
        
        self.running = True
        
        threat_thread = threading.Thread(target=self._threat_monitor, daemon=True)
        threat_thread.start()
        
        autonomous_thread = threading.Thread(target=self._autonomous_loop, daemon=True)
        autonomous_thread.start()
        
        logger.info("\n🛡️ NetGuardAI is now protecting your network...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()
    
    def _threat_monitor(self):
        """Monitor for threats continuously"""
        while self.running:
            try:
                threats = self.threat_detector.scan()
                
                for threat in threats:
                    self.stats["threats_detected"] += 1
                    self.threat_count += 1
                    
                    severity = threat.get("severity", "MEDIUM")
                    source_ip = threat.get("source_ip", "unknown")
                    
                    self.security_logger.log_threat(threat)
                    
                    if self.autonomous_engine.should_block(severity):
                        self._block_threat(source_ip, threat)
                    
                    self._generate_alert(threat)
                    
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")
            
            time.sleep(5)
    
    def _autonomous_loop(self):
        """Autonomous security operations"""
        while self.running:
            try:
                self.autonomous_engine.analyze()
                
                new_rules = self.autonomous_engine.suggest_rules()
                for rule in new_rules:
                    self.firewall.add_rule(rule)
                    self.stats["rules_created"] += 1
                
                self.autonomous_engine.cleanup_old_blocks(self.blocked_ips)
                
            except Exception as e:
                logger.error(f"Autonomous loop error: {e}")
            
            time.sleep(60)
    
    def _block_threat(self, ip, threat):
        """Block a malicious IP"""
        if ip in self.blocked_ips:
            return
        
        try:
            self.firewall.block_ip(ip)
            self.blocked_ips.add(ip)
            self.stats["threats_blocked"] += 1
            self.security_logger.log_block(ip, threat)
            logger.warning(f"🚫 Blocked malicious IP: {ip}")
        except Exception as e:
            logger.error(f"Failed to block {ip}: {e}")
    
    def _generate_alert(self, threat):
        """Generate security alert"""
        self.stats["alerts_generated"] += 1
        alert = {
            "timestamp": datetime.now().isoformat(),
            "threat": threat,
            "action": "BLOCKED" if threat.get("blocked") else "DETECTED"
        }
        self.security_logger.log_alert(alert)
    
    def get_status(self):
        """Get current system status"""
        uptime = "N/A"
        if self.stats["start_time"]:
            start = datetime.fromisoformat(self.stats["start_time"])
            delta = datetime.now() - start
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, _ = divmod(remainder, 60)
            uptime = f"{hours}h {minutes}m"
        
        return {
            "status": "PROTECTED" if self.running else "STOPPED",
            "uptime": uptime,
            "firewall": "ACTIVE",
            "ids": "ACTIVE",
            "autonomous": "ENABLED",
            "blocked_ips": len(self.blocked_ips),
            "threats_detected": self.stats["threats_detected"],
            "threats_blocked": self.stats["threats_blocked"],
            "alerts": self.stats["alerts_generated"],
            "rules": self.stats["rules_created"]
        }
    
    def block_ip(self, ip):
        """Manually block an IP"""
        if self._check_permissions():
            self._block_threat(ip, {"type": "manual", "reason": "User requested"})
            return True
        return False
    
    def unblock_ip(self, ip):
        """Manually unblock an IP"""
        if self._check_permissions():
            self.firewall.unblock_ip(ip)
            self.blocked_ips.discard(ip)
            self.security_logger.log_event("UNBLOCK", f"IP {ip} unblocked by user")
            return True
        return False
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def scan_network(self):
        """Scan network for devices"""
        return self.network_scanner.scan()
    
    def get_logs(self, limit=100):
        """Get recent security logs"""
        return self.security_logger.get_recent(limit)
    
    def get_threats(self, limit=50):
        """Get recent threats"""
        return self.security_logger.get_threats(limit)
    
    def shutdown(self):
        """Shutdown NetGuardAI gracefully"""
        logger.info("Shutting down NetGuardAI...")
        self.running = False
        self.autonomous_engine.stop()
        self.snort.stop()
        self.security_logger.log_event("SYSTEM", "NetGuardAI stopped")
        logger.info("✅ NetGuardAI shutdown complete")


def main():
    guard = NetGuardAI()
    guard.start()


if __name__ == "__main__":
    main()
