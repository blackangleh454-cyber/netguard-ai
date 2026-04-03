"""
Firewall Manager - iptables/nftables wrapper for NetGuardAI
"""

import subprocess
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class FirewallManager:
    def __init__(self):
        self.chains = ["INPUT", "OUTPUT", "FORWARD"]
        self.rules_file = "/tmp/netguard_rules.txt"
        self.custom_rules = []
    
    def initialize(self):
        """Initialize firewall with default rules"""
        logger.info("Configuring firewall...")
        
        try:
            self._execute(["iptables", "-F"])
            self._execute(["iptables", "-X"])
            
            self._execute(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            self._execute(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            
            self._execute([
                "iptables", "-A", "INPUT", "-m", "state", 
                "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ])
            
            self._execute([
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
                "-j", "ACCEPT"
            ])
            
            self._execute([
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80",
                "-j", "ACCEPT"
            ])
            
            self._execute([
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443",
                "-j", "ACCEPT"
            ])
            
            self._create_netguard_chain()
            
            self._execute([
                "iptables", "-A", "INPUT", "-j", "NETGUARD"
            ])
            
            self._execute([
                "iptables", "-A", "INPUT", "-j", "LOG", 
                "--log-prefix", "NetGuard: "
            ])
            
            self._execute([
                "iptables", "-A", "INPUT", "-j", "DROP"
            ])
            
            self._save_rules()
            
            logger.info("Firewall initialized with default rules")
            
        except Exception as e:
            logger.error(f"Firewall initialization failed: {e}")
            raise
    
    def _create_netguard_chain(self):
        """Create NETGUARD chain for custom rules"""
        self._execute(["iptables", "-N", "NETGUARD"])
        self._execute(["iptables", "-F", "NETGUARD"])
    
    def _execute(self, cmd: List[str]) -> tuple:
        """Execute iptables command"""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True
            )
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Command failed: {' '.join(cmd)} - {e}")
            return False, "", str(e)
    
    def block_ip(self, ip: str, duration: int = 3600):
        """Block an IP address"""
        success, _, _ = self._execute([
            "iptables", "-A", "NETGUARD",
            "-s", ip, "-j", "DROP"
        ])
        
        if success:
            self.custom_rules.append({
                "ip": ip,
                "action": "DROP",
                "source": "NETGUARD",
                "timestamp": self._get_timestamp()
            })
            logger.info(f"Blocked IP: {ip}")
        
        return success
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        success, _, _ = self._execute([
            "iptables", "-D", "NETGUARD",
            "-s", ip, "-j", "DROP"
        ])
        
        if success:
            self.custom_rules = [r for r in self.custom_rules if r.get("ip") != ip]
            logger.info(f"Unblocked IP: {ip}")
        
        return success
    
    def allow_ip(self, ip: str):
        """Allow an IP through firewall"""
        success, _, _ = self._execute([
            "iptables", "-I", "NETGUARD",
            "-s", ip, "-j", "ACCEPT"
        ])
        
        if success:
            self.custom_rules.append({
                "ip": ip,
                "action": "ACCEPT",
                "source": "NETGUARD",
                "timestamp": self._get_timestamp()
            })
        
        return success
    
    def block_port(self, port: int, protocol: str = "tcp"):
        """Block a port"""
        return self._execute([
            "iptables", "-A", "INPUT",
            "-p", protocol, "--dport", str(port),
            "-j", "DROP"
        ])[0]
    
    def allow_port(self, port: int, protocol: str = "tcp"):
        """Allow a port"""
        return self._execute([
            "iptables", "-A", "INPUT",
            "-p", protocol, "--dport", str(port),
            "-j", "ACCEPT"
        ])[0]
    
    def add_rule(self, rule: Dict):
        """Add custom rule"""
        action = rule.get("action", "DROP").upper()
        src = rule.get("source_ip", "0.0.0.0/0")
        dst = rule.get("dest_ip", "0.0.0.0/0")
        port = rule.get("port")
        protocol = rule.get("protocol", "tcp")
        
        cmd = ["iptables", "-A", "NETGUARD"]
        
        if src != "0.0.0.0/0":
            cmd.extend(["-s", src])
        if dst != "0.0.0.0/0":
            cmd.extend(["-d", dst])
        if port:
            cmd.extend(["-p", protocol, "--dport", str(port)])
        
        cmd.extend(["-j", action])
        
        success, _, _ = self._execute(cmd)
        
        if success:
            self.custom_rules.append({
                **rule,
                "source": "NETGUARD",
                "timestamp": self._get_timestamp()
            })
        
        return success
    
    def remove_rule(self, rule: Dict):
        """Remove custom rule"""
        action = rule.get("action", "DROP").upper()
        src = rule.get("source_ip", "0.0.0.0/0")
        port = rule.get("port")
        protocol = rule.get("protocol", "tcp")
        
        cmd = ["iptables", "-D", "NETGUARD"]
        
        if src != "0.0.0.0/0":
            cmd.extend(["-s", src])
        if port:
            cmd.extend(["-p", protocol, "--dport", str(port)])
        cmd.extend(["-j", action])
        
        return self._execute(cmd)[0]
    
    def get_rules(self) -> List[Dict]:
        """Get current firewall rules"""
        return self.custom_rules.copy()
    
    def get_active_connections(self) -> List[Dict]:
        """Get active network connections"""
        connections = []
        
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split("\n")[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        connections.append({
                            "proto": parts[0],
                            "local": parts[4],
                            "peer": parts[5] if len(parts) > 5 else "N/A"
                        })
        except Exception as e:
            logger.error(f"Failed to get connections: {e}")
        
        return connections
    
    def get_blocked_count(self) -> int:
        """Get count of blocked IPs"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "NETGUARD", "-n", "-v"],
                capture_output=True, text=True
            )
            count = 0
            for line in result.stdout.split("\n"):
                if "DROP" in line:
                    count += 1
            return count
        except:
            return 0
    
    def enable_logging(self):
        """Enable firewall logging"""
        self._execute([
            "iptables", "-A", "NETGUARD",
            "-j", "LOG", "--log-prefix", "NETGUARD-DROP: "
        ])
    
    def disable_logging(self):
        """Disable firewall logging"""
        self._execute([
            "iptables", "-D", "NETGUARD",
            "-j", "LOG", "--log-prefix", "NETGUARD-DROP: "
        ])
    
    def _save_rules(self):
        """Save rules to file for persistence"""
        try:
            with open(self.rules_file, "w") as f:
                subprocess.run(
                    ["iptables-save"],
                    stdout=f, check=True
                )
            logger.info(f"Rules saved to {self.rules_file}")
        except Exception as e:
            logger.error(f"Failed to save rules: {e}")
    
    def restore_rules(self):
        """Restore rules from file"""
        try:
            subprocess.run(
                ["iptables-restore", "<", self.rules_file],
                shell=True, check=True
            )
            logger.info("Rules restored")
        except Exception as e:
            logger.error(f"Failed to restore rules: {e}")
    
    def get_status(self) -> Dict:
        """Get firewall status"""
        return {
            "active": True,
            "chain": "NETGUARD",
            "custom_rules": len(self.custom_rules),
            "blocked_count": self.get_blocked_count()
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
