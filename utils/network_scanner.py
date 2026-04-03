"""
Network Scanner - Network discovery and analysis utilities
"""

import subprocess
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NetworkScanner:
    def __init__(self):
        self.local_ip = self._get_local_ip()
        self.network_range = self._get_network_range()
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            result = subprocess.run(
                ["hostname", "-I"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split()[0]
        except Exception:
            pass
        return "127.0.0.1"
    
    def _get_network_range(self) -> str:
        """Get local network range"""
        if self.local_ip and self.local_ip != "127.0.0.1":
            parts = self.local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"
    
    def scan(self) -> List[Dict]:
        """Scan network for devices"""
        devices = []
        
        devices.extend(self._arp_scan())
        devices.extend(self._ping_scan())
        
        seen = set()
        unique = []
        for d in devices:
            ip = d.get("ip")
            if ip and ip not in seen:
                seen.add(ip)
                unique.append(d)
        
        return unique
    
    def _arp_scan(self) -> List[Dict]:
        """ARP scan for devices"""
        devices = []
        
        try:
            result = subprocess.run(
                ["sudo", "arp", "-a"],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split("\n"):
                if "(" in line and ")" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ip = parts[0].strip("()")
                            mac = parts[3] if len(parts) > 3 else "unknown"
                            
                            if ip != self.local_ip:
                                devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "method": "arp",
                                    "timestamp": datetime.now().isoformat()
                                })
                        except IndexError:
                            continue
                            
        except Exception as e:
            logger.debug(f"ARP scan: {e}")
        
        return devices
    
    def _ping_scan(self) -> List[Dict]:
        """Ping scan for devices"""
        devices = []
        
        try:
            result = subprocess.run(
                ["nmap", "-sn", self.network_range, "-oG", "-"],
                capture_output=True, text=True, timeout=60
            )
            
            for line in result.stdout.split("\n"):
                if "Up" in line and "Host:" in line:
                    parts = line.split()
                    ip = None
                    for i, p in enumerate(parts):
                        if p == "Host:":
                            ip = parts[i + 1]
                            break
                    
                    if ip and ip != self.local_ip:
                        devices.append({
                            "ip": ip,
                            "method": "ping",
                            "timestamp": datetime.now().isoformat()
                        })
                        
        except Exception as e:
            logger.debug(f"Ping scan: {e}")
        
        return devices
    
    def port_scan(self, target: str, ports: str = "1-1000") -> List[Dict]:
        """Scan ports on target"""
        open_ports = []
        
        try:
            result = subprocess.run(
                ["nmap", "-sS", "-p", ports, "--open", target],
                capture_output=True, text=True, timeout=120
            )
            
            for line in result.stdout.split("\n"):
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    for part in parts:
                        if "/tcp" in part or "/udp" in part:
                            port_proto = part.split("/")[0]
                            service = parts[-1] if len(parts) > 1 else "unknown"
                            
                            open_ports.append({
                                "port": int(port_proto),
                                "protocol": "tcp" if "/tcp" in part else "udp",
                                "service": service,
                                "target": target
                            })
                            
        except Exception as e:
            logger.debug(f"Port scan: {e}")
        
        return open_ports
    
    def get_network_info(self) -> Dict:
        """Get network information"""
        info = {
            "local_ip": self.local_ip,
            "network_range": self.network_range,
            "hostname": self._get_hostname(),
            "dns_servers": self._get_dns_servers(),
            "gateway": self._get_gateway()
        }
        
        return info
    
    def _get_hostname(self) -> str:
        """Get hostname"""
        try:
            result = subprocess.run(
                ["hostname"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except:
            return "unknown"
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        dns = []
        
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1:
                            dns.append(parts[1])
        except:
            pass
        
        return dns
    
    def _get_gateway(self) -> str:
        """Get default gateway"""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            
            parts = result.stdout.split()
            if "via" in parts:
                idx = parts.index("via")
                return parts[idx + 1]
                
        except:
            pass
        
        return "unknown"
    
    def check_internet(self) -> bool:
        """Check internet connectivity"""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False
