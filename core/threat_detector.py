"""
Threat Detector - AI-powered threat detection and analysis
"""

import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


class ThreatDetector:
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.threat_history = []
        self.ip_tracker = defaultdict(list)
        self.anomaly_scores = defaultdict(float)
        
        self.baseline_normal = {
            "requests_per_minute": 60,
            "failed_auth_per_ip": 3,
            "unique_ports": 20,
            "packet_size_avg": 512
        }
        
        self.lock = threading.Lock()
    
    def _load_threat_patterns(self) -> Dict:
        """Load known threat patterns"""
        return {
            "port_scan": {
                "pattern": r"(?i)(scan|port.*\d+|sweep)",
                "severity": "HIGH",
                "threshold": 10
            },
            "brute_force": {
                "pattern": r"(?i)(fail|denied|invalid|wrong.*password|auth.*fail)",
                "severity": "HIGH",
                "threshold": 5
            },
            "sql_injection": {
                "pattern": r"(?i)(union.*select|or\s+1\s*=\s*1|drop\s+table|';\s*--)",
                "severity": "CRITICAL",
                "threshold": 1
            },
            "xss": {
                "pattern": r"(?i)(<script|javascript:|onerror=|onload=)",
                "severity": "HIGH",
                "threshold": 1
            },
            "dos": {
                "pattern": r"(?i)(flood|too\s+many|syn\s+flood|ddos)",
                "severity": "CRITICAL",
                "threshold": 50
            },
            "malware": {
                "pattern": r"(?i)(malware|virus|trojan|backdoor|exploit|payload)",
                "severity": "CRITICAL",
                "threshold": 1
            },
            "phishing": {
                "pattern": r"(?i)(phish|fake.*login|credential.*harvest)",
                "severity": "HIGH",
                "threshold": 1
            },
            "recon": {
                "pattern": r"(?i)(nmap|masscan|nikto|gobuster|dirb|amass)",
                "severity": "MEDIUM",
                "threshold": 3
            }
        }
    
    def scan(self) -> List[Dict]:
        """Scan for threats across all sources"""
        threats = []
        
        threats.extend(self._scan_iptables_logs())
        threats.extend(self._scan_auth_logs())
        threats.extend(self._scan_network_traffic())
        threats.extend(self._detect_anomalies())
        
        with self.lock:
            for threat in threats:
                self._record_threat(threat)
        
        return threats
    
    def _scan_iptables_logs(self) -> List[Dict]:
        """Scan iptables logs for threats"""
        threats = []
        
        try:
            import subprocess
            result = subprocess.run(
                ["sudo", "tail", "-n", "100", "/var/log/kern.log"],
                capture_output=True, text=True, timeout=5
            )
            
            for line in result.stdout.split("\n"):
                if "NetGuard" in line or "iptables" in line.lower():
                    threat = self._analyze_log_line(line)
                    if threat:
                        threats.append(threat)
                        
        except Exception as e:
            logger.debug(f"iptables log scan: {e}")
        
        return threats
    
    def _scan_auth_logs(self) -> List[Dict]:
        """Scan authentication logs for brute force"""
        threats = []
        
        try:
            import subprocess
            
            log_files = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog"
            ]
            
            for log_file in log_files:
                try:
                    result = subprocess.run(
                        ["sudo", "tail", "-n", "100", log_file],
                        capture_output=True, text=True, timeout=5
                    )
                    
                    for line in result.stdout.split("\n"):
                        if any(x in line.lower() for x in ["failed", "invalid", "denied", "break-in"]):
                            threat = self._analyze_auth_log(line)
                            if threat:
                                threats.append(threat)
                                
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"auth log scan: {e}")
        
        return threats
    
    def _scan_network_traffic(self) -> List[Dict]:
        """Scan network traffic for anomalies"""
        threats = []
        
        try:
            import subprocess
            result = subprocess.run(
                ["ss", "-tunap", "state", "established"],
                capture_output=True, text=True, timeout=5
            )
            
            connections = []
            for line in result.stdout.split("\n")[1:]:
                if line.strip():
                    conn = self._parse_connection(line)
                    if conn:
                        connections.append(conn)
            
            threats.extend(self._detect_connection_anomalies(connections))
            
        except Exception as e:
            logger.debug(f"network scan: {e}")
        
        return threats
    
    def _parse_connection(self, line: str) -> Optional[Dict]:
        """Parse ss connection line"""
        try:
            parts = line.split()
            if len(parts) < 5:
                return None
            
            return {
                "proto": parts[0],
                "local": parts[4],
                "peer": parts[5] if len(parts) > 5 else "N/A"
            }
        except:
            return None
    
    def _detect_connection_anomalies(self, connections: List[Dict]) -> List[Dict]:
        """Detect anomalies in connection patterns"""
        threats = []
        
        ip_ports = defaultdict(list)
        for conn in connections:
            if ":" in conn.get("peer", ""):
                ip = conn["peer"].split(":")[0]
                ip_ports[ip].append(conn)
        
        for ip, conns in ip_ports.items():
            if len(conns) > 50:
                threats.append({
                    "type": "high_connection_volume",
                    "source_ip": ip,
                    "severity": "MEDIUM",
                    "description": f"Unusual connection count: {len(conns)}",
                    "timestamp": datetime.now().isoformat()
                })
        
        return threats
    
    def _detect_anomalies(self) -> List[Dict]:
        """Detect anomalies using baseline comparison"""
        threats = []
        
        try:
            import subprocess
            
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, timeout=5
            )
            
            lines = result.stdout.split("\n")
            established = [l for l in lines if "ESTABLISHED" in l]
            time_wait = [l for l in lines if "TIME_WAIT" in l]
            
            if len(time_wait) > len(established) * 3:
                threats.append({
                    "type": "connection_anomaly",
                    "severity": "MEDIUM",
                    "description": "Unusual TIME_WAIT connections (possible SYN flood)",
                    "timestamp": datetime.now().isoformat()
                })
                
        except Exception as e:
            logger.debug(f"anomaly detection: {e}")
        
        return threats
    
    def _analyze_log_line(self, line: str) -> Optional[Dict]:
        """Analyze a log line for threats"""
        for threat_type, config in self.threat_patterns.items():
            if re.search(config["pattern"], line):
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                source_ip = ip_match.group(0) if ip_match else "unknown"
                
                return {
                    "type": threat_type,
                    "source_ip": source_ip,
                    "severity": config["severity"],
                    "description": f"Detected {threat_type} pattern",
                    "log_line": line[:200],
                    "timestamp": datetime.now().isoformat()
                }
        
        return None
    
    def _analyze_auth_log(self, line: str) -> Optional[Dict]:
        """Analyze authentication log for threats"""
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        source_ip = ip_match.group(0) if ip_match else "unknown"
        
        if "failed" in line.lower() or "invalid" in line.lower():
            with self.lock:
                self.ip_tracker[source_ip].append(datetime.now())
                
                recent = [
                    t for t in self.ip_tracker[source_ip]
                    if datetime.now() - t < timedelta(minutes=5)
                ]
                self.ip_tracker[source_ip] = recent
                
                if len(recent) >= 5:
                    return {
                        "type": "brute_force",
                        "source_ip": source_ip,
                        "severity": "HIGH",
                        "description": f"Multiple failed logins: {len(recent)} attempts",
                        "timestamp": datetime.now().isoformat()
                    }
        
        return None
    
    def _record_threat(self, threat: Dict):
        """Record threat in history"""
        self.threat_history.append(threat)
        
        if len(self.threat_history) > 1000:
            self.threat_history = self.threat_history[-500:]
        
        ip = threat.get("source_ip", "unknown")
        if ip != "unknown":
            self.anomaly_scores[ip] += self._severity_weight(threat.get("severity", "MEDIUM"))
    
    def _severity_weight(self, severity: str) -> float:
        """Get weight for severity level"""
        weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 1.0}
        return weights.get(severity, 1.0)
    
    def get_ip_threat_score(self, ip: str) -> float:
        """Get threat score for an IP"""
        return self.anomaly_scores.get(ip, 0.0)
    
    def get_threat_history(self, limit: int = 100) -> List[Dict]:
        """Get recent threat history"""
        return self.threat_history[-limit:]
    
    def get_top_threat_ips(self, limit: int = 10) -> List[Dict]:
        """Get IPs with highest threat scores"""
        sorted_ips = sorted(
            self.anomaly_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"ip": ip, "score": score}
            for ip, score in sorted_ips[:limit]
        ]
    
    def should_block(self, ip: str, threshold: float = 20.0) -> bool:
        """Determine if an IP should be blocked"""
        return self.anomaly_scores.get(ip, 0.0) >= threshold
    
    def clear_ip_score(self, ip: str):
        """Clear threat score for an IP"""
        with self.lock:
            if ip in self.anomaly_scores:
                del self.anomaly_scores[ip]
            if ip in self.ip_tracker:
                del self.ip_tracker[ip]
