"""
Autonomous Engine - Self-managing security operations
"""

import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict
from threading import Thread, Event
import json

logger = logging.getLogger(__name__)


class AutonomousEngine:
    def __init__(self):
        self.running = False
        self.autonomous_mode = True
        self.check_interval = 60
        
        self.block_duration = 3600
        self.rate_limit_threshold = 100
        self.scan_threshold = 10
        
        self.blocked_ips = {}
        self.trusted_ips = set([
            "127.0.0.1",
            "::1",
            "localhost"
        ])
        
        self.threat_log = []
        self.action_log = []
        
        self._stop_event = Event()
        self._thread = None
        
        self.severity_rules = {
            "CRITICAL": {"block": True, "duration": 86400},
            "HIGH": {"block": True, "duration": 3600},
            "MEDIUM": {"block": True, "duration": 1800},
            "LOW": {"block": False, "duration": 0}
        }
    
    def initialize(self):
        """Initialize autonomous engine"""
        self.running = True
        self._stop_event.clear()
        
        logger.info("Autonomous Engine initialized")
        self._log_action("ENGINE_START", "Autonomous monitoring enabled")
    
    def start(self, interval: int = 60):
        """Start autonomous monitoring"""
        self.check_interval = interval
        self._thread = Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"Autonomous monitoring started (interval: {interval}s)")
    
    def stop(self):
        """Stop autonomous monitoring"""
        self._stop_event.set()
        self.running = False
        
        if self._thread:
            self._thread.join(timeout=5)
        
        self._log_action("ENGINE_STOP", "Autonomous monitoring disabled")
        logger.info("Autonomous Engine stopped")
    
    def _run_loop(self):
        """Main autonomous loop"""
        while not self._stop_event.is_set():
            try:
                self.analyze()
                self.cleanup_old_blocks(self.blocked_ips)
            except Exception as e:
                logger.error(f"Autonomous loop error: {e}")
            
            self._stop_event.wait(self.check_interval)
    
    def analyze(self):
        """Analyze current threat landscape"""
        try:
            self._check_rate_limits()
            self._check_connection_patterns()
            self._check_failed_auth_patterns()
            self._generate_recommendations()
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
    
    def _check_rate_limits(self):
        """Check for rate limit violations"""
        try:
            import subprocess
            
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True
            )
            
            established_count = result.stdout.count("ESTABLISHED")
            time_wait_count = result.stdout.count("TIME_WAIT")
            
            if time_wait_count > established_count * 5:
                self._log_threat({
                    "type": "rate_limit",
                    "severity": "MEDIUM",
                    "description": f"Unusual TIME_WAIT ratio: {time_wait_count}/{established_count}"
                })
                
        except Exception as e:
            logger.debug(f"Rate limit check: {e}")
    
    def _check_connection_patterns(self):
        """Check for suspicious connection patterns"""
        try:
            import subprocess
            
            result = subprocess.run(
                ["ss", "-tunap", "state", "notly"],
                capture_output=True, text=True
            )
            
            ip_counts = {}
            for line in result.stdout.split("\n")[1:]:
                if "ESTABLISHED" in line or "SYN-SENT" in line:
                    parts = line.split()
                    if len(parts) > 5:
                        peer = parts[5]
                        if ":" in peer:
                            ip = peer.rsplit(":", 1)[0]
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            for ip, count in ip_counts.items():
                if count > self.rate_limit_threshold and ip not in self.trusted_ips:
                    self._log_threat({
                        "type": "connection_flood",
                        "source_ip": ip,
                        "severity": "HIGH",
                        "description": f"High connection count: {count}"
                    })
                    
        except Exception as e:
            logger.debug(f"Connection pattern check: {e}")
    
    def _check_failed_auth_patterns(self):
        """Check for brute force patterns"""
        try:
            import subprocess
            
            auth_logs = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
            
            for log_file in auth_logs:
                try:
                    result = subprocess.run(
                        ["sudo", "tail", "-n", "200", log_file],
                        capture_output=True, text=True, timeout=5
                    )
                    
                    failed_ips = {}
                    for line in result.stdout.split("\n"):
                        if "Failed password" in line or "authentication failure" in line:
                            import re
                            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                            if ip_match:
                                ip = ip_match.group(0)
                                if ip not in self.trusted_ips:
                                    failed_ips[ip] = failed_ips.get(ip, 0) + 1
                    
                    for ip, count in failed_ips.items():
                        if count >= self.scan_threshold:
                            self._log_threat({
                                "type": "brute_force",
                                "source_ip": ip,
                                "severity": "HIGH",
                                "description": f"Failed auth attempts: {count}"
                            })
                            
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"Auth pattern check: {e}")
    
    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        try:
            import subprocess
            
            result = subprocess.run(
                ["df", "-h"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split("\n"):
                if "/" in line and "Use%" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        usage = parts[4].rstrip("%")
                        if int(usage) > 90:
                            recommendations.append({
                                "type": "storage",
                                "severity": "MEDIUM",
                                "description": f"Disk usage critical: {usage}%",
                                "action": "Consider cleaning logs or expanding storage"
                            })
            
            result = subprocess.run(
                ["free", "-m"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split("\n"):
                if "Mem:" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        total = int(parts[1])
                        used = int(parts[2])
                        if used / total > 0.9:
                            recommendations.append({
                                "type": "memory",
                                "severity": "HIGH",
                                "description": "Memory usage critical",
                                "action": "Consider freeing memory or adding RAM"
                            })
                            
        except Exception as e:
            logger.debug(f"Recommendation generation: {e}")
        
        return recommendations
    
    def should_block(self, severity: str) -> bool:
        """Determine if threat should be auto-blocked"""
        return self.severity_rules.get(severity, {}).get("block", False)
    
    def get_block_duration(self, severity: str) -> int:
        """Get block duration for severity"""
        return self.severity_rules.get(severity, {}).get("duration", 3600)
    
    def suggest_rules(self) -> List[Dict]:
        """Suggest new firewall rules based on analysis"""
        suggestions = []
        
        top_threats = self._get_top_threat_sources()
        for threat in top_threats[:5]:
            suggestions.append({
                "source_ip": threat["ip"],
                "action": "DROP",
                "duration": self.get_block_duration(threat["severity"]),
                "reason": f"Auto-generated: {threat['description']}"
            })
        
        return suggestions
    
    def _get_top_threat_sources(self) -> List[Dict]:
        """Get top threat sources from log"""
        ip_threats = {}
        
        for threat in self.threat_log:
            ip = threat.get("source_ip", "unknown")
            if ip == "unknown":
                continue
            
            if ip not in ip_threats:
                ip_threats[ip] = {
                    "ip": ip,
                    "count": 0,
                    "severity": "LOW",
                    "description": ""
                }
            
            ip_threats[ip]["count"] += 1
            
            severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            current_rank = severity_rank.get(ip_threats[ip]["severity"], 0)
            new_rank = severity_rank.get(threat.get("severity", "LOW"), 0)
            
            if new_rank > current_rank:
                ip_threats[ip]["severity"] = threat.get("severity", "MEDIUM")
                ip_threats[ip]["description"] = threat.get("description", "")
        
        sorted_threats = sorted(
            ip_threats.values(),
            key=lambda x: (severity_rank.get(x["severity"], 0), x["count"]),
            reverse=True
        )
        
        return sorted_threats
    
    def cleanup_old_blocks(self, blocked_ips: set):
        """Clean up expired blocks"""
        now = datetime.now()
        expired = []
        
        for ip, block_time in list(self.blocked_ips.items()):
            duration = (now - block_time).total_seconds()
            max_duration = 86400
            
            if duration > max_duration:
                expired.append(ip)
        
        for ip in expired:
            del self.blocked_ips[ip]
            blocked_ips.discard(ip)
            self._log_action("UNBLOCK_AUTO", f"Block expired: {ip}")
    
    def add_trusted_ip(self, ip: str):
        """Add IP to trusted list"""
        self.trusted_ips.add(ip)
        self._log_action("TRUST_ADD", f"Added trusted IP: {ip}")
    
    def remove_trusted_ip(self, ip: str):
        """Remove IP from trusted list"""
        self.trusted_ips.discard(ip)
        self._log_action("TRUST_REMOVE", f"Removed trusted IP: {ip}")
    
    def get_trusted_ips(self) -> set:
        """Get list of trusted IPs"""
        return self.trusted_ips.copy()
    
    def set_autonomous_mode(self, enabled: bool):
        """Enable/disable autonomous mode"""
        self.autonomous_mode = enabled
        status = "enabled" if enabled else "disabled"
        self._log_action("MODE_CHANGE", f"Autonomous mode {status}")
        logger.info(f"Autonomous mode {status}")
    
    def get_status(self) -> Dict:
        """Get autonomous engine status"""
        return {
            "running": self.running,
            "autonomous_mode": self.autonomous_mode,
            "check_interval": self.check_interval,
            "blocked_ips_count": len(self.blocked_ips),
            "threats_logged": len(self.threat_log),
            "actions_taken": len(self.action_log)
        }
    
    def get_summary(self) -> str:
        """Get human-readable status summary"""
        threats_24h = sum(
            1 for t in self.threat_log
            if datetime.fromisoformat(t["timestamp"]) > datetime.now() - timedelta(hours=24)
        )
        
        summary = f"""
┌──────────────────────────────────────┐
│     AUTONOMOUS ENGINE STATUS          │
├──────────────────────────────────────┤
│  Mode: {'ENABLED' if self.autonomous_mode else 'DISABLED'}                       │
│  Running: {'YES' if self.running else 'NO'}                             │
│  Check Interval: {self.check_interval}s                    │
├──────────────────────────────────────┤
│  Currently Blocked: {len(self.blocked_ips):<17}│
│  Threats (24h): {threats_24h:<20}│
│  Actions Taken: {len(self.action_log):<19}│
└──────────────────────────────────────┘
"""
        return summary
    
    def _log_threat(self, threat: Dict):
        """Log detected threat"""
        threat["timestamp"] = datetime.now().isoformat()
        self.threat_log.append(threat)
        
        if len(self.threat_log) > 1000:
            self.threat_log = self.threat_log[-500:]
    
    def _log_action(self, action: str, details: str):
        """Log autonomous action"""
        self.action_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        })
        
        if len(self.action_log) > 1000:
            self.action_log = self.action_log[-500:]
    
    def get_threat_log(self, limit: int = 100) -> List[Dict]:
        """Get threat log"""
        return self.threat_log[-limit:]
    
    def get_action_log(self, limit: int = 100) -> List[Dict]:
        """Get action log"""
        return self.action_log[-limit:]
