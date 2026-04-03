"""
Snort IDS Controller - Interface with Snort Intrusion Detection System
"""

import subprocess
import threading
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class SnortController:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.rules_dir = self.base_dir / "rules"
        self.log_dir = self.base_dir / "logs"
        self.config_dir = self.base_dir / "config"
        
        self.rules_dir.mkdir(exist_ok=True)
        self.log_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        
        self.snort_conf = self.config_dir / "snort.conf"
        self.alert_file = self.log_dir / "snort_alerts.json"
        
        self.interface = "eth0"
        self.running = False
        self.process = None
        self.alert_thread = None
        
        self.alerts = []
        self.stats = {
            "alerts_total": 0,
            "alerts_by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "last_alert": None
        }
        
        self._create_config()
        self._create_rules()
    
    def _create_config(self):
        """Create Snort configuration file"""
        config_content = f"""
# NetGuardAI Snort Configuration
ipvar HOME_NET any
ipvar EXTERNAL_NET any

var RULE_PATH {self.rules_dir}
var SO_RULE_PATH {self.rules_dir}
var PREPROC_RULE_PATH {self.rules_dir}

var HTTP_PORTS 80
var SHELLCODE_PORTS 80
var ORACLE_PORTS 1521

preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy first detect_anomalies

preprocessor stream5_global: max_tcp 8192, track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy first, ports client 21 22 23 25 42 53 80 110 111 135 136 137 138 139 143 161 445 513 514 587 646 691 1433 1521 3306 3389 5556 6660 6661 6662 6663 6664 6665 6666 6667 6668 6669 7000 7001 8000 8080 8180 8443
preprocessor stream5_udp: ports {21 53 67 68 69 111 123 135 136 137 138 161 500 513 514 515 518 520 634 640 641 666 700 1025 1026 1027 1028 1029 1030 1434 1701 1812 1813 2049 5060 5061 5353 5632 17000}

preprocessor http_inspect: global \\
    compress_depth 65535 decompress_depth 65535

preprocessor http_inspect_server: server default \\
    http_methods GET POST PUT DELETE HEAD OPTIONS \\
    ports {{ 80 81 82 83 84 85 86 87 88 89 90 311 383 555 591 593 631 801 808 818 901 972 1158 1220 1414 1533 1741 1742 1812 1813 1830 1900 2001 2002 2049 2065 2068 2099 2222 2233 2301 2375 2376 2483 2484 2575 2809 3000 3001 3002 3031 3050 3100 3102 3104 3105 3128 3333 3400 3690 3780 4000 4200 4242 4443 4444 4445 4658 4840 4843 4848 5000 5001 5009 5051 5060 5061 5080 5101 5104 5108 5190 5280 5357 5432 5433 5500 5631 5632 5800 5801 5802 5803 5900 5901 5902 5903 6000 6001 6002 6003 6004 6005 6006 6007 6008 6009 6010 6022 6060 6100 6379 6600 6646 6660 6661 6662 6663 6664 6665 6666 6667 6668 6669 6697 7000 7001 7002 7003 7004 7005 7006 7007 7008 7009 7010 7100 7200 7201 7400 7443 7444 7474 7547 7548 7549 7627 7777 7778 7779 7800 7801 7802 8000 8001 8002 8003 8008 8009 8010 8011 8020 8021 8022 8028 8030 8042 8043 8044 8045 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8091 8092 8118 8123 8138 8139 8140 8180 8181 8182 8200 8222 8243 8280 8281 8333 8334 8400 8443 8444 8445 8500 8530 8531 8761 8765 8787 8800 8801 8802 8804 8888 8889 9000 9001 9002 9003 9009 9010 9042 9060 9080 9090 9091 9092 9093 9094 9095 9096 9097 9098 9099 9100 9101 9102 9103 9104 9105 9110 9111 9200 9201 9202 9290 9300 9301 9302 9303 9306 9309 9312 9390 9391 9392 9393 9394 9395 9396 9397 9398 9399 9443 9500 9530 9600 9876 9877 9878 9898 9900 9943 9944 9980 9981 10000 10001 10002 10003 10004 10005 10006 10007 10008 10009 10010 10080 10081 10082 10083 10084 10085 10086 10087 10088 10089 10090 10091 10092 10093 10094 10095 10096 10097 10098 10099 10100 10250 10255 10256 10880 10990 11001 11080 11110 11211 11235 11311 12000 12345 12443 12444 13000 13443 14000 14443 15000 16000 16001 16080 17000 17001 18000 18080 18081 18091 18092 18093 18094 18095 18096 18097 18098 18099 18100 19000 19080 20000 22000 22222 23023 24000 25000 25105 25565 26000 27000 27017 27018 27019 27020 28000 28080 29000 30000 30080 31000 31337 32400 33060 33400 33848 34000 34443 35000 36000 37000 37892 38000 39000 40000 40001 40002 40003 40004 40005 40006 40007 40008 40009 40010 42000 43000 44000 45000 45001 45002 45003 45004 45005 45006 45007 45008 45009 45010 45011 45012 45013 45014 45015 45016 45017 45018 45019 45020 45454 47000 47808 48000 48080 48400 49000 50000 50000 50030 50060 50070 50090 51000 52000 53000 54000 55000 55555 56000 56001 57000 58000 59000 60000 60080 61000 62000 63000 64000 65000 65500 }} \\
    server_flow_depth 0 client_flow_depth 0 \\
    normalize_cookies normalize_url normalize_double_encode normalize_utf_16_to_utf8 normalize_http_headers normalize_javascript compress_pace 8192

output alert_fast: {self.alert_file}

logdir {self.log_dir}
"""
        
        with open(self.snort_conf, "w") as f:
            f.write(config_content)
    
    def _create_rules(self):
        """Create NetGuardAI custom Snort rules"""
        rules_content = """
# NetGuardAI Custom IDS Rules
# Author: Mirza Muhammad Usman

# === MALICIOUS ACTIVITY ===

# Suspicious port scanning
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PORT SCAN Attempt"; flags:S; sid:1000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Null Scan Detected"; flags:0; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"FIN Scan Detected"; flags:F; sid:1000003; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Xmas Scan Detected"; flags:FPU; sid:1000004; rev:1;)

# Brute Force Detection
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000010; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (msg:"Telnet Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; sid:1000011; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"MySQL Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000012; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (msg:"PostgreSQL Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000013; rev:1;)

# SQL Injection Attempts
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt - UNION SELECT"; content:"UNION SELECT"; nocase; sid:1000020; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt - OR 1=1"; content:"OR 1=1"; nocase; sid:1000021; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt - DROP TABLE"; content:"DROP TABLE"; nocase; sid:1000022; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt - EXECUTE"; content:"EXECUTE"; nocase; sid:1000023; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt - ';--"; content:";--"; sid:1000024; rev:1;)

# XSS Attacks
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS Attack - Script Tag"; content:"<script"; nocase; sid:1000030; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS Attack - Javascript URI"; content:"javascript:"; nocase; sid:1000031; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS Attack - OnError"; content:"onerror="; nocase; sid:1000032; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS Attack - OnLoad"; content:"onload="; nocase; sid:1000033; rev:1;)

# Command Injection
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection - Pipe"; content:"|"; sid:1000040; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection - Semicolon"; content:";"; sid:1000041; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection - Backtick"; content:"`"; sid:1000042; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection - $()"; content:"$("; sid:1000043; rev:1;)

# Path Traversal
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Path Traversal - ../"; content:"../"; sid:1000050; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Path Traversal - /etc/passwd"; content:"/etc/passwd"; sid:1000051; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Path Traversal - Windows"; content:"..\\\\"; sid:1000052; rev:1;)

# Malware Patterns
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Malware - Suspicious Download"; content:"Content-Disposition|3A| attachment"; sid:1000060; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Malware - Executable Download"; content:"Content-Type|3A| application/octet-stream"; sid:1000061; rev:1;)

# DDoS Patterns
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"DDoS - SYN Flood"; flags:S; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000070; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"DDoS - HTTP Flood"; flags:PA; threshold:type threshold, track by_src, count 50, seconds 10; sid:1000071; rev:1;)

# Suspicious Protocols
alert tcp $EXTERNAL_NET 6660:6670 -> $HOME_NET any (msg:"Suspicious - IRC Traffic"; sid:1000080; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (msg:"Suspicious - Metasploit Payload"; sid:1000081; rev:1;)

# DNS Tunneling
alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"DNS Query - Long Subdomain (Possible Tunnel)"; dsize:>100; sid:1000090; rev:1;)

# ICMP Tunneling
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP - Large Payload (Possible Tunnel)"; dsize:>100; sid:1000091; rev:1;)

# === POLICY VIOLATIONS ===

# Unauthorized Access
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"RDP Connection Attempt"; sid:1000100; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Connection Attempt"; sid:1000101; rev:1;)

# Sensitive Data Exfiltration
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Data Exfiltration"; content:"password="; sid:1000110; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Credential Leak"; content:"Authorization|3A| Basic"; sid:1000111; rev:1;)

# Cryptomining
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Cryptomining Pool Connection"; content:"stratum+tcp"; sid:1000120; rev:1;)

# == SCANNING ==

# Nmap Detection
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Nmap Scan - Version Probe"; content:"OSScan"; sid:1000130; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Nmap Scan - OS Probe"; content:"nmap"; sid:1000131; rev:1;)
"""
        
        rules_file = self.rules_dir / "netguard.rules"
        with open(rules_file, "w") as f:
            f.write(rules_content)
        
        logger.info(f"Created {len(rules_content.splitlines())} custom rules")
    
    def initialize(self):
        """Initialize Snort IDS"""
        if not self._check_snort():
            logger.warning("Snort not installed - running in simulation mode")
            return
        
        logger.info("Starting Snort IDS...")
        
        try:
            cmd = [
                "snort",
                "-c", str(self.snort_conf),
                "-i", self.interface,
                "-A", "fast",
                "-Q", "--daq", "nfq",
                "-k", "notla",
                "-l", str(self.log_dir),
                "-D"
            ]
            
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            
            self.running = True
            self.alert_thread = threading.Thread(
                target=self._monitor_alerts, daemon=True
            )
            self.alert_thread.start()
            
            logger.info("Snort IDS started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Snort: {e}")
            self.running = False
    
    def _check_snort(self) -> bool:
        """Check if Snort is installed"""
        try:
            subprocess.run(["which", "snort"], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _monitor_alerts(self):
        """Monitor Snort alert file"""
        while self.running:
            try:
                if self.alert_file.exists():
                    with open(self.alert_file, "r") as f:
                        content = f.read()
                        if content.strip():
                            alerts = self._parse_alerts(content)
                            for alert in alerts:
                                self._process_alert(alert)
            except Exception as e:
                logger.error(f"Alert monitoring error: {e}")
            
            threading.Event().wait(2)
    
    def _parse_alerts(self, content: str) -> List[Dict]:
        """Parse Snort alert content"""
        alerts = []
        
        for line in content.split("\n"):
            if "[Priority:" in line:
                alert = self._extract_alert_info(line)
                if alert:
                    alerts.append(alert)
        
        return alerts
    
    def _extract_alert_info(self, line: str) -> Optional[Dict]:
        """Extract alert information from Snort log line"""
        try:
            parts = line.split("**")
            
            if len(parts) < 3:
                return None
            
            classification = parts[1].strip("() ")
            
            timestamp = datetime.now().isoformat()
            
            severity = "HIGH"
            if "Priority: 2" in line or "Priority:3" in line:
                severity = "LOW"
            elif "Priority: 1" in line:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            source_ip = "unknown"
            dest_ip = "unknown"
            
            ip_match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if len(ip_match) >= 2:
                source_ip = ip_match[0]
                dest_ip = ip_match[1]
            
            return {
                "timestamp": timestamp,
                "classification": classification,
                "severity": severity,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "raw": line
            }
            
        except Exception as e:
            logger.error(f"Failed to parse alert: {e}")
            return None
    
    def _process_alert(self, alert: Dict):
        """Process incoming Snort alert"""
        self.alerts.append(alert)
        
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-500:]
        
        self.stats["alerts_total"] += 1
        self.stats["alerts_by_severity"][alert["severity"]] += 1
        self.stats["last_alert"] = alert["timestamp"]
    
    def get_alerts(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get recent alerts"""
        alerts = self.alerts
        
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        
        return alerts[-limit:]
    
    def get_stats(self) -> Dict:
        """Get Snort statistics"""
        return {
            **self.stats,
            "running": self.running,
            "interface": self.interface,
            "config": str(self.snort_conf),
            "rules_count": len(self._create_rules.__doc__ or "").splitlines()
        }
    
    def add_rule(self, rule: str):
        """Add custom Snort rule"""
        rules_file = self.rules_dir / "netguard.rules"
        
        with open(rules_file, "a") as f:
            f.write(f"\n{rule}\n")
        
        if self.running:
            self.reload()
        
        logger.info(f"Added custom rule: {rule[:50]}...")
    
    def remove_rule(self, sid: int):
        """Remove Snort rule by SID"""
        rules_file = self.rules_dir / "netguard.rules"
        
        with open(rules_file, "r") as f:
            lines = f.readlines()
        
        lines = [l for l in lines if f"sid:{sid};" not in l]
        
        with open(rules_file, "w") as f:
            f.writelines(lines)
        
        if self.running:
            self.reload()
    
    def reload(self):
        """Reload Snort configuration"""
        if self.running and self.process:
            self.process.terminate()
            time.sleep(1)
            self.initialize()
            logger.info("Snort configuration reloaded")
    
    def stop(self):
        """Stop Snort IDS"""
        self.running = False
        
        if self.process:
            self.process.terminate()
            self.process = None
        
        logger.info("Snort IDS stopped")
    
    def test_rules(self) -> bool:
        """Test Snort rules for syntax errors"""
        try:
            result = subprocess.run(
                ["snort", "-c", str(self.snort_conf), "-T"],
                capture_output=True, text=True, timeout=30
            )
            
            if "Snort successfully validated the configuration" in result.stdout:
                logger.info("Snort rules validation passed")
                return True
            else:
                logger.error("Snort rules validation failed")
                logger.error(result.stderr)
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Snort rules test timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to test rules: {e}")
            return False
