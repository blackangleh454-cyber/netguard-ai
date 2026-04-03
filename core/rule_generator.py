"""
Rule Generator - AI-powered Snort rule generation
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RuleGenerator:
    def __init__(self):
        self.custom_rules = []
        self.rule_templates = self._load_templates()
    
    def _load_templates(self) -> Dict:
        """Load Snort rule templates"""
        return {
            "block_ip": {
                "template": 'alert tcp {source} any -> {dest} any (msg:"Blocked IP"; sid:{sid}; rev:1;)',
                "params": ["source", "dest"]
            },
            "port_scan": {
                "template": 'alert tcp {source} any -> {dest} any (msg:"Port Scan"; flags:S; threshold:type threshold, track by_src, count {count}, seconds {seconds}; sid:{sid}; rev:1;)',
                "params": ["source", "dest", "count", "seconds"]
            },
            "brute_force": {
                "template": 'alert tcp {source} any -> {dest} {port} (msg:"Brute Force"; flags:S; threshold:type threshold, track by_src, count {count}, seconds {seconds}; sid:{sid}; rev:1;)',
                "params": ["source", "dest", "port", "count", "seconds"]
            },
            "malware_signature": {
                "template": 'alert tcp {source} any -> {dest} any (msg:"Malware Signature"; content:"{signature}"; sid:{sid}; rev:1;)',
                "params": ["source", "dest", "signature"]
            },
            "ddos": {
                "template": 'alert tcp {source} any -> {dest} any (msg:"DDoS Pattern"; flags:S; threshold:type threshold, track by_src, count {count}, seconds {seconds}; sid:{sid}; rev:1;)',
                "params": ["source", "dest", "count", "seconds"]
            }
        }
    
    def generate_rule(self, rule_type: str, params: Dict) -> Optional[str]:
        """Generate Snort rule from template"""
        template = self.rule_templates.get(rule_type)
        
        if not template:
            logger.error(f"Unknown rule type: {rule_type}")
            return None
        
        try:
            sid = self._get_next_sid()
            
            rule_text = template["template"].format(
                sid=sid,
                **{k: v for k, v in params.items() if k in template["params"]}
            )
            
            rule = {
                "id": sid,
                "type": rule_type,
                "params": params,
                "rule": rule_text,
                "created": datetime.now().isoformat(),
                "enabled": True
            }
            
            self.custom_rules.append(rule)
            
            logger.info(f"Generated rule: {rule_type}")
            return rule_text
            
        except KeyError as e:
            logger.error(f"Missing parameter: {e}")
            return None
    
    def _get_next_sid(self) -> int:
        """Get next rule SID"""
        if not self.custom_rules:
            return 2000001
        
        return max(r["id"] for r in self.custom_rules) + 1
    
    def generate_iptables_rule(self, action: str, ip: str = None, port: int = None, 
                               protocol: str = "tcp") -> str:
        """Generate iptables rule"""
        rule = ["iptables", "-A", "NETGUARD"]
        
        if ip:
            rule.extend(["-s", ip])
        
        if port:
            rule.extend(["-p", protocol, "--dport", str(port)])
        
        rule.extend(["-j", action.upper()])
        
        return " ".join(rule)
    
    def suggest_rules_from_threats(self, threats: List[Dict]) -> List[Dict]:
        """Suggest rules based on threat patterns"""
        suggestions = []
        
        ip_frequency = {}
        for threat in threats:
            ip = threat.get("source_ip")
            if ip and ip != "unknown":
                ip_frequency[ip] = ip_frequency.get(ip, 0) + 1
        
        for ip, count in ip_frequency.items():
            if count >= 3:
                suggestions.append({
                    "type": "block_repeating_attacker",
                    "action": "DROP",
                    "source_ip": ip,
                    "reason": f"Detected in {count} threats"
                })
        
        threat_types = {}
        for threat in threats:
            t_type = threat.get("type", "unknown")
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        for t_type, count in threat_types.items():
            if count >= 5:
                suggestions.append({
                    "type": f"detect_{t_type}",
                    "action": "ALERT",
                    "description": f"High frequency {t_type} ({count} occurrences)"
                })
        
        return suggestions
    
    def create_dynamic_blocklist(self, ips: List[str], duration: int = 3600) -> List[str]:
        """Create blocklist rules for multiple IPs"""
        rules = []
        
        for ip in ips:
            rule = {
                "ip": ip,
                "iptables": self.generate_iptables_rule("DROP", ip=ip),
                "duration": duration,
                "expires": (datetime.now().timestamp() + duration)
            }
            rules.append(rule)
        
        return rules
    
    def get_custom_rules(self) -> List[Dict]:
        """Get all custom rules"""
        return self.custom_rules.copy()
    
    def enable_rule(self, rule_id: int):
        """Enable a rule"""
        for rule in self.custom_rules:
            if rule["id"] == rule_id:
                rule["enabled"] = True
                logger.info(f"Enabled rule: {rule_id}")
                return True
        return False
    
    def disable_rule(self, rule_id: int):
        """Disable a rule"""
        for rule in self.custom_rules:
            if rule["id"] == rule_id:
                rule["enabled"] = False
                logger.info(f"Disabled rule: {rule_id}")
                return True
        return False
    
    def export_rules(self, format: str = "snort") -> str:
        """Export rules to file format"""
        if format == "snort":
            lines = [r["rule"] for r in self.custom_rules if r.get("enabled", True)]
            return "\n".join(lines)
        
        elif format == "iptables":
            lines = []
            for rule in self.custom_rules:
                if rule["type"] in ["block_ip", "ddos"]:
                    ip = rule["params"].get("source", "*")
                    lines.append(self.generate_iptables_rule("DROP", ip=ip))
            return "\n".join(lines)
        
        return ""
