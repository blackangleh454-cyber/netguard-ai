"""
Config Manager - Configuration handling for NetGuardAI
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    def __init__(self, config_file: str = None):
        if config_file is None:
            config_file = Path(__file__).parent.parent / "config" / "config.json"
        
        self.config_file = Path(config_file)
        self.config_file.parent.mkdir(exist_ok=True)
        
        self.config = self._load_config()
        
        if not self.config:
            self.config = self._default_config()
            self._save_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Failed to save config: {e}")
    
    def _default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "firewall": {
                "interface": "eth0",
                "default_policy": "DROP",
                "allowed_ports": [22, 80, 443],
                "rate_limit": 100,
                "block_duration": 3600
            },
            "snort": {
                "enabled": True,
                "interface": "eth0",
                "alert_level": "fast",
                "custom_rules_dir": "rules"
            },
            "autonomous": {
                "enabled": True,
                "check_interval": 60,
                "auto_block": True,
                "severity_thresholds": {
                    "CRITICAL": 0,
                    "HIGH": 50,
                    "MEDIUM": 100,
                    "LOW": 200
                }
            },
            "logging": {
                "level": "INFO",
                "retention_days": 30,
                "log_dir": "logs"
            },
            "notifications": {
                "enabled": False,
                "email": "",
                "webhook_url": ""
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split(".")
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split(".")
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self._save_config()
    
    def update(self, updates: Dict):
        """Update multiple configuration values"""
        self.config.update(updates)
        self._save_config()
