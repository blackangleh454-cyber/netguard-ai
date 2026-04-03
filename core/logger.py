"""
Security Logger - Centralized logging for NetGuardAI
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from collections import deque


class SecurityLogger:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = Path(__file__).parent.parent / "logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        self.event_log = self.log_dir / "events.jsonl"
        self.threat_log = self.log_dir / "threats.jsonl"
        self.alert_log = self.log_dir / "alerts.jsonl"
        self.block_log = self.log_dir / "blocks.jsonl"
        
        self._setup_file_logging()
        
        self.recent_events = deque(maxlen=500)
        self.recent_threats = deque(maxlen=500)
    
    def _setup_file_logging(self):
        """Setup Python logging configuration"""
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        file_handler = logging.FileHandler(self.log_dir / "netguard.log")
        file_handler.setFormatter(logging.Formatter(log_format))
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        
        logger = logging.getLogger("netguard")
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    def log_event(self, event_type: str, message: str, data: Dict = None):
        """Log general event"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "message": message,
            "data": data or {}
        }
        
        self._write_jsonl(self.event_log, entry)
        self.recent_events.append(entry)
        
        logging.getLogger("netguard").info(f"[{event_type}] {message}")
    
    def log_threat(self, threat: Dict):
        """Log detected threat"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat.get("type", "unknown"),
            "source_ip": threat.get("source_ip", "unknown"),
            "severity": threat.get("severity", "MEDIUM"),
            "description": threat.get("description", ""),
            "raw_data": threat
        }
        
        self._write_jsonl(self.threat_log, entry)
        self.recent_threats.append(entry)
    
    def log_alert(self, alert: Dict):
        """Log security alert"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": alert.get("action", "UNKNOWN"),
            "threat": alert.get("threat", {}),
            "resolved": False
        }
        
        self._write_jsonl(self.alert_log, entry)
    
    def log_block(self, ip: str, threat: Dict):
        """Log IP block"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "reason": threat.get("type", "manual"),
            "severity": threat.get("severity", "MEDIUM"),
            "duration": threat.get("duration", 3600)
        }
        
        self._write_jsonl(self.block_log, entry)
    
    def _write_jsonl(self, file_path: Path, entry: Dict):
        """Write entry to JSONL file"""
        try:
            with open(file_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logging.error(f"Failed to write log: {e}")
    
    def _read_jsonl(self, file_path: Path, limit: int = 100) -> List[Dict]:
        """Read entries from JSONL file"""
        entries = []
        
        try:
            if file_path.exists():
                with open(file_path, "r") as f:
                    lines = f.readlines()
                
                for line in lines[-limit:]:
                    try:
                        entries.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logging.error(f"Failed to read log: {e}")
        
        return entries
    
    def get_recent(self, limit: int = 100) -> List[Dict]:
        """Get recent events"""
        return list(self.recent_events)[-limit:]
    
    def get_threats(self, limit: int = 100) -> List[Dict]:
        """Get recent threats"""
        return list(self.recent_threats)[-limit:]
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent alerts"""
        return self._read_jsonl(self.alert_log, limit)
    
    def get_blocks(self, limit: int = 100) -> List[Dict]:
        """Get recent blocks"""
        return self._read_jsonl(self.block_log, limit)
    
    def get_stats(self) -> Dict:
        """Get log statistics"""
        stats = {
            "events": 0,
            "threats": 0,
            "alerts": 0,
            "blocks": 0
        }
        
        for log_file, key in [
            (self.event_log, "events"),
            (self.threat_log, "threats"),
            (self.alert_log, "alerts"),
            (self.block_log, "blocks")
        ]:
            if log_file.exists():
                with open(log_file, "r") as f:
                    stats[key] = sum(1 for _ in f)
        
        return stats
    
    def clear_old_logs(self, days: int = 7):
        """Clear logs older than specified days"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        
        for log_file in [self.event_log, self.threat_log, self.alert_log, self.block_log]:
            if log_file.exists():
                self._clean_jsonl(log_file, cutoff)
    
    def _clean_jsonl(self, file_path: Path, cutoff: datetime):
        """Remove old entries from JSONL file"""
        try:
            entries = []
            with open(file_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry["timestamp"])
                        if entry_time > cutoff:
                            entries.append(entry)
                    except (json.JSONDecodeError, KeyError):
                        continue
            
            with open(file_path, "w") as f:
                for entry in entries:
                    f.write(json.dumps(entry) + "\n")
                    
        except Exception as e:
            logging.error(f"Failed to clean log: {e}")
    
    def export_logs(self, output_file: str, log_type: str = "all", days: int = 7):
        """Export logs to file"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        entries = []
        
        log_files = {
            "events": self.event_log,
            "threats": self.threat_log,
            "alerts": self.alert_log,
            "blocks": self.block_log
        }
        
        if log_type == "all":
            files_to_export = log_files.values()
        else:
            files_to_export = [log_files.get(log_type)]
        
        for log_file in files_to_export:
            if log_file and log_file.exists():
                with open(log_file, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time > cutoff:
                                entries.append(entry)
                        except (json.JSONDecodeError, KeyError):
                            continue
        
        entries.sort(key=lambda x: x.get("timestamp", ""))
        
        output_path = Path(output_file)
        with open(output_path, "w") as f:
            json.dump(entries, f, indent=2)
        
        return str(output_path)
