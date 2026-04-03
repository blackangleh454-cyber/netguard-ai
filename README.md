# 🛡️ NetGuardAI

### Autonomous Firewall & IDS Manager powered by Snort

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Snort](https://img.shields.io/badge/Snort-IDS-FF5722?style=flat&logo=shield&logoColor=white)](https://www.snort.org/)
[![Linux](https://img.shields.io/badge/Linux-Security-FCC624?style=flat&logo=linux&logoColor=black)](https://www.linux.org/)

---

<p align="center">
  <img src="https://img.shields.io/badge/NetGuardAI-Autonomous_Security_Manager-1E90FF?style=for-the-badge&logo=shield&logoColor=white" alt="NetGuardAI Banner"/>
</p>

> **NetGuardAI** — An intelligent, autonomous firewall and Intrusion Detection System (IDS) manager that uses AI to detect, analyze, and respond to network threats in real-time.

---

## 🎯 What is NetGuardAI?

NetGuardAI is a comprehensive network security solution that:

- 🔥 **Autonomous Firewall** — iptables-based firewall with automatic rule management
- 🐍 **Snort IDS Integration** — Industry-standard intrusion detection
- 🤖 **AI-Powered Threat Detection** — Intelligent analysis of network patterns
- ⚡ **Auto-Response** — Automatic blocking of malicious IPs
- 📊 **Real-Time Monitoring** — Live dashboard of network security events
- 🔧 **Self-Managing** — Learns and adapts to new threats automatically

---

## ⚡ Features

### 🛡️ Firewall Management
| Feature | Description |
|---------|-------------|
| **IP Blocking** | Block/unblock IPs with automatic expiration |
| **Port Control** | Open/close ports on demand |
| **Rate Limiting** | Prevent DoS/DDoS attacks |
| **Connection Tracking** | Monitor active connections |
| **Rule Management** | Custom firewall rules |
| **Persistent Rules** | Save/restore firewall configuration |

### 🐍 Snort IDS
| Feature | Description |
|---------|-------------|
| **Real-Time Detection** | Monitor network traffic for threats |
| **Custom Rules** | Add your own detection rules |
| **Alert System** | Instant notifications of threats |
| **Pattern Matching** | Detect known attack signatures |
| **Anomaly Detection** | Identify suspicious behavior |

### 🤖 Autonomous Engine
| Feature | Description |
|---------|-------------|
| **Auto-Block** | Automatically block threat sources |
| **Threat Analysis** | Analyze patterns and predict attacks |
| **Self-Learning** | Improve detection over time |
| **Zero-Config** | Works out of the box |
| **Smart Cleanup** | Auto-expire old blocks |

### 📊 Security Monitoring
| Feature | Description |
|---------|-------------|
| **Live Dashboard** | Real-time security status |
| **Threat Log** | Complete history of detected threats |
| **Network Scanner** | Discover devices on your network |
| **Connection Monitor** | Track all network connections |
| **Alert System** | Get notified of security events |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetGuardAI                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    AUTONOMOUS ENGINE                      │  │
│  │  ┌────────────┐  ┌─────────────┐  ┌──────────────────┐   │  │
│  │  │  THREAT   │  │   AUTO     │  │     RULE        │   │  │
│  │  │  DETECTOR │  │   RESPONSE │  │   GENERATOR     │   │  │
│  │  └────────────┘  └─────────────┘  └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌────────────────────┐     ┌────────────────────┐             │
│  │   FIREWALL         │     │    SNORT IDS       │             │
│  │   (iptables)       │     │  (Intrusion        │             │
│  │                    │     │   Detection)       │             │
│  │  • Block IPs       │     │                    │             │
│  │  • Port Control    │     │  • Pattern Match   │             │
│  │  • Rate Limit      │     │  • Alert System   │             │
│  │  • Connection Mon  │     │  • Custom Rules   │             │
│  └────────────────────┘     └────────────────────┘             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    SECURITY LOGGER                       │  │
│  │  • Event Log  • Threat Log  • Alert Log  • Block Log   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Installation

### Prerequisites

```bash
# Update system
sudo apt update

# Install required tools
sudo apt install -y iptables snort tcpdump nmap net-tools ss iputils-ping

# Install Python dependencies
pip3 install -r requirements.txt
```

### Quick Install

```bash
# Clone or download the project
cd NetGuardAI

# Make scripts executable
chmod +x netguard.py netguard-cli.py

# Run (requires sudo for firewall access)
sudo python3 netguard.py
```

---

## 🚀 Usage

### Start NetGuardAI

```bash
# Full GUI mode
sudo python3 netguard.py

# CLI mode
sudo python3 netguard-cli.py <command>
```

### CLI Commands

```bash
# Check status
sudo python3 netguard-cli.py status

# Block an IP
sudo python3 netguard-cli.py block 192.168.1.100

# Unblock an IP
sudo python3 netguard-cli.py unblock 192.168.1.100

# List blocked IPs
sudo python3 netguard-cli.py blocked

# View recent logs
sudo python3 netguard-cli.py logs

# View recent threats
sudo python3 netguard-cli.py threats

# Scan network
sudo python3 netguard-cli.py scan
```

### Python API

```python
from netguard import NetGuardAI

# Initialize
guard = NetGuardAI()
guard.initialize()

# Block an IP
guard.block_ip("192.168.1.100")

# Get status
status = guard.get_status()
print(status)

# Get blocked IPs
blocked = guard.get_blocked_ips()
print(f"Blocked IPs: {blocked}")

# Get threats
threats = guard.get_threats(limit=50)
for threat in threats:
    print(f"{threat['severity']}: {threat['type']} from {threat['source_ip']}")

# Shutdown
guard.shutdown()
```

---

## 📋 Built-in Snort Rules

NetGuardAI includes pre-configured rules for:

### 🔴 Critical Threats
- SQL Injection attacks
- Command Injection
- Malware downloads
- DDoS attacks

### 🟠 High Severity
- Port scanning detection
- Brute force attempts
- XSS attacks
- Path traversal

### 🟡 Medium Severity
- Suspicious protocols
- DNS tunneling
- ICMP anomalies
- Policy violations

### 🟢 Informational
- Nmap detection
- Reconnaissance
- Traffic anomalies

---

## ⚙️ Configuration

Configuration is stored in `config/config.json`:

```json
{
  "firewall": {
    "interface": "eth0",
    "default_policy": "DROP",
    "allowed_ports": [22, 80, 443],
    "block_duration": 3600
  },
  "snort": {
    "enabled": true,
    "interface": "eth0",
    "alert_level": "fast"
  },
  "autonomous": {
    "enabled": true,
    "check_interval": 60,
    "auto_block": true
  },
  "logging": {
    "level": "INFO",
    "retention_days": 30
  }
}
```

---

## 📁 Project Structure

```
NetGuardAI/
├── netguard.py              # Main application
├── netguard-cli.py          # CLI interface
├── requirements.txt         # Python dependencies
├── README.md               # This file
│
├── core/                   # Core modules
│   ├── __init__.py
│   ├── firewall_manager.py # iptables wrapper
│   ├── snort_controller.py  # Snort IDS integration
│   ├── threat_detector.py   # AI threat detection
│   ├── autonomous_engine.py # Self-managing logic
│   ├── rule_generator.py    # Auto rule generation
│   └── logger.py            # Security logging
│
├── config/                 # Configuration
│   ├── config.json
│   └── snort.conf
│
├── rules/                  # Snort rules
│   └── netguard.rules
│
├── logs/                    # Security logs
│   ├── events.jsonl
│   ├── threats.jsonl
│   ├── alerts.jsonl
│   └── blocks.jsonl
│
└── utils/                   # Utilities
    ├── config.py
    └── network_scanner.py
```

---

## 🔍 How It Works

### 1. Threat Detection
```
Network Traffic → Snort IDS → Pattern Match → Threat Alert
                                    ↓
                            Threat Detector
                                    ↓
                    ┌────────────────┴────────────────┐
                    │                                 │
            Low Severity                        High Severity
                    │                                 │
            Log Only                             Auto-Block
                                                     │
                                              Firewall Rule
```

### 2. Autonomous Response
```
Threat Detected → Severity Check → Auto-Block?
                                        │
                        ┌───────────────┼───────────────┐
                        │               │               │
                    CRITICAL         HIGH          MEDIUM
                        │               │               │
                    Block 24h        Block 1h       Block 30m
```

### 3. Network Monitoring
```
Continuous → Log Analysis → Pattern Detection → Alert/Block
Scanning                                    ↓
                                        Dashboard
```

---

## 🛡️ Security Rules

### Default Firewall Rules
- Allow established connections
- Allow loopback traffic
- Allow ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Log and drop everything else

### Auto-Block Triggers
| Threat Level | Condition | Action |
|---------------|-----------|--------|
| CRITICAL | Any detection | Block 24 hours |
| HIGH | 3+ detections | Block 1 hour |
| MEDIUM | 5+ detections | Block 30 minutes |

---

## 📊 Logs

All logs are stored in JSONL format in `logs/`:

```json
{"timestamp": "2026-04-03T12:00:00", "type": "THREAT", "severity": "HIGH", "source_ip": "192.168.1.100"}
{"timestamp": "2026-04-03T12:01:00", "type": "BLOCK", "ip": "192.168.1.100", "reason": "brute_force"}
{"timestamp": "2026-04-03T12:02:00", "type": "ALERT", "action": "BLOCKED"}
```

---

## 🔧 Customization

### Add Custom Snort Rules

```python
from core.snort_controller import SnortController

snort = SnortController()
snort.add_rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Custom Rule"; content:"malicious"; sid:3000001; rev:1;)')
```

### Add Custom Firewall Rules

```python
from core.firewall_manager import FirewallManager

fw = FirewallManager()
fw.add_rule({
    "action": "DROP",
    "source_ip": "192.168.1.100",
    "port": 3389,
    "protocol": "tcp"
})
```

### Disable Autonomous Mode

```python
guard = NetGuardAI()
guard.autonomous_engine.autonomous_mode = False
```

---

## 🚨 Troubleshooting

### "Permission denied" error
```bash
sudo python3 netguard.py
```

### Snort not installed
```bash
sudo apt install snort
```

### View logs
```bash
tail -f logs/netguard.log
```

### Reset firewall
```bash
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
```

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👤 Author

### Mirza Muhammad Usman

> *Cybersecurity Engineer | Network Architect | AI Agent Builder*

[![Twitter](https://img.shields.io/badge/Twitter-@blackangleh454-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://twitter.com/blackangleh454)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mirza%20Muhammad%20Usman-0077B5?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/mirza-muhammad-usman)
[![GitHub](https://img.shields.io/badge/GitHub-blackangleh454--cyber-100000?style=flat&logo=github&logoColor=white)](https://github.com/blackangleh454-cyber)

**Certifications:**
- 🛡️ CISSP — Certified Information Systems Security Professional
- 🌐 CCNA — Cisco Certified Network Associate
- 🔍 Ethical Hacking — EC-Council

---

<p align="center">
  <sub>Built with ❤️ by Mirza Muhammad Usman</sub>
  <br>
  <sub>Defending networks, one packet at a time.</sub>
</p>

---

<p align="center">
  <strong>NetGuardAI — Autonomous Security, Zero Compromise.</strong>
</p>
