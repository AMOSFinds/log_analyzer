# Security Log Analyzer

Advanced threat detection tool for analyzing security logs and identifying suspicious activities. Demonstrates SIEM principles, pattern recognition, and automated security monitoring capabilities.

## Features
- **Multi-format log parsing** - Supports syslog, auth logs, Apache, Nginx formats
- **Brute force detection** - Automated identification of login attacks
- **Suspicious pattern recognition** - Detects privilege escalation, command injection, file access anomalies
- **IP reputation analysis** - Geographic and behavioral analysis
- **Real-time monitoring** - Live log surveillance capabilities
- **Attack pattern correlation** - Identifies distributed and coordinated attacks
- **Professional reporting** - Structured security alerts and recommendations

## Technical Skills Demonstrated
- Log parsing and regex pattern matching
- Threat detection algorithm development
- Real-time data processing
- Statistical analysis for anomaly detection
- Security incident classification
- SIEM-like functionality implementation

## Usage
```bash
# Analyze log file
python log_analyzer.py /var/log/auth.log

# Real-time monitoring
python log_analyzer.py -m /var/log/secure

# Export results
python log_analyzer.py access.log -o results.json

# Custom thresholds
python log_analyzer.py --threshold 3 auth.log
