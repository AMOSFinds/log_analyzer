#!/usr/bin/env python3
"""
Security Log Analyzer - Professional Log Analysis Tool
Author: Amos Mashele
Description: Analyzes security logs for suspicious activities and threats
"""

import re
import os
import sys
import json
import time
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from colorama import init, Fore, Style
import threading
import geoip2.database
import requests

# Initialize colorama
init()

class LogAnalyzer:
    def __init__(self):
        self.suspicious_patterns = self.load_suspicious_patterns()
        self.known_malicious_ips = set()
        self.failed_login_threshold = 5
        self.time_window = 300  # 5 minutes
        self.analysis_results = {
            'failed_logins': defaultdict(list),
            'suspicious_activities': [],
            'ip_analysis': defaultdict(int),
            'user_analysis': defaultdict(int),
            'attack_patterns': [],
            'security_events': []
        }
        
    def load_suspicious_patterns(self):
        """Load patterns that indicate suspicious activity"""
        patterns = {
            'brute_force': [
                r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
                r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
                r'Failed login.*from (\d+\.\d+\.\d+\.\d+)'
            ],
            'privilege_escalation': [
                r'sudo.*COMMAND=.*',
                r'su.*session opened',
                r'USER_AUTH.*su.*',
                r'CRON.*root.*'
            ],
            'suspicious_commands': [
                r'wget.*http',
                r'curl.*http',
                r'nc.*-l.*',
                r'python.*-c.*',
                r'bash.*-i.*',
                r'sh.*-i.*'
            ],
            'file_access': [
                r'opened.*\/etc\/passwd',
                r'opened.*\/etc\/shadow',
                r'opened.*\/etc\/sudoers',
                r'accessed.*\/var\/log\/'
            ],
            'network_activity': [
                r'connection.*refused',
                r'port.*blocked',
                r'firewall.*denied',
                r'intrusion.*detected'
            ]
        }
        return patterns
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                        SECURITY LOG ANALYZER                                                         ║
║                                     Professional Threat Detection                                                    ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def parse_log_entry(self, line):
        """Parse a single log entry and extract relevant information"""
        # Common log formats
        patterns = {
            'syslog': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(.+)',
            'auth': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+):\s*(.+)',
            'apache': r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*"([^"]+)".*(\d+)',
            'nginx': r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*"([^"]+)".*(\d+)'
        }
        
        entry = {
            'timestamp': None,
            'host': None,
            'service': None,
            'message': line.strip(),
            'ip_address': None,
            'user': None,
            'severity': 'info'
        }
        
        # Try to match different log formats
        for format_name, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                if format_name in ['syslog', 'auth']:
                    entry['timestamp'] = match.group(1)
                    entry['host'] = match.group(2)
                    entry['service'] = match.group(3) if len(match.groups()) > 3 else None
                    entry['message'] = match.group(4) if len(match.groups()) > 3 else match.group(3)
                break
        
        # Extract IP addresses
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            entry['ip_address'] = ip_match.group(1)
        
        # Extract usernames
        user_patterns = [
            r'user\s+(\w+)',
            r'for\s+(\w+)',
            r'USER=(\w+)',
            r'login:\s*(\w+)'
        ]
        for pattern in user_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                entry['user'] = match.group(1)
                break
        
        return entry
    
    def analyze_failed_logins(self, entries):
        """Analyze failed login attempts for brute force attacks"""
        failed_logins = defaultdict(list)
        
        for entry in entries:
            message = entry['message'].lower()
            
            # Check for failed login patterns
            failed_patterns = [
                'failed password',
                'authentication failure',
                'invalid user',
                'failed login',
                'login failed',
                'access denied'
            ]
            
            if any(pattern in message for pattern in failed_patterns):
                ip = entry['ip_address']
                user = entry['user']
                timestamp = entry['timestamp']
                
                if ip:
                    failed_logins[ip].append({
                        'timestamp': timestamp,
                        'user': user,
                        'message': entry['message']
                    })
        
        # Identify brute force attacks
        brute_force_attacks = []
        for ip, attempts in failed_logins.items():
            if len(attempts) >= self.failed_login_threshold:
                brute_force_attacks.append({
                    'ip': ip,
                    'attempts': len(attempts),
                    'users_targeted': len(set(a['user'] for a in attempts if a['user'])),
                    'first_attempt': attempts[0]['timestamp'],
                    'last_attempt': attempts[-1]['timestamp'],
                    'details': attempts
                })
        
        return brute_force_attacks
    
    def analyze_suspicious_patterns(self, entries):
        """Analyze logs for suspicious patterns"""
        suspicious_activities = []
        
        for entry in entries:
            message = entry['message']
            
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, message, re.IGNORECASE)
                    if match:
                        suspicious_activities.append({
                            'category': category,
                            'pattern': pattern,
                            'match': match.group(0),
                            'ip': entry['ip_address'],
                            'user': entry['user'],
                            'timestamp': entry['timestamp'],
                            'full_message': message
                        })
        
        return suspicious_activities
    
    def analyze_ip_addresses(self, entries):
        """Analyze IP addresses for geographic and reputation information"""
        ip_stats = defaultdict(lambda: {
            'count': 0,
            'users': set(),
            'activities': [],
            'first_seen': None,
            'last_seen': None
        })
        
        for entry in entries:
            ip = entry['ip_address']
            if ip and self.is_valid_ip(ip):
                ip_stats[ip]['count'] += 1
                if entry['user']:
                    ip_stats[ip]['users'].add(entry['user'])
                ip_stats[ip]['activities'].append(entry['message'])
                
                # Track time window
                if not ip_stats[ip]['first_seen']:
                    ip_stats[ip]['first_seen'] = entry['timestamp']
                ip_stats[ip]['last_seen'] = entry['timestamp']
        
        return dict(ip_stats)
    
    def is_valid_ip(self, ip):
        """Check if IP address is valid and not private"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            nums = [int(part) for part in parts]
            if not all(0 <= num <= 255 for num in nums):
                return False
                
            # Skip private IP ranges
            if (nums[0] == 10 or
                (nums[0] == 172 and 16 <= nums[1] <= 31) or
                (nums[0] == 192 and nums[1] == 168)):
                return False
            
            return True
        except ValueError:
            return False
    
    def detect_attack_patterns(self, entries):
        """Detect common attack patterns"""
        attack_patterns = []
        
        # Time-based analysis
        time_windows = defaultdict(list)
        for entry in entries:
            # Group by minute for analysis
            if entry['timestamp']:
                time_key = entry['timestamp'][:16]  # YYYY-MM-DD HH:MM
                time_windows[time_key].append(entry)
        
        # Detect rapid-fire attacks
        for time_window, window_entries in time_windows.items():
            if len(window_entries) > 20:  # More than 20 events per minute
                attack_patterns.append({
                    'type': 'rapid_fire',
                    'time_window': time_window,
                    'event_count': len(window_entries),
                    'unique_ips': len(set(e['ip_address'] for e in window_entries if e['ip_address'])),
                    'description': f'High activity detected: {len(window_entries)} events in 1 minute'
                })
        
        # Detect distributed attacks
        ip_activity = defaultdict(int)
        for entry in entries:
            if entry['ip_address']:
                ip_activity[entry['ip_address']] += 1
        
        if len(ip_activity) > 50:  # Many different IPs
            attack_patterns.append({
                'type': 'distributed_attack',
                'unique_ips': len(ip_activity),
                'total_events': sum(ip_activity.values()),
                'description': f'Distributed attack detected: {len(ip_activity)} unique IPs'
            })
        
        return attack_patterns
    
    def generate_security_alerts(self, analysis_results):
        """Generate security alerts based on analysis"""
        alerts = []
        
        # High-priority alerts
        if analysis_results['brute_force']:
            for attack in analysis_results['brute_force']:
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'Brute Force Attack',
                    'description': f"Brute force attack from {attack['ip']} - {attack['attempts']} failed attempts",
                    'recommendation': 'Block IP address and investigate user accounts'
                })
        
        if analysis_results['attack_patterns']:
            for pattern in analysis_results['attack_patterns']:
                alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Attack Pattern',
                    'description': pattern['description'],
                    'recommendation': 'Investigate and implement rate limiting'
                })
        
        # Suspicious activity alerts
        suspicious_count = len(analysis_results['suspicious_activities'])
        if suspicious_count > 10:
            alerts.append({
                'severity': 'MEDIUM',
                'type': 'Suspicious Activity',
                'description': f'{suspicious_count} suspicious activities detected',
                'recommendation': 'Review suspicious activities and implement monitoring'
            })
        
        return alerts
    
    def analyze_log_file(self, file_path):
        """Analyze a single log file"""
        if not os.path.exists(file_path):
            print(f"{Fore.RED}Error: Log file '{file_path}' not found{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}Analyzing log file: {file_path}{Style.RESET_ALL}")
        
        entries = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        entry = self.parse_log_entry(line)
                        entry['line_number'] = line_num
                        entries.append(entry)
        except Exception as e:
            print(f"{Fore.RED}Error reading log file: {e}{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.YELLOW}Parsed {len(entries)} log entries{Style.RESET_ALL}")
        
        # Perform analysis
        print(f"{Fore.CYAN}Performing security analysis...{Style.RESET_ALL}")
        
        analysis_results = {
            'file_path': file_path,
            'total_entries': len(entries),
            'brute_force': self.analyze_failed_logins(entries),
            'suspicious_activities': self.analyze_suspicious_patterns(entries),
            'ip_analysis': self.analyze_ip_addresses(entries),
            'attack_patterns': self.detect_attack_patterns(entries),
            'timestamp': datetime.now().isoformat()
        }
        
        # Generate alerts
        analysis_results['alerts'] = self.generate_security_alerts(analysis_results)
        
        return analysis_results
    
    def display_results(self, results):
        """Display analysis results in a formatted way"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                                           ANALYSIS RESULTS                                                          ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}File:{Style.RESET_ALL} {results['file_path']}")
        print(f"{Fore.YELLOW}Total Entries:{Style.RESET_ALL} {results['total_entries']:,}")
        print(f"{Fore.YELLOW}Analysis Time:{Style.RESET_ALL} {results['timestamp']}")
        
        # Security Alerts
        if results['alerts']:
            print(f"\n{Fore.RED}🚨 SECURITY ALERTS:{Style.RESET_ALL}")
            for alert in results['alerts']:
                color = Fore.RED if alert['severity'] == 'HIGH' else Fore.YELLOW
                print(f"  {color}[{alert['severity']}]{Style.RESET_ALL} {alert['type']}: {alert['description']}")
                print(f"    💡 Recommendation: {alert['recommendation']}")
        
        # Brute Force Attacks
        if results['brute_force']:
            print(f"\n{Fore.RED}🔴 BRUTE FORCE ATTACKS DETECTED:{Style.RESET_ALL}")
            for attack in results['brute_force']:
                print(f"  IP: {Fore.RED}{attack['ip']}{Style.RESET_ALL}")
                print(f"    Failed attempts: {attack['attempts']}")
                print(f"    Users targeted: {attack['users_targeted']}")
                print(f"    Time window: {attack['first_attempt']} - {attack['last_attempt']}")
                print()
        
        # Suspicious Activities
        if results['suspicious_activities']:
            print(f"\n{Fore.YELLOW}⚠️  SUSPICIOUS ACTIVITIES:{Style.RESET_ALL}")
            
            # Group by category
            by_category = defaultdict(list)
            for activity in results['suspicious_activities']:
                by_category[activity['category']].append(activity)
            
            for category, activities in by_category.items():
                print(f"  {Fore.YELLOW}{category.replace('_', ' ').title()}:{Style.RESET_ALL} {len(activities)} incidents")
                for activity in activities[:3]:  # Show first 3
                    print(f"    • {activity['match']} (IP: {activity['ip'] or 'N/A'})")
                if len(activities) > 3:
                    print(f"    ... and {len(activities) - 3} more")
                print()
        
        # IP Analysis
        if results['ip_analysis']:
            print(f"\n{Fore.CYAN}🌐 IP ADDRESS ANALYSIS:{Style.RESET_ALL}")
            
            # Sort by activity count
            sorted_ips = sorted(results['ip_analysis'].items(), 
                              key=lambda x: x[1]['count'], reverse=True)
            
            for ip, stats in sorted_ips[:10]:  # Show top 10
                print(f"  {Fore.CYAN}{ip}{Style.RESET_ALL}: {stats['count']} events")
                if stats['users']:
                    users_list = list(stats['users'])
                    print(f"    Users: {', '.join(users_list[:3])}")
                    if len(users_list) > 3:
                        print(f"    ... and {len(users_list) - 3} more users")
        
        # Attack Patterns
        if results['attack_patterns']:
            print(f"\n{Fore.MAGENTA}🎯 ATTACK PATTERNS:{Style.RESET_ALL}")
            for pattern in results['attack_patterns']:
                print(f"  {Fore.MAGENTA}{pattern['type'].replace('_', ' ').title()}:{Style.RESET_ALL}")
                print(f"    {pattern['description']}")
                print()
        
        # Summary
        print(f"\n{Fore.GREEN}📊 SUMMARY:{Style.RESET_ALL}")
        print(f"  • {len(results['brute_force'])} brute force attacks")
        print(f"  • {len(results['suspicious_activities'])} suspicious activities")
        print(f"  • {len(results['ip_analysis'])} unique IP addresses")
        print(f"  • {len(results['attack_patterns'])} attack patterns")
        print(f"  • {len(results['alerts'])} security alerts")
    
    def export_results(self, results, output_file):
        """Export results to JSON file"""
        # Convert sets to lists for JSON serialization
        json_results = json.loads(json.dumps(results, default=str))
        
        try:
            with open(output_file, 'w') as f:
                json.dump(json_results, f, indent=2)
            print(f"{Fore.GREEN}Results exported to: {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error exporting results: {e}{Style.RESET_ALL}")
    
    def monitor_log_file(self, file_path, interval=5):
        """Monitor log file for real-time analysis"""
        print(f"{Fore.CYAN}Monitoring log file: {file_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop monitoring{Style.RESET_ALL}")
        
        if not os.path.exists(file_path):
            print(f"{Fore.RED}Error: Log file '{file_path}' not found{Style.RESET_ALL}")
            return
        
        # Get initial file size
        last_size = os.path.getsize(file_path)
        
        try:
            while True:
                current_size = os.path.getsize(file_path)
                
                if current_size > last_size:
                    # File has grown, analyze new content
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        new_lines = f.readlines()
                    
                    if new_lines:
                        print(f"\n{Fore.YELLOW}New log entries detected:{Style.RESET_ALL}")
                        
                        # Analyze new lines
                        entries = []
                        for line in new_lines:
                            if line.strip():
                                entry = self.parse_log_entry(line)
                                entries.append(entry)
                        
                        # Quick analysis of new entries
                        if entries:
                            brute_force = self.analyze_failed_logins(entries)
                            suspicious = self.analyze_suspicious_patterns(entries)
                            
                            if brute_force:
                                print(f"{Fore.RED}🚨 BRUTE FORCE DETECTED:{Style.RESET_ALL}")
                                for attack in brute_force:
                                    print(f"  IP: {attack['ip']} - {attack['attempts']} attempts")
                            
                            if suspicious:
                                print(f"{Fore.YELLOW}⚠️  SUSPICIOUS ACTIVITY:{Style.RESET_ALL}")
                                for activity in suspicious:
                                    print(f"  {activity['category']}: {activity['match']}")
                    
                    last_size = current_size
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}Monitoring stopped{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Security Log Analyzer')
    parser.add_argument('logfile', nargs='?', help='Log file to analyze')
    parser.add_argument('-m', '--monitor', action='store_true', help='Monitor log file in real-time')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-i', '--interval', type=int, default=5, help='Monitoring interval in seconds')
    parser.add_argument('--threshold', type=int, default=5, help='Failed login threshold for brute force detection')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    analyzer.print_banner()
    
    if args.threshold:
        analyzer.failed_login_threshold = args.threshold
    
    if not args.logfile:
        print(f"{Fore.RED}Error: Please specify a log file to analyze{Style.RESET_ALL}")
        print(f"Usage: {sys.argv[0]} /path/to/logfile.log")
        sys.exit(1)
    
    if args.monitor:
        analyzer.monitor_log_file(args.logfile, args.interval)
    else:
        results = analyzer.analyze_log_file(args.logfile)
        if results:
            analyzer.display_results(results)
            
            if args.output:
                analyzer.export_results(results, args.output)

if __name__ == "__main__":
    main()
