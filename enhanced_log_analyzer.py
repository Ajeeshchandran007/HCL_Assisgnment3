from collections import Counter, defaultdict
import csv
import re
from datetime import datetime
from typing import Dict, List, Tuple

class LogAnalyzer:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        # Compile regex patterns for better performance
        self.ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        self.datetime_pattern = re.compile(r'\[(.*?)\]')
        self.request_pattern = re.compile(r'"([^"]*)"')
        self.status_pattern = re.compile(r'" (\d{3}) ')

    def parse_log_line(self, line: str) -> dict:
        """Parse a single log line and return structured data."""
        data = {}
        
        # Extract IP
        ip_match = self.ip_pattern.search(line)
        if ip_match:
            data['ip'] = ip_match.group(1)
        
        # Extract datetime
        datetime_match = self.datetime_pattern.search(line)
        if datetime_match:
            try:
                date_str = datetime_match.group(1)
                data['timestamp'] = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                data['timestamp'] = None
        
        # Extract request
        request_match = self.request_pattern.search(line)
        if request_match:
            data['request'] = request_match.group(1)
        
        # Extract status code
        status_match = self.status_pattern.search(line)
        if status_match:
            data['status'] = int(status_match.group(1))
        
        return data

    def analyze_logs(self) -> Tuple[Counter, Dict, Dict]:
        """Analyze logs and return multiple metrics."""
        ip_counter = Counter()
        status_by_ip = defaultdict(Counter)
        requests_by_ip = defaultdict(list)
        
        with open(self.log_file_path, 'r') as file:
            for line in file:
                data = self.parse_log_line(line)
                if 'ip' in data:
                    ip = data['ip']
                    ip_counter[ip] += 1
                    
                    if 'status' in data:
                        status_by_ip[ip][data['status']] += 1
                    
                    if 'request' in data:
                        requests_by_ip[ip].append(data['request'])
        
        return ip_counter, status_by_ip, requests_by_ip

    def save_analysis(self, output_file: str):
        """Save detailed analysis to CSV file."""
        ip_counter, status_by_ip, requests_by_ip = self.analyze_logs()
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header
            writer.writerow(['IP Address', 'Total Requests', '200 Responses', 'Other Responses', 'Sample Requests'])
            
            # Write data for each IP
            for ip, count in ip_counter.most_common():
                status_counts = status_by_ip[ip]
                ok_responses = status_counts[200]
                other_responses = sum(v for k, v in status_counts.items() if k != 200)
                
                # Get up to 3 sample requests for this IP
                sample_requests = '; '.join(requests_by_ip[ip][:3])
                
                writer.writerow([ip, count, ok_responses, other_responses, sample_requests])
        
        # Print summary
        print("\nAnalysis Summary:")
        print("-" * 50)
        print("Top 5 IPs by request count:")
        for ip, count in ip_counter.most_common(5):
            print(f"IP: {ip}")
            print(f"  Total Requests: {count}")
            print(f"  Status Codes: {dict(status_by_ip[ip])}")
            print(f"  Sample Request: {requests_by_ip[ip][0]}")
            print()

if __name__ == "__main__":
    analyzer = LogAnalyzer("access.log")
    analyzer.save_analysis("detailed_ip_analysis.csv")
