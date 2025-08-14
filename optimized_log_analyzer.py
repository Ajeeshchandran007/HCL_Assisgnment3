from collections import Counter, defaultdict, namedtuple
import csv
import re
from datetime import datetime
from typing import Dict, List, Tuple, Generator
from pathlib import Path
import concurrent.futures
from itertools import islice

# Create a named tuple for parsed log entries
LogEntry = namedtuple('LogEntry', ['ip', 'timestamp', 'request', 'status', 'bytes'])

class LogAnalyzer:
    def __init__(self, log_file_path: str):
        self.log_file_path = Path(log_file_path)
        # Compile regex patterns for better performance
        self.log_pattern = re.compile(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'\s+-\s+-\s+'
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]\s+'  # DateTime
            r'"([^"]+)"\s+'  # Request
            r'(\d{3})\s+'    # Status
            r'(\d+)'         # Bytes
        )

    def parse_log_line(self, line: str) -> LogEntry:
        """Parse a single log line and return structured data using named tuple."""
        match = self.log_pattern.match(line)
        if match:
            ip, date_str, request, status, bytes_sent = match.groups()
            try:
                timestamp = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')
                return LogEntry(
                    ip=ip,
                    timestamp=timestamp,
                    request=request,
                    status=int(status),
                    bytes=int(bytes_sent)
                )
            except ValueError:
                return None
        return None

    def process_chunk(self, chunk: List[str]) -> Tuple[Counter, Dict, Dict, Dict]:
        """Process a chunk of log lines."""
        ip_counter = Counter()
        status_by_ip = defaultdict(Counter)
        requests_by_ip = defaultdict(list)
        bytes_by_ip = defaultdict(int)

        for line in chunk:
            entry = self.parse_log_line(line)
            if entry:
                ip_counter[entry.ip] += 1
                status_by_ip[entry.ip][entry.status] += 1
                requests_by_ip[entry.ip].append(entry.request)
                bytes_by_ip[entry.ip] += entry.bytes

        return ip_counter, status_by_ip, requests_by_ip, bytes_by_ip

    def chunk_reader(self, chunk_size: int = 1000) -> Generator[List[str], None, None]:
        """Read the log file in chunks for parallel processing."""
        with open(self.log_file_path, 'r') as file:
            while True:
                chunk = list(islice(file, chunk_size))
                if not chunk:
                    break
                yield chunk

    def analyze_logs(self) -> Tuple[Counter, Dict, Dict, Dict]:
        """Analyze logs using parallel processing."""
        total_ip_counter = Counter()
        total_status_by_ip = defaultdict(Counter)
        total_requests_by_ip = defaultdict(list)
        total_bytes_by_ip = defaultdict(int)

        # Process chunks in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_chunk = {
                executor.submit(self.process_chunk, chunk): chunk 
                for chunk in self.chunk_reader()
            }

            for future in concurrent.futures.as_completed(future_to_chunk):
                ip_counter, status_by_ip, requests_by_ip, bytes_by_ip = future.result()
                total_ip_counter.update(ip_counter)
                
                for ip, counters in status_by_ip.items():
                    total_status_by_ip[ip].update(counters)
                
                for ip, requests in requests_by_ip.items():
                    total_requests_by_ip[ip].extend(requests[:3])  # Keep only up to 3 samples
                
                for ip, bytes_sent in bytes_by_ip.items():
                    total_bytes_by_ip[ip] += bytes_sent

        return total_ip_counter, total_status_by_ip, total_requests_by_ip, total_bytes_by_ip

    def save_analysis(self, output_file: str):
        """Save detailed analysis to CSV file with additional metrics."""
        ip_counter, status_by_ip, requests_by_ip, bytes_by_ip = self.analyze_logs()
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header with additional columns
            writer.writerow([
                'IP Address', 'Total Requests', '200 Responses', 
                'Other Responses', 'Total Bytes', 'Avg Bytes/Request',
                'Sample Requests'
            ])
            
            # Write data for each IP
            for ip, count in ip_counter.most_common():
                status_counts = status_by_ip[ip]
                ok_responses = status_counts[200]
                other_responses = sum(v for k, v in status_counts.items() if k != 200)
                total_bytes = bytes_by_ip[ip]
                avg_bytes = total_bytes // count if count > 0 else 0
                
                # Get up to 3 sample requests for this IP
                sample_requests = '; '.join(requests_by_ip[ip][:3])
                
                writer.writerow([
                    ip, count, ok_responses, other_responses,
                    total_bytes, avg_bytes, sample_requests
                ])
        
        # Print summary with additional statistics
        print("\nAnalysis Summary:")
        print("-" * 50)
        print(f"Total Unique IPs: {len(ip_counter)}")
        print("\nTop 5 IPs by request count:")
        for ip, count in ip_counter.most_common(5):
            print(f"IP: {ip}")
            print(f"  Total Requests: {count}")
            print(f"  Status Codes: {dict(status_by_ip[ip])}")
            print(f"  Total Bytes: {bytes_by_ip[ip]:,} bytes")
            print(f"  Avg Bytes/Request: {bytes_by_ip[ip] // count:,} bytes")
            print(f"  Sample Request: {requests_by_ip[ip][0] if requests_by_ip[ip] else 'N/A'}")
            print()

if __name__ == "__main__":
    analyzer = LogAnalyzer("access.log")
    analyzer.save_analysis("detailed_ip_analysis.csv")
