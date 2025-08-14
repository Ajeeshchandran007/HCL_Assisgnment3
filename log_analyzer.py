from collections import Counter
import csv
import re

def analyze_log_file(log_file_path, output_csv_path):
    # Regular expression pattern for IP addresses
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    # Dictionary to store IP counts using Counter for efficient counting
    ip_counter = Counter()
    
    try:
        # Read the log file and count IPs
        with open(log_file_path, 'r') as file:
            for line in file:
                # Find IP address in the line
                match = re.search(ip_pattern, line)
                if match:
                    ip = match.group(1)
                    ip_counter[ip] += 1
        
        # Get the top 5 IPs by request count
        top_5_ips = ip_counter.most_common(5)
        
        # Write results to CSV
        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header
            writer.writerow(['IP Address', 'Request Count'])
            # Write all IP addresses and their counts
            for ip, count in ip_counter.items():
                writer.writerow([ip, count])
        
        print(f"Analysis complete! Results saved to {output_csv_path}")
        print("\nTop 5 IPs by request count:")
        for ip, count in top_5_ips:
            print(f"IP: {ip}, Requests: {count}")
            
    except FileNotFoundError:
        print(f"Error: Could not find the log file: {log_file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    log_file = "access.log"
    output_file = "ip_analysis.csv"
    analyze_log_file(log_file, output_file)
