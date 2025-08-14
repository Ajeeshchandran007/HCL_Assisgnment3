# Log Analysis Tools

This repository contains three implementations of a log analyzer with increasing levels of sophistication and optimization.

## Overview

The project provides three different implementations for analyzing web server access logs:

1. `log_analyzer.py` - Basic implementation
2. `enhanced_log_analyzer.py` - Enhanced version with additional features
3. `optimized_log_analyzer.py` - Fully optimized version with parallel processing

## Features Comparison

### 1. Basic Log Analyzer (`log_analyzer.py`)
- Simple IP address counting
- Basic CSV output
- Single-pass processing
- Output: `ip_analysis.csv`
  - IP Address
  - Request Count

### 2. Enhanced Log Analyzer (`enhanced_log_analyzer.py`)
- More detailed analysis
- Request type tracking
- HTTP status code analysis
- Sample request storage
- Output: `detailed_ip_analysis.csv`
  - IP Address
  - Total Requests
  - 200 Responses
  - Other Responses
  - Sample Requests

### 3. Optimized Log Analyzer (`optimized_log_analyzer.py`)
- Parallel processing with ThreadPoolExecutor
- Memory-efficient chunk processing
- Structured data using namedtuples
- Enhanced regex parsing
- Comprehensive metrics
- Output: `detailed_ip_analysis.csv`
  - IP Address
  - Total Requests
  - 200 Responses
  - Other Responses
  - Total Bytes
  - Average Bytes/Request
  - Sample Requests

## Technical Details

### Optimized Features

1. **Efficient Data Structures**
   - `Counter` for IP address counting
   - `defaultdict` for status codes and requests
   - `namedtuple` for structured log entries

2. **Performance Optimizations**
   - Pre-compiled regex patterns
   - Parallel chunk processing
   - Generator-based file reading
   - Memory-efficient processing

3. **Input Processing**
   - Handles standard Apache/Nginx log formats
   - Robust datetime parsing
   - Error handling for malformed entries

### Log Format Support

The analyzers support the standard Apache/Nginx log format:
```
IP - - [timestamp] "REQUEST" STATUS BYTES
```

Example:
```
192.168.1.100 - - [13/Aug/2025:10:00:01 -0400] "GET /index.html HTTP/1.1" 200 2326
```

## Usage

1. **Basic Analysis**
```python
python log_analyzer.py
```

2. **Enhanced Analysis**
```python
python enhanced_log_analyzer.py
```

3. **Optimized Analysis**
```python
python optimized_log_analyzer.py
```

## Output Files

1. `ip_analysis.csv`: Basic IP address count
2. `detailed_ip_analysis.csv`: Comprehensive analysis with all metrics

## Requirements

- Python 3.6+
- Standard library modules only:
  - collections
  - csv
  - re
  - datetime
  - concurrent.futures
  - itertools
  - pathlib

## Implementation Details

### Regex Pattern
```python
r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
r'\s+-\s+-\s+'
r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]\s+'  # DateTime
r'"([^"]+)"\s+'  # Request
r'(\d{3})\s+'    # Status
r'(\d+)'         # Bytes
```

### Data Processing Pipeline
1. Read log file in chunks
2. Parse log entries using regex
3. Process data in parallel
4. Aggregate results
5. Generate CSV output

## Performance Considerations

- Uses parallel processing for large log files
- Memory-efficient chunk processing
- Optimized data structures
- Pre-compiled regex patterns

## Example Output

```plaintext
Analysis Summary:
--------------------------------------------------
Total Unique IPs: 22
Top 5 IPs by request count:
IP: 192.168.1.100
  Total Requests: 5
  Status Codes: {200: 5}
  Total Bytes: 16,662 bytes
  Avg Bytes/Request: 3,332 bytes
  Sample Request: GET /index.html HTTP/1.1
```
