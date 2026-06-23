# PortSi - Professional Vulnerability Assessment Tool

PortSi is a high-performance, production-hardened network security auditing tool developed in Python. It combines multi-layered socket scanning capabilities with real-time National Vulnerability Database (NVD) API intelligence to generate comprehensive baseline perimeter defense assessments.

A vulnerability scanner demonstrating clean architecture, comprehensive security analysis, and executive-level reporting.

## Key Features
* **Adaptive Scanning Delay:** Built-in rate limiting (0.1s to 0.2s connection pacing) to ensure fast socket scans do not trigger network firewalls or simulate Denial of Service (DoS) attack structures on live enterprise assets.
* **Resilient Threat Intel:** Deep integration with the NVD API featuring structured try-except blocks, graceful HTTP 424/429 rate-limit handling, exponential backoff, and clean warnings instead of execution crashes.
* **Automated Report Generation:** Compiles findings instantly into professional, production-ready PDF vulnerability logs using ReportLab templates with automated HTML/XML escaping to handle raw API responses safely.

## Architecture & Tech Stack
* **Core Language:** Python 3.12+ (Fully typed with strict Type Hints)
* **Network Auditing:** `nmap` binaries & `python-nmap` integration
* **Reporting Engine:** `reportlab` with customized flowables and defensive styling
* **API Integrations:** `requests` with dynamic query management


## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    main.py (Orchestration)                  │
│                  ├── Argument parsing (argparse)            │
│                  └── Pipeline coordination                  │
└─────────────────────────────────────────────────────────────┘
                         │
                         ↓
┌────────────────────────────────────────────────────────────┐
│          scanner.py (Reconnaissance)                       │
│  ├── Target validation (socket, ipaddress, DNS)            │
│  ├── Fast socket scan (multi-threaded)                     │
│  └── Nmap service fingerprinting (-sV -O -T4)              │
└────────────────────────────────────────────────────────────┘
                         │
                         ↓
┌────────────────────────────────────────────────────────────┐
│      vnum_checker.py (Vulnerability Analysis)              │
│  ├── NIST NVD API v2 queries                               │
│  ├── Exponential backoff retry (rate limiting)             │
│  └── Fallback to local vulnerability database              │
└────────────────────────────────────────────────────────────┘
                         │
                         ↓
┌────────────────────────────────────────────────────────────┐
│        reporter.py (Report Generation)                     │
│  ├── ReportLab PDF generation                              │
│  ├── Executive summary metrics                             │
│  ├── Detailed findings table                               │ 
│  └── CVE details with CVSS scores                          │
└────────────────────────────────────────────────────────────┘
                         │
                         ↓
                  ✓ scan_report_*.pdf
```

## Module Details

### scanner.py (Reconnaissance)
- **validate_target(target: str) → str**
  - Validates IPv4/IPv6 addresses and hostnames
  - Rejects loopback addresses (127.0.0.0/8, ::1)
  - Prevents command injection via input sanitization
  - Performs DNS resolution for hostnames

- **fast_socket_scan(target: str, ports: List[int]) → List[int]**
  - Multi-threaded TCP connect scan using ThreadPoolExecutor
  - Default: Top 20 common ports
  - Timeout: 2 seconds per port
  - Returns list of open ports sorted numerically

- **run_nmap_scan(target: str, open_ports: List[int]) → Dict[int, Dict[str, Any]]**
  - Deep service fingerprinting with Nmap
  - Arguments: `-sV` (service version), `-O` (OS detection), `-T4` (speed)
  - Returns: {port: {service, version, cpe, state}}

### vnum_checker.py (Vulnerability Analysis)
- **fetch_cves_for_service(cpe_string: str, keyword: str) → List[Dict]**
  - Queries NIST NVD API v2 endpoint
  - Exponential backoff: 1s, 2s, 4s for HTTP 429 (rate limited)
  - Fallback to local database on persistent API failures
  - Returns: [{cve_id, cvss_score, severity, description}, ...]

- **FallbackVulnerabilityDB()**
  - Local JSON database of known critical vulnerabilities
  - Covers: Apache, OpenSSL, MySQL, SSH, nginx
  - Activated when NVD API is unavailable

### reporter.py (Report Generation)
- **VulnerabilityReport.generate_pdf() → str**
  - ReportLab-based PDF generation
  - Custom color palette (Dark Slate Gray, Crimson Red)
  - Sections:
    - Header: Target, timestamp
    - Executive Summary: Metrics table
    - Detailed Findings: Ports, services, CVEs, CVSS scores
    - CVE Details: Full vulnerability listing
  - Output: `scan_report_[target]_[timestamp].pdf`

### main.py (Orchestration)
- **VulnerabilityScanner.execute()**
  - Coordinates complete pipeline
  - Stages: validation → socket scan → nmap → CVE analysis → reporting
  - Graceful error handling
  - Detailed logging with timestamps


### Virtual Environment Setup & Dependency Installation

#### MacOS Setup
```bash
# Activate existing virtual environment
source env/bin/activate

# Verify Python version
python --version # Should be 3.12.4

# Install Dependencies
pip install --upgrade pip
pip install nmap requests pillow reportlab

# Verify Nmap Installation
which nmap
nmap --version # Should show 7.x or later
```

#### Windows Setup
```bash
# Activate existing virtual environment
call env\Scripts\activate

# Verify Python version
python --version

# Install Dependencies
python -m pip install --upgrade pip
pip install nmap requests pillow reportlab

# Verify Nmap Installation
where nmap
nmap --version
```

#### Linux Setup
```bash
# Activate existing virtual environment
source env/bin/activate

# Verify Python version
python3 --version

# Install Dependencies
pip install --upgrade pip
pip install nmap requests pillow reportlab

# Verify Nmap Installation
which nmap
nmap --version
```

---

## Usage

### Basic Scan
```bash
python main.py --target 192.168.1.1
```

### Scan with Custom Ports
```bash
python main.py --target example.com --ports 22,80,443,3306,5432
```

### Verbose Logging
```bash
python main.py --target 10.0.0.5 --verbose
```

### Hostname Scanning
```bash
python main.py --target example.com
```

## Output

### Log File
- `vuln_scanner.log` - Complete execution logs with timestamps

### PDF Report
- `scan_report_[target]_[timestamp].pdf`
- Example: `scan_report_192.168.1.1_20260621_143022.pdf`

### Report Contents
```
┌─────────────────────────────────────┐
│  VULNERABILITY SCAN REPORT          │
├─────────────────────────────────────┤
│  Target: 192.168.1.1                │
│  Date: 2026-06-21 14:30:22          │
├─────────────────────────────────────┤
│  EXECUTIVE SUMMARY                  │
│  ├─ Total Open Ports: 5             │
│  ├─ Total CVEs Found: 12            │
│  ├─ Critical: 2                     │
│  ├─ High: 4                         │
│  ├─ Medium: 5                       │
│  └─ Low: 1                          │
├─────────────────────────────────────┤
│  DETAILED FINDINGS                  │
│  Port │ Service │ Version │ CVSS    │
│─────────────────────────────────────│
│  22   │ SSH     │ 7.4     │ 7.5/H   │
│  80   │ HTTP    │ 1.1     │ 9.8/C   │
│  443  │ HTTPS   │ TLS 1.2 │ 5.3/M   │
│       │ ...     │ ...     │ ...     │
├─────────────────────────────────────┤
│  CVE DETAILS                        │
│  CVE-2021-44228    │  10.0 │CRITICAL│
│  CVE-2021-3129     │  9.8  │CRITICAL│
│       ...          │  ...  │  ...   │
└─────────────────────────────────────┘
```

## Security Features

1. **Input Validation**
   - Character whitelist (alphanumerics, dots, hyphens, colons)
   - Length constraints (max 255 characters)
   - IPv4/IPv6/hostname validation
   - Loopback address rejection

2. **Command Injection Prevention**
   - No raw shell execution
   - Safe argument passing to Nmap via python-nmap library
   - Input sanitization before any system calls

3. **Network Security**
   - Socket connection timeouts (2 seconds)
   - Context managers for resource cleanup
   - HTTPS for NVD API queries
   - User-Agent headers for API requests

4. **Data Integrity**
   - Structured exception handling
   - Validation of service versions before CVE lookup
   - Graceful degradation with fallback mechanisms

5. **Logging & Audit Trail**
   - Comprehensive logging to file and console
   - Timestamps on all operations
   - No sensitive data in logs
   - DEBUG and INFO levels for diagnostic capability

## Error Handling

### Graceful Degradation
- If Nmap fails: Reports socket scan results only
- If NVD API fails: Falls back to local vulnerability database
- If service version unknown: Skips CVE lookup (no false positives)
- Keyboard interrupt (Ctrl+C): Exits cleanly with zero exit code

### Exception Handling Hierarchy
1. **ValueError** - Input validation failures (caught and reported cleanly)
2. **socket.gaierror** - DNS resolution failures
3. **nmap.PortScannerError** - Nmap execution errors
4. **requests.RequestException** - Network/API errors
5. **KeyboardInterrupt** - User termination

## Performance Characteristics

- **Socket Scan**: ~2-5 seconds (10 concurrent threads × 2s timeout)
- **Nmap Scan**: 30-120 seconds (depends on port count and timing template)
- **CVE Lookup**: 5-15 seconds per service (API queries + retries)
- **Report Generation**: 1-2 seconds
- **Total Scan Time**: 5-15 minutes (typical network, varies by system count)

## Logging Format

```
2026-06-21 14:30:22,123 - scanner - INFO - Validating target: 192.168.1.1
2026-06-21 14:30:22,456 - scanner - INFO - Valid IP address: 192.168.1.1
2026-06-21 14:30:22,789 - scanner - INFO - Starting fast socket scan on 192.168.1.1 for 20 ports
2026-06-21 14:30:25,012 - scanner - INFO - Fast socket scan completed. Open ports: [22, 80, 443]
2026-06-21 14:30:25,345 - scanner - INFO - Starting Nmap scan on 192.168.1.1 for ports: 22,80,443
```

## Troubleshooting

### "Nmap: command not found"
```bash
brew install nmap
# Verify
which nmap
nmap --version
```

### "Permission denied" on socket scan
```bash
# Some ports require elevated privileges
sudo python main.py --target 192.168.1.1
```

### NVD API Rate Limiting (429 Errors)
- Automatic exponential backoff: 1s, 2s, 4s delays
- Falls back to local database after retries
- Check logs for details: `grep -i "rate limit" vuln_scanner.log`

### "Connection refused" on Nmap execution
- Verify nmap is installed: `which nmap`
- Verify nmap is executable: `ls -la /usr/local/bin/nmap`
- Reinstall if needed: `brew reinstall nmap`

## Code Quality Standards

✓ **Type Hints**: All functions fully typed (Python 3.12+)
✓ **Logging**: Professional logging instead of print statements
✓ **Error Handling**: Comprehensive exception handling with context
✓ **Security**: Input validation, injection prevention, secure APIs
✓ **Modularity**: Clean separation of concerns across 4 modules
✓ **Documentation**: Docstrings, inline comments, comprehensive README
✓ **Resource Management**: Context managers (with statements) throughout
✓ **Exit Codes**: Proper exit codes (0=success, 1=failure)

## Portfolio Highlights

1. **Enterprise Architecture**: Modular design, clean separation of concerns
2. **Security Engineering**: Input validation, injection prevention, secure defaults
3. **API Integration**: NVD API v2 with rate limiting and fallback mechanisms
4. **Concurrent Programming**: Multi-threaded socket scanning
5. **Professional Reporting**: PDF generation with ReportLab styling
6. **Error Resilience**: Exponential backoff, graceful degradation
7. **Logging & Observability**: Comprehensive audit trails
8. **Python Best Practices**: Type hints, context managers, comprehensions

## References

- [NVD API v2 Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [python-nmap Documentation](https://xael.org/pages/python-nmap-en.html)
- [ReportLab Documentation](https://www.reportlab.com/docs/reportlab-userguide.pdf)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

## License

This project is provided as-is for portfolio demonstration purposes.

## Author

VulnScanner 1.0 - Cybersecurity Engineer Portfolio Project
