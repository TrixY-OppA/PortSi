#!/usr/bin/env python3
"""
VulnScanner - Quick Reference & Usage Examples
This file demonstrates the API usage patterns for the vulnerability scanner.
"""

# =============================================================================
# QUICK START EXAMPLES
# =============================================================================

# Example 1: Basic scanning with default ports
# python main.py --target 192.168.1.1

# Example 2: Custom port list
# python main.py --target example.com --ports 22,80,443,3306,5432

# Example 3: Verbose logging for troubleshooting
# python main.py --target api.example.com --verbose

# =============================================================================
# MODULE API REFERENCE
# =============================================================================

# SCANNER MODULE
# ==============
# from scanner import validate_target, fast_socket_scan, run_nmap_scan

# 1. Validate a target (required for security)
# target = validate_target("192.168.1.1")
# target = validate_target("example.com")  # Hostname with DNS resolution
# target = validate_target("::1")  # IPv6 address

# Raises ValueError for:
# - Loopback addresses (127.0.0.1, ::1)
# - Invalid characters (contains symbols)
# - Unresolvable hostnames

# 2. Fast socket scan (multi-threaded)
# open_ports = fast_socket_scan("192.168.1.1")
# # Returns: [22, 80, 443]  (sorted list of open ports)

# With custom ports:
# open_ports = fast_socket_scan("192.168.1.1", ports=[8080, 9200, 27017])
# # Returns: [9200]  (example: only port 9200 is open)

# 3. Deep Nmap scan with service detection
# results = run_nmap_scan("192.168.1.1", [22, 80, 443])
# # Returns: {
# #   22: {
# #     'service': 'ssh',
# #     'version': 'OpenSSH 7.4',
# #     'cpe': 'cpe:/a:openbsd:openssh:7.4',
# #     'state': 'open'
# #   },
# #   80: {
# #     'service': 'http',
# #     'version': 'Apache httpd 2.4.6',
# #     'cpe': 'cpe:/a:apache:http_server:2.4.6',
# #     'state': 'open'
# #   }
# # }

# VULNERABILITY CHECKER MODULE
# =============================
# from vnum_checker import fetch_cves_for_service

# Fetch CVEs for a service
# cves = fetch_cves_for_service(
#     "cpe:/a:apache:http_server:2.4.6",
#     "Apache"
# )
# # Returns: [
# #   {
# #     'cve_id': 'CVE-2021-44228',
# #     'cvss_score': 10.0,
# #     'severity': 'CRITICAL',
# #     'description': 'Apache Log4j RCE vulnerability...'
# #   },
# #   {...}
# # ]

# Severity levels:
# - CRITICAL: 9.0-10.0
# - HIGH: 7.0-8.9
# - MEDIUM: 4.0-6.9
# - LOW: 0.1-3.9
# - NONE: 0.0

# REPORTER MODULE
# ================
# from reporter import VulnerabilityReport

# Create a report
# report = VulnerabilityReport("192.168.1.1")
# pdf_path = report.generate_pdf(scan_results, vulnerability_data)
# print(f"Report saved to: {pdf_path}")
# # Output: Report saved to: scan_report_192.168.1.1_20260621_143022.pdf

# MAIN ORCHESTRATION
# ===================
# from main import VulnerabilityScanner

# Orchestrate complete pipeline
# scanner = VulnerabilityScanner("192.168.1.1", ports=[22, 80, 443])
# pdf_report = scanner.execute()
# # Automatically runs: validate → socket_scan → nmap → cve_lookup → report

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Logs are written to: vuln_scanner.log
# Format: TIMESTAMP - MODULE - LEVEL - MESSAGE
#
# Example log output:
# 2026-06-21 14:30:22,123 - scanner - INFO - Validating target: 192.168.1.1
# 2026-06-21 14:30:25,456 - scanner - INFO - Fast socket scan completed. Open ports: [22, 80, 443]
# 2026-06-21 14:30:45,789 - vnum_checker - INFO - NVD API returned 8 CVEs for apache:http_server
# 2026-06-21 14:35:30,012 - reporter - INFO - PDF report successfully generated

# Enable DEBUG logging with --verbose flag:
# python main.py --target 192.168.1.1 --verbose

# =============================================================================
# ERROR HANDLING PATTERNS
# =============================================================================

# Input Validation Errors
# Error: Target contains invalid characters
# Solution: Only use alphanumerics, dots, hyphens, colons (e.g., "192.168.1.1" or "my-host.example.com")

# DNS Resolution Errors
# Error: Hostname cannot be resolved
# Solution: Verify hostname is correct and resolvable from your network

# Nmap Execution Errors
# Error: Nmap scan error
# Solution: Ensure nmap is installed (brew install nmap) and in PATH

# NVD API Rate Limiting
# Automatic: Exponential backoff (1s, 2s, 4s delays)
# Fallback: Local vulnerability database is used if API fails

# Permission Errors
# Error: Permission denied on socket operations
# Solution: Use sudo for scanning low-numbered ports (< 1024)

# =============================================================================
# COMMAND-LINE USAGE EXAMPLES
# =============================================================================

# Basic IP scan (IPv4)
# $ python main.py --target 192.168.1.1
# Scan complete! Report: scan_report_192.168.1.1_20260621_143022.pdf

# Hostname scan with DNS resolution
# $ python main.py --target database.internal
# Scan complete! Report: scan_report_database.internal_20260621_143022.pdf

# IPv6 address scan
# $ python main.py --target "2001:db8::1"
# Scan complete! Report: scan_report_2001:db8::1_20260621_143022.pdf

# Custom port specification
# $ python main.py --target 192.168.1.1 --ports 22,80,443,3306,5432
# Scans only ports 22, 80, 443, 3306, 5432 (instead of default top 20)

# Verbose debugging
# $ python main.py --target 192.168.1.1 --verbose
# Outputs DEBUG-level messages for troubleshooting

# Exit codes
# Exit 0: Successful scan (report generated)
# Exit 1: Error during scan (validation, network, API)
# Exit 0: User interrupted (Ctrl+C)

# =============================================================================
# EXPECTED OUTPUT FILES
# =============================================================================

# Log File (always created)
# vuln_scanner.log
#
# Sample output:
# 2026-06-21 14:30:22,123 - __main__ - INFO - Initialized VulnerabilityScanner for target: 192.168.1.1
# 2026-06-21 14:30:22,456 - scanner - INFO - Validating target: 192.168.1.1
# 2026-06-21 14:30:22,789 - scanner - INFO - Valid IP address: 192.168.1.1
# 2026-06-21 14:30:23,012 - scanner - INFO - Starting fast socket scan on 192.168.1.1 for 20 ports
# 2026-06-21 14:30:25,345 - scanner - INFO - Fast socket scan completed. Open ports: [22, 80, 443]
# 2026-06-21 14:30:25,678 - scanner - INFO - Starting Nmap scan on 192.168.1.1 for ports: 22,80,443
# 2026-06-21 14:35:12,890 - scanner - INFO - Nmap scan completed. Found 3 service(s)
# 2026-06-21 14:35:13,123 - __main__ - INFO - Analyzing port 22/ssh (OpenSSH 7.4)...
# 2026-06-21 14:35:20,456 - vnum_checker - INFO - Fetching CVEs for CPE: cpe:/a:openbsd:openssh:7.4
# 2026-06-21 14:35:28,789 - vnum_checker - INFO - NVD API returned 5 CVEs for openbsd:openssh
# 2026-06-21 14:35:29,012 - __main__ - INFO - Port 22: 5 CVE(s) found
# 2026-06-21 14:35:30,345 - reporter - INFO - Initialized report generator for target: 192.168.1.1
# 2026-06-21 14:35:32,678 - reporter - INFO - PDF report successfully generated: scan_report_192.168.1.1_20260621_143032.pdf
# 2026-06-21 14:35:32,901 - __main__ - INFO - Report saved to: /Users/tejasanand/Desktop/VulnScannerProject/scan_report_192.168.1.1_20260621_143032.pdf

# PDF Report (generated based on findings)
# scan_report_192.168.1.1_20260621_143032.pdf
#
# Contents:
# - Header: Target IP, scan date/time
# - Executive Summary: Metrics table
#   - Total open ports: 3
#   - Total CVEs: 12
#   - Critical: 2, High: 4, Medium: 5, Low: 1
# - Detailed Findings: Port-by-port analysis
#   - Port 22: SSH, OpenSSH 7.4, 5 CVEs, Max CVSS 7.5, HIGH
#   - Port 80: HTTP, Apache 2.4.6, 4 CVEs, Max CVSS 9.8, CRITICAL
#   - Port 443: HTTPS, Apache 2.4.6, 3 CVEs, Max CVSS 8.1, HIGH
# - CVE Details: Individual vulnerability information
#   - CVE-2021-44228, CVSS 10.0, CRITICAL, Log4j RCE
#   - CVE-2023-25136, CVSS 8.1, HIGH, OpenSSL buffer overflow
#   - ...

# =============================================================================
# PERFORMANCE NOTES
# =============================================================================

# Socket Scan: 2-5 seconds
# - 20 ports checked in parallel (10 worker threads)
# - 2-second timeout per port

# Nmap Scan: 30-120 seconds
# - Depends on port count and target responsiveness
# - T4 timing template for speed
# - Service version detection (-sV) adds time

# CVE Lookup: 5-15 seconds per service
# - NVD API v2 queries
# - Retry with exponential backoff for rate limits
# - Fallback to local database on persistent failures

# Report Generation: 1-2 seconds
# - ReportLab PDF compilation

# Total: 5-15 minutes (typical network scan)

# =============================================================================
# TROUBLESHOOTING CHECKLIST
# =============================================================================

# ✓ Python version: 3.12.4+
# ✓ Virtual environment: source env/bin/activate
# ✓ Nmap installed: brew install nmap
# ✓ Dependencies: pip install nmap requests reportlab pillow
# ✓ Network connectivity: ping nist.gov (for NVD API)
# ✓ Target reachable: ping 192.168.1.1
# ✓ Permissions: sudo for ports < 1024
# ✓ Firewall: Allow outbound HTTPS (port 443) for NVD API

# =============================================================================
# PORTFOLIO VALUE
# =============================================================================

# This project demonstrates:
#
# 1. Enterprise architecture
#    - Clean 4-module design
#    - Separation of concerns
#    - Reusable components
#
# 2. Security engineering
#    - Input validation with whitelisting
#    - Command injection prevention
#    - Secure network calls
#
# 3. API integration
#    - NIST NVD API v2
#    - Rate limiting with exponential backoff
#    - Fallback mechanisms
#
# 4. Concurrent programming
#    - ThreadPoolExecutor for parallel operations
#    - Resource cleanup with context managers
#
# 5. Professional reporting
#    - PDF generation with ReportLab
#    - Executive-level styling
#    - Data visualization
#
# 6. Production-grade Python
#    - Type hints on all functions
#    - Comprehensive logging
#    - Exception handling
#    - PEP 8 compliance
#
# 7. Deployment readiness
#    - Exit codes for automation
#    - Graceful shutdown (Ctrl+C)
#    - Audit trails via logging

print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                          VULNSCANNER v1.0                                 ║
║                   Professional Vulnerability Assessment Tool              ║
╚═══════════════════════════════════════════════════════════════════════════╝

QUICK START:
  python main.py --target 192.168.1.1
  python main.py --target example.com --ports 22,80,443,3306
  python main.py --target api.example.com --verbose

DOCUMENTATION:
  README.md              - Full project documentation
  IMPLEMENTATION_GUIDE.md - Technical implementation details
  QUICK_REFERENCE.py    - This file (API usage examples)

FILES INCLUDED:
  main.py               - CLI orchestration and pipeline
  scanner.py            - Reconnaissance (ports, services, fingerprinting)
  vnum_checker.py       - CVE analysis (NVD API integration)
  reporter.py           - PDF report generation

FEATURES:
  ✓ Multi-threaded socket scanning (20 ports default)
  ✓ Nmap service fingerprinting (-sV -O -T4)
  ✓ NIST NVD API v2 integration with rate limiting
  ✓ Exponential backoff retry mechanism
  ✓ Fallback vulnerability database
  ✓ Professional PDF reports with custom styling
  ✓ Comprehensive logging and audit trails
  ✓ Full type hints and security validation

SECURITY FEATURES:
  ✓ Input validation with character whitelisting
  ✓ Command injection prevention
  ✓ Loopback address rejection
  ✓ Private network warnings
  ✓ Graceful error handling
  ✓ HTTPS for API calls

OUTPUT:
  scan_report_[target]_[timestamp].pdf
  vuln_scanner.log

For detailed usage, run:
  python main.py --help
""")
