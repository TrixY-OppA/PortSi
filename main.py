"""
Main Orchestration Module: CLI entrypoint and execution pipeline.
Coordinates target validation, reconnaissance, vulnerability analysis, and reporting.
"""

import logging
import sys
import argparse
from typing import Optional, List, Dict, Any
from pathlib import Path

# Import project modules
from scanner import validate_target, fast_socket_scan, run_nmap_scan
from vnum_checker import fetch_cves_for_service
from reporter import VulnerabilityReport

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """Main orchestration class for the vulnerability scanning pipeline."""
    
    def __init__(self, target: str, ports: Optional[List[int]] = None):
        """
        Initialize scanner with target and optional port list.
        
        Args:
            target: IP address, hostname, or FQDN to scan
            ports: Optional list of specific ports to scan (default: top 20)
        """
        self.target = target
        self.ports = ports
        self.scan_results: Dict[int, Dict[str, Any]] = {}
        self.vulnerability_data: Dict[int, List[Dict[str, Any]]] = {}
        logger.info(f"Initialized VulnerabilityScanner for target: {target}")
    
    def execute(self) -> str:
        """
        Execute complete scanning pipeline.
        
        Pipeline stages:
        1. Target validation (socket, ipaddress, hostname resolution)
        2. Fast socket scan on common ports
        3. Deep Nmap service fingerprinting
        4. CVE lookup via NVD API with fallback
        5. Professional PDF report generation
        
        Returns:
            Path to generated PDF report
            
        Raises:
            ValueError: If target validation fails
            Exception: For network or system errors
        """
        try:
            # Stage 1: Validate target
            logger.info("=" * 60)
            logger.info("STAGE 1: TARGET VALIDATION")
            logger.info("=" * 60)
            validated_target = validate_target(self.target)
            logger.info(f"✓ Target validation successful: {validated_target}")
            
            # Stage 2: Fast socket scan
            logger.info("\n" + "=" * 60)
            logger.info("STAGE 2: FAST PORT SCAN")
            logger.info("=" * 60)
            open_ports = fast_socket_scan(validated_target, self.ports)
            
            if not open_ports:
                logger.warning("No open ports detected. Generating minimal report...")
                report_generator = VulnerabilityReport(validated_target)
                report_path = report_generator.generate_pdf({}, {})
                logger.info(f"✓ Report generated: {report_path}")
                return report_path
            
            logger.info(f"✓ Found {len(open_ports)} open port(s): {open_ports}")
            
            # Stage 3: Deep Nmap scan with service detection
            logger.info("\n" + "=" * 60)
            logger.info("STAGE 3: NMAP SERVICE DETECTION")
            logger.info("=" * 60)
            self.scan_results = run_nmap_scan(validated_target, open_ports)
            logger.info(f"✓ Nmap scan complete. Identified {len(self.scan_results)} service(s)")
            
            # Stage 4: CVE analysis for each discovered service
            logger.info("\n" + "=" * 60)
            logger.info("STAGE 4: CVE VULNERABILITY ANALYSIS")
            logger.info("=" * 60)
            self._analyze_vulnerabilities()
            
            # Count total CVEs
            total_cves = sum(len(cves) for cves in self.vulnerability_data.values())
            logger.info(f"✓ CVE analysis complete. Found {total_cves} total vulnerability/vulnerabilities)")
            
            # Stage 5: Generate PDF report
            logger.info("\n" + "=" * 60)
            logger.info("STAGE 5: REPORT GENERATION")
            logger.info("=" * 60)
            report_generator = VulnerabilityReport(validated_target)
            report_path = report_generator.generate_pdf(self.scan_results, self.vulnerability_data)
            logger.info(f"✓ Professional PDF report generated")
            
            logger.info("\n" + "=" * 60)
            logger.info("SCAN COMPLETE")
            logger.info("=" * 60)
            logger.info(f"Report saved to: {report_path}")
            
            return report_path
        
        except KeyboardInterrupt:
            logger.warning("\n\nScan interrupted by user (Ctrl+C). Exiting gracefully...")
            sys.exit(0)
        except Exception as e:
            logger.error(f"\nFatal error during scan: {e}", exc_info=True)
            raise
    
    def _analyze_vulnerabilities(self) -> None:
        """
        Analyze each discovered service for known vulnerabilities.
        
        Queries NVD API for each service, with fallback to local database.
        Handles unknown services gracefully.
        """
        for port, service_info in self.scan_results.items():
            service_name = service_info.get("service", "Unknown")
            version = service_info.get("version", "Unknown")
            cpe = service_info.get("cpe", "")
            
            logger.info(f"Analyzing port {port}/{service_name} ({version})...")
            
            # Skip analysis if version is unknown
            if version == "Unknown":
                logger.warning(f"Port {port}: Unknown service version - skipping CVE lookup")
                self.vulnerability_data[port] = []
                continue
            
            # Extract service name from version string for fallback lookup
            service_keyword = service_name.split()[0] if service_name else "Unknown"
            
            # Fetch CVEs from NVD or fallback
            cves = fetch_cves_for_service(cpe, service_keyword)
            self.vulnerability_data[port] = cves
            
            if cves:
                # Calculate severity summary
                severities = [cve.get("severity", "NONE") for cve in cves]
                critical_count = severities.count("CRITICAL")
                high_count = severities.count("HIGH")
                
                if critical_count > 0:
                    logger.warning(
                        f"Port {port}: ⚠️  {len(cves)} CVE(s) found - "
                        f"{critical_count} CRITICAL, {high_count} HIGH"
                    )
                else:
                    logger.info(f"Port {port}: {len(cves)} CVE(s) found")
            else:
                logger.info(f"Port {port}: No known vulnerabilities found")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Required:
        --target: IP address, hostname, or FQDN
    
    Optional:
        --ports: Comma-separated list of specific ports to scan
        --verbose: Enable verbose logging
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="VulnScanner",
        description="Production-grade vulnerability scanner with NVD integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 192.168.1.1
  python main.py --target example.com
  python main.py --target 10.0.0.5 --ports 22,80,443,3306
        """
    )
    
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target IP address, hostname, or FQDN to scan"
    )
    
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated list of specific ports to scan (e.g., 22,80,443)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the vulnerability scanner.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Adjust logging level if verbose flag is set
        if args.verbose:
            for handler in logger.handlers:
                handler.setLevel(logging.DEBUG)
            logger.setLevel(logging.DEBUG)
            logger.debug("Verbose logging enabled")
        
        # Parse ports if provided
        ports = None
        if args.ports:
            try:
                ports = [int(p.strip()) for p in args.ports.split(",")]
                logger.info(f"Custom port list provided: {ports}")
            except ValueError:
                logger.error("Invalid port specification. Use comma-separated integers (e.g., 22,80,443)")
                return 1
        
        # Execute scanning pipeline
        scanner = VulnerabilityScanner(args.target, ports)
        report_path = scanner.execute()
        
        print(f"\n✓ Scan complete! Report: {report_path}")
        return 0
    
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 0
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
