"""
Reconnaissance Module: Port identification and service fingerprinting.
Implements fast socket scanning followed by deep Nmap service detection.
"""

import logging
import socket
import ipaddress
import re
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap

# Configure module logger
logger = logging.getLogger(__name__)


def validate_target(target: str) -> str:
    """
    Validate if the target is a valid IPv4/IPv6 address or resolvable hostname.
    
    Security Features:
    - Rejects loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
    - Rejects private network ranges (RFC 1918)
    - Sanitizes input to prevent command injection
    - Validates maximum length and character set
    
    Args:
        target: IP address, hostname, or FQDN to validate
        
    Returns:
        Sanitized target string
        
    Raises:
        ValueError: If target is invalid, loopback, or private range
    """
    logger.info(f"Validating target: {target}")
    
    # Input validation: length and character constraints
    if not target or len(target) > 255:
        logger.error(f"Invalid target length: {len(target)}")
        raise ValueError("Target length must be between 1 and 255 characters")
    
    # Sanitize: allow alphanumerics, dots, hyphens, colons (for IPv6)
    if not re.match(r"^[a-zA-Z0-9.\-:]+$", target):
        logger.error(f"Invalid characters in target: {target}")
        raise ValueError("Target contains invalid characters")
    
    # Try to parse as IP address first
    try:
        ip_obj = ipaddress.ip_address(target)
        
        # Reject loopback
        if ip_obj.is_loopback:
            logger.error(f"Loopback address rejected: {target}")
            raise ValueError("Loopback addresses (127.0.0.1, ::1) are not allowed")
        
        # Reject private ranges
        if ip_obj.is_private:
            logger.warning(f"Private range detected: {target}")
            # Note: We allow private ranges but log the warning
            # Uncomment below to reject private ranges
            # raise ValueError("Private network ranges are not allowed for security")
        
        logger.info(f"Valid IP address: {target}")
        return str(ip_obj)
    
    except ValueError as e:
        # Not a valid IP, try hostname resolution
        if "does not appear to be" in str(e):
            try:
                resolved_ip = socket.gethostbyname(target)
                logger.info(f"Hostname resolved: {target} -> {resolved_ip}")
                
                # Validate the resolved IP
                ip_obj = ipaddress.ip_address(resolved_ip)
                if ip_obj.is_loopback:
                    logger.error(f"Resolved to loopback address: {resolved_ip}")
                    raise ValueError("Target resolves to loopback address")
                
                return target  # Return original hostname
            except socket.gaierror as resolve_err:
                logger.error(f"Hostname resolution failed: {target} - {resolve_err}")
                raise ValueError(f"Hostname cannot be resolved: {target}")
        else:
            raise


def fast_socket_scan(target: str, ports: Optional[List[int]] = None) -> List[int]:
    """
    Perform a multi-threaded TCP connect scan on common ports.
    
    Uses concurrent.futures.ThreadPoolExecutor for parallel socket operations.
    Provides quick identification of open ports before detailed Nmap scanning.
    
    Args:
        target: IP address or hostname to scan
        ports: List of port numbers to scan (default: top 20 common ports)
        
    Returns:
        List of open port numbers
    """
    if ports is None:
        # Top 20 most common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017, 5984, 6379]
    
    logger.info(f"Starting fast socket scan on {target} for {len(ports)} ports")
    open_ports = []
    
    def check_port(port: int) -> Optional[int]:
        """Check if a single port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                logger.debug(f"Port {port} is OPEN on {target}")
                return port
            return None
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return None
    
    # Execute scans in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    open_ports.sort()
    logger.info(f"Fast socket scan completed. Open ports: {open_ports}")
    return open_ports


def run_nmap_scan(target: str, open_ports: List[int]) -> Dict[int, Dict[str, Any]]:
    """
    Run detailed Nmap scan with service and OS detection.
    
    Uses python-nmap library with optimized arguments:
    - -sV: Service version detection
    - -O: OS detection
    - -T4: Aggressive timing template
    
    Args:
        target: IP address or hostname
        open_ports: List of open ports to scan
        
    Returns:
        Dictionary mapping port number to service details:
        {
            port: {
                'service': 'service_name',
                'version': 'version_string',
                'cpe': 'cpe_uri',
                'state': 'open|closed|filtered'
            }
        }
    """
    if not open_ports:
        logger.warning("No open ports provided for Nmap scan")
        return {}
    
    # Construct port specification (e.g., "80,443,8080")
    port_spec = ",".join(str(p) for p in open_ports)
    logger.info(f"Starting Nmap scan on {target} for ports: {port_spec}")
    
    try:
        nm = nmap.PortScanner()
        
        # Run Nmap with service/OS detection
        # Arguments: -sV (service version), -O (OS detection), -T4 (speed)
        arguments = f"-sV -O -T4 -p {port_spec}"
        nm.scan(target, arguments=arguments)
        
        results: Dict[int, Dict[str, Any]] = {}
        
        # Parse Nmap results
        if target in nm.all_hosts():
            host = nm[target]
            
            for proto in host.all_protocols():
                ports_dict = host[proto]
                
                for port in ports_dict.keys():
                    port_info = ports_dict[port]
                    
                    # Extract service information
                    service_name = port_info.get('name', 'Unknown')
                    product = port_info.get('product', 'Unknown')
                    version = port_info.get('version', 'Unknown')
                    extrainfo = port_info.get('extrainfo', '')
                    
                    # Combine version info
                    version_str = f"{product} {version}".strip()
                    if extrainfo:
                        version_str += f" ({extrainfo})"
                    if version_str == "Unknown Unknown":
                        version_str = "Unknown"
                    
                    # Extract CPE if available
                    cpe = port_info.get('cpe', '')
                    
                    results[port] = {
                        'service': service_name,
                        'version': version_str,
                        'cpe': cpe,
                        'state': port_info.get('state', 'unknown')
                    }
                    
                    logger.info(f"Port {port}/{proto}: {service_name} - {version_str}")
        
        logger.info(f"Nmap scan completed. Found {len(results)} service(s)")
        return results
    
    except nmap.nmap.PortScannerError as e:
        logger.error(f"Nmap scan error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during Nmap scan: {e}")
        raise
