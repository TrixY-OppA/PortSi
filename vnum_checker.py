"""
Vulnerability Analysis Module: CVE lookup and risk assessment.
Integrates with NIST NVD API with exponential backoff and fallback mechanism.
"""

import logging
import requests
import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

# Configure module logger
logger = logging.getLogger(__name__)

# NVD API v2 endpoint
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_TIMEOUT = 10


class FallbackVulnerabilityDB:
    """Local fallback database of known critical vulnerabilities."""
    
    def __init__(self):
        """Initialize fallback database with common legacy vulnerabilities."""
        self.vulnerabilities = {
            "Apache": [
                {
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "description": "Log4Shell - Apache Log4j RCE vulnerability"
                },
                {
                    "cve_id": "CVE-2021-3129",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "description": "Laravel Ignition debug mode RCE"
                }
            ],
            "OpenSSL": [
                {
                    "cve_id": "CVE-2022-0778",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "description": "OpenSSL BN_mod_sqrt() infinite loop DoS"
                },
                {
                    "cve_id": "CVE-2022-1292",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "description": "OpenSSL c_rehash script injection"
                }
            ],
            "MySQL": [
                {
                    "cve_id": "CVE-2022-21853",
                    "cvss_score": 4.9,
                    "severity": "MEDIUM",
                    "description": "MySQL Server vulnerability in Performance Schema"
                }
            ],
            "SSH": [
                {
                    "cve_id": "CVE-2023-25136",
                    "cvss_score": 8.1,
                    "severity": "HIGH",
                    "description": "OpenSSH vulnerable buffer overflow"
                }
            ],
            "nginx": [
                {
                    "cve_id": "CVE-2022-41742",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "description": "nginx HTTP/2 implementation DoS"
                }
            ]
        }
    
    def lookup(self, service_name: str, keyword: str) -> List[Dict[str, Any]]:
        results = []
        for key in self.vulnerabilities:
            if key.lower() in service_name.lower() or service_name.lower() in key.lower():
                results.extend(self.vulnerabilities[key])
        logger.debug(f"Fallback DB lookup for '{service_name}': found {len(results)} vulnerabilities")
        return results


def fetch_cves_for_service(cpe_string: str, keyword: str, max_retries: int = 3) -> List[Dict[str, Any]]:
    """
    Fetch CVEs from NIST NVD API with exponential backoff retry.
    """
    if not cpe_string or cpe_string == "Unknown":
        logger.debug(f"Skipping CVE lookup for unknown service: {keyword}")
        return []
    
    logger.info(f"Fetching CVEs for CPE: {cpe_string}")
    
    cpe_parts = cpe_string.split(":")
    if len(cpe_parts) < 4:
        logger.warning(f"Invalid CPE format: {cpe_string}")
        return _use_fallback_db(keyword)
    
    vendor = cpe_parts[2] if len(cpe_parts) > 2 else ""
    product = cpe_parts[3] if len(cpe_parts) > 3 else ""
    
    if not vendor or not product:
        logger.warning(f"Missing vendor/product in CPE: {cpe_string}")
        return _use_fallback_db(keyword)
    
    query = f"{vendor}:{product}"
    
    for attempt in range(max_retries):
        try:
            logger.debug(f"NVD API request (attempt {attempt + 1}/{max_retries}): {query}")
            params = {"keywordSearch": query, "resultsPerPage": 20}
            
            response = requests.get(
                NVD_API_BASE,
                params=params,
                timeout=NVD_API_TIMEOUT,
                headers={"User-Agent": "PortSi/1.0"}
            )
            
            if response.status_code == 429:
                wait_time = (2 ** attempt) + 1  # Adaptive backoff calculation
                logger.warning(f"HTTP 429 Rate Limited. Backing off for {wait_time}s...")
                time.sleep(wait_time)
                continue
                
            response.raise_for_status()
            data = response.json()
            vulnerabilities = []
            
            if "vulnerabilities" in data:
                for vuln_item in data["vulnerabilities"]:
                    cve = vuln_item.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    description = cve.get("descriptions", [{}])[0].get("value", "No description available")
                    
                    cvss_score = 0.0
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                    elif "cvssMetricV30" in metrics:
                        cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
                    
                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": _calculate_severity(cvss_score),
                        "description": description[:200]
                    })
                return vulnerabilities
                
            return []
            
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logger.warning(f"NVD API attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                logger.error("Max retries exhausted for NVD API. Switching to Fallback DB.")
                return _use_fallback_db(keyword)
                
    return _use_fallback_db(keyword)


def _use_fallback_db(keyword: str) -> List[Dict[str, Any]]:
    logger.info(f"Using fallback vulnerability database for: {keyword}")
    fallback_db = FallbackVulnerabilityDB()
    return fallback_db.lookup(keyword, keyword)


def _calculate_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0: return "CRITICAL"
    elif cvss_score >= 7.0: return "HIGH"
    elif cvss_score >= 4.0: return "MEDIUM"
    elif cvss_score > 0: return "LOW"
    return "NONE"