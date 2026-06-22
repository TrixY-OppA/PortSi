"""
PortSi - Enterprise Vulnerability Scanner
Main Orchestration & Interactive CLI Interface
"""

import logging
import sys
import argparse
import shutil
import subprocess
import time
from typing import Optional, List, Dict, Any
from pathlib import Path
import threading

# Import project modules
from scanner import validate_target, fast_socket_scan, run_nmap_scan
from vnum_checker import fetch_cves_for_service
from reporter import VulnerabilityReport

log_path = Path(__file__).parent.resolve() / 'portsi.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_path)),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class TerminalLoader:
    def __init__(self, message: str = "Scanning"):
        self.message = message
        self.is_running = False
        self.thread = None
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.frame_index = 0
    
    def start(self) -> None:
        self.is_running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()
    
    def _animate(self) -> None:
        while self.is_running:
            frame = self.frames[self.frame_index % len(self.frames)]
            sys.stdout.write(f"\r  {frame}  {self.message}...")
            sys.stdout.flush()
            self.frame_index += 1
            time.sleep(0.1)
    
    def stop(self) -> None:
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()


class DependencyChecker:
    def __init__(self):
        self.missing_deps = []
        self.warnings = []
    
    def check_all(self, interactive: bool = True) -> bool:
        print("\n[?] PortSi requires external binaries. Run system diagnostic check? (y/n): ", end="", flush=True)
        if not interactive:
            response = 'y'
        else:
            try: response = input().lower().strip() or 'n'
            except (EOFError, KeyboardInterrupt): return False
        
        if response != 'y': return True
        
        if not self._check_nmap(): self.missing_deps.append('nmap')
        self._check_python_imports()
        
        if not self.missing_deps and not self.warnings:
            print("[✓] All dependencies verified. Press Enter to proceed...", end="", flush=True)
            try: input()
            except (EOFError, KeyboardInterrupt): pass
            return True
        
        if self.missing_deps:
            print(f"\n[!] Missing dependencies found: {', '.join(self.missing_deps)}")
            print("[?] Attempt auto-remediation via system installer? (y/n): ", end="", flush=True)
            try: response = input().lower().strip() or 'n'
            except (EOFError, KeyboardInterrupt): return False
            
            if response == 'y': return self._auto_remediate()
            return False
        return True
    
    def _check_nmap(self) -> bool:
        nmap_path = shutil.which('nmap')
        if nmap_path:
            try:
                result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
                print(f"[✓] nmap found: {result.stdout.split('\n')[0]}")
                return True
            except Exception: return False
        return False
    
    def _check_python_imports(self) -> None:
        for package in ['requests', 'reportlab', 'nmap']:
            try:
                __import__(package)
                print(f"[✓] Python package '{package}' available")
            except ImportError:
                self.missing_deps.append(package)

    def _auto_remediate(self) -> bool:
        success = True
        for dep in self.missing_deps:
            cmd = ['brew', 'install', 'nmap'] if dep == 'nmap' else [sys.executable, '-m', 'pip', 'install', dep]
            try:
                print(f"\n[→] Installing {dep}...")
                res = subprocess.run(cmd, timeout=300, capture_output=True)
                if res.returncode == 0: print(f"[✓] {dep} installation successful")
                else: success = False
            except Exception: success = False
        return success


class PortSiScanner:
    def __init__(self, target: str, ports: Optional[List[int]] = None):
        self.target = target
        self.ports = ports
        self.scan_results: Dict[int, Dict[str, Any]] = {}
        self.vulnerability_data: Dict[int, List[Dict[str, Any]]] = {}
        self.loader = TerminalLoader()
    
    def execute(self) -> str:
        try:
            # Stage 1: Validate target
            self.loader = TerminalLoader("Validating target boundary")
            self.loader.start()
            validated_target = validate_target(self.target)
            self.loader.stop()
            print(f"[✓] Target validation successful: {validated_target}\n")
            
            # Stage 2: Fast socket scan
            self.loader = TerminalLoader("Running rate-controlled socket scan")
            self.loader.start()
            open_ports = fast_socket_scan(validated_target, self.ports)
            self.loader.stop()
            print(f"[✓] Fast socket scan complete: {len(open_ports)} port(s) open\n")
            
            if not open_ports:
                print("[⚠] No open ports detected. Moving to secure environmental reporting state.\n")
            else:
                # Stage 3: Nmap service fingerprinting
                self.loader = TerminalLoader("Running Nmap fingerprinting engine")
                self.loader.start()
                self.scan_results = run_nmap_scan(validated_target, open_ports)
                self.loader.stop()
                print(f"[✓] Nmap scan complete: {len(self.scan_results)} service(s) detected\n")
                
                # Stage 4: CVE analysis
                self.loader = TerminalLoader("Querying NVD intelligence framework")
                self.loader.start()
                self._analyze_vulnerabilities()
                self.loader.stop()
                total_cves = sum(len(cves) for cves in self.vulnerability_data.values())
                print(f"[✓] CVE analysis complete: {total_cves} vulnerability found\n")
            
            # Stage 5: Report generation with interactive destination (Runs EVERY time)
            print("=" * 70)
            print("STAGE 5: REPORT GENERATION")
            print("=" * 70)
            return self._generate_report_interactive(validated_target)
            
        except KeyboardInterrupt:
            self.loader.stop()
            print("\n[!] Operation aborted. Exiting safely.\n")
            sys.exit(0)

    def _analyze_vulnerabilities(self) -> None:
        for port, service_info in self.scan_results.items():
            cpe = service_info.get("cpe", "")
            service_name = service_info.get("service", "Unknown")
            service_keyword = service_name.split()[0] if service_name else "Unknown"
            
            if service_info.get("version", "Unknown") == "Unknown":
                self.vulnerability_data[port] = []
                continue
                
            try:
                self.vulnerability_data[port] = fetch_cves_for_service(cpe, service_keyword)
            except Exception:
                self.vulnerability_data[port] = []

    def _generate_report_interactive(self, target: str) -> str:
        print("[?] Enter the full directory path to save the PDF report")
        print("    (Press Enter for current directory): ", end="", flush=True)
        
        try: user_path = input().strip() or "."
        except (EOFError, KeyboardInterrupt): user_path = "."
        
        target_dir = Path(user_path)
        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)
            
        report_gen = VulnerabilityReport(target, self.scan_results, self.vulnerability_data)
        report_path = report_gen.generate_pdf(output_dir=str(target_dir))
        print(f"\n[✓] Scan complete! Report saved to: {report_path}\n")
        return report_path


def main() -> int:
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                          PortSi v1.0                                      ║
║           Enterprise Vulnerability Scanner & Threat Intelligence          ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(prog="PortSi")
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--ports", type=str, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--skip-check", action="store_true")
    args = parser.parse_args()
    
    if not args.skip_check:
        if not DependencyChecker().check_all(interactive=True):
            print("[✗] Pre-flight requirements verification failed.\n")
            return 1
            
    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else None
    PortSiScanner(args.target, ports).execute()
    return 0


if __name__ == "__main__":
    sys.exit(main())