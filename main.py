#!/usr/bin/env python3
"""
Complete Scanner Engine - Main Integration Module
Links discover.py, port_scan.py, banners.py, MAC lookup, and TTL OS fingerprinting 
into a unified scanning tool with reporting integration.
"""

import argparse
import json
import time
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional

# Import from the scanner module
try:
    from scanner.discover import discover_hosts
    from scanner.port_scan import scan_ports
    from scanner.banners import grab_service_banners
    from scanner.plugin_manager import PluginManager
    from fingerprints.mac_lookup import MACLookup
    from fingerprints.ttl_fingerprint import TTLFingerprinter
    # Import reporting functions
    from report.output_cli import generate_cli_output
    from report.output_json import generate_json_output
    from report.output_csv import generate_csv_output
    from report.output_html import generate_html_output
except ImportError as e:
    print(f"[!] Error importing modules: {e}")
    print("[!] Make sure all required modules are in the directory and that rich and jinja2 are installed.")
    sys.exit(1)


class ScannerEngine:
    """Complete network scanner engine integrating all modules."""
    
    def __init__(self, config: Dict):
        """Initialize scanner engine with configuration."""
        self.config = config
        self.results = {
            'scan_info': {
                'start_time': None,
                'end_time': None,
                'duration': 0,
                'targets': [],
                'ports': [],
                'options': {}
            },
            'discovery': {
                'total_targets': 0,
                'live_hosts': []
            },
            'port_scan_raw': {},  # Raw port scan results (host -> {port: status})
            'banners_raw': {},    # Raw banner results (host -> {port: {service: '', banner: ''}})
            'final_results': [],  # Flattened list of dictionaries for reporting engine
            'fingerprinting': {}, # New section for MAC and OS fingerprinting
            'plugins': {}         # Plugin detection results
        }
        
        # Initialize plugin manager
        plugin_folder = os.path.join(os.path.dirname(__file__), '..', 'plugins')
        self.plugin_manager = PluginManager(plugin_folder=plugin_folder, max_workers=20)

    def _process_raw_to_final_results(self):
        """
        Processes raw port scan and banner results into the 'final_results'
        list as required by the reporting engine.
        """
        self.results['final_results'] = []
        for host, ports_data in self.results['port_scan_raw'].items():
            for port, status in ports_data.items():
                banner_info = self.results['banners_raw'].get(host, {}).get(port, {})
                self.results['final_results'].append({
                    'host': host,
                    'port': port,
                    'status': status,
                    'banner': banner_info.get('banner', 'N/A')
                })

    def _run_plugins_on_scan(self):
        """Run all loaded plugins on scanned hosts and banners."""
        if not self.results['final_results']:
            return

        scan_targets = {}
        banners = {}
        for host, ports_data in self.results['port_scan_raw'].items():
            scan_targets[host] = list(ports_data.keys())
            banners[host] = self.results['banners_raw'].get(host, {})

        plugin_results = self.plugin_manager.run_scan_batch(scan_targets, banners)
        self.results['plugins'] = plugin_results

    def run_complete_scan(self, targets: List[str], ports: List[int],
                         skip_discovery: bool = False,
                         skip_port_scan: bool = False,
                         skip_banners: bool = False,
                         udp_scan: bool = False,
                         perform_mac: bool = False,
                         perform_os: bool = False,
                         ttl: Optional[int] = None,
                         window: Optional[int] = None) -> Dict:
        """
        Run complete network scan: discovery -> port scan -> banner grabbing -> fingerprinting.
        """
        start_time = time.time()
        self.results['scan_info']['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
        self.results['scan_info']['targets'] = targets
        self.results['scan_info']['ports'] = ports
        self.results['scan_info']['options'] = {
            'skip_discovery': skip_discovery,
            'skip_port_scan': skip_port_scan,
            'skip_banners': skip_banners,
            'udp_scan': udp_scan,
            'mac_lookup': perform_mac,
            'os_fingerprinting': perform_os
        }
        
        print(f"{'='*80}")
        print(f"NETWORK SCANNER ENGINE - COMPLETE SCAN")
        print(f"{'='*80}")
        print(f"Start time: {self.results['scan_info']['start_time']}")
        print(f"Targets: {len(targets)} {'target' if len(targets) == 1 else 'targets'}")
        print(f"Ports: {len(ports)} ports")
        print(f"Protocol: {'UDP' if udp_scan else 'TCP'}")
        print(f"{'='*80}")
        
        # Phase 1: Host Discovery
        if skip_discovery:
            print("\n[*] PHASE 1: HOST DISCOVERY - SKIPPED")
            # Treat targets as live hosts
            live_hosts = [t for t in targets if '/' not in t]
            self.results['discovery']['live_hosts'] = live_hosts
            self.results['discovery']['total_targets'] = len(live_hosts)
        else:
            print("\n[*] PHASE 1: HOST DISCOVERY")
            print("-" * 40)
            live_hosts = discover_hosts(targets)
            self.results['discovery']['live_hosts'] = live_hosts
            self.results['discovery']['total_targets'] = len(live_hosts)
        
        if not live_hosts:
            print("[!] No live hosts found. Scan terminated.")
            return self._finalize_results(start_time)  # Finalize even if no hosts
        
        print(f"[+] Phase 1 complete: {len(live_hosts)} live hosts")
        
        # Phase 2: Port Scanning
        port_results = {}
        if skip_port_scan:
            print("\n[*] PHASE 2: PORT SCANNING - SKIPPED")
        else:
            print(f"\n[*] PHASE 2: {'UDP' if udp_scan else 'TCP'} PORT SCANNING")
            print("-" * 40)
            port_results = scan_ports(live_hosts, ports, udp_scan)
            self.results['port_scan_raw'] = port_results
        
        if not port_results and not skip_port_scan:
            print("[!] No open ports found. Skipping banner grabbing.")
        
        # Phase 3: Banner Grabbing
        banner_results = {}
        if skip_banners or udp_scan:
            if udp_scan:
                print("\n[*] PHASE 3: BANNER GRABBING - SKIPPED (UDP scan)")
            else:
                print("\n[*] PHASE 3: BANNER GRABBING - SKIPPED")
        else:
            print("\n[*] PHASE 3: SERVICE BANNER GRABBING")
            print("-" * 40)
            banner_results = grab_service_banners(port_results)
            self.results['banners_raw'] = banner_results
            total_banners = sum(len(host_banners) for host_banners in banner_results.values())
            print(f"[+] Phase 3 complete: {total_banners} service banners grabbed")
        
        # Process raw results into final_results for reporting
        self._process_raw_to_final_results()

        # Phase 4: Plugin Execution
        print("\n[*] Running plugins for device/service detection...")
        self._run_plugins_on_scan()
        num_plugin_hosts = len(self.results.get('plugins', []))
        print(f"[+] Plugins executed for {num_plugin_hosts} hosts")
        
        # Phase 5: MAC Vendor Lookup
        if perform_mac:
            print("\n[*] PHASE 5: MAC VENDOR LOOKUP")
            mac_lookup = MACLookup()
            mac_results = {}
            for host in live_hosts:
                # This part needs actual MAC address retrieval.
                print(f"[!] Warning: MAC address retrieval not implemented. Using dummy MAC for {host}.")
                dummy_mac = "00:11:22:33:44:55" 
                mac_results[host] = mac_lookup.lookup_mac(dummy_mac)
            self.results['fingerprinting']['mac'] = mac_results
            print(f"[+] MAC vendor lookup completed for {len(mac_results)} hosts")
        
        # Phase 6: TTL-based OS Fingerprinting
        if perform_os:
            print("\n[*] PHASE 6: TTL-BASED OS FINGERPRINTING")
            if ttl is None or window is None:
                print("[!] TTL and Window values required for OS fingerprinting (--ttl, --window)")
            else:
                ttl_fp = TTLFingerprinter()
                os_results = {}
                for host in live_hosts:
                    os_results[host] = ttl_fp.fingerprint_os(ttl, window)
                self.results['fingerprinting']['os'] = os_results
                print(f"[+] OS fingerprinting completed for {len(os_results)} hosts")
        
        return self._finalize_results(start_time)
    
    def _finalize_results(self, start_time: float) -> Dict:
        """Finalize scan results with timing and summary information."""
        end_time = time.time()
        duration = end_time - start_time
        self.results['scan_info']['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
        self.results['scan_info']['duration'] = round(duration, 2)
        return self.results
    
    def print_summary(self) -> None:
        """Print comprehensive scan summary."""
        print(f"\n{'='*80}")
        print(f"SCAN SUMMARY")
        print(f"{'='*80}")
        
        # Timing information
        print(f"Start time: {self.results['scan_info']['start_time']}")
        print(f"End time: {self.results['scan_info']['end_time']}")
        print(f"Duration: {self.results['scan_info']['duration']} seconds")
        
        # Discovery results
        live_hosts = self.results['discovery']['live_hosts']
        print(f"\nHosts discovered: {len(live_hosts)}")
        
        # Port scan results
        total_open_ports = len(self.results['final_results'])
        print(f"Open ports found: {total_open_ports}")
        
        # Banner results
        total_banners = sum(1 for res in self.results['final_results'] if res['banner'] != 'N/A')
        print(f"Service banners: {total_banners}")
        
        # Fingerprinting results
        fingerprinting = self.results.get('fingerprinting', {})
        if fingerprinting.get('mac'):
            print("\nMAC Vendor Information:")
            for host, vendor in fingerprinting['mac'].items():
                print(f"  {host} -> {vendor}")
        
        if fingerprinting.get('os'):
            print("\nOS Fingerprinting Information:")
            for host, os_name in fingerprinting['os'].items():
                print(f"  {host} -> {os_name}")
        
        # Plugin results
        plugin_results = self.results.get('plugins', {})
        if plugin_results:
            print("\nDetected Devices / Services by Plugins:")
            for host, results in plugin_results.items():
                for r in results:
                    print(f"  {host} -> {r['device_type']} ({r['vendor']}) Notes: {r.get('notes','')}")
        
        # Detailed results from the 'final_results' list
        if self.results['final_results']:
            print(f"\n{'OPEN PORT DETAILS'}")
            print(f"{'-'*80}")
            # Group for CLI-like output or iterate directly
            grouped_for_summary = {}
            for res in self.results['final_results']:
                if res['host'] not in grouped_for_summary:
                    grouped_for_summary[res['host']] = []
                grouped_for_summary[res['host']].append(res)
            
            for host in sorted(grouped_for_summary.keys()):
                host_ports = grouped_for_summary[host]
                print(f"\n{host} ({len(host_ports)} open ports)")
                for r in sorted(host_ports, key=lambda x: x['port']):
                    banner_str = f" - {r['banner']}" if r['banner'] != 'N/A' else ""
                    print(f"  {r['port']:<5}/{r['status']:<7}{banner_str}")
        
        print(f"\n{'='*80}")
    
    def save_results(self, filename: str, format: str = 'json') -> None:
        """
        Save scan results to file using the reporting engine functions.
        Also keeps original JSON and TXT saving for legacy/raw data.
        """
        if format.lower() == 'json':
            # Use the new reporting JSON function
            generate_json_output(self.results['final_results'], filename=filename)
        elif format.lower() == 'csv':
            generate_csv_output(self.results['final_results'], filename=filename)
        elif format.lower() == 'html':
            generate_html_output(self.results['final_results'], filename=filename)
        elif format.lower() == 'cli':
            # CLI output doesn't save to a file, but displays
            print("\n[!] CLI output is displayed directly, not saved to a file.")
            generate_cli_output(self.results['final_results'])
        elif format.lower() == 'txt':
            # Keep original txt saving for historical/raw data output
            try:
                with open(filename, 'w') as f:
                    f.write("NETWORK SCAN RESULTS\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Start time: {self.results['scan_info']['start_time']}\n")
                    f.write(f"Duration: {self.results['scan_info']['duration']} seconds\n")
                    f.write(f"Live hosts: {len(self.results['discovery']['live_hosts'])}\n\n")
                    
                    fingerprinting = self.results.get('fingerprinting', {})
                    if fingerprinting.get('mac'):
                        f.write("MAC Vendor Information:\n")
                        for host, vendor in fingerprinting['mac'].items():
                            f.write(f"  {host} -> {vendor}\n")
                        f.write("\n")
                    
                    if fingerprinting.get('os'):
                        f.write("OS Fingerprinting Information:\n")
                        for host, os_name in fingerprinting['os'].items():
                            f.write(f"  {host} -> {os_name}\n")
                        f.write("\n")
                    
                    # Plugin results
                    plugin_results = self.results.get('plugins', {})
                    if plugin_results:
                        f.write("Plugin Detection Results:\n")
                        for host, results in plugin_results.items():
                            for r in results:
                                f.write(f"  {host} -> {r['device_type']} ({r['vendor']}) Notes: {r.get('notes','')}\n")
                        f.write("\n")
                    
                    if self.results['final_results']:
                        f.write("Open Port Details:\n")
                        grouped_for_txt = {}
                        for res in self.results['final_results']:
                            if res['host'] not in grouped_for_txt:
                                grouped_for_txt[res['host']] = []
                            grouped_for_txt[res['host']].append(res)
                        
                        for host in sorted(grouped_for_txt.keys()):
                            host_ports = grouped_for_txt[host]
                            f.write(f"\nHost: {host} ({len(host_ports)} open ports)\n")
                            f.write("-" * 30 + "\n")
                            for r in sorted(host_ports, key=lambda x: x['port']):
                                banner_str = f" - {r['banner']}" if r['banner'] != 'N/A' else ""
                                f.write(f"{r['port']}/{r['status']} - {banner_str.strip()}\n")
                
                print(f"[+] Results saved to {filename} (Text format)")
            except Exception as e:
                print(f"[!] Error saving results to TXT: {e}")
        else:
            print(f"[!] Unknown output format: {format}")


# Helper function to parse port strings
def get_port_list(port_spec: str) -> List[int]:
    """Convert port specification string to list of port numbers."""
    ports = []
    for part in port_spec.split(','):
        if '-' in part:
            start, end = part.split('-')
            try:
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return sorted(set(ports))


# This function can be called from main.py
def run_scan_from_cli(args):
    """Run a scan based on CLI arguments."""
    # Process targets
    targets = []
    for target in args.targets:
        if os.path.isfile(target):
            try:
                with open(target, 'r') as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                targets.extend(file_targets)
                print(f"[+] Loaded {len(file_targets)} targets from {target}")
            except Exception as e:
                print(f"[!] Error reading target file {target}: {e}")
        else:
            targets.append(target)
    
    if not targets:
        print("[!] No valid targets specified")
        return None
    
    # Process ports
    if hasattr(args, 'top_ports') and args.top_ports:
        common_ports = [
            21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,
            5432,5900,6000,8000,8080,8443,8888,20,69,123,161,162,389,636,1521,2049,
            3690,5060,5061,6379,11211,27017,50000
        ]
        ports = common_ports[:args.top_ports]
    else:
        ports = get_port_list(args.ports)
    
    if not ports:
        print("[!] No valid ports specified")
        return None
    
    # Initialize scanner engine
    config = {'timeout': getattr(args, 'timeout', 3.0), 'verbose': getattr(args, 'verbose', False)}
    scanner = ScannerEngine(config)
    
    try:
        results = scanner.run_complete_scan(
            targets=targets,
            ports=ports,
            skip_discovery=getattr(args, 'skip_discovery', False),
            skip_port_scan=getattr(args, 'skip_port_scan', False),
            skip_banners=getattr(args, 'skip_banners', False),
            udp_scan=getattr(args, 'udp', False),
            perform_mac=getattr(args, 'mac', False),
            perform_os=getattr(args, 'os', False),
            ttl=getattr(args, 'ttl', None),
            window=getattr(args, 'window', None)
        )
        
        # Print summary
        scanner.print_summary()
        
        # Generate and save report based on specified format
        output_format = getattr(args, 'format', 'cli')
        output_file = getattr(args, 'output', None)
        
        if output_format == 'cli':
            # CLI output is already handled by scanner.print_summary() based on original design
            # We can also explicitly call generate_cli_output for a more structured table.
            print("\n[+] Generating CLI report details:")
            generate_cli_output(scanner.results['final_results'])
        elif output_file:
            scanner.save_results(output_file, output_format)
        else:
            print("[!] Output file not specified for non-CLI format. Report not saved.")
            
        return results
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Scan error: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
    
    return None


# For standalone execution if needed
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Complete Network Scanner Engine - Discovery, Port Scanning, Banner Grabbing, MAC & OS Fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scanner_engine.py 192.168.1.0/24 -p 22,80,443 --mac --os --ttl 128 --window 8192
  python scanner_engine.py target_list.txt --udp -p 53,161,123 --mac
  python scanner_engine.py 192.168.1.105 -p 80 --format html -o report.html
        """
    )
    
    # Target specification
    parser.add_argument('targets', nargs='+', help='Target IP addresses, CIDR networks, or file containing targets')
    
    # Port specification
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', default='21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5900,8000,8080,8443', 
                           help='Port specification: ranges, lists, or comma-separated (default: common ports)')
    port_group.add_argument('--top-ports', type=int, help='Scan top N most common ports')
    
    # Scan options
    parser.add_argument('--skip-discovery', action='store_true', help='Skip host discovery phase')
    parser.add_argument('--skip-port-scan', action='store_true', help='Skip port scanning phase')
    parser.add_argument('--skip-banners', action='store_true', help='Skip banner grabbing phase')
    parser.add_argument('--udp', action='store_true', help='Perform UDP scan instead of TCP')
    parser.add_argument('--mac', action='store_true', help='Perform MAC vendor lookup')
    parser.add_argument('--os', action='store_true', help='Perform TTL-based OS fingerprinting')
    parser.add_argument('--ttl', type=int, help='Observed TTL value for OS fingerprinting')
    parser.add_argument('--window', type=int, help='Observed TCP window size for OS fingerprinting')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results (e.g., report.json, report.csv, report.html)')
    # Added 'cli' for direct console output without saving
    parser.add_argument('--format', choices=['json', 'txt', 'csv', 'html', 'cli'], default='cli', 
                        help='Output format (default: cli - displays in console)')
    
    # Performance options
    parser.add_argument('--timeout', type=float, default=3.0, help='Network timeout in seconds (default: 3.0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    run_scan_from_cli(args)