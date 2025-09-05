#!/usr/bin/env python3
"""
Port Scanning Module - Scanner Engine
Implements TCP SYN scan, TCP connect scan, and UDP scan capabilities.
"""

import socket
import struct
import random
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple
import ipaddress

try:
    from scapy.all import IP, TCP, UDP, sr1, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. SYN scan will not be available.")
    SCAPY_AVAILABLE = False

class PortScanner:
    """Port scanner class implementing TCP SYN, TCP connect, and UDP scanning."""
    
    def __init__(self, timeout: float = 3.0, max_threads: int = 100):
        """
        Initialize port scanner with configurable timeout and thread pool.
        
        Args:
            timeout: Network timeout in seconds
            max_threads: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_results: Dict[str, Dict[int, str]] = {}
        self.lock = threading.Lock()
        
        # Common ports for quick scanning
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6000, 6001, 8000, 8080, 8443, 8888
        ]
    
    def _tcp_syn_scan(self, host: str, port: int) -> str:
        """
        Perform TCP SYN scan using raw packets (requires scapy and privileges).
        
        Args:
            host: Target IP address
            port: Target port number
            
        Returns:
            str: Port status ('open', 'closed', 'filtered', 'error')
        """
        if not SCAPY_AVAILABLE:
            return 'error'
            
        try:
            # Create SYN packet with random source port
            src_port = RandShort()
            syn_packet = IP(dst=host) / TCP(sport=src_port, dport=port, flags='S')
            
            # Send packet and wait for response
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            
            if response:
                if response.haslayer(TCP):
                    tcp_layer = response[TCP]
                    if tcp_layer.flags == 18:  # SYN-ACK (0x12)
                        # Send RST to close connection
                        rst_packet = IP(dst=host) / TCP(sport=src_port, dport=port, flags='R')
                        sr1(rst_packet, timeout=0.1, verbose=0)
                        return 'open'
                    elif tcp_layer.flags == 4:  # RST (0x04)
                        return 'closed'
                elif response.haslayer('ICMP'):
                    # ICMP error indicates filtered
                    return 'filtered'
            else:
                # No response typically means filtered
                return 'filtered'
                
        except Exception as e:
            return 'error'
        
        return 'filtered'
    
    def _tcp_connect_scan(self, host: str, port: int) -> str:
        """
        Perform TCP connect scan using full TCP handshake.
        
        Args:
            host: Target IP address
            port: Target port number
            
        Returns:
            str: Port status ('open', 'closed', 'filtered', 'error')
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return 'open'
            else:
                return 'closed'
                
        except socket.gaierror:
            return 'error'
        except Exception:
            return 'filtered'
    
    def _udp_scan(self, host: str, port: int) -> str:
        """
        Perform UDP scan by sending UDP packets and analyzing responses.
        
        Args:
            host: Target IP address
            port: Target port number
            
        Returns:
            str: Port status ('open', 'closed', 'open|filtered', 'error')
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (host, port))
            
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                return 'open'  # Got UDP response
            except socket.timeout:
                sock.close()
                return 'open|filtered'  # No response, could be open or filtered
            except socket.error as e:
                sock.close()
                if "Connection refused" in str(e):
                    return 'closed'  # ICMP port unreachable
                return 'filtered'
                
        except Exception:
            return 'error'
    
    def _scan_port(self, host: str, port: int, udp: bool = False) -> Tuple[str, int, str]:
        """
        Scan a single port on a host using appropriate method.
        
        Args:
            host: Target IP address
            port: Target port number
            udp: Whether to perform UDP scan
            
        Returns:
            Tuple[str, int, str]: (host, port, status)
        """
        if udp:
            status = self._udp_scan(host, port)
        else:
            # Try SYN scan first, fallback to connect scan
            if SCAPY_AVAILABLE:
                status = self._tcp_syn_scan(host, port)
                if status == 'error':
                    status = self._tcp_connect_scan(host, port)
            else:
                status = self._tcp_connect_scan(host, port)
        
        return host, port, status
    
    def _scan_worker(self, host: str, port: int, udp: bool = False) -> None:
        """
        Worker function for threaded port scanning.
        
        Args:
            host: Target IP address
            port: Target port number
            udp: Whether to perform UDP scan
        """
        host_result, port_result, status = self._scan_port(host, port, udp)
        
        with self.lock:
            if host_result not in self.scan_results:
                self.scan_results[host_result] = {}
            self.scan_results[host_result][port_result] = status
            
            # Print progress for open ports
            if status == 'open':
                protocol = 'UDP' if udp else 'TCP'
                print(f"[+] {host_result}:{port_result}/{protocol} - {status}")

def scan_ports(hosts: List[str], ports: List[int], udp: bool = False) -> Dict[str, Dict[int, str]]:
    """
    Scan specified ports on given hosts using TCP SYN scan with connect fallback.
    
    Args:
        hosts: List of IP addresses to scan
        ports: List of port numbers to scan
        udp: Whether to perform UDP scan instead of TCP
        
    Returns:
        Dict: Nested dictionary {host: {port: status}} containing scan results
    """
    if not hosts:
        print("[!] No hosts provided for scanning")
        return {}
    
    if not ports:
        print("[!] No ports provided for scanning")
        return {}
    
    scanner = PortScanner()
    protocol = 'UDP' if udp else 'TCP'
    
    print(f"[*] Starting {protocol} port scan...")
    print(f"[*] Targets: {len(hosts)} hosts")
    print(f"[*] Ports: {len(ports)} ports")
    print(f"[*] Total scans: {len(hosts) * len(ports)}")
    print(f"[*] Scan method: {'SYN scan' if not udp and SCAPY_AVAILABLE else 'Connect scan' if not udp else 'UDP scan'}")
    print()
    
    # Create list of all scan tasks
    scan_tasks = [(host, port, udp) for host in hosts for port in ports]
    total_scans = len(scan_tasks)
    
    # Perform threaded scanning
    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        # Submit all scan tasks
        futures = {
            executor.submit(scanner._scan_worker, host, port, udp): (host, port)
            for host, port, udp in scan_tasks
        }
        
        # Process completed scans
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                progress = (completed / total_scans) * 100
                print(f"[*] Progress: {completed}/{total_scans} ({progress:.1f}%)")
    
    # Filter results to show only meaningful statuses
    filtered_results = {}
    for host, port_results in scanner.scan_results.items():
        filtered_results[host] = {}
        for port, status in port_results.items():
            # Include open ports and potentially open UDP ports
            if status == 'open' or (udp and status == 'open|filtered'):
                filtered_results[host][port] = status
    
    print(f"\n[+] {protocol} scan complete")
    return filtered_results

def get_port_list(port_spec: str) -> List[int]:
    """
    Parse port specification string into list of port numbers.
    
    Args:
        port_spec: Port specification (e.g., "80,443,1000-1010")
        
    Returns:
        List[int]: List of port numbers
    """
    ports = []
    
    for part in port_spec.split(','):
        if '-' in part:
            # Port range
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                ports.extend(range(start_port, end_port + 1))
            except ValueError:
                print(f"[!] Invalid port range: {part}")
        else:
            # Single port
            try:
                port = int(part.strip())
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"[!] Port out of range: {port}")
            except ValueError:
                print(f"[!] Invalid port: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort

def main():
    """Main CLI interface for port scanning."""
    parser = argparse.ArgumentParser(
        description="Port Scanner - TCP SYN/Connect and UDP port scanning tool"
    )
    parser.add_argument(
        'hosts',
        nargs='+',
        help='Target IP addresses to scan'
    )
    parser.add_argument(
        '-p', '--ports',
        default='21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8000,8080,8443',
        help='Port specification: single ports, ranges, or comma-separated (e.g., "22,80,443,1000-1010")'
    )
    parser.add_argument(
        '--top-ports',
        type=int,
        help='Scan top N most common ports instead of custom port list'
    )
    parser.add_argument(
        '-u', '--udp',
        action='store_true',
        help='Perform UDP scan instead of TCP scan'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=3.0,
        help='Timeout for port connections in seconds (default: 3.0)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Maximum number of concurrent threads (default: 100)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate hosts
    valid_hosts = []
    for host in args.hosts:
        try:
            ipaddress.ip_address(host)
            valid_hosts.append(host)
        except ValueError:
            print(f"[!] Invalid IP address: {host}")
    
    if not valid_hosts:
        print("[!] No valid hosts provided")
        return
    
    # Determine ports to scan
    if args.top_ports:
        # Use top N common ports
        scanner = PortScanner()
        all_common = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6000, 6001, 8000, 8080, 8443, 8888,
            20, 69, 123, 161, 162, 389, 636, 1433, 1521, 2049, 3690, 5060,
            5061, 5432, 6379, 11211, 27017
        ]
        ports = all_common[:args.top_ports]
    else:
        ports = get_port_list(args.ports)
    
    if not ports:
        print("[!] No valid ports specified")
        return
    
    if args.verbose:
        protocol = 'UDP' if args.udp else 'TCP'
        print(f"[*] Configuration:")
        print(f"    Protocol: {protocol}")
        print(f"    Hosts: {valid_hosts}")
        print(f"    Ports: {len(ports)} ports")
        print(f"    Port list: {ports[:10]}{'...' if len(ports) > 10 else ''}")
        print(f"    Timeout: {args.timeout}s")
        print(f"    Max threads: {args.threads}")
        print(f"    Scapy available: {SCAPY_AVAILABLE}")
        print()
    
    # Perform port scan
    start_time = time.time()
    results = scan_ports(valid_hosts, ports, args.udp)
    end_time = time.time()
    
    # Display results
    protocol = 'UDP' if args.udp else 'TCP'
    print(f"\n{'='*80}")
    print(f"PORT SCAN RESULTS ({protocol})")
    print(f"{'='*80}")
    
    total_open = 0
    for host in sorted(results.keys(), key=ipaddress.ip_address):
        open_ports = results[host]
        if open_ports:
            total_open += len(open_ports)
            print(f"\nHost: {host}")
            print(f"Open ports: {len(open_ports)}")
            
            # Sort ports and display in rows
            sorted_ports = sorted(open_ports.keys())
            for i, port in enumerate(sorted_ports):
                status = open_ports[port]
                if i % 5 == 0 and i > 0:
                    print()
                print(f"  {port}/{protocol.lower():<3} ({status})", end="  ")
            print()
    
    if total_open == 0:
        print("No open ports found.")
    
    print(f"\n{'='*80}")
    print(f"Scan Summary:")
    print(f"  Hosts scanned: {len(valid_hosts)}")
    print(f"  Ports scanned per host: {len(ports)}")
    print(f"  Total open ports: {total_open}")
    print(f"  Scan duration: {end_time - start_time:.2f} seconds")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()