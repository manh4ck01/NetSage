#!/usr/bin/env python3
"""
Host Discovery Module - Scanner Engine
Implements ICMP ping sweep and ARP discovery for live host detection.
"""

import socket
import struct
import time
import threading
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
import sys
import os

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. ARP discovery and ICMP will be limited.")
    SCAPY_AVAILABLE = False

class HostDiscovery:
    """Host discovery class implementing ping sweep and ARP discovery methods."""
    
    def __init__(self, timeout: float = 2.0, max_threads: int = 50):
        """
        Initialize host discovery with configurable timeout and thread pool size.
        
        Args:
            timeout: Timeout for network operations in seconds
            max_threads: Maximum number of concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.live_hosts: Set[str] = set()
        self.lock = threading.Lock()
    
    def _icmp_ping_raw(self, host: str) -> bool:
        """
        Perform raw ICMP ping using scapy.
        
        Args:
            host: Target IP address string
            
        Returns:
            bool: True if host responds to ICMP ping
        """
        if not SCAPY_AVAILABLE:
            return False
            
        try:
            # Create ICMP packet
            packet = IP(dst=host) / ICMP()
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(ICMP):
                # Check if it's an echo reply
                if response[ICMP].type == 0:  # Echo reply
                    return True
                    
        except Exception as e:
            # Silently handle permission errors and other exceptions
            pass
            
        return False
    
    def _tcp_ping(self, host: str, port: int = 80) -> bool:
        """
        Perform TCP connect test to common ports as ping alternative.
        
        Args:
            host: Target IP address string
            port: Port to test (default 80)
            
        Returns:
            bool: True if TCP connection successful
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _ping_host(self, host: str) -> bool:
        """
        Ping a single host using multiple methods.
        
        Args:
            host: Target IP address string
            
        Returns:
            bool: True if host is alive
        """
        # Try ICMP ping first
        if self._icmp_ping_raw(host):
            return True
            
        # Fallback to TCP ping on common ports
        common_ports = [80, 443, 22, 21, 25, 53]
        for port in common_ports[:3]:  # Test only first 3 for speed
            if self._tcp_ping(host, port):
                return True
                
        return False
    
    def _arp_discover_subnet(self, network: str) -> List[str]:
        """
        Perform ARP discovery on local subnet using scapy.
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List[str]: List of responding IP addresses
        """
        if not SCAPY_AVAILABLE:
            return []
            
        live_hosts = []
        
        try:
            # Create ARP request for entire subnet
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_packet = broadcast / arp_request
            
            # Send packet and receive responses
            answered_list = srp(arp_packet, timeout=self.timeout, verbose=0)[0]
            
            # Extract IP addresses from responses
            for element in answered_list:
                ip = element[1].psrc
                live_hosts.append(ip)
                
        except Exception as e:
            print(f"ARP discovery error: {e}")
            
        return live_hosts
    
    def _ping_worker(self, host: str) -> None:
        """
        Worker function for threaded ping operations.
        
        Args:
            host: Target IP address string
        """
        if self._ping_host(host):
            with self.lock:
                self.live_hosts.add(host)
                print(f"[+] Host alive: {host}")

def discover_hosts(targets: List[str]) -> List[str]:
    """
    Discover live hosts from target list using ICMP ping sweep and ARP discovery.
    
    Args:
        targets: List of IP addresses or CIDR networks to scan
        
    Returns:
        List[str]: List of live IP addresses discovered
    """
    discovery = HostDiscovery()
    all_hosts = set()
    
    print("[*] Starting host discovery...")
    
    # Process each target
    for target in targets:
        try:
            # Check if target is a network (CIDR notation)
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                
                # For local networks, try ARP discovery first
                if network.is_private and len(list(network.hosts())) <= 254:
                    print(f"[*] Performing ARP discovery on {target}")
                    arp_hosts = discovery._arp_discover_subnet(target)
                    all_hosts.update(arp_hosts)
                    print(f"[*] ARP discovered {len(arp_hosts)} hosts")
                
                # Add all hosts in network for ping sweep
                host_list = [str(ip) for ip in network.hosts()]
                if len(host_list) > 1000:
                    print(f"[!] Warning: Large network {target} ({len(host_list)} hosts)")
                    print("[!] Consider using smaller subnets for better performance")
                
                all_hosts.update(host_list)
                
            else:
                # Single IP address
                try:
                    ip = ipaddress.ip_address(target)
                    all_hosts.add(str(ip))
                except ValueError:
                    print(f"[!] Invalid target: {target}")
                    continue
                    
        except ValueError as e:
            print(f"[!] Invalid target format: {target} - {e}")
            continue
    
    # Convert to list for ping sweep
    host_list = list(all_hosts)
    print(f"[*] Starting ping sweep for {len(host_list)} hosts...")
    
    # Perform threaded ping sweep
    with ThreadPoolExecutor(max_workers=discovery.max_threads) as executor:
        # Submit ping tasks
        futures = {executor.submit(discovery._ping_worker, host): host 
                  for host in host_list}
        
        # Process completed futures
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"[*] Pinged {completed}/{len(host_list)} hosts...")
    
    live_hosts = sorted(list(discovery.live_hosts), key=ipaddress.ip_address)
    
    print(f"\n[+] Discovery complete: {len(live_hosts)} live hosts found")
    for host in live_hosts:
        print(f"    {host}")
    
    return live_hosts

def main():
    """Main CLI interface for host discovery."""
    parser = argparse.ArgumentParser(
        description="Host Discovery Tool - Find live hosts using ICMP ping and ARP discovery"
    )
    parser.add_argument(
        'targets', 
        nargs='+',
        help='Target IP addresses or CIDR networks (e.g., 192.168.1.1 192.168.1.0/24)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=2.0,
        help='Timeout for ping operations in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Maximum number of concurrent threads (default: 50)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[*] Configuration:")
        print(f"    Targets: {args.targets}")
        print(f"    Timeout: {args.timeout}s")
        print(f"    Max threads: {args.threads}")
        print(f"    Scapy available: {SCAPY_AVAILABLE}")
        print()
    
    # Check for root privileges if using scapy
    if SCAPY_AVAILABLE and os.geteuid() != 0:
        print("[!] Warning: Running without root privileges. ICMP ping may not work.")
        print("[!] Consider running with sudo for full functionality.")
        print()
    
    # Discover hosts
    start_time = time.time()
    live_hosts = discover_hosts(args.targets)
    end_time = time.time()
    
    # Display results
    print(f"\n{'='*60}")
    print(f"HOST DISCOVERY RESULTS")
    print(f"{'='*60}")
    print(f"Total live hosts found: {len(live_hosts)}")
    print(f"Scan duration: {end_time - start_time:.2f} seconds")
    print(f"{'='*60}")
    
    if live_hosts:
        print("\nLive Hosts:")
        for i, host in enumerate(live_hosts, 1):
            print(f"{i:3d}. {host}")
    else:
        print("\nNo live hosts discovered.")

if __name__ == "__main__":
    main()