#!/usr/bin/env python3
"""
Service Banner Grabbing Module - Scanner Engine
Implements banner grabbing for common network services.
"""

import socket
import ssl
import threading
import time
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
import re

class BannerGrabber:
    """Banner grabbing class for service detection and fingerprinting."""
    
    def __init__(self, timeout: float = 5.0, max_threads: int = 50):
        """
        Initialize banner grabber with configurable timeout and threads.
        
        Args:
            timeout: Network timeout in seconds
            max_threads: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.lock = threading.Lock()
        
        # Service probes for different protocols
        self.service_probes = {
            21: {'name': 'FTP', 'probe': b'', 'ssl': False},
            22: {'name': 'SSH', 'probe': b'', 'ssl': False},
            23: {'name': 'Telnet', 'probe': b'', 'ssl': False},
            25: {'name': 'SMTP', 'probe': b'EHLO banner-grab\r\n', 'ssl': False},
            53: {'name': 'DNS', 'probe': b'', 'ssl': False},
            80: {'name': 'HTTP', 'probe': b'HEAD / HTTP/1.1\r\nHost: %HOST%\r\n\r\n', 'ssl': False},
            110: {'name': 'POP3', 'probe': b'', 'ssl': False},
            143: {'name': 'IMAP', 'probe': b'', 'ssl': False},
            443: {'name': 'HTTPS', 'probe': b'HEAD / HTTP/1.1\r\nHost: %HOST%\r\n\r\n', 'ssl': True},
            993: {'name': 'IMAPS', 'probe': b'', 'ssl': True},
            995: {'name': 'POP3S', 'probe': b'', 'ssl': True},
            1433: {'name': 'MSSQL', 'probe': b'', 'ssl': False},
            3306: {'name': 'MySQL', 'probe': b'', 'ssl': False},
            3389: {'name': 'RDP', 'probe': b'', 'ssl': False},
            5432: {'name': 'PostgreSQL', 'probe': b'', 'ssl': False},
            5900: {'name': 'VNC', 'probe': b'', 'ssl': False},
            8000: {'name': 'HTTP-Alt', 'probe': b'HEAD / HTTP/1.1\r\nHost: %HOST%\r\n\r\n', 'ssl': False},
            8080: {'name': 'HTTP-Proxy', 'probe': b'HEAD / HTTP/1.1\r\nHost: %HOST%\r\n\r\n', 'ssl': False},
            8443: {'name': 'HTTPS-Alt', 'probe': b'HEAD / HTTP/1.1\r\nHost: %HOST%\r\n\r\n', 'ssl': True},
        }
    
    def _grab_banner_raw(self, host: str, port: int) -> Optional[str]:
        """
        Grab banner using raw socket connection.
        
        Args:
            host: Target IP address
            port: Target port number
            
        Returns:
            Optional[str]: Banner string if successful, None otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Get service probe if available
            service_info = self.service_probes.get(port, {'probe': b'', 'ssl': False})
            probe = service_info['probe']
            use_ssl = service_info['ssl']
            
            # Wrap with SSL if needed
            if use_ssl:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                except Exception:
                    sock.close()
                    return None
            
            # Send probe if specified
            if probe:
                probe_data = probe.replace(b'%HOST%', host.encode())
                sock.send(probe_data)
            
            # Receive banner
            banner_data = sock.recv(4096)
            sock.close()
            
            # Decode banner
            try:
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                banner = str(banner_data)
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _grab_http_banner(self, host: str, port: int, use_ssl: bool = False) -> Optional[str]:
        """
        Grab HTTP/HTTPS banner with enhanced header parsing.
        
        Args:
            host: Target IP address
            port: Target port number
            use_ssl: Whether to use SSL/TLS
            
        Returns:
            Optional[str]: HTTP banner with server info
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            if use_ssl:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                except Exception:
                    sock.close()
                    return None
            
            # Send HTTP HEAD request
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Scanner/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Receive response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse HTTP response for interesting headers
            lines = response.split('\n')
            if lines:
                status_line = lines[0].strip()
                server_info = []
                
                for line in lines[1:]:
                    if line.lower().startswith('server:'):
                        server_info.append(line.strip())
                    elif line.lower().startswith('x-powered-by:'):
                        server_info.append(line.strip())
                
                banner_parts = [status_line]
                banner_parts.extend(server_info)
                return ' | '.join(banner_parts)
            
            return None
            
        except Exception:
            return None
    
    def _identify_service(self, banner: str, port: int) -> str:
        """
        Identify service type based on banner content and port.
        
        Args:
            banner: Banner string
            port: Port number
            
        Returns:
            str: Identified service name
        """
        if not banner:
            return self.service_probes.get(port, {}).get('name', 'Unknown')
        
        banner_lower = banner.lower()
        
        # Service identification patterns
        patterns = {
            'SSH': ['ssh', 'openssh'],
            'FTP': ['ftp', '220 '],
            'HTTP': ['http', 'apache', 'nginx', 'iis'],
            'HTTPS': ['http', 'apache', 'nginx', 'iis'],
            'SMTP': ['smtp', 'mail', 'postfix', 'sendmail'],
            'POP3': ['pop3', '+ok'],
            'IMAP': ['imap', '* ok'],
            'MySQL': ['mysql', 'mariadb'],
            'PostgreSQL': ['postgresql', 'postgres'],
            'MSSQL': ['microsoft sql', 'mssql'],
            'VNC': ['rfb', 'vnc'],
            'RDP': ['terminal', 'rdp'],
            'DNS': ['dns', 'bind'],
            'Telnet': ['telnet', 'login:']
        }
        
        # Check banner against patterns
        for service, keywords in patterns.items():
            for keyword in keywords:
                if keyword in banner_lower:
                    return service
        
        # Fallback to port-based identification
        return self.service_probes.get(port, {}).get('name', 'Unknown')
    
    def _grab_banner_for_port(self, host: str, port: int) -> Tuple[str, int, str, str]:
        """
        Grab banner for a specific host:port combination.
        
        Args:
            host: Target IP address
            port: Target port number
            
        Returns:
            Tuple[str, int, str, str]: (host, port, banner, service)
        """
        banner = None
        
        # Try specialized HTTP banner grabbing for web services
        if port in [80, 443, 8000, 8080, 8443]:
            use_ssl = port in [443, 8443]
            banner = self._grab_http_banner(host, port, use_ssl)
        
        # Fallback to raw banner grabbing
        if not banner:
            banner = self._grab_banner_raw(host, port)
        
        # Clean up banner
        if banner:
            banner = ' '.join(banner.split())  # Normalize whitespace
            if len(banner) > 200:  # Truncate very long banners
                banner = banner[:197] + "..."
        
        service = self._identify_service(banner, port)
        
        return host, port, banner or "No banner", service

def grab_service_banners(scan_results: Dict[str, Dict[int, str]]) -> Dict[str, Dict[int, Dict[str, str]]]:
    """
    Grab service banners for all open ports in scan results.
    
    Args:
        scan_results: Dictionary from port scan {host: {port: status}}
        
    Returns:
        Dict: Enhanced results {host: {port: {'status': status, 'banner': banner, 'service': service}}}
    """
    if not scan_results:
        print("[!] No scan results provided for banner grabbing")
        return {}
    
    grabber = BannerGrabber()
    enhanced_results = {}
    
    # Count total open ports to scan
    total_ports = sum(
        len([p for p, s in ports.items() if s == 'open']) 
        for ports in scan_results.values()
    )
    
    if total_ports == 0:
        print("[!] No open ports found for banner grabbing")
        return {}
    
    print(f"[*] Starting banner grabbing for {total_ports} open ports...")
    
    # Create list of banner grabbing tasks
    tasks = []
    for host, ports in scan_results.items():
        for port, status in ports.items():
            if status == 'open':
                tasks.append((host, port))
    
    # Perform threaded banner grabbing
    with ThreadPoolExecutor(max_workers=grabber.max_threads) as executor:
        # Submit banner grabbing tasks
        futures = {
            executor.submit(grabber._grab_banner_for_port, host, port): (host, port)
            for host, port in tasks
        }
        
        # Process completed tasks
        completed = 0
        for future in as_completed(futures):
            completed += 1
            host, port, banner, service = future.result()
            
            # Initialize host entry if needed
            if host not in enhanced_results:
                enhanced_results[host] = {}
            
            # Store enhanced results
            enhanced_results[host][port] = {
                'status': 'open',
                'banner': banner,
                'service': service
            }
            
            # Print progress
            print(f"[+] {host}:{port} - {service} - {banner[:50]}{'...' if len(banner) > 50 else ''}")
            
            if completed % 10 == 0:
                progress = (completed / total_ports) * 100
                print(f"[*] Banner progress: {completed}/{total_ports} ({progress:.1f}%)")
    
    print(f"\n[+] Banner grabbing complete for {len(enhanced_results)} hosts")
    return enhanced_results

def parse_scan_results(results_text: str) -> Dict[str, Dict[int, str]]:
    """
    Parse scan results from text format for testing purposes.
    
    Args:
        results_text: Text representation of scan results
        
    Returns:
        Dict: Parsed scan results {host: {port: status}}
    """
    results = {}
    
    lines = results_text.strip().split('\n')
    current_host = None
    
    for line in lines:
        line = line.strip()
        if line.startswith('Host:'):
            current_host = line.split()[-1]
            results[current_host] = {}
        elif current_host and '/' in line and ('open' in line or 'closed' in line):
            # Parse port line like "80/tcp (open)"
            parts = line.split()
            if parts:
                port_proto = parts[0]
                if '/' in port_proto:
                    port = int(port_proto.split('/')[0])
                    status = 'open' if 'open' in line else 'closed'
                    if status == 'open':
                        results[current_host][port] = status
    
    return results

def main():
    """Main CLI interface for banner grabbing."""
    parser = argparse.ArgumentParser(
        description="Banner Grabber - Service detection and banner grabbing tool"
    )
    
    # Input methods
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--host-port',
        action='append',
        help='Single host:port combination (can be used multiple times)'
    )
    input_group.add_argument(
        '--scan-file',
        help='File containing scan results to process'
    )
    input_group.add_argument(
        '--json-results',
        help='JSON file with scan results'
    )
    
    # Configuration options
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=5.0,
        help='Timeout for banner grabbing in seconds (default: 5.0)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Maximum number of concurrent threads (default: 50)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse input based on method
    scan_results = {}
    
    if args.host_port:
        # Parse host:port combinations
        for hp in args.host_port:
            if ':' not in hp:
                print(f"[!] Invalid host:port format: {hp}")
                continue
            
            host, port_str = hp.rsplit(':', 1)
            try:
                port = int(port_str)
                if host not in scan_results:
                    scan_results[host] = {}
                scan_results[host][port] = 'open'
            except ValueError:
                print(f"[!] Invalid port number in: {hp}")
                continue
    
    elif args.json_results:
        # Load from JSON file
        try:
            with open(args.json_results, 'r') as f:
                scan_results = json.load(f)
        except Exception as e:
            print(f"[!] Error loading JSON file: {e}")
            return
    
    elif args.scan_file:
        # Parse text scan results
        try:
            with open(args.scan_file, 'r') as f:
                content = f.read()
            scan_results = parse_scan_results(content)
        except Exception as e:
            print(f"[!] Error reading scan file: {e}")
            return
    
    if not scan_results:
        print("[!] No valid scan results provided")
        return
    
    if args.verbose:
        total_hosts = len(scan_results)
        total_ports = sum(len(ports) for ports in scan_results.values())
        print(f"[*] Configuration:")
        print(f"    Hosts: {total_hosts}")
        print(f"    Total open ports: {total_ports}")
        print(f"    Timeout: {args.timeout}s")
        print(f"    Max threads: {args.threads}")
        print()
    
    # Perform banner grabbing
    start_time = time.time()
    enhanced_results = grab_service_banners(scan_results)
    end_time = time.time()
    
    # Display results
    print(f"\n{'='*100}")
    print(f"BANNER GRABBING RESULTS")
    print(f"{'='*100}")
    
    total_banners = 0
    for host in sorted(enhanced_results.keys()):
        port_results = enhanced_results[host]
        if port_results:
            print(f"\nHost: {host}")
            print("-" * 50)
            
            for port in sorted(port_results.keys()):
                info = port_results[port]
                service = info['service']
                banner = info['banner']
                total_banners += 1
                
                print(f"  {port:>5}/tcp  {service:<12} {banner}")
    
    if total_banners == 0:
        print("No banners grabbed.")
    
    print(f"\n{'='*100}")
    print(f"Banner Summary:")
    print(f"  Hosts processed: {len(enhanced_results)}")
    print(f"  Total banners grabbed: {total_banners}")
    print(f"  Grab duration: {end_time - start_time:.2f} seconds")
    print(f"{'='*100}")
    
    # Save results to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(enhanced_results, f, indent=2)
            print(f"\n[+] Results saved to: {args.output}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")

if __name__ == "__main__":
    main()