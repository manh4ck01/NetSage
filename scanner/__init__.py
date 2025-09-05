"""
Scanner Engine Package
A comprehensive network scanning toolkit with host discovery, port scanning, and banner grabbing.

Modules:
    discover: Host discovery using ICMP ping and ARP scanning
    port_scan: TCP/UDP port scanning with SYN scan capability  
    banners: Service banner grabbing and fingerprinting
    main: Complete integrated scanner engine

Usage:
    # As individual modules
    from scanner.discover import discover_hosts
    from scanner.port_scan import scan_ports
    from scanner.banners import grab_service_banners
    
    # As complete engine
    from scanner import ScannerEngine
    
    # CLI usage
    python -m scanner.main target_list -p 80,443,22
"""

__version__ = "1.0.0"
__author__ = "Scanner Engine"
__description__ = "Network scanning toolkit with discovery, port scanning, and banner grabbing"

# Import main classes for easy access
try:
    from .main import ScannerEngine
    from .scanner.discover import discover_hosts
    from .port_scan import scan_ports
    from .banners import grab_service_banners
    
    __all__ = [
        'ScannerEngine',
        'discover_hosts', 
        'scan_ports',
        'grab_service_banners'
    ]
    
except ImportError:
    # Handle case where dependencies might not be available
    __all__ = []

# Configuration constants
DEFAULT_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157
]