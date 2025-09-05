#!/usr/bin/env python3
"""
Service Banner Parser Module
Part of the Fingerprinting System

This module analyzes service banners to extract device type and software information.
Supports common protocols: HTTP, SSH, FTP, SMTP, Telnet, SMB, and more.

Author: Network Scanner Framework
Version: 1.0.0
"""

import re
import json
import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


@dataclass
class BannerInfo:
    """Data class for parsed banner information."""
    service: Optional[str] = None
    version: Optional[str] = None
    device_type: Optional[str] = None
    os_hint: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    confidence: float = 0.0
    raw_banner: str = ""


class BannerParser:
    """
    Service banner parser with pattern matching and heuristics.
    
    Attributes:
        signatures (Dict): Banner signatures and patterns
        device_patterns (List): Device identification patterns
    """
    
    def __init__(self, signatures_file: str = "device_signatures.json"):
        """
        Initialize banner parser with signature database.
        
        Args:
            signatures_file: Path to device signatures JSON file
        """
        self.signatures_path = Path(__file__).parent / signatures_file
        self.signatures = self._load_signatures()
        self.device_patterns = self._compile_patterns()
        
    def _load_signatures(self) -> Dict:
        """
        Load banner signatures from JSON file.
        
        Returns:
            Dictionary containing banner patterns and device signatures
        """
        try:
            if self.signatures_path.exists():
                with open(self.signatures_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('banner_signatures', {})
            else:
                logger.warning(f"Signatures file not found: {self.signatures_path}")
                return {}
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading banner signatures: {e}")
            return {}
    
    def _compile_patterns(self) -> List[Tuple[re.Pattern, Dict]]:
        """
        Compile regex patterns for efficient matching.
        
        Returns:
            List of compiled patterns with associated metadata
        """
        patterns = []
        
        # Common service patterns
        service_patterns = [
            # HTTP Server headers
            (r'Server:\s*([^\r\n]+)', {'service': 'HTTP'}),
            (r'nginx/?([\d.]+)?', {'service': 'nginx', 'extract_version': True}),
            (r'Apache/?([\d.]+)?', {'service': 'Apache', 'extract_version': True}),
            (r'Microsoft-IIS/?([\d.]+)?', {'service': 'IIS', 'os_hint': 'Windows', 'extract_version': True}),
            (r'lighttpd/?([\d.]+)?', {'service': 'lighttpd', 'extract_version': True}),
            
            # SSH banners
            (r'SSH-([\d.]+)-OpenSSH[_\s]*([\d.]+)', {'service': 'OpenSSH', 'extract_version': 2}),
            (r'SSH-.*-dropbear[_\s]*([\d.]+)', {'service': 'Dropbear', 'extract_version': 1}),
            (r'SSH-.*-Cisco', {'service': 'SSH', 'vendor': 'Cisco', 'device_type': 'Network Device'}),
            
            # FTP banners
            (r'220.*ProFTPD\s+([\d.]+)', {'service': 'ProFTPD', 'extract_version': 1}),
            (r'220.*vsftpd\s+([\d.]+)', {'service': 'vsftpd', 'extract_version': 1}),
            (r'220.*Microsoft FTP', {'service': 'FTP', 'os_hint': 'Windows'}),
            
            # SMTP banners
            (r'220.*Postfix', {'service': 'Postfix'}),
            (r'220.*Exim\s+([\d.]+)', {'service': 'Exim', 'extract_version': 1}),
            (r'220.*Microsoft.*SMTP', {'service': 'Exchange', 'os_hint': 'Windows'}),
            
            # Device-specific patterns
            (r'HP[\s-]*(LaserJet|OfficeJet|DeskJet|[\w\d]+)', {'vendor': 'HP', 'device_type': 'Printer'}),
            (r'EPSON[\s-]*([\w\d]+)', {'vendor': 'Epson', 'device_type': 'Printer'}),
            (r'Brother[\s-]*([\w\d]+)', {'vendor': 'Brother', 'device_type': 'Printer'}),
            (r'Canon[\s-]*([\w\d]+)', {'vendor': 'Canon', 'device_type': 'Printer/Scanner'}),
            
            # IoT devices
            (r'(?i)(camera|ipcam|webcam|nvr|dvr)', {'device_type': 'Camera/NVR'}),
            (r'(?i)(router|gateway|modem)', {'device_type': 'Network Device'}),
            (r'(?i)(alexa|echo|google[\s-]?home)', {'device_type': 'Smart Speaker'}),
            (r'(?i)(smart[\s-]?tv|android[\s-]?tv|roku|chromecast)', {'device_type': 'Smart TV/Streaming'}),
            (r'(?i)(nas|synology|qnap|netgear[\s-]?stora)', {'device_type': 'NAS Storage'}),
            
            # Operating System hints
            (r'(?i)windows[\s-]?([\d.]+|server|xp|vista|7|8|10|11)', {'os_hint': 'Windows'}),
            (r'(?i)(ubuntu|debian|centos|redhat|fedora|linux)', {'os_hint': 'Linux'}),
            (r'(?i)(macos|mac[\s-]?os[\s-]?x|darwin)', {'os_hint': 'macOS'}),
            (r'(?i)(freebsd|openbsd|netbsd)', {'os_hint': 'BSD'}),
            (r'(?i)android[\s-]?([\d.]+)?', {'os_hint': 'Android'}),
            (r'(?i)ios[\s-]?([\d.]+)?', {'os_hint': 'iOS'}),
        ]
        
        # Compile patterns
        for pattern_str, metadata in service_patterns:
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
                patterns.append((compiled, metadata))
            except re.error as e:
                logger.error(f"Failed to compile pattern '{pattern_str}': {e}")
                
        return patterns
    
    def parse_banner(self, banner: str, port: Optional[int] = None) -> str:
        """
        Parse service banner to extract device/software information.
        
        Args:
            banner: Raw service banner string
            port: Optional port number for context
            
        Returns:
            Formatted string with extracted information
        """
        info = self._extract_info(banner, port)
        return self._format_result(info)
    
    def _extract_info(self, banner: str, port: Optional[int] = None) -> BannerInfo:
        """
        Extract detailed information from banner.
        
        Args:
            banner: Raw banner string
            port: Optional port for context
            
        Returns:
            BannerInfo object with extracted details
        """
        info = BannerInfo(raw_banner=banner[:500])  # Limit stored banner length
        
        # Clean banner for processing
        banner_clean = banner.replace('\x00', '').strip()
        
        # Apply pattern matching
        for pattern, metadata in self.device_patterns:
            match = pattern.search(banner_clean)
            if match:
                # Extract version if specified
                if 'extract_version' in metadata:
                    version_group = metadata['extract_version']
                    if isinstance(version_group, int) and len(match.groups()) >= version_group:
                        info.version = match.group(version_group)
                    elif version_group is True and match.groups():
                        info.version = match.group(1)
                
                # Update info fields
                for key, value in metadata.items():
                    if key != 'extract_version' and hasattr(info, key):
                        setattr(info, key, value)
                
                # Increase confidence for each match
                info.confidence = min(info.confidence + 0.3, 1.0)
        
        # Port-based heuristics
        if port:
            port_hints = {
                22: ('SSH', None),
                23: ('Telnet', None),
                25: ('SMTP', None),
                80: ('HTTP', None),
                443: ('HTTPS', None),
                445: ('SMB', 'Windows'),
                3389: ('RDP', 'Windows'),
                5900: ('VNC', None),
                8080: ('HTTP-Alt', None),
                9100: ('Printer', None),
            }
            
            if port in port_hints:
                service_hint, os_hint = port_hints[port]
                if not info.service:
                    info.service = service_hint
                if os_hint and not info.os_hint:
                    info.os_hint = os_hint
        
        # Check custom signatures from JSON
        if self.signatures:
            for sig_name, sig_data in self.signatures.items():
                if 'pattern' in sig_data:
                    if re.search(sig_data['pattern'], banner_clean, re.IGNORECASE):
                        if 'device_type' in sig_data:
                            info.device_type = sig_data['device_type']
                        if 'vendor' in sig_data:
                            info.vendor = sig_data['vendor']
                        info.confidence = min(info.confidence + 0.4, 1.0)
        
        return info
    
    def _format_result(self, info: BannerInfo) -> str:
        """
        Format BannerInfo into human-readable string.
        
        Args:
            info: BannerInfo object
            
        Returns:
            Formatted result string
        """
        parts = []
        
        if info.device_type:
            parts.append(f"Device: {info.device_type}")
        
        if info.vendor:
            if info.model:
                parts.append(f"Vendor: {info.vendor} {info.model}")
            else:
                parts.append(f"Vendor: {info.vendor}")
        
        if info.service:
            if info.version:
                parts.append(f"Service: {info.service}/{info.version}")
            else:
                parts.append(f"Service: {info.service}")
        
        if info.os_hint:
            parts.append(f"OS: {info.os_hint}")
        
        if info.confidence > 0:
            confidence_pct = int(info.confidence * 100)
            parts.append(f"Confidence: {confidence_pct}%")
        
        if parts:
            return " | ".join(parts)
        else:
            return "Unknown service/device"
    
    def parse_multiple(self, banners: List[Tuple[str, Optional[int]]]) -> List[str]:
        """
        Parse multiple banners in batch.
        
        Args:
            banners: List of (banner, port) tuples
            
        Returns:
            List of parsed results
        """
        results = []
        for banner, port in banners:
            results.append(self.parse_banner(banner, port))
        return results


# Standalone function for direct import
_default_parser = None

def parse_banner(banner: str) -> str:
    """
    Standalone function to parse service banner.
    
    Args:
        banner: Raw banner string
        
    Returns:
        Formatted string with extracted information
    """
    global _default_parser
    if _default_parser is None:
        _default_parser = BannerParser()
    return _default_parser.parse_banner(banner)


def main():
    """CLI interface for banner parser testing."""
    parser = argparse.ArgumentParser(
        description='Service Banner Parser Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --banner "Apache/2.4.41 (Ubuntu)"
  %(prog)s --banner "SSH-2.0-OpenSSH_8.2p1" --port 22
  %(prog)s --file banners.txt
  %(prog)s --interactive
        """
    )
    
    parser.add_argument('--banner', '-b', type=str,
                       help='Banner string to parse')
    parser.add_argument('--port', '-p', type=int,
                       help='Port number for context')
    parser.add_argument('--file', '-f', type=str,
                       help='File containing banners (one per line)')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Interactive mode for testing')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize parser
    banner_parser = BannerParser()
    
    if args.banner:
        result = banner_parser.parse_banner(args.banner, args.port)
        print(f"\n=== Banner Analysis ===")
        print(f"Input: {args.banner[:100]}...")
        if args.port:
            print(f"Port: {args.port}")
        print(f"Result: {result}")
        
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                banners = []
                for line in f:
                    line = line.strip()
                    if line:
                        # Support format: banner|port or just banner
                        if '|' in line:
                            banner, port_str = line.rsplit('|', 1)
                            try:
                                port = int(port_str)
                            except ValueError:
                                port = None
                        else:
                            banner = line
                            port = None
                        banners.append((banner, port))
            
            results = banner_parser.parse_multiple(banners)
            print("\n=== Batch Banner Analysis ===")
            for (banner, port), result in zip(banners, results):
                print(f"\nBanner: {banner[:50]}...")
                if port:
                    print(f"Port: {port}")
                print(f"Result: {result}")
                
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
            
    elif args.interactive:
        print("Interactive Banner Parser (type 'quit' to exit)")
        print("-" * 50)
        while True:
            try:
                banner = input("\nEnter banner string: ").strip()
                if banner.lower() == 'quit':
                    break
                    
                port_str = input("Enter port (optional, press Enter to skip): ").strip()
                port = int(port_str) if port_str else None
                
                result = banner_parser.parse_banner(banner, port)
                print(f"Result: {result}")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
                
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()