#!/usr/bin/env python3
"""
MAC Address Vendor Lookup Module
Part of the Fingerprinting System

This module provides MAC address to vendor name resolution using IEEE OUI database.
Includes caching, batch lookup optimization, and CLI interface for testing.

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
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class MACLookup:
    """
    MAC Address vendor lookup with optimized caching and batch processing.
    
    Attributes:
        oui_db (Dict): In-memory OUI database for fast lookups
        signatures_path (Path): Path to device signatures JSON file
    """
    
    def __init__(self, signatures_file: str = "device_signatures.json"):
        """
        Initialize MAC lookup with local OUI database.
        
        Args:
            signatures_file: Path to device signatures JSON file
        """
        self.signatures_path = Path(__file__).parent / signatures_file
        self.oui_db = self._load_oui_database()
        
    def _load_oui_database(self) -> Dict[str, str]:
        """
        Load OUI database from JSON file.
        
        Returns:
            Dictionary mapping OUI prefixes to vendor names
        """
        try:
            if self.signatures_path.exists():
                with open(self.signatures_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('oui_database', {})
            else:
                logger.warning(f"Signatures file not found: {self.signatures_path}")
                return {}
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading OUI database: {e}")
            return {}
    
    @staticmethod
    def normalize_mac(mac_address: str) -> Optional[str]:
        """
        Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX).
        
        Args:
            mac_address: MAC address in various formats
            
        Returns:
            Normalized MAC address or None if invalid
        """
        # Remove common separators and convert to uppercase
        mac_clean = re.sub(r'[.:\-\s]', '', mac_address.upper())
        
        # Validate length (12 hex characters)
        if not re.match(r'^[0-9A-F]{12}$', mac_clean):
            return None
            
        # Format as XX:XX:XX:XX:XX:XX
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    
    @lru_cache(maxsize=1024)
    def lookup_mac(self, mac_address: str) -> str:
        """
        Lookup vendor name for a given MAC address.
        
        Args:
            mac_address: MAC address in any common format
            
        Returns:
            Vendor name or "Unknown" if not found
        """
        # Normalize MAC address
        normalized = self.normalize_mac(mac_address)
        if not normalized:
            logger.debug(f"Invalid MAC address format: {mac_address}")
            return "Unknown"
        
        # Extract OUI (first 3 octets)
        oui = normalized[:8]  # XX:XX:XX
        
        # Lookup in database (try with and without colons)
        vendor = self.oui_db.get(oui)
        if not vendor:
            # Try without colons for compatibility
            oui_compact = oui.replace(':', '')
            vendor = self.oui_db.get(oui_compact)
        
        if vendor:
            logger.debug(f"Found vendor '{vendor}' for MAC {mac_address}")
            return vendor
        
        # Check for locally administered or multicast addresses
        first_octet = int(normalized[:2], 16)
        if first_octet & 0x02:  # Locally administered bit
            return "Locally Administered"
        
        return "Unknown"
    
    def lookup_batch(self, mac_addresses: List[str]) -> Dict[str, str]:
        """
        Perform batch lookup of multiple MAC addresses (optimized).
        
        Args:
            mac_addresses: List of MAC addresses
            
        Returns:
            Dictionary mapping MAC addresses to vendor names
        """
        results = {}
        for mac in mac_addresses:
            results[mac] = self.lookup_mac(mac)
        return results
    
    def get_vendor_statistics(self) -> Dict[str, int]:
        """
        Get statistics about loaded OUI database.
        
        Returns:
            Dictionary with database statistics
        """
        return {
            'total_ouis': len(self.oui_db),
            'unique_vendors': len(set(self.oui_db.values())),
            'database_loaded': bool(self.oui_db)
        }


# Standalone function for direct import
_default_lookup = None

def lookup_mac(mac_address: str) -> str:
    """
    Standalone function to lookup MAC vendor.
    
    Args:
        mac_address: MAC address string
        
    Returns:
        Vendor name or "Unknown"
    """
    global _default_lookup
    if _default_lookup is None:
        _default_lookup = MACLookup()
    return _default_lookup.lookup_mac(mac_address)


def main():
    """CLI interface for MAC lookup testing."""
    parser = argparse.ArgumentParser(
        description='MAC Address Vendor Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mac 00:11:22:33:44:55
  %(prog)s --mac "00-11-22-33-44-55"
  %(prog)s --batch macs.txt
  %(prog)s --stats
        """
    )
    
    parser.add_argument('--mac', '-m', type=str,
                       help='Single MAC address to lookup')
    parser.add_argument('--batch', '-b', type=str,
                       help='File containing MAC addresses (one per line)')
    parser.add_argument('--stats', '-s', action='store_true',
                       help='Show OUI database statistics')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize lookup instance
    mac_lookup = MACLookup()
    
    # Handle different modes
    if args.stats:
        stats = mac_lookup.get_vendor_statistics()
        print("\n=== OUI Database Statistics ===")
        for key, value in stats.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
            
    elif args.mac:
        vendor = mac_lookup.lookup_mac(args.mac)
        normalized = mac_lookup.normalize_mac(args.mac) or args.mac
        print(f"\nMAC Address: {normalized}")
        print(f"Vendor: {vendor}")
        
    elif args.batch:
        try:
            with open(args.batch, 'r') as f:
                mac_list = [line.strip() for line in f if line.strip()]
            
            results = mac_lookup.lookup_batch(mac_list)
            print("\n=== Batch Lookup Results ===")
            for mac, vendor in results.items():
                normalized = mac_lookup.normalize_mac(mac) or mac
                print(f"{normalized:20} -> {vendor}")
                
        except FileNotFoundError:
            print(f"Error: File '{args.batch}' not found", file=sys.stderr)
            sys.exit(1)
            
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()