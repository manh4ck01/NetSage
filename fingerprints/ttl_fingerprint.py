#!/usr/bin/env python3
"""
TTL-based OS Fingerprinting Module

This module provides OS fingerprinting capabilities based on TTL (Time To Live) 
values and TCP window sizes observed in network packets. Different operating 
systems have characteristic default TTL values and TCP window configurations.

Author: Network Fingerprinting System
Version: 1.0
"""

import argparse
import sys
from typing import Dict, List, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TTLFingerprinter:
    """
    OS fingerprinting based on TTL values and TCP window sizes.
    
    This class contains the logic for identifying operating systems based on
    network packet characteristics, primarily TTL and window size values.
    """
    
    def __init__(self):
        """Initialize the TTL fingerprinter with OS signature database."""
        self.os_signatures = self._load_os_signatures()
        
    def _load_os_signatures(self) -> Dict[str, Dict]:
        """
        Load OS signature database with TTL and window size patterns.
        
        Returns:
            Dict containing OS signatures with TTL ranges and window sizes
        """
        return {
            "Windows 10/11": {
                "ttl_range": (128, 128),
                "common_windows": [8192, 65535, 64240, 16384],
                "confidence_boost": ["8192", "65535"],
                "description": "Modern Windows (10/11) with TTL 128"
            },
            "Windows 7/8": {
                "ttl_range": (128, 128),
                "common_windows": [8192, 65535, 64240],
                "confidence_boost": ["8192"],
                "description": "Older Windows versions with TTL 128"
            },
            "Windows XP/2003": {
                "ttl_range": (128, 128),
                "common_windows": [65535, 16384, 64240],
                "confidence_boost": ["65535"],
                "description": "Legacy Windows with TTL 128"
            },
            "Linux (Modern)": {
                "ttl_range": (64, 64),
                "common_windows": [29200, 14600, 5840, 65495],
                "confidence_boost": ["29200", "14600"],
                "description": "Modern Linux distributions with TTL 64"
            },
            "Linux (Kernel 2.4/2.6)": {
                "ttl_range": (64, 64),
                "common_windows": [5840, 32768, 65535],
                "confidence_boost": ["5840"],
                "description": "Older Linux kernels with TTL 64"
            },
            "MacOS (Big Sur+)": {
                "ttl_range": (64, 64),
                "common_windows": [65535, 32768, 131072],
                "confidence_boost": ["131072", "65535"],
                "description": "Modern macOS with TTL 64"
            },
            "MacOS (Legacy)": {
                "ttl_range": (64, 64),
                "common_windows": [65535, 32768, 16384],
                "confidence_boost": ["32768"],
                "description": "Older macOS versions with TTL 64"
            },
            "iOS": {
                "ttl_range": (64, 64),
                "common_windows": [65535, 32768],
                "confidence_boost": ["65535"],
                "description": "iOS devices with TTL 64"
            },
            "Android": {
                "ttl_range": (64, 64),
                "common_windows": [65535, 14600, 29200],
                "confidence_boost": ["29200"],
                "description": "Android devices with TTL 64"
            },
            "Cisco IOS": {
                "ttl_range": (255, 255),
                "common_windows": [4128, 8192, 16384],
                "confidence_boost": ["4128"],
                "description": "Cisco networking equipment with TTL 255"
            },
            "FreeBSD": {
                "ttl_range": (64, 64),
                "common_windows": [65535, 57344, 32768],
                "confidence_boost": ["57344"],
                "description": "FreeBSD systems with TTL 64"
            },
            "OpenBSD": {
                "ttl_range": (255, 255),
                "common_windows": [16384, 65535],
                "confidence_boost": ["16384"],
                "description": "OpenBSD systems with TTL 255"
            },
            "Solaris": {
                "ttl_range": (255, 255),
                "common_windows": [24820, 32768, 49640],
                "confidence_boost": ["24820"],
                "description": "Oracle Solaris with TTL 255"
            },
            "AIX": {
                "ttl_range": (255, 255),
                "common_windows": [16384, 65535],
                "confidence_boost": [],
                "description": "IBM AIX systems with TTL 255"
            }
        }
    
    def fingerprint_os(self, ttl: int, window_size: int, verbose: bool = False) -> str:
        """
        Identify the operating system based on TTL and TCP window size.
        
        Args:
            ttl (int): Time To Live value from packet
            window_size (int): TCP window size from packet
            verbose (bool): Enable verbose output for debugging
            
        Returns:
            str: Best guess of the operating system
        """
        if verbose:
            logger.info(f"Analyzing TTL: {ttl}, Window Size: {window_size}")
        
        matches = []
        
        # Find all OS signatures that match the TTL
        for os_name, signature in self.os_signatures.items():
            ttl_min, ttl_max = signature["ttl_range"]
            
            # Check if TTL falls within the expected range (accounting for hops)
            if self._ttl_matches(ttl, ttl_min, ttl_max):
                confidence = self._calculate_confidence(signature, window_size, ttl, ttl_min)
                matches.append((os_name, confidence, signature["description"]))
                
                if verbose:
                    logger.info(f"  Match: {os_name} (confidence: {confidence:.2f})")
        
        if not matches:
            return f"Unknown OS (TTL: {ttl}, Window: {window_size})"
        
        # Sort by confidence and return the best match
        matches.sort(key=lambda x: x[1], reverse=True)
        best_match = matches[0]
        
        if verbose:
            logger.info(f"Best match: {best_match[0]} with confidence {best_match[1]:.2f}")
        
        return best_match[0]
    
    def _ttl_matches(self, observed_ttl: int, min_ttl: int, max_ttl: int) -> bool:
        """
        Check if observed TTL matches expected range, accounting for network hops.
        
        Args:
            observed_ttl (int): TTL value observed in packet
            min_ttl (int): Minimum expected TTL for OS
            max_ttl (int): Maximum expected TTL for OS
            
        Returns:
            bool: True if TTL could match after accounting for hops
        """
        # TTL decreases by 1 for each router hop
        # We assume max 30 hops for reasonable network paths
        for original_ttl in range(min_ttl, max_ttl + 1):
            if observed_ttl <= original_ttl and (original_ttl - observed_ttl) <= 30:
                return True
        return False
    
    def _calculate_confidence(self, signature: Dict, window_size: int, 
                            observed_ttl: int, expected_ttl: int) -> float:
        """
        Calculate confidence score for OS match.
        
        Args:
            signature (Dict): OS signature data
            window_size (int): Observed TCP window size
            observed_ttl (int): Observed TTL value
            expected_ttl (int): Expected TTL for this OS
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        confidence = 0.5  # Base confidence for TTL match
        
        # Boost confidence if window size matches common values
        if window_size in signature["common_windows"]:
            confidence += 0.3
            
        # Extra boost for highly characteristic window sizes
        if str(window_size) in signature["confidence_boost"]:
            confidence += 0.2
        
        # Reduce confidence based on TTL hop distance
        hop_distance = expected_ttl - observed_ttl
        if hop_distance > 0:
            confidence -= min(0.1, hop_distance * 0.01)
        
        return min(1.0, max(0.0, confidence))
    
    def get_detailed_analysis(self, ttl: int, window_size: int) -> Dict:
        """
        Get detailed analysis of all possible OS matches.
        
        Args:
            ttl (int): Time To Live value
            window_size (int): TCP window size
            
        Returns:
            Dict: Detailed analysis with all possible matches
        """
        results = {
            "input": {"ttl": ttl, "window_size": window_size},
            "matches": [],
            "analysis": {}
        }
        
        for os_name, signature in self.os_signatures.items():
            ttl_min, ttl_max = signature["ttl_range"]
            
            if self._ttl_matches(ttl, ttl_min, ttl_max):
                confidence = self._calculate_confidence(signature, window_size, ttl, ttl_min)
                
                results["matches"].append({
                    "os": os_name,
                    "confidence": confidence,
                    "description": signature["description"],
                    "window_match": window_size in signature["common_windows"],
                    "characteristic_window": str(window_size) in signature["confidence_boost"]
                })
        
        # Sort matches by confidence
        results["matches"].sort(key=lambda x: x["confidence"], reverse=True)
        
        # Add analysis summary
        if results["matches"]:
            best_match = results["matches"][0]
            results["analysis"] = {
                "best_guess": best_match["os"],
                "confidence": best_match["confidence"],
                "total_matches": len(results["matches"])
            }
        else:
            results["analysis"] = {
                "best_guess": "Unknown",
                "confidence": 0.0,
                "total_matches": 0
            }
        
        return results


def main():
    """
    Command-line interface for TTL-based OS fingerprinting.
    """
    parser = argparse.ArgumentParser(
        description="OS Fingerprinting based on TTL and TCP Window Size",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ttl 128 --window 8192
  %(prog)s --ttl 64 --window 29200 --verbose
  %(prog)s --ttl 255 --window 4128 --detailed
        """
    )
    
    parser.add_argument(
        "--ttl", 
        type=int, 
        required=True,
        help="TTL value observed in packet (1-255)"
    )
    
    parser.add_argument(
        "--window", 
        type=int, 
        required=True,
        help="TCP window size observed in packet"
    )
    
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--detailed", 
        action="store_true",
        help="Show detailed analysis of all possible matches"
    )
    
    args = parser.parse_args()
    
    # Validate input ranges
    if not (1 <= args.ttl <= 255):
        print(f"Error: TTL must be between 1 and 255 (got {args.ttl})")
        sys.exit(1)
        
    if not (1 <= args.window <= 65535):
        print(f"Error: Window size must be between 1 and 65535 (got {args.window})")
        sys.exit(1)
    
    # Create fingerprinter and analyze
    fingerprinter = TTLFingerprinter()
    
    print("=" * 60)
    print("TTL-Based OS Fingerprinting Analysis")
    print("=" * 60)
    print(f"Input: TTL={args.ttl}, Window Size={args.window}")
    print("-" * 60)
    
    if args.detailed:
        # Show detailed analysis
        analysis = fingerprinter.get_detailed_analysis(args.ttl, args.window)
        
        print(f"Total Possible Matches: {analysis['analysis']['total_matches']}")
        print(f"Best Guess: {analysis['analysis']['best_guess']}")
        print(f"Confidence: {analysis['analysis']['confidence']:.2f}")
        print()
        
        if analysis['matches']:
            print("Detailed Match Analysis:")
            print("-" * 40)
            for i, match in enumerate(analysis['matches'], 1):
                print(f"{i}. {match['os']}")
                print(f"   Confidence: {match['confidence']:.2f}")
                print(f"   Description: {match['description']}")
                print(f"   Window Match: {'Yes' if match['window_match'] else 'No'}")
                print(f"   Characteristic: {'Yes' if match['characteristic_window'] else 'No'}")
                print()
        else:
            print("No matching OS signatures found.")
    else:
        # Simple fingerprinting
        result = fingerprinter.fingerprint_os(args.ttl, args.window, args.verbose)
        print(f"OS Identification: {result}")
    
    print("=" * 60)


if __name__ == "__main__":
    main()