#!/usr/bin/env python3
"""
NetSage CLI Main Entry Point
A comprehensive command-line interface for the NetSage network scanner.
"""

import argparse
import sys
import os
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

# Import local modules (these would be implemented in the full project)
try:
    from .config import ConfigManager
    from .help_text import MAIN_HELP, SCAN_HELP, CONFIG_HELP, EXAMPLES, get_examples_text
except ImportError:
    # For development/testing when running directly
    from config import ConfigManager
    from help_text import MAIN_HELP, SCAN_HELP, CONFIG_HELP, EXAMPLES, get_examples_text

__version__ = "1.0.0"


class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter for better help display"""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)


class NetSageCLI:
    """Main CLI class for NetSage network scanner"""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.logger = self._setup_logging()
        
    def _setup_logging(self, level=logging.INFO):
        """Setup logging configuration"""
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger('netsage')
        
    def _validate_targets(self, targets: List[str]) -> List[str]:
        """Validate and process target inputs"""
        validated_targets = []
        
        for target in targets:
            # Check if it's a file
            if os.path.isfile(target):
                try:
                    with open(target, 'r') as f:
                        file_targets = [line.strip() for line in f if line.strip()]
                    validated_targets.extend(file_targets)
                    self.logger.info(f"Loaded {len(file_targets)} targets from {target}")
                except IOError as e:
                    self.logger.error(f"Error reading target file {target}: {e}")
                    sys.exit(1)
            else:
                # Assume it's an IP, CIDR, or range
                validated_targets.append(target)
                
        return validated_targets
    
    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse port specification string into list of port numbers"""
        ports = []
        
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                # Port range
                try:
                    start, end = map(int, part.split('-', 1))
                    if start > end or start < 1 or end > 65535:
                        raise ValueError(f"Invalid port range: {part}")
                    ports.extend(range(start, end + 1))
                except ValueError as e:
                    self.logger.error(f"Invalid port range '{part}': {e}")
                    sys.exit(1)
            else:
                # Single port
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port must be between 1-65535: {port}")
                    ports.append(port)
                except ValueError as e:
                    self.logger.error(f"Invalid port '{part}': {e}")
                    sys.exit(1)
                    
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def _get_top_ports(self, n: int) -> List[int]:
        """Get top N most common ports"""
        # Top 100 most common ports
        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 993, 995, 1723, 3389, 5900, 8080,
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 993, 995, 1723, 3389, 5900, 8080,
            135, 445, 1433, 3306, 5432, 1521, 3000, 5000,
            8000, 8008, 8443, 8888, 9000, 9090, 10000,
            5432, 3306, 1433, 5984, 6379, 27017, 28017,
            161, 162, 69, 123, 137, 138, 514, 1900,
            5353, 5060, 5061, 1720, 1719, 554, 8554,
            554, 1935, 80, 8080, 443, 8443, 3128, 1080
        ]
        
        return sorted(list(set(top_ports[:n])))
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser"""
        parser = argparse.ArgumentParser(
            prog='netsage',
            description=MAIN_HELP,
            formatter_class=CustomFormatter,
            epilog=get_examples_text()
        )
        
        parser.add_argument(
            '--version', 
            action='version', 
            version=f'NetSage {__version__}'
        )
        
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='{scan,config,train,version}'
        )
        
        # Scan command
        self._add_scan_parser(subparsers)
        
        # Config command
        self._add_config_parser(subparsers)
        
        # Train command (placeholder for future ML features)
        self._add_train_parser(subparsers)
        
        return parser
    
    def _add_scan_parser(self, subparsers):
        """Add scan command parser"""
        scan_parser = subparsers.add_parser(
            'scan',
            help='Perform network scans',
            description=SCAN_HELP,
            formatter_class=CustomFormatter
        )
        
        # Required arguments
        scan_parser.add_argument(
            '--target', '-t',
            required=True,
            action='append',
            help='Target IPs, CIDR ranges, or files containing targets (can be specified multiple times)'
        )
        
        # Port specification (mutually exclusive)
        port_group = scan_parser.add_mutually_exclusive_group()
        port_group.add_argument(
            '--ports', '-p',
            default=self.config_manager.get('scan.default_ports', 
                                          '21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5900,8000,8080,8443'),
            help='Comma-separated ports/ranges (e.g., 22,80,443,8000-8100)'
        )
        port_group.add_argument(
            '--top-ports',
            type=int,
            metavar='N',
            help='Scan top N most common ports'
        )
        
        # Scan options
        scan_parser.add_argument(
            '--skip-discovery',
            action='store_true',
            help='Skip host discovery phase'
        )
        scan_parser.add_argument(
            '--skip-port-scan',
            action='store_true',
            help='Skip port scanning phase'
        )
        scan_parser.add_argument(
            '--skip-banners',
            action='store_true',
            help='Skip banner grabbing phase'
        )
        scan_parser.add_argument(
            '--udp',
            action='store_true',
            help='Perform UDP scan instead of TCP'
        )
        scan_parser.add_argument(
            '--mac',
            action='store_true',
            help='Perform MAC vendor lookup'
        )
        scan_parser.add_argument(
            '--os',
            action='store_true',
            help='Perform TTL-based OS fingerprinting'
        )
        scan_parser.add_argument(
            '--ttl',
            type=int,
            metavar='VALUE',
            help='Observed TTL value for OS fingerprinting'
        )
        scan_parser.add_argument(
            '--window',
            type=int,
            metavar='SIZE',
            help='Observed TCP window size for OS fingerprinting'
        )
        
        # Output options
        scan_parser.add_argument(
            '--output', '-o',
            metavar='FILE',
            help='Output file for results'
        )
        scan_parser.add_argument(
            '--format',
            choices=['json', 'txt', 'csv', 'html', 'cli'],
            default=self.config_manager.get('output.default_format', 'cli'),
            help='Output format (default: cli)'
        )
        
        # Performance options
        scan_parser.add_argument(
            '--timeout',
            type=float,
            default=self.config_manager.get('scan.timeout', 3.0),
            metavar='SECONDS',
            help='Network timeout in seconds (default: 3.0)'
        )
        scan_parser.add_argument(
            '--threads', '-T',
            type=int,
            default=self.config_manager.get('scan.threads', 50),
            metavar='COUNT',
            help='Number of concurrent threads (default: 50)'
        )
        
        # Other options
        scan_parser.add_argument(
            '--verbose', '-v',
            action='count',
            default=0,
            help='Verbose output (use -v, -vv, or -vvv for increasing verbosity)'
        )
        scan_parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='Quiet mode (suppress non-essential output)'
        )
        scan_parser.add_argument(
            '--config',
            metavar='FILE',
            help='Specify alternate configuration file'
        )
        scan_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be scanned without executing'
        )
        
        scan_parser.set_defaults(func=self.handle_scan)
    
    def _add_config_parser(self, subparsers):
        """Add config command parser"""
        config_parser = subparsers.add_parser(
            'config',
            help='Manage configuration settings',
            description=CONFIG_HELP,
            formatter_class=CustomFormatter
        )
        
        config_group = config_parser.add_mutually_exclusive_group(required=True)
        config_group.add_argument(
            '--show',
            action='store_true',
            help='Show current configuration'
        )
        config_group.add_argument(
            '--set',
            metavar='KEY=VALUE',
            help='Set a configuration value (e.g., scan.timeout=5.0)'
        )
        config_group.add_argument(
            '--reset',
            action='store_true',
            help='Reset to default configuration'
        )
        
        config_parser.add_argument(
            '--file',
            metavar='FILE',
            help='Configuration file to operate on'
        )
        
        config_parser.set_defaults(func=self.handle_config)
    
    def _add_train_parser(self, subparsers):
        """Add train command parser (placeholder for ML features)"""
        train_parser = subparsers.add_parser(
            'train',
            help='Train ML models (future feature)',
            description='Train machine learning models for enhanced scanning capabilities'
        )
        
        train_parser.add_argument(
            '--data',
            metavar='FILE',
            help='Training data file'
        )
        train_parser.add_argument(
            '--model-type',
            choices=['os-detection', 'service-classification', 'vulnerability-assessment'],
            help='Type of model to train'
        )
        
        train_parser.set_defaults(func=self.handle_train)
    
    def handle_scan(self, args):
        """Handle scan command"""
        # Set logging level based on verbosity
        if args.quiet:
            logging.getLogger().setLevel(logging.ERROR)
        elif args.verbose >= 3:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose >= 2:
            logging.getLogger().setLevel(logging.INFO)
        elif args.verbose >= 1:
            logging.getLogger().setLevel(logging.WARNING)
        
        # Load alternate config if specified
        if args.config:
            try:
                self.config_manager = ConfigManager(args.config)
            except Exception as e:
                self.logger.error(f"Error loading config file {args.config}: {e}")
                sys.exit(1)
        
        # Validate and process targets
        targets = self._validate_targets(args.target)
        if not targets:
            self.logger.error("No valid targets specified")
            sys.exit(1)
        
        # Process port specification
        if args.top_ports:
            ports = self._get_top_ports(args.top_ports)
            self.logger.info(f"Scanning top {args.top_ports} ports")
        else:
            # Convert comma-separated string to list if needed
            if isinstance(args.ports, str):
                ports = self._parse_ports(args.ports)
            else:
                ports = args.ports
        
        # Validate thread count
        max_threads = self.config_manager.get('performance.max_threads', 100)
        if args.threads > max_threads:
            self.logger.warning(f"Thread count {args.threads} exceeds maximum {max_threads}, using {max_threads}")
            args.threads = max_threads
        
        # Build scan configuration
        scan_config = {
            'targets': targets,
            'ports': ports,
            'skip_discovery': args.skip_discovery,
            'skip_port_scan': args.skip_port_scan,
            'skip_banners': args.skip_banners,
            'udp_scan': args.udp,
            'mac_lookup': args.mac,
            'os_detection': args.os,
            'ttl_value': args.ttl,
            'window_size': args.window,
            'timeout': args.timeout,
            'threads': args.threads,
            'output_file': args.output,
            'output_format': args.format,
            'verbose': args.verbose,
            'quiet': args.quiet
        }
        
        if args.dry_run:
            self._show_scan_plan(scan_config)
            return
        
        # This would integrate with the actual scanner engine
        self.logger.info("Starting scan with configuration:")
        for key, value in scan_config.items():
            if key != 'targets' or len(value) <= 5:
                self.logger.info(f"  {key}: {value}")
            else:
                self.logger.info(f"  {key}: {len(value)} targets")

        # Run the scanner engine with parsed CLI args
self.logger.info("Executing scan with scanner engine...")
results = run_scan_from_cli(args)

if results is None:
    self.logger.error("Scan failed or returned no results")
    sys.exit(1)

# Save results if output file is specified
if args.output:
    try:
        from scanner_engine.main import ScannerEngine
        scanner = ScannerEngine({})
        scanner.results = results  # attach results from run_scan_from_cli
        scanner.save_results(args.output, args.format)
        self.logger.info(f"Results saved to {args.output} in {args.format} format")
    except Exception as e:
        self.logger.error(f"Error saving results: {e}")

        
        # TODO: Integrate with scanner engine
        # Run the scanner engine
self.logger.info("Executing scan with scanner engine...")
results = run_scan_from_cli(args)

if results is None:
    self.logger.error("Scan failed or returned no results")
    sys.exit(1)

# Save results if output file is specified
if args.output:
    try:
        from scanner_engine.main import ScannerEngine
        scanner = ScannerEngine({})
        scanner.results = results  # attach results
        scanner.save_results(args.output, args.format)
        self.logger.info(f"Results saved to {args.output} in {args.format} format")
    except Exception as e:
        self.logger.error(f"Error saving results: {e}")

    
    def _show_scan_plan(self, config):
        """Show what would be scanned in dry-run mode"""
        print("=== NetSage Scan Plan (Dry Run) ===")
        print(f"Targets: {len(config['targets'])}")
        for i, target in enumerate(config['targets'][:10], 1):
            print(f"  {i}. {target}")
        if len(config['targets']) > 10:
            print(f"  ... and {len(config['targets']) - 10} more")
        
        print(f"Ports: {len(config['ports'])}")
        if len(config['ports']) <= 20:
            print(f"  {', '.join(map(str, config['ports']))}")
        else:
            print(f"  {', '.join(map(str, config['ports'][:20]))} ... and {len(config['ports']) - 20} more")
        
        print(f"Scan Type: {'UDP' if config['udp_scan'] else 'TCP'}")
        print(f"Threads: {config['threads']}")
        print(f"Timeout: {config['timeout']}s")
        print(f"Output Format: {config['output_format']}")
        if config['output_file']:
            print(f"Output File: {config['output_file']}")
        
        options = []
        if config['skip_discovery']:
            options.append("Skip Discovery")
        if config['skip_port_scan']:
            options.append("Skip Port Scan")
        if config['skip_banners']:
            options.append("Skip Banners")
        if config['mac_lookup']:
            options.append("MAC Lookup")
        if config['os_detection']:
            options.append("OS Detection")
        
        if options:
            print(f"Options: {', '.join(options)}")
    
    def handle_config(self, args):
        """Handle config command"""
        if args.file:
            try:
                self.config_manager = ConfigManager(args.file)
            except Exception as e:
                self.logger.error(f"Error loading config file {args.file}: {e}")
                sys.exit(1)
        
        if args.show:
            self._show_config()
        elif args.set:
            self._set_config(args.set)
        elif args.reset:
            self._reset_config()
    
    def _show_config(self):
        """Show current configuration"""
        print("=== NetSage Configuration ===")
        config_dict = self.config_manager._config
        self._print_config_section("Scan Settings", config_dict.get('scan', {}))
        self._print_config_section("Output Settings", config_dict.get('output', {}))
        self._print_config_section("Fingerprinting", config_dict.get('fingerprinting', {}))
        self._print_config_section("Performance", config_dict.get('performance', {}))
        
        print(f"\nConfig file: {self.config_manager.config_path}")
    
    def _print_config_section(self, title, section):
        """Print a configuration section"""
        print(f"\n[{title}]")
        for key, value in section.items():
            print(f"  {key}: {value}")
    
    def _set_config(self, key_value):
        """Set configuration value"""
        try:
            key, value = key_value.split('=', 1)
            
            # Try to convert value to appropriate type
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            elif value.isdigit():
                value = int(value)
            elif '.' in value and all(part.isdigit() for part in value.split('.', 1)):
                value = float(value)
            
            self.config_manager.set(key, value)
            self.config_manager.save_config()
            print(f"Set {key} = {value}")
            
        except ValueError:
            self.logger.error("Invalid key=value format")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Error setting configuration: {e}")
            sys.exit(1)
    
    def _reset_config(self):
        """Reset configuration to defaults"""
        try:
            self.config_manager.reset_to_defaults()
            self.config_manager.save_config()
            print("Configuration reset to defaults")
        except Exception as e:
            self.logger.error(f"Error resetting configuration: {e}")
            sys.exit(1)
    
    def handle_train(self, args):
        """Handle train command (placeholder)"""
        print("ML training functionality will be implemented in future versions")
        print("Planned features:")
        print("  - OS detection model training")
        print("  - Service classification")
        print("  - Vulnerability assessment")
    
    def run(self, args=None):
        """Main entry point"""
        parser = self.create_parser()
        
        # Parse arguments
        if args is None:
            args = sys.argv[1:]
        
        parsed_args = parser.parse_args(args)
        
        # If no command specified, show help
        if not parsed_args.command:
            parser.print_help()
            return
        
        # Execute the appropriate handler
        try:
            parsed_args.func(parsed_args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(130)
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            if parsed_args.command == 'scan' and hasattr(parsed_args, 'verbose') and parsed_args.verbose >= 3:
                import traceback
                traceback.print_exc()
            sys.exit(1)


def main():
    """Entry point for the netsage command"""
    cli = NetSageCLI()
    cli.run()


if __name__ == '__main__':
    main()

# At the end of handle_scan()
self.logger.info("Scan would be executed here...")
# TODO: call scanner engine