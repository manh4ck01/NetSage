# netsage/cli/__init__.py
"""NetSage CLI Module
Command-line interface and configuration management
"""

# CLI Module Exports: Export main CLI components
# Config Access: Provide easy access to configuration manager
# Command Interface: Export the main CLI entry point
from .main import main, create_parser
from .config import ConfigManager
from .help_text import SCAN_EXAMPLES, MAIN_HELP

__all__ = [
    'main',
    'create_parser',
    'ConfigManager',
    'SCAN_EXAMPLES',
    'MAIN_HELP'
]

# Version specific to CLI module
__version__ = "0.1.0"
