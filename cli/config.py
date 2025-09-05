#!/usr/bin/env python3
"""
NetSage Configuration Manager
Handles configuration loading, saving, and management with support for multiple formats.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union, List
from copy import deepcopy


class ConfigError(Exception):
    """Custom exception for configuration errors"""
    pass


class ConfigManager:
    """Configuration manager with support for YAML/JSON, multiple locations, and environment variables"""
    
    # Default configuration
    DEFAULT_CONFIG = {
        "scan": {
            "default_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443],
            "timeout": 3.0,
            "threads": 50,
            "skip_discovery": False,
            "skip_banners": False,
            "udp_scan": False
        },
        "output": {
            "default_format": "cli",
            "json_indent": 2,
            "html_template": "default"
        },
        "fingerprinting": {
            "enable_mac": True,
            "enable_os": True,
            "mac_db_path": "data/oui.txt"
        },
        "performance": {
            "max_threads": 100,
            "connection_timeout": 5.0,
            "retry_attempts": 2
        },
        "logging": {
            "level": "INFO",
            "file": None,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "version": "1.0.0"
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Optional path to specific config file
        """
        self.logger = logging.getLogger(__name__)
        self.config_path = None
        self._config = {}
        
        # Set initial config path if provided
        if config_path:
            self.config_path = Path(config_path).resolve()
            if not self.config_path.exists():
                raise ConfigError(f"Config file not found: {config_path}")
        
        # Load configuration
        self.load_config()
    
    def _get_config_locations(self) -> List[Path]:
        """
        Get list of configuration file locations in order of precedence
        
        Returns:
            List of Path objects for potential config file locations
        """
        locations = []
        
        # 1. Command-line specified config file (already set in __init__)
        if self.config_path:
            locations.append(self.config_path)
            return locations
        
        # 2. Current directory
        for ext in ['yaml', 'yml', 'json']:
            locations.append(Path(f"./netsage.{ext}"))
        
        # 3. User config directory
        user_config_dir = Path.home() / ".config" / "netsage"
        for ext in ['yaml', 'yml', 'json']:
            locations.append(user_config_dir / f"config.{ext}")
        
        # 4. System-wide config
        system_locations = [
            Path("/etc/netsage/config.yaml"),
            Path("/etc/netsage/config.yml"),
            Path("/etc/netsage/config.json")
        ]
        locations.extend(system_locations)
        
        return locations
    
    def _detect_config_format(self, file_path: Path) -> str:
        """
        Detect configuration file format based on extension
        
        Args:
            file_path: Path to config file
            
        Returns:
            Format string ('yaml' or 'json')
        """
        ext = file_path.suffix.lower()
        if ext in ['.yaml', '.yml']:
            return 'yaml'
        elif ext == '.json':
            return 'json'
        else:
            # Try to detect by content
            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    if content.startswith('{') and content.endswith('}'):
                        return 'json'
                    else:
                        return 'yaml'
            except Exception:
                return 'yaml'  # Default to YAML
    
    def _load_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """Load YAML configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                return content if content is not None else {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {file_path}: {e}")
        except Exception as e:
            raise ConfigError(f"Error reading YAML file {file_path}: {e}")
    
    def _load_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Load JSON configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {file_path}: {e}")
        except Exception as e:
            raise ConfigError(f"Error reading JSON file {file_path}: {e}")
    
    def _save_yaml_file(self, file_path: Path, config: Dict[str, Any]):
        """Save configuration as YAML file"""
        try:
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, default_flow_style=False, indent=2, sort_keys=True)
        except Exception as e:
            raise ConfigError(f"Error saving YAML file {file_path}: {e}")
    
    def _save_json_file(self, file_path: Path, config: Dict[str, Any]):
        """Save configuration as JSON file"""
        try:
            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, sort_keys=True)
        except Exception as e:
            raise ConfigError(f"Error saving JSON file {file_path}: {e}")
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two configuration dictionaries recursively
        
        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        result = deepcopy(base)
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = deepcopy(value)
        
        return result
    
    def _apply_environment_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration
        
        Environment variables should be prefixed with NETSAGE_ and use underscores
        to separate nested keys (e.g., NETSAGE_SCAN_TIMEOUT=5.0)
        
        Args:
            config: Configuration dictionary to modify
            
        Returns:
            Configuration with environment overrides applied
        """
        result = deepcopy(config)
        
        for env_var, env_value in os.environ.items():
            if not env_var.startswith('NETSAGE_'):
                continue
            
            # Remove prefix and convert to config key path
            key_path = env_var[8:].lower().split('_')  # Remove 'NETSAGE_' prefix
            
            # Navigate to the correct nested dictionary
            current = result
            for key in key_path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Convert environment value to appropriate type
            final_key = key_path[-1]
            converted_value = self._convert_env_value(env_value)
            current[final_key] = converted_value
            
            self.logger.debug(f"Applied environment override: {'.'.join(key_path)} = {converted_value}")
        
        return result
    
    def _convert_env_value(self, value: str) -> Union[str, int, float, bool, List]:
        """
        Convert environment variable string value to appropriate Python type
        
        Args:
            value: String value from environment variable
            
        Returns:
            Converted value
        """
        # Handle boolean values
        if value.lower() in ['true', 'yes', '1', 'on']:
            return True
        elif value.lower() in ['false', 'no', '0', 'off']:
            return False
        
        # Handle numeric values
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # Handle comma-separated lists
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # Return as string if no other conversion applies
        return value
    
    def load_config(self):
        """Load configuration from file, environment variables, and defaults"""
        # Start with default configuration
        self._config = deepcopy(self.DEFAULT_CONFIG)
        
        # Find and load config file
        config_locations = self._get_config_locations()
        config_loaded = False
        
        for location in config_locations:
            if location.exists():
                try:
                    self.logger.debug(f"Loading config from {location}")
                    format_type = self._detect_config_format(location)
                    
                    if format_type == 'yaml':
                        file_config = self._load_yaml_file(location)
                    else:
                        file_config = self._load_json_file(location)
                    
                    # Merge file configuration with defaults
                    self._config = self._merge_configs(self._config, file_config)
                    self.config_path = location
                    config_loaded = True
                    self.logger.info(f"Loaded configuration from {location}")
                    break
                    
                except ConfigError as e:
                    self.logger.warning(f"Skipping invalid config file {location}: {e}")
                    continue
        
        # If no config file was found, set default save location
        if not config_loaded:
            # Default to user config directory
            user_config_dir = Path.home() / ".config" / "netsage"
            self.config_path = user_config_dir / "config.yaml"
            self.logger.info(f"No config file found, will use {self.config_path}")
        
        # Apply environment variable overrides
        self._config = self._apply_environment_overrides(self._config)
        
        # Validate configuration
        self.validate_config()
    
    def save_config(self, path: Optional[str] = None):
        """
        Save current configuration to file
        
        Args:
            path: Optional path to save to, uses current config_path if not specified
        """
        if path:
            save_path = Path(path).resolve()
        else:
            save_path = self.config_path
        
        if not save_path:
            raise ConfigError("No config file path specified")
        
        # Determine format based on file extension
        format_type = self._detect_config_format(save_path)
        
        try:
            if format_type == 'yaml':
                self._save_yaml_file(save_path, self._config)
            else:
                self._save_json_file(save_path, self._config)
            
            self.logger.info(f"Configuration saved to {save_path}")
            
        except Exception as e:
            raise ConfigError(f"Failed to save configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key in dot notation (e.g., 'scan.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        current = self._config
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key in dot notation (e.g., 'scan.timeout')
            value: Value to set
        """
        keys = key.split('.')
        current = self._config
        
        # Navigate to the parent of the final key
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Set the final value
        current[keys[-1]] = value
        
        # Re-validate configuration
        self.validate_config()
        
        self.logger.debug(f"Set configuration: {key} = {value}")
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self._config = deepcopy(self.DEFAULT_CONFIG)
        self.logger.info("Configuration reset to defaults")
    
    def validate_config(self):
        """
        Validate current configuration values
        
        Raises:
            ConfigError: If configuration is invalid
        """
        errors = []
        
        # Validate scan settings
        scan_config = self._config.get('scan', {})
        
        # Validate timeout
        timeout = scan_config.get('timeout', 0)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append("scan.timeout must be a positive number")
        
        # Validate thread count
        threads = scan_config.get('threads', 0)
        if not isinstance(threads, int) or threads <= 0:
            errors.append("scan.threads must be a positive integer")
        
        max_threads = self._config.get('performance', {}).get('max_threads', 100)
        if threads > max_threads:
            errors.append(f"scan.threads ({threads}) exceeds maximum ({max_threads})")
        
        # Validate ports
        ports = scan_config.get('default_ports', [])
        if not isinstance(ports, (list, str)):
            errors.append("scan.default_ports must be a list or string")
        elif isinstance(ports, list):
            for port in ports:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    errors.append(f"Invalid port in default_ports: {port}")
        
        # Validate output settings
        output_config = self._config.get('output', {})
        
        format_type = output_config.get('default_format', 'cli')
        valid_formats = ['json', 'txt', 'csv', 'html', 'cli']
        if format_type not in valid_formats:
            errors.append(f"output.default_format must be one of: {', '.join(valid_formats)}")
        
        json_indent = output_config.get('json_indent', 2)
        if not isinstance(json_indent, int) or json_indent < 0:
            errors.append("output.json_indent must be a non-negative integer")
        
        # Validate performance settings
        perf_config = self._config.get('performance', {})
        
        max_threads_val = perf_config.get('max_threads', 100)
        if not isinstance(max_threads_val, int) or max_threads_val <= 0:
            errors.append("performance.max_threads must be a positive integer")
        
        conn_timeout = perf_config.get('connection_timeout', 5.0)
        if not isinstance(conn_timeout, (int, float)) or conn_timeout <= 0:
            errors.append("performance.connection_timeout must be a positive number")
        
        retry_attempts = perf_config.get('retry_attempts', 2)
        if not isinstance(retry_attempts, int) or retry_attempts < 0:
            errors.append("performance.retry_attempts must be a non-negative integer")
        
        # Validate fingerprinting settings
        fp_config = self._config.get('fingerprinting', {})
        
        enable_mac = fp_config.get('enable_mac', True)
        if not isinstance(enable_mac, bool):
            errors.append("fingerprinting.enable_mac must be a boolean")
        
        enable_os = fp_config.get('enable_os', True)
        if not isinstance(enable_os, bool):
            errors.append("fingerprinting.enable_os must be a boolean")
        
        mac_db_path = fp_config.get('mac_db_path', '')
        if mac_db_path and not isinstance(mac_db_path, str):
            errors.append("fingerprinting.mac_db_path must be a string")
        
        # Validate logging settings
        log_config = self._config.get('logging', {})
        
        log_level = log_config.get('level', 'INFO')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level not in valid_levels:
            errors.append(f"logging.level must be one of: {', '.join(valid_levels)}")
        
        if errors:
            raise ConfigError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get complete configuration dictionary
        
        Returns:
            Copy of current configuration
        """
        return deepcopy(self._config)
    
    def update(self, updates: Dict[str, Any]):
        """
        Update configuration with a dictionary of values
        
        Args:
            updates: Dictionary of configuration updates
        """
        self._config = self._merge_configs(self._config, updates)
        self.validate_config()
    
    def migrate_config(self, from_version: str, to_version: str):
        """
        Migrate configuration from one version to another
        
        Args:
            from_version: Source version
            to_version: Target version
        """
        self.logger.info(f"Migrating configuration from {from_version} to {to_version}")
        
        # Version-specific migration logic would go here
        # For now, just update the version number
        self._config['version'] = to_version
        
        # Re-validate after migration
        self.validate_config()
    
    def backup_config(self, backup_path: Optional[str] = None) -> Path:
        """
        Create a backup of the current configuration
        
        Args:
            backup_path: Optional path for backup file
            
        Returns:
            Path to backup file
        """
        if backup_path:
            backup_file = Path(backup_path)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.config_path.with_name(f"{self.config_path.stem}_backup_{timestamp}{self.config_path.suffix}")
        
        # Save current config to backup location
        format_type = self._detect_config_format(backup_file)
        
        if format_type == 'yaml':
            self._save_yaml_file(backup_file, self._config)
        else:
            self._save_json_file(backup_file, self._config)
        
        self.logger.info(f"Configuration backed up to {backup_file}")
        return backup_file
    
    def restore_config(self, backup_path: str):
        """
        Restore configuration from a backup file
        
        Args:
            backup_path: Path to backup configuration file
        """
        backup_file = Path(backup_path)
        
        if not backup_file.exists():
            raise ConfigError(f"Backup file not found: {backup_path}")
        
        # Load backup configuration
        format_type = self._detect_config_format(backup_file)
        
        try:
            if format_type == 'yaml':
                backup_config = self._load_yaml_file(backup_file)
            else:
                backup_config = self._load_json_file(backup_file)
            
            # Merge with defaults to ensure all keys are present
            self._config = self._merge_configs(self.DEFAULT_CONFIG, backup_config)
            
            # Validate restored configuration
            self.validate_config()
            
            self.logger.info(f"Configuration restored from {backup_path}")
            
        except Exception as e:
            raise ConfigError(f"Failed to restore configuration from {backup_path}: {e}")
    
    def list_config_files(self) -> List[Path]:
        """
        List all potential configuration file locations
        
        Returns:
            List of configuration file paths (existing and potential)
        """
        locations = self._get_config_locations()
        return [{'path': loc, 'exists': loc.exists(), 'readable': loc.exists() and os.access(loc, os.R_OK)} 
                for loc in locations]
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return f"ConfigManager(path={self.config_path}, sections={list(self._config.keys())})"
    
    def __repr__(self) -> str:
        """Detailed string representation"""
        return f"ConfigManager(config_path='{self.config_path}', config={self._config})"


# Import datetime for backup functionality
from datetime import datetime
