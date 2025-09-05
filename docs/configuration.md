markdown
# Configuration Guide

## File Locations

NetSage looks for configuration files in this order:
1. Command-line specified config file (`--config` option)
2. `./netsage.yaml` or `./netsage.json` (current directory)
3. `~/.config/netsage/config.yaml` (user config directory)
4. `/etc/netsage/config.yaml` (system-wide config)

## Environment Variables

You can override config values using environment variables:
```bash
export NETSCAN_TIMEOUT=5.0
export NETSCAN_THREADS=100
export NETSCAN_OUTPUT_FORMAT=json
Configuration Sections
Scan Settings
timeout: Network timeout in seconds

threads: Number of concurrent scanning threads

default_ports: Default ports to scan

Output Settings
default_format: Output format (cli, json, csv, html, txt)

json_indent: JSON output indentation

colorize_cli: Enable/disable colored CLI output

Fingerprinting Settings
enable_mac: Enable MAC vendor lookup

enable_os: Enable OS fingerprinting

mac_db_path: Path to OUI database

Example Configurations
Minimal Configuration
yaml
scan:
  timeout: 2.0
  threads: 30
Comprehensive Configuration
yaml
scan:
  default_ports: "21,22,80,443,3389"
  timeout: 3.0
  threads: 50
  skip_discovery: false

output:
  default_format: "html"
  json_indent: 2

fingerprinting:
  enable_mac: true
  enable_os: true
text

## 9. Run the following commands to set up your project:

```bash
# Create all the directories and files
mkdir -p data/models docs tests

# Create config file
cat > config.example.yaml << 'EOF'
# NetSage Configuration Example
# Copy this file to config.yaml and customize for your needs

scan:
  default_ports: "21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5900,8000,8080,8443"
  timeout: 3.0
  threads: 50
  skip_discovery: false
  skip_banners: false
  udp_scan: false

output:
  default_format: "cli"
  json_indent: 2
  html_template: "default"
  colorize_cli: true

fingerprinting:
  enable_mac: true
  enable_os: true
  mac_db_path: "data/oui.txt"
  default_ttl: 64
  default_window: 5840

performance:
  max_threads: 100
  connection_timeout: 5.0
  retry_attempts: 2
  retry_delay: 1.0

logging:
  level: "INFO"
  file_path: ""
  max_file_size: 10
  backup_count: 5

plugins:
  enabled: true
  plugin_dir: "plugins"
  auto_reload: false

ml:
  enabled: false
  model_path: "data/models/device_classifier.pkl"
  confidence_threshold: 0.7
  dataset_path: "data/sample_dataset.csv"
EOF

# Create __init__.py files
echo '"""NetSage Data Module"""' > data/__init__.py
echo 'import os' >> data/__init__.py
echo 'from pathlib import Path' >> data/__init__.py
echo '' >> data/__init__.py
echo 'DATA_DIR = Path(__file__).parent' >> data/__init__.py
echo 'OUI_DB_PATH = DATA_DIR / "oui.txt"' >> data/__init__.py
echo 'ML_MODELS_DIR = DATA_DIR / "models"' >> data/__init__.py
echo 'SAMPLE_DATA_DIR = DATA_DIR / "samples"' >> data/__init__.py
echo '' >> data/__init__.py
echo 'def ensure_data_directories():' >> data/__init__.py
echo '    for directory in [ML_MODELS_DIR, SAMPLE_DATA_DIR]:' >> data/__init__.py
echo '        directory.mkdir(exist_ok=True, parents=True)' >> data/__init__.py
echo '' >> data/__init__.py
echo 'ensure_data_directories()' >> data/__init__.py

echo '"""NetSage Test Suite"""' > tests/__init__.py
echo '__version__ = "0.1.0"' >> tests/__init__.py

# Create docs files
echo '# NetSage Documentation' > docs/README.md
echo '## API Reference' >> docs/README.md
echo 'See individual documentation files for details.' >> docs/README.md

# Create documentation placeholder files
for file in api configuration plugins ml troubleshooting benchmarks; do
    echo "# ${file^} Documentation" > docs/${file}.md
    echo "This documentation is under development." >> docs/${file}.md
done

echo "All missing files and directories have been created!"
