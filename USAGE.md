# NetSage - ML-Powered Network Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

NetSage is an advanced, open-source network scanner that combines traditional scanning techniques with machine learning for intelligent device classification and comprehensive network analysis.

## 🚀 Features

- **Multi-Protocol Scanning**: TCP SYN, TCP Connect, and UDP scanning
- **Host Discovery**: ICMP ping sweeps and ARP discovery
- **Service Fingerprinting**: Banner grabbing and service detection
- **Device Identification**: MAC vendor lookup and OS fingerprinting
- **ML-Powered Classification**: Automatic device type prediction
- **Multiple Output Formats**: CLI, JSON, CSV, and HTML reports
- **Extensible Architecture**: Plugin system for custom detection rules
- **Configuration Management**: YAML/JSON config support

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone https://github.com/manh4ck01/netsage.git
cd netsage

# Install dependencies
pip install -r requirements.txt

# Make executable (Unix/Linux/Mac)
chmod +x netsage.py

# Or create symlink for easy access
sudo ln -s $(pwd)/netsage.py /usr/local/bin/netsage
```

### Development Install
```bash
# Install development dependencies
pip install -r requirements-dev.txt
```

## 🏗️ Project Structure

```
netsage/
├── cli/                 # Command-line interface
│   ├── main.py         # Main entry point
│   ├── config.py       # Configuration handling
│   └── help_text.py    # Help documentation
├── scanner/            # Core scanning engine
│   ├── discover.py     # Host discovery
│   ├── port_scan.py    # Port scanning
│   ├── banners.py      # Banner grabbing
│   └── engine.py       # Main scanner engine
├── fingerprints/       # Device fingerprinting
│   ├── mac_lookup.py   # MAC vendor lookup
│   └── ttl_fingerprint.py # OS fingerprinting
├── ml/                 # Machine learning
│   ├── train.py        # Model training
│   ├── predict.py      # Device prediction
│   └── features.py     # Feature extraction
├── report/             # Reporting engine
│   ├── output_cli.py   # CLI output
│   ├── output_json.py  # JSON output
│   ├── output_csv.py   # CSV output
│   ├── output_html.py  # HTML reports
│   └── templates/      # HTML templates
├── plugins/            # Custom plugins
│   ├── detect_camera.py
│   ├── detect_nas.py
│   └── README.md
├── data/               # Data files
│   ├── oui.txt         # MAC vendor database
│   └── models/         # ML models
├── docs/               # Documentation
├── tests/              # Test suite
├── requirements.txt    # Dependencies
├── config.example.yaml # Example configuration
├── target.txt.example  # Example target list
└── USAGE.md          # This file
```

## 🚀 Quick Start

### Basic Usage Examples

**1. Simple Network Scan**
```bash
# Scan a single host
netsage scan --target 192.168.1.1

# Scan a network range
netsage scan --target 192.168.1.0/24

# Scan multiple targets
netsage scan --target 192.168.1.1 192.168.1.100 192.168.1.150
```

**2. Specific Port Scanning**
```bash
# Scan common ports
netsage scan --target 192.168.1.0/24 --ports 22,80,443,8080

# Scan port ranges
netsage scan --target 192.168.1.1 --ports 1-1000

# Scan top 50 most common ports
netsage scan --target 192.168.1.0/24 --top-ports 50
```

**3. Advanced Scanning with Fingerprinting**
```bash
# Enable MAC vendor lookup and OS fingerprinting
netsage scan --target 192.168.1.0/24 --mac --os --ttl 64 --window 5840

# UDP scanning
netsage scan --target 192.168.1.1 --ports 53,67,161 --udp

# Skip discovery (treat all targets as live hosts)
netsage scan --target 192.168.1.1-192.168.1.50 --skip-discovery
```

**3.1 Advanced Usage
bash
# Comprehensive network scan with fingerprinting
netsage scan --target 192.168.1.0/24 --top-ports 100 --mac --os --format json

# UDP service discovery
netsage scan --target 10.0.0.1 --ports 53,67,161,123 --udp --output udp_scan.json

# Custom plugin development
# See plugins/ directory for examples and documentation
```

**4. Output Formats**
```bash
# CLI output (default)
netsage scan --target 192.168.1.1 --format cli

# JSON output
netsage scan --target 192.168.1.0/24 --format json --output scan_results.json

# HTML report
netsage scan --target 192.168.1.0/24 --format html --output network_report.html

# CSV output
netsage scan --target 192.168.1.0/24 --format csv --output results.csv
```

## ⚙️ Configuration

### Initial Setup
```bash
# Copy example configuration
cp config.example.yaml config.yaml

# Copy example target list
cp target.txt.example target.txt

# Edit configuration as needed
nano config.yaml
```

### Example Config (config.yaml)
```yaml
scan:
  default_ports: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
  timeout: 3.0
  threads: 50
  skip_discovery: false
  skip_banners: false

output:
  default_format: cli
  json_indent: 2
  html_template: default

fingerprinting:
  enable_mac: true
  enable_os: true
  mac_db_path: data/oui.txt

performance:
  max_threads: 100
  connection_timeout: 5.0
```

### Example Target File (target.txt)
```txt
# NetSage Target File
# Lines starting with # are comments

192.168.1.1          # Router
192.168.1.0/24       # Main network
192.168.1.100-192.168.1.150 # Device range
10.0.0.0/16          # Additional network
```

## 🎯 Practical Use Cases

### Home Network Inventory
```bash
netsage scan --target 192.168.1.0/24 --ports 22,80,443,8080,8443 --mac --os --format html --output home_network.html
```

### Security Assessment
```bash
netsage scan --target 10.0.0.0/24 --top-ports 100 --format json --output security_scan.json
```

### Network Monitoring
```bash
# Regular scanning with timestamped outputs
netsage scan --target 192.168.1.0/24 --format json --output scan_$(date +%Y%m%d_%H%M%S).json
```

## 🔧 Troubleshooting

### Common Issues
```bash
# Permission errors for raw socket operations
sudo netsage scan --target 192.168.1.1

# Download MAC OUI database
python -c "from fingerprints.mac_lookup import download_oui_database; download_oui_database()"

# Verbose output for debugging
netsage scan --target 192.168.1.1 -vvv
```

### Performance Tips
```bash
# Adjust thread count
netsage scan --target 192.168.1.0/24 --threads 100

# Increase timeout for slow networks
netsage scan --target 192.168.1.0/24 --timeout 5.0

# Skip banner grabbing for faster scans
netsage scan --target 192.168.1.0/24 --skip-banners
```

## 🧩 Extensibility

### Creating Plugins
Create Python files in the `plugins/` directory:

```python
# plugins/detect_camera.py
def detect_camera(scan_data):
    if scan_data.get('port') == 80 and 'camera' in scan_data.get('banner', '').lower():
        return {
            "device_type": "Network Camera",
            "vendor": "Camera Manufacturer",
            "confidence": 0.95,
            "notes": "Detected via HTTP banner"
        }
    return None
```

### API Usage
```python
from scanner.engine import ScannerEngine
from report.output_json import generate_json_output

# Initialize scanner
config = {'timeout': 3.0, 'verbose': False}
scanner = ScannerEngine(config)

# Run scan
results = scanner.run_complete_scan(
    targets=["192.168.1.0/24"],
    ports=[22, 80, 443],
    perform_mac=True,
    perform_os=True
)

# Generate report
generate_json_output(results['final_results'], "scan_results.json")
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Scapy community for packet manipulation capabilities
- IEEE for maintaining the OUI database
- Various open-source security tools that inspired this project

## 📞 Support

If you have any questions or issues:

1. Check the [documentation](docs/)
2. Search existing [issues](https://github.com/manh4ck01/netsage/issues)
3. Create a new issue with detailed information

## 🚀 Roadmap

- [ ] Web dashboard interface
- [ ] Real-time scanning updates
- [ ] Advanced ML models for device classification
- [ ] Integration with popular SIEM systems
- [ ] Scheduled scanning and alerts
- [ ] API for external integrations

---

**Disclaimer**: Use this tool responsibly and only on networks you own or have permission to scan. Unauthorized scanning may be illegal.
```

## Additional Files You Should Create:

### .gitignore
```gitignore
# NetSage Git Ignore File

# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sbin/
share/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/
.env/
.venv/

# Scan results and output files
*.json
*.html
*.csv
*.txt
!requirements.txt
!target.txt.example

# Data files and databases
*.db
*.sqlite
*.sqlite3
data/
*.pkl
*.joblib
*.h5
*.hdf5

# Model files
models/
*.model
*.weights

# MAC OUI database (should be downloaded automatically)
oui.txt
oui.db

# Configuration files (except example configs)
*.yaml
*.yml
*.json
!config.example.yaml
!config.example.json

# Log files
*.log
logs/

# Temporary files
*.tmp
*.temp
temp/
tmp/

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Development tools
.pytest_cache/
.mypy_cache/

# Build and distribution
dist/
build/
*.egg-info/

# Jupyter notebooks (if any)
.ipynb_checkpoints/

# Environment variables
.env
.env.local
.env.production

# Test data
test_data/
test_results/

# Plugin development cache
plugins/__pycache__/

# Keep example files but ignore actual data
!*.example

# Keep documentation but ignore generated docs
docs/_build/

# Keep requirements but ignore virtual env
!requirements.txt
!requirements-dev.txt
```

### LICENSE
```text
MIT License

Copyright (c) 2023 NetSage Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

