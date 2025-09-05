markdown
# NetSage Documentation

## 📚 Table of Contents

- [API Reference](api.md)
- [Configuration Guide](configuration.md)
- [Plugin Development](plugins.md)
- [ML Integration](ml.md)
- [Troubleshooting](troubleshooting.md)

## 🏗️ Architecture Overview

NetSage follows a modular architecture:
Application Layer (CLI)
↓
Business Logic Layer (Scanner Engine)
↓
Service Layer (Discovery, Port Scan, Banner Grab)
↓
Data Layer (Fingerprinting, ML, Reporting)

text

## 🔌 API Reference

### ScannerEngine Class
```python
from scanner.engine import ScannerEngine

# Initialize
scanner = ScannerEngine(config)

# Run complete scan
results = scanner.run_complete_scan(
    targets=["192.168.1.0/24"],
    ports=[22, 80, 443],
    perform_mac=True,
    perform_os=True
)
🧪 Testing
Run the test suite:

bash
python -m pytest tests/ -v
Run specific test categories:

bash
python -m pytest tests/test_scanner.py -v
python -m pytest tests/test_fingerprints.py -v
📊 Performance Benchmarks
See benchmarks.md for performance metrics and optimization tips.

text

## 7. Create placeholder files for the docs:

```bash
# Create documentation files
touch docs/api.md
touch docs/configuration.md
touch docs/plugins.md
touch docs/ml.md
touch docs/troubleshooting.md
touch docs/benchmarks.md