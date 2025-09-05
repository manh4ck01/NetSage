Here’s your README updated with you as the author and your GitHub link, without changing any other content:

---

# Scanner Engine - Usage Guide

**Author:** Makhosi Andile Surge
**GitHub:** [https://github.com/manh4ck/net-scan]

A comprehensive network scanning toolkit that integrates host discovery, port scanning, and banner grabbing into a unified CLI tool.

## 📁 Directory Structure

```
/scanner/
├── __init__.py          # Package initialization
├── discover.py          # Host discovery module  
├── port_scan.py         # Port scanning module
├── banners.py           # Banner grabbing module
├── main.py              # Complete integrated scanner
├── requirements.txt     # Dependencies
└── USAGE.md             # This file
```

## 🚀 Installation

1. **Install Python dependencies:**

```bash
pip install -r requirements.txt
```

2. **For full functionality (raw sockets), run with privileges:**

```bash
sudo python main.py [options]
```

## 🔗 How the Modules Link Together

### Integration Flow:

```
1. discover.py → Live host IPs
2. port_scan.py → Open ports per host  
3. banners.py → Service banners for open ports
4. main.py → Orchestrates all modules + results
```

### Direct Module Integration:

```python
from scanner import ScannerEngine
from scanner.discover import discover_hosts
from scanner.port_scan import scan_ports
from scanner.banners import grab_service_banners

# Method 1: Use individual modules
targets = ["192.168.1.0/24"]
live_hosts = discover_hosts(targets)
scan_results = scan_ports(live_hosts, [22, 80, 443])
enhanced_results = grab_service_banners(scan_results)

# Method 2: Use complete scanner engine
scanner = ScannerEngine({})
results = scanner.run_complete_scan(
    targets=["192.168.1.0/24"],
    ports=[22, 80, 443, 3389, 5900]
)
```

## 📋 Usage Examples

### 1. Complete Network Scan (All Phases)

**Basic scan with common ports:**

```bash
python main.py 192.168.1.0/24
```

**Scan specific ports:**

```bash
python main.py 192.168.1.10 192.168.1.20 -p "22,80,443,3389,5900"
```

**Scan port ranges:**

```bash
python main.py 10.0.0.1-10.0.0.50 -p "1-1000,8000-8100"
```

**Top ports scan:**

```bash
python main.py 192.168.1.0/24 --top-ports 100
```

### 2. Individual Module Usage

**Host Discovery Only:**

```bash
python discover.py 192.168.1.0/24 10.0.0.1
```

**Port Scanning Only:**

```bash
python port_scan.py 192.168.1.10 192.168.1.20 -p "22,80,443"
```

**Banner Grabbing Only:**

```bash
python banners.py --host-port 192.168.1.10:80 --host-port 192.168.1.10:443
```

### 3. Advanced Scanning Options

**UDP Scan:**

```bash
python main.py 192.168.1.0/24 --udp -p "53,161,123,69"
```

**Skip phases for faster scans:**

```bash
# Skip discovery (treat targets as live)
python main.py 192.168.1.10 --skip-discovery -p "1-65535"

# Skip banner grabbing
python main.py 192.168.1.0/24 --skip-banners -p "1-1000"
```

**Save results:**

```bash
python main.py 192.168.1.0/24 -o scan_results.json
python main.py 192.168.1.0/24 -o report.txt --format txt
```

### 4. Target Input Methods

**Multiple target formats:**

```bash
python main.py 192.168.1.10 192.168.1.20 10.0.0.0/24
```

**From file:**

```bash
echo "192.168.1.0/24" > targets.txt
echo "10.0.0.1" >> targets.txt  
python main.py targets.txt -p "22,80,443"
```

### 5. Performance Tuning

**Adjust timeouts and threads:**

```bash
python main.py 192.168.1.0/24 --timeout 1.0 -p "22,80,443"
```

**Individual module tuning:**

```bash
python port_scan.py 192.168.1.0/24 -p "1-65535" --threads 200 --timeout 2.0
```

## 🔧 Programming Interface

### Method 1: Individual Module Functions

```python
from scanner.discover import discover_hosts
from scanner.port_scan import scan_ports
from scanner.banners import grab_service_banners

# Step 1: Discover live hosts
targets = ["192.168.1.0/24", "10.0.0.1"]
live_hosts = discover_hosts(targets)
print(f"Found {len(live_hosts)} live hosts")

# Step 2: Scan ports on live hosts
ports = [22, 80, 443, 3389, 5900]
scan_results = scan_ports(live_hosts, ports)
print(f"Scan results: {scan_results}")

# Step 3: Grab banners for open ports
banner_results = grab_service_banners(scan_results)
print(f"Enhanced results: {banner_results}")
```

### Method 2: Complete Scanner Engine

```python
from scanner import ScannerEngine

# Initialize scanner
scanner = ScannerEngine({'timeout': 3.0, 'verbose': True})

# Run complete scan
results = scanner.run_complete_scan(
    targets=["192.168.1.0/24"],
    ports=[22, 80, 443, 3389, 5432, 3306],
    skip_discovery=False,
    skip_banners=False,
    udp_scan=False
)

# Process results
live_hosts = results['discovery']['live_hosts']
port_results = results['port_scan']
banner_results = results['banners']

# Print summary
scanner.print_summary()

# Save results
scanner.save_results('scan_output.json', 'json')
```

### Method 3: Custom Integration

```python
import json
from scanner import discover_hosts, scan_ports, grab_service_banners

class CustomScanner:
    def __init__(self):
        self.results = {}
    
    def scan_network(self, network, ports):
        # Discovery phase
        print(f"[*] Discovering hosts in {network}")
        hosts = discover_hosts([network])
        
        if not hosts:
            print("[!] No live hosts found")
            return None
            
        # Port scanning phase  
        print(f"[*] Scanning {len(ports)} ports on {len(hosts)} hosts")
        port_results = scan_ports(hosts, ports)
        
        # Banner grabbing phase
        print(f"[*] Grabbing service banners")
        banner_results = grab_service_banners(port_results)
        
        # Custom processing
        self.results = {
            'network': network,
            'live_hosts': hosts,
            'services': banner_results
        }
        
        return self.results
    
    def export_to_csv(self, filename):
        """Export results to CSV format"""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Port', 'Service', 'Banner'])
            
            for host, services in self.results.get('services', {}).items():
                for port, info in services.items():
                    writer.writerow([
                        host, 
                        port, 
                        info.get('service', 'Unknown'),
                        info.get('banner', 'No banner')
                    ])

# Usage
scanner = CustomScanner()
results = scanner.scan_network("192.168.1.0/24", [22, 80, 443])
scanner.export_to_csv("scan_results.csv")
```
