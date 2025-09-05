#!/usr/bin/env python3
"""
Integration layer between main.py (scanner) and ML device classifier.

- Runs a complete network scan using ScannerEngine
- Extracts scan data into ML features
- Classifies devices with the trained model (ml/model.pkl)
- Prints predictions with confidence scores
"""

import sys
from pathlib import Path
from typing import Dict, Any, List

# Make sure parent directory is on path to import main.py
base_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(base_dir))

# Import scanner engine
from main import ScannerEngine
# Import ML classifier
from ml.predict import predict_device_type


def _build_raw_scan(host: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert scanner output for a single host into the raw_scan format
    expected by features.py and predict.py.
    """
    banners = scan_results.get("banners", {})
    ports = scan_results.get("port_scan", {})
    macs = scan_results.get("fingerprinting", {}).get("mac", {})
    oss = scan_results.get("fingerprinting", {}).get("os", {})

    raw_scan = {
        "open_ports": [],
        "ttl": None,
        "mac_vendor": None,
        "os": None,
    }

    # Collect open ports with service info
    if host in banners:
        for port, info in banners[host].items():
            raw_scan["open_ports"].append({
                "port": port,
                "proto": "tcp",
                "service": info.get("service", "unknown")
            })
    elif host in ports:
        for port in ports[host]:
            raw_scan["open_ports"].append({
                "port": port,
                "proto": "tcp",
                "service": "unknown"
            })

    # Add fingerprinting info if available
    raw_scan["mac_vendor"] = macs.get(host)
    raw_scan["os"] = oss.get(host)

    return raw_scan


def classify_devices(scan_results: Dict[str, Any], model_path: str = "ml/model.pkl") -> None:
    """
    Run ML classifier on scan results and print predictions.
    """
    hosts: List[str] = scan_results.get("discovery", {}).get("live_hosts", [])

    if not hosts:
        print("\n[ML CLASSIFIER] No live hosts to classify.")
        return

    print("\n" + "=" * 80)
    print("MACHINE LEARNING DEVICE CLASSIFICATION")
    print("=" * 80)

    for host in hosts:
        raw_scan = _build_raw_scan(host, scan_results)

        try:
            pred, conf = predict_device_type(raw_scan, model_path=model_path)
            print(f"[ML] {host:<15} -> {pred:<10} (confidence: {conf:.2f})")
        except Exception as e:
            print(f"[!] Prediction error for {host}: {e}")


def run_with_classification(
    targets: List[str],
    ports: List[int],
    **kwargs
) -> None:
    """
    Run scan using ScannerEngine and classify devices.
    """
    scanner = ScannerEngine(config={"timeout": 3.0, "verbose": True})
    results = scanner.run_complete_scan(targets=targets, ports=ports, **kwargs)
    scanner.print_summary()
    classify_devices(results)


if __name__ == "__main__":
    # Example direct run
    # Replace targets with your subnet or host list
    run_with_classification(
        targets=["192.168.1.10"],
        ports=[22, 80, 443],
        skip_discovery=True
    )
