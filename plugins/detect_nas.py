# netsage/plugins/detect_nas.py

def run_scan(host: str, port: int, banner: str) -> dict:
    """
    Detect NAS devices via common banners or open ports.
    Returns dict with keys:
      - 'detected': bool
      - 'device_type': str
      - 'vendor': str
      - 'model': str
      - 'notes': str
    """
    detected = False
    device_type = "NAS Device"
    vendor = "Unknown"
    model = ""
    notes = ""

    # Banner detection
    if banner:
        if "Synology" in banner:
            detected = True
            vendor = "Synology"
            notes = "Synology NAS detected via banner"
        elif "QNAP" in banner:
            detected = True
            vendor = "QNAP"
            notes = "QNAP NAS detected via banner"
        elif "Netgear ReadyNAS" in banner:
            detected = True
            vendor = "Netgear"
            notes = "Netgear ReadyNAS detected via banner"

    # Port heuristics
    if not detected:
        if port in [5000, 5001, 445, 139]:
            detected = True
            notes = "Likely NAS device based on common ports"

    return {
        "detected": detected,
        "device_type": device_type,
        "vendor": vendor,
        "model": model,
        "notes": notes
    }
