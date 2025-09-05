# netsage/plugins/detect_camera.py

def run_scan(host: str, port: int, banner: str) -> dict:
    """
    Detect common IP cameras based on banner or open port patterns.
    Returns dict with keys:
      - 'detected': bool
      - 'device_type': str
      - 'vendor': str
      - 'model': str
      - 'notes': str
    """
    detected = False
    device_type = "IP Camera"
    vendor = "Unknown"
    model = ""
    notes = ""

    # Simple banner matching
    if banner:
        if "Axis" in banner:
            detected = True
            vendor = "Axis"
            notes = "Axis camera detected via banner"
        elif "Hikvision" in banner:
            detected = True
            vendor = "Hikvision"
            notes = "Hikvision camera detected via banner"
        elif "Dahua" in banner:
            detected = True
            vendor = "Dahua"
            notes = "Dahua camera detected via banner"

    # Optional port-based heuristic
    if not detected:
        if port in [554, 8000, 8080]:
            detected = True
            notes = "Likely IP camera based on port"

    return {
        "detected": detected,
        "device_type": device_type,
        "vendor": vendor,
        "model": model,
        "notes": notes
    }
