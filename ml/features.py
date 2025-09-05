"""
Feature extraction utilities for Device Type Classification.
Convert raw network scan results (JSON or dict) into an ML-ready pandas DataFrame.
No network calls. Pure offline transforms.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Union
import json
import re
import pandas as pd
import numpy as np


RawScan = Union[Mapping[str, Any], str]  # dict-like or JSON string


# --- Tunable keyword lists ---
BANNER_KEYWORDS = [
    "rtsp", "telnet", "ssh", "ftp", "smtp", "pop3", "imap",
    "http", "https", "upnp", "ssdp", "printer", "ipp", "ippusb",
    "smb", "afp", "rdp", "vnc", "mqtt", "coap", "rtmp",
    "hikvision", "dahua", "tplink", "cisco", "apple", "samsung",
    "hp", "canon", "sony", "xiaomi", "roku", "echo", "alexa",
]

TOP_PORTS = [22, 23, 53, 80, 443, 554, 8000, 8080, 8443, 1900]


def _safe_json_load(obj: RawScan) -> Dict[str, Any]:
    if isinstance(obj, str):
        return json.loads(obj)
    return dict(obj)  # shallow copy


def _list_open_ports(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a flat list of open port dicts with fields: port, proto, service, banner (optional)."""
    ports = []
    # Common input shapes supported:
    # 1) {"open_ports": [{"port": 80, "proto": "tcp", "service": "http", "banner": "Apache httpd"}]}
    for p in scan.get("open_ports", []):
        d = {
            "port": int(p.get("port", -1)),
            "proto": str(p.get("proto", "") or "").lower(),
            "service": str(p.get("service", "") or "").lower(),
            "banner": str(p.get("banner", "") or ""),
        }
        ports.append(d)
    # 2) Nmap-style: {"tcp": {"80": {"state":"open","name":"http","product":"Apache"}}}
    for proto_key in ("tcp", "udp"):
        proto_map = scan.get(proto_key, {})
        if isinstance(proto_map, dict):
            for port_str, meta in proto_map.items():
                try:
                    port = int(port_str)
                except Exception:
                    continue
                state = str(meta.get("state", "")).lower()
                if state and state != "open":
                    continue
                service = str(meta.get("name", "") or meta.get("service", "") or "").lower()
                product = str(meta.get("product", "") or meta.get("version", "") or "")
                banner = product or service
                ports.append({"port": port, "proto": proto_key, "service": service, "banner": banner})
    return ports


def _keyword_hits(text: str, keywords: Iterable[str]) -> Dict[str, int]:
    text_l = text.lower()
    hits = {}
    for kw in keywords:
        hits[f"kw_{kw}"] = 1 if kw in text_l else 0
    return hits


def _normalize_vendor(v: str) -> str:
    v = (v or "").strip().lower()
    # collapse some common vendor aliases
    if not v:
        return "unknown"
    alias = {
        "amazon": "amazon",
        "alexa": "amazon",
        "echo": "amazon",
        "apple": "apple",
        "cisco": "cisco",
        "tplink": "tplink",
        "tp-link": "tplink",
        "d-link": "dlink",
        "dlink": "dlink",
        "hikvision": "hikvision",
        "dahua": "dahua",
        "samsung": "samsung",
        "xiaomi": "xiaomi",
        "hp": "hp",
        "hewlett packard": "hp",
        "canon": "canon",
        "roku": "roku",
        "mikrotik": "mikrotik",
        "ubiquiti": "ubiquiti",
        "huawei": "huawei",
        "zte": "zte",
        "zte corporation": "zte",
        "lenovo": "lenovo",
        "dell": "dell",
        "asus": "asus",
        "acer": "acer",
        "sony": "sony",
        "google": "google",
    }
    for key, norm in alias.items():
        if key in v:
            return norm
    return re.sub(r"[^a-z0-9]+", "_", v)[:20] or "unknown"


def extract_features(scan: RawScan) -> pd.DataFrame:
    """
    Convert one raw scan (dict or JSON string) to a single-row DataFrame of features.
    Supported top-level fields (best-effort): mac, mac_vendor, oui, ttl, os, hostname, upnp, ssdp, dhcp.
    """
    s = _safe_json_load(scan)

    ports = _list_open_ports(s)
    num_open = len(ports)
    tcp = [p for p in ports if p.get("proto") == "tcp"]
    udp = [p for p in ports if p.get("proto") == "udp"]
    tcp_count = len(tcp)
    udp_count = len(udp)

    all_services = " ".join([p.get("service", "") for p in ports])
    all_banners = " ".join([p.get("banner", "") for p in ports])
    all_text = " ".join([all_services, all_banners, str(s.get("hostname", ""))])

    top_port_flags = {f"port_{p}": 0 for p in TOP_PORTS}
    for p in ports:
        if p.get("port") in top_port_flags:
            top_port_flags[f"port_{p.get('port')}"] = 1

    # service counts (basic)
    service_counts = {}
    for name in ["http", "https", "rtsp", "telnet", "ssh", "ftp", "dns", "mdns", "ipp", "ippusb", "smb", "rdp", "vnc", "mqtt", "coap"]:
        service_counts[f"svc_{name}"] = sum(1 for p in ports if name in (p.get("service") or ""))

    # Ports statistics
    port_nums = [p["port"] for p in ports if isinstance(p.get("port"), int) and p["port"] >= 0]
    port_min = min(port_nums) if port_nums else -1
    port_max = max(port_nums) if port_nums else -1
    port_mean = float(np.mean(port_nums)) if port_nums else -1.0

    # Device metadata
    ttl = int(s.get("ttl", -1) or -1)
    os_guess = str(s.get("os", "") or "").lower()
    mac_vendor = _normalize_vendor(str(s.get("mac_vendor", "") or s.get("oui", "") or ""))

    # Protocol toggles
    has_upnp = 1 if (s.get("upnp") or "upnp" in all_text or 1900 in [p.get("port") for p in ports]) else 0
    has_ssdp = 1 if (s.get("ssdp") or "ssdp" in all_text or 1900 in [p.get("port") for p in ports]) else 0
    has_dhcp = 1 if (s.get("dhcp") or "dhcp" in all_text or 67 in [p.get("port") for p in ports] or 68 in [p.get("port") for p in ports]) else 0

    # Keyword hits from banners/services/hostname
    kw = _keyword_hits(all_text, BANNER_KEYWORDS)

    row = {
        "num_open_ports": num_open,
        "num_tcp_open": tcp_count,
        "num_udp_open": udp_count,
        "port_min": port_min,
        "port_max": port_max,
        "port_mean": port_mean,
        "ttl": ttl,
        "os_guess": os_guess if os_guess else "unknown",
        "mac_vendor": mac_vendor if mac_vendor else "unknown",
        "has_upnp": has_upnp,
        "has_ssdp": has_ssdp,
        "has_dhcp": has_dhcp,
    }
    row.update(top_port_flags)
    row.update(service_counts)
    row.update(kw)

    df = pd.DataFrame([row])
    return df


def batch_extract_features(scans: Iterable[RawScan]) -> pd.DataFrame:
    """Convert a list/iterable of scans into a DataFrame of features."""
    frames = [extract_features(s) for s in scans]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def get_feature_columns() -> List[str]:
    """Returns the ordered list of expected feature column names produced by extract_features()."""
    # Use a sentinel scan to enumerate columns deterministically
    sample = {
        "open_ports": [{"port": p, "proto": "tcp", "service": "http", "banner": "sample"} for p in TOP_PORTS],
        "ttl": 64,
        "os": "linux",
        "mac_vendor": "Generic",
        "upnp": True,
        "ssdp": True,
        "dhcp": False,
        "hostname": "sample-host",
    }
    return list(extract_features(sample).columns)
