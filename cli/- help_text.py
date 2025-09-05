#!/usr/bin/env python3
"""
NetSage Help Text and Examples
Extended help text, examples, and usage documentation for the NetSage CLI.
"""

MAIN_HELP = """
NetSage - Intelligent Network Scanner with Machine Learning Capabilities

NetSage is a powerful, Python-based network scanner that combines traditional
network reconnaissance techniques with machine learning for enhanced accuracy
and intelligence. It provides comprehensive host discovery, port scanning,
service detection, and OS fingerprinting capabilities.

Key Features:
  • Fast multi-threaded scanning with customizable concurrency
  • TCP and UDP port scanning with intelligent timing
  • Banner grabbing and service detection
  • MAC address vendor lookup
  • TTL-based operating system fingerprinting
  • Multiple output formats (CLI, JSON, HTML, CSV, TXT)
  • Flexible target specification (IPs, CIDR, ranges, files)
  • Advanced configuration management
  • ML-powered analysis (future features)

Security Notice:
This tool is intended for authorized network testing and security assessment
only. Users are responsible for complying with applicable laws and obtaining
proper authorization before scanning networks they do not own.
"""

SCAN_HELP = """
Perform comprehensive network scans with flexible options.

The scan command is the primary interface for network reconnaissance. It supports
various scan types, target specifications, and output formats to meet different
security assessment needs.

Target Specification:
  Targets can be specified in multiple formats:
  • Single IP: 192.168.1.1
  • IP range: 192.168.1.1-192.168.1.100
  • CIDR notation: 192.168.1.0/24
  • Hostname: example.com
  • File containing targets: targets.txt

Port Specification:
  Ports can be specified as:
  • Single ports: 80,443,8080
  • Port ranges: 1-1000,8000-9000
  • Top common ports: --top-ports 100
  • Default common ports (used if not specified)

Scan Phases:
  1. Host Discovery: Determine which hosts are alive
  2. Port Scanning: Identify open ports on live hosts
  3. Banner Grabbing: Retrieve service banners and versions
  4. Fingerprinting: Perform OS and service detection

Performance Tuning:
  Use --threads to control concurrency (default: 50, max: 100)
  Adjust --timeout for network conditions (default: 3.0 seconds)
  Consider network capacity and target responsiveness when tuning
"""

CONFIG_HELP = """
Manage NetSage configuration settings.

The config command allows you to view, modify, and manage NetSage configuration
settings. Configuration is stored in YAML format for human readability and can
be located in several standard locations.

Configuration Hierarchy:
  1. Command-line specified config (--config file.yaml)
  2. Current directory (./netsage.yaml)
  3. User config (~/.config/netsage/config.yaml)
  4. System config (/etc/netsage/config.yaml)

Environment Variables:
  Configuration can be overridden using environment variables with the
  NETSAGE_ prefix. Use underscores to separate nested keys:
  
  NETSAGE_SCAN_TIMEOUT=5.0
  NETSAGE_OUTPUT_DEFAULT_FORMAT=json
  NETSAGE_PERFORMANCE_MAX_THREADS=200

Configuration Sections:
  • scan: Default scanning parameters
  • output: Output formatting options
  • fingerprinting: OS and service detection settings
  • performance: Threading and timing parameters
  • logging: Log level and output configuration
"""

# Comprehensive examples organized by use case
SCAN_EXAMPLES = {
    "basic_host": {
        "command": "netsage scan --target 192.168.1.1 --ports 22,80,443",
        "description": "Basic scan of a single host on common ports"
    },
    "network_range": {
        "command": "netsage scan --target 192.168.1.0/24 --ports 1-1000",
        "description": "Scan entire subnet with port range"
    },
    "top_ports": {
        "command": "netsage scan --target 192.168.1.1 --top-ports 100",
        "description": "Scan the top 100 most common ports"
    },
    "file_targets": {
        "command": "netsage scan --target targets.txt --ports 22,80,443,8080",
        "description": "Scan targets from a file"
    },
    "comprehensive": {
        "command": "netsage scan --target 192.168.1.0/24 --ports 22,80,443,8080 --mac --os --format html --output scan_report.html",
        "description": "Comprehensive scan with MAC lookup, OS detection, and HTML report"
    },
    "udp_scan": {
        "command": "netsage scan --target 192.168.1.1 --ports 53,67,68,161 --udp",
        "description": "UDP scan for common services"
    },
    "fast_discovery": {
        "command": "netsage scan --target 192.168.1.0/24 --skip-port-scan --mac",
        "description": "Host discovery only with MAC vendor lookup"
    },
    "stealth_scan": {
        "command": "netsage scan --target 192.168.1.1 --ports 22,80,443 --timeout 10 --threads 10",
        "description": "Slower, stealthier scan with reduced concurrency"
    },
    "service_detection": {
        "command": "netsage scan --target 192.168.1.100 --ports 1-65535 --threads 100 --format json --output services.json",
        "description": "Full port scan with service detection and JSON output"
    },
    "multiple_targets": {
        "command": "netsage scan --target 192.168.1.1 --target 192.168.1.50 --target 10.0.0.0/8 --ports 22,80,443",
        "description": "Scan multiple different targets in one command"
    }
}

CONFIG_EXAMPLES = {
    "show_config": {
        "command": "netsage config --show",
        "description": "Display current configuration settings"
    },
    "set_timeout": {
        "command": "netsage config --set scan.timeout=5.0",
        "description": "Set default network timeout to 5 seconds"
    },
    "set_ports": {
        "command": "netsage config --set scan.default_ports=22,80,443,8080,8443",
        "description": "Set default port list for scans"
    },
    "set_format": {
        "command": "netsage config --set output.default_format=json",
        "description": "Change default output format to JSON"
    },
    "reset_config": {
        "command": "netsage config --reset",
        "description": "Reset all settings to defaults"
    },
    "custom_config": {
        "command": "netsage config --file ~/.netsage-custom.yaml --show",
        "description": "View configuration from custom file"
    }
}

ADVANCED_EXAMPLES = {
    "os_fingerprinting": {
        "command": "netsage scan --target 192.168.1.0/24 --ports 22,80,135,139,445 --os --ttl 64 --format html",
        "description": "OS fingerprinting with TTL analysis and HTML report"
    },
    "custom_timing": {
        "command": "netsage scan --target 192.168.1.0/24 --timeout 1.5 --threads 200 --skip-discovery",
        "description": "Fast scan with custom timing (requires high-performance network)"
    },
    "targeted_services": {
        "command": "netsage scan --target web-servers.txt --ports 80,443,8080,8443,9000 --format csv --output web-audit.csv",
        "description": "Web server focused scan with CSV output"
    },
    "database_scan": {
        "command": "netsage scan --target db-subnet.txt --ports 1433,3306,5432,1521,27017 --format json --quiet",
        "description": "Database server discovery scan"
    }
}

# Common troubleshooting scenarios
TROUBLESHOOTING = {
    "permission_denied": {
        "problem": "Permission denied errors during scan",
        "solution": "Run with appropriate privileges or adjust firewall settings. Some scan types require root/administrator access."
    },
    "slow_scanning": {
        "problem": "Scans are running very slowly",
        "solution": "Increase thread count (--threads), reduce timeout (--timeout), or scan fewer ports. Consider network bandwidth limitations."
    },
    "no_results": {
        "problem": "Scan completes but shows no open ports",
        "solution": "Verify targets are reachable, check firewall rules, try different ports, or use --verbose for detailed output."
    },
    "config_errors": {
        "problem": "Configuration file errors",
        "solution": "Validate YAML/JSON syntax, check file permissions, or reset to defaults with 'netsage config --reset'."
    },
    "timeout_errors": {
        "problem": "Frequent timeout errors",
        "solution": "Increase --timeout value, reduce --threads count, or check network connectivity and latency."
    },
    "memory_usage": {
        "problem": "High memory usage during large scans",
        "solution": "Reduce thread count, scan smaller target ranges, or increase system memory/swap space."
    }
}

# Tips and best practices
BEST_PRACTICES = {
    "authorization": "Always obtain proper authorization before scanning networks you don't own",
    "rate_limiting": "Use appropriate thread counts and timeouts to avoid overwhelming target networks",
    "documentation": "Save scan results in multiple formats for comprehensive documentation",
    "validation": "Use --dry-run to validate scan parameters before executing large scans",
    "incremental": "Break large scans into smaller chunks for better manageability",
    "monitoring": "Monitor scan progress with --verbose flags and log outputs",
    "backup": "Backup configuration files before making changes",
    "testing": "Test scan parameters on known targets before production use"
}

def get_examples_text() -> str:
    """Generate formatted examples text for help display"""
    text = "\nCommon Usage Examples:\n\n"
    
    # Basic examples
    text += "Basic Scanning:\n"
    for key, example in list(SCAN_EXAMPLES.items())[:4]:
        text += f"  {example['command']}\n"
        text += f"    {example['description']}\n\n"
    
    # Configuration examples
    text += "Configuration Management:\n"
    for key, example in list(CONFIG_EXAMPLES.items())[:3]:
        text += f"  {example['command']}\n"
        text += f"    {example['description']}\n\n"
    
    text += "For more examples and detailed documentation, visit: https://github.com/example/netsage\n"
    
    return text

def get_scan_examples() -> str:
    """Get formatted scan examples for scan command help"""
    text = "\nScan Examples:\n\n"
    
    for key, example in SCAN_EXAMPLES.items():
        text += f"{example['description']}:\n"
        text += f"  {example['command']}\n\n"
    
    return text

def get_advanced_examples() -> str:
    """Get formatted advanced examples"""
    text = "\nAdvanced Usage Examples:\n\n"
    
    for key, example in ADVANCED_EXAMPLES.items():
        text += f"{example['description']}:\n"
        text += f"  {example['command']}\n\n"
    
    return text

def get_troubleshooting_help() -> str:
    """Get formatted troubleshooting help"""
    text = "\nCommon Issues and Solutions:\n\n"
    
    for key, info in TROUBLESHOOTING.items():
        text += f"Problem: {info['problem']}\n"
        text += f"Solution: {info['solution']}\n\n"
    
    return text

def get_best_practices() -> str:
    """Get formatted best practices"""
    text = "\nBest Practices:\n\n"
    
    for key, practice in BEST_PRACTICES.items():
        text += f"• {practice}\n"
    
    return text + "\n"

# Port lists for reference
COMMON_PORTS = {
    "web": [80, 443, 8080, 8443, 3000, 8000, 9000],
    "ssh": [22, 2222],
    "ftp": [21, 20],
    "mail": [25, 110, 143, 993, 995, 587],
    "dns": [53],
    "database": [1433, 3306, 5432, 1521, 27017],
    "windows": [135, 139, 445, 3389],
    "remote": [3389, 5900, 22, 23],
    "monitoring": [161, 162, 10050, 10051]
}

TOP_1000_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
]

# Service detection patterns and signatures
SERVICE_SIGNATURES = {
    "http": {
        "ports": [80, 8080, 8000, 3000, 9000],
        "banner_patterns": ["HTTP/", "Server:", "Apache", "nginx", "IIS"],
        "probe": "GET / HTTP/1.1\r\nHost: {}\r\n\r\n"
    },
    "https": {
        "ports": [443, 8443, 9443],
        "banner_patterns": ["HTTP/", "Server:", "SSL", "TLS"],
        "probe": "GET / HTTP/1.1\r\nHost: {}\r\n\r\n"
    },
    "ssh": {
        "ports": [22, 2222],
        "banner_patterns": ["SSH-2.0", "SSH-1.99", "OpenSSH"],
        "probe": ""
    },
    "ftp": {
        "ports": [21],
        "banner_patterns": ["220", "FTP", "vsftpd", "ProFTPD"],
        "probe": ""
    },
    "smtp": {
        "ports": [25, 587, 465],
        "banner_patterns": ["220", "SMTP", "ESMTP", "Postfix", "Sendmail"],
        "probe": "EHLO test\r\n"
    },
    "dns": {
        "ports": [53],
        "banner_patterns": [],
        "probe": ""
    },
    "pop3": {
        "ports": [110, 995],
        "banner_patterns": ["+OK", "POP3", "Dovecot"],
        "probe": ""
    },
    "imap": {
        "ports": [143, 993],
        "banner_patterns": ["* OK", "IMAP", "Dovecot", "Courier"],
        "probe": ""
    },
    "snmp": {
        "ports": [161],
        "banner_patterns": [],
        "probe": ""
    },
    "mysql": {
        "ports": [3306],
        "banner_patterns": ["mysql", "MariaDB"],
        "probe": ""
    },
    "postgresql": {
        "ports": [5432],
        "banner_patterns": ["PostgreSQL"],
        "probe": ""
    },
    "mssql": {
        "ports": [1433],
        "banner_patterns": ["SQL Server"],
        "probe": ""
    },
    "rdp": {
        "ports": [3389],
        "banner_patterns": ["RDP", "Terminal"],
        "probe": ""
    },
    "vnc": {
        "ports": [5900, 5901, 5902, 5903],
        "banner_patterns": ["RFB"],
        "probe": ""
    },
    "telnet": {
        "ports": [23],
        "banner_patterns": ["login:", "Password:", "Username:"],
        "probe": ""
    }
}

# OS fingerprinting signatures based on TTL and TCP window sizes
OS_SIGNATURES = {
    "Windows": {
        "ttl_ranges": [(64, 64), (128, 128), (255, 255)],
        "window_sizes": [8192, 16384, 65535],
        "characteristics": ["TTL 128", "Window size variations"]
    },
    "Linux": {
        "ttl_ranges": [(64, 64)],
        "window_sizes": [5840, 14600, 29200],
        "characteristics": ["TTL 64", "Consistent window scaling"]
    },
    "macOS": {
        "ttl_ranges": [(64, 64)],
        "window_sizes": [65535, 32768],
        "characteristics": ["TTL 64", "Large initial window"]
    },
    "FreeBSD": {
        "ttl_ranges": [(64, 64)],
        "window_sizes": [57344, 65535],
        "characteristics": ["TTL 64", "BSD-style windowing"]
    },
    "Solaris": {
        "ttl_ranges": [(255, 255)],
        "window_sizes": [8760, 24656],
        "characteristics": ["TTL 255", "Solaris-specific window sizes"]
    },
    "AIX": {
        "ttl_ranges": [(60, 60)],
        "window_sizes": [16384],
        "characteristics": ["TTL 60", "AIX-specific characteristics"]
    }
}

def get_service_info(port: int) -> dict:
    """Get service information for a given port"""
    for service, info in SERVICE_SIGNATURES.items():
        if port in info["ports"]:
            return {
                "service": service,
                "common_port": True,
                "patterns": info["banner_patterns"],
                "probe": info["probe"]
            }
    
    return {
        "service": "unknown",
        "common_port": False,
        "patterns": [],
        "probe": ""
    }

def get_os_suggestions(ttl: int = None, window_size: int = None) -> list:
    """Get OS suggestions based on TTL and window size"""
    suggestions = []
    
    for os_name, signature in OS_SIGNATURES.items():
        score = 0
        reasons = []
        
        if ttl is not None:
            for ttl_min, ttl_max in signature["ttl_ranges"]:
                if ttl_min <= ttl <= ttl_max:
                    score += 2
                    reasons.append(f"TTL {ttl} matches {os_name}")
                    break
        
        if window_size is not None:
            if window_size in signature["window_sizes"]:
                score += 2
                reasons.append(f"Window size {window_size} matches {os_name}")
        
        if score > 0:
            suggestions.append({
                "os": os_name,
                "confidence": min(score * 25, 100),
                "reasons": reasons,
                "characteristics": signature["characteristics"]
            })
    
    return sorted(suggestions, key=lambda x: x["confidence"], reverse=True)

# Command-line completion helpers
def get_completion_suggestions():
    """Get command completion suggestions for bash/zsh"""
    return {
        "commands": ["scan", "config", "train", "version"],
        "scan_options": [
            "--target", "-t", "--ports", "-p", "--top-ports",
            "--skip-discovery", "--skip-port-scan", "--skip-banners",
            "--udp", "--mac", "--os", "--ttl", "--window",
            "--output", "-o", "--format", "--timeout", "--threads", "-T",
            "--verbose", "-v", "--quiet", "-q", "--config", "--dry-run"
        ],
        "config_options": ["--show", "--set", "--reset", "--file"],
        "formats": ["json", "txt", "csv", "html", "cli"],
        "common_ports": "21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5900,8000,8080,8443"
    }

# Template for generating bash completion script
BASH_COMPLETION_TEMPLATE = '''
_netsage_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    if [[ ${COMP_CWORD} == 1 ]] ; then
        local commands="scan config train version help"
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi
    
    # Command-specific completions
    case "${COMP_WORDS[1]}" in
        scan)
            case "${prev}" in
                --target|-t)
                    # Complete with files or let user type IP/CIDR
                    COMPREPLY=( $(compgen -f -- ${cur}) )
                    return 0
                    ;;
                --ports|-p)
                    COMPREPLY=( $(compgen -W "21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,5900,8000,8080,8443" -- ${cur}) )
                    return 0
                    ;;
                --format)
                    COMPREPLY=( $(compgen -W "json txt csv html cli" -- ${cur}) )
                    return 0
                    ;;
                --output|-o)
                    COMPREPLY=( $(compgen -f -- ${cur}) )
                    return 0
                    ;;
                *)
                    local scan_opts="--target -t --ports -p --top-ports --skip-discovery --skip-port-scan --skip-banners --udp --mac --os --ttl --window --output -o --format --timeout --threads -T --verbose -v --quiet -q --config --dry-run"
                    COMPREPLY=( $(compgen -W "${scan_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
        config)
            case "${prev}" in
                --set)
                    local config_keys="scan.timeout scan.threads scan.default_ports output.default_format performance.max_threads"
                    COMPREPLY=( $(compgen -W "${config_keys}" -- ${cur}) )
                    return 0
                    ;;
                --file)
                    COMPREPLY=( $(compgen -f -- ${cur}) )
                    return 0
                    ;;
                *)
                    local config_opts="--show --set --reset --file"
                    COMPREPLY=( $(compgen -W "${config_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
    esac
}

complete -F _netsage_completion netsage
'''