python
"""
Unit tests for scanner module
"""

import unittest
from unittest.mock import patch, MagicMock
from scanner.discover import discover_hosts
from scanner.port_scan import scan_ports

class TestScanner(uncover(unittest.TestCase):

    @patch('scanner.discover.ping_sweep')
    def test_discover_hosts(self, mock_ping_sweep):
        """Test host discovery functionality"""
        mock_ping_sweep.return_value = ['192.168.1.1', '192.168.1.100']
        
        targets = ['192.168.1.0/24']
        result = discover_hosts(targets)
        
        self.assertEqual(len(result), 2)
        self.assertIn('192.168.1.1', result)
        self.assertIn('192.168.1.100', result)

    @patch('scanner.port_scan.check_port')
    def test_scan_ports(self, mock_check_port):
        """Test port scanning functionality"""
        mock_check_port.return_value = {
            'host': '192.168.1.1',
            'port': 80,
            'status': 'open',
            'banner': 'HTTP/1.1 200 OK'
        }
        
        hosts = ['192.168.1.1']
        ports = [80, 443]
        result = scan_ports(hosts, ports, False)
        
        self.assertIn('192.168.1.1', result)
        self.assertIn(80, result['192.168.1.1'])

if __name__ == '__main__':
    unittest.main()
