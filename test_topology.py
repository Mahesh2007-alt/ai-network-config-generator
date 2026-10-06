"""Unit tests for topology visualization and routing matrix."""

import unittest
from topology import calculate_subnet_details, generate_routing_matrix, generate_topology_svg, generate_mermaid_syntax

class TestTopology(unittest.TestCase):

    def setUp(self):
        self.router_data = {
            "hostname": "Border-GW-West",
            "interfaces": [
                {
                    "name": "Loopback0",
                    "description": "router management and BGP router ID",
                    "ip": "10.255.0.1",
                    "subnet_mask": "255.255.255.255",
                    "cidr": 32,
                    "shutdown": False,
                },
                {
                    "name": "GigabitEthernet0/0",
                    "description": "WAN interface connecting to upstream ISP peer",
                    "ip": "198.51.100.2",
                    "subnet_mask": "255.255.255.252",
                    "cidr": 30,
                    "shutdown": False,
                },
            ],
            "vlans": [],
            "routing": {
                "protocol": "bgp",
                "as_number": 65000,
                "router_id": "10.255.0.1",
                "neighbors": [{"ip": "198.51.100.1", "remote_as": 65001}],
            },
            "acls": [],
        }

    def test_calculate_subnet_details(self):
        res_32 = calculate_subnet_details("10.255.0.1", 32)
        self.assertEqual(res_32["usable_count"], "1")
        self.assertEqual(res_32["network"], "10.255.0.1")

        res_30 = calculate_subnet_details("198.51.100.2", 30)
        self.assertEqual(res_30["usable_count"], "2")
        self.assertEqual(res_30["network"], "198.51.100.0")
        self.assertEqual(res_30["broadcast"], "198.51.100.3")

    def test_generate_routing_matrix(self):
        matrix = generate_routing_matrix(self.router_data)
        self.assertEqual(len(matrix), 2)
        self.assertEqual(matrix[0]["Component / Port"], "Loopback0")
        self.assertEqual(matrix[1]["Component / Port"], "GigabitEthernet0/0")
        self.assertIn("198.51.100.2/30", matrix[1]["IP / CIDR"])

    def test_generate_topology_svg(self):
        svg = generate_topology_svg(self.router_data)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("Border-GW-West", svg)
        self.assertIn("Loopback0", svg)
        self.assertIn("GigabitEthernet0/0", svg)

    def test_generate_mermaid_syntax(self):
        mermaid = generate_mermaid_syntax(self.router_data)
        self.assertIn("graph TD", mermaid)
        self.assertIn("Border-GW-West", mermaid)
        self.assertIn("BGP Domain", mermaid)

    def test_roas_topology(self):
        roas_data = {
            "hostname": "RoAS-Core-Rtr",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0/0",
                    "description": "Physical trunk carrier",
                    "ip": None,
                    "subnet_mask": None,
                    "cidr": None,
                    "shutdown": False,
                },
                {
                    "name": "GigabitEthernet0/0/0.10",
                    "description": "Accounts department",
                    "ip": "10.1.10.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                    "vlan_id": 10,
                    "encapsulation": "dot1Q 10",
                    "shutdown": False,
                },
            ],
            "vlans": [],
            "routing": {"protocol": "none"},
            "security": {
                "domain_name": "enterprise.local",
                "rsa_bits": 1024,
                "users": [{"username": "netadmin", "privilege": 15, "secret": "CiscoPass123"}],
                "ssh": {"vty_lines": "0 4", "transport_input": "ssh", "login": "local"},
            },
            "acls": [],
        }
        matrix = generate_routing_matrix(roas_data)
        self.assertEqual(len(matrix), 2)
        self.assertEqual(matrix[0]["Component / Port"], "GigabitEthernet0/0/0")
        self.assertEqual(matrix[0]["Link Type"], "802.1Q Trunk Carrier")
        self.assertEqual(matrix[1]["Link Type"], "802.1Q Subinterface (VLAN 10)")
        self.assertEqual(matrix[1]["Usable Hosts"], "254")

        svg = generate_topology_svg(roas_data)
        self.assertIn("RoAS-Core-Rtr", svg)
        self.assertIn("Trunk Carrier (No IP)", svg)
        self.assertIn("netadmin@enterprise.local", svg)


if __name__ == "__main__":
    unittest.main()
