"""Comprehensive Unit Tests for Network Validator."""

import unittest
from validator import validate_network_schema, _is_valid_netmask, _is_valid_wildcard


class TestNetworkValidator(unittest.TestCase):

    def test_valid_campus_schema(self):
        data = {
            "hostname": "Core-Switch-01",
            "vlans": [
                {
                    "id": 10,
                    "name": "Management",
                    "ip": "192.168.10.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                },
                {
                    "id": 20,
                    "name": "Engineering",
                    "ip": "192.168.20.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                },
            ],
            "routing": {
                "protocol": "ospf",
                "process_id": 10,
                "networks": [
                    {
                        "network_ip": "192.168.10.0",
                        "wildcard_mask": "0.0.0.255",
                        "area": 0,
                    },
                    {
                        "network_ip": "192.168.20.0",
                        "wildcard_mask": "0.0.0.255",
                        "area": 0,
                    },
                ],
            },
        }
        res = validate_network_schema(data)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["errors"]), 0)

    def test_detect_overlapping_subnets(self):
        data = {
            "hostname": "Overlap-SW",
            "vlans": [
                {
                    "id": 10,
                    "name": "HQ-LAN",
                    "ip": "172.16.1.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                },
                {
                    "id": 20,
                    "name": "Finance",
                    "ip": "172.16.1.129",
                    "subnet_mask": "255.255.255.128",
                    "cidr": 25,
                },
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("overlap" in err.lower() for err in res["errors"]))

    def test_invalid_ip_and_masks(self):
        data = {
            "hostname": "Bad-IP-Switch",
            "vlans": [
                {
                    "id": 10,
                    "name": "VLAN10",
                    "ip": "999.999.999.999",
                    "subnet_mask": "255.255.0.1",
                    "cidr": 24,
                }
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("Invalid IPv4 address" in err for err in res["errors"]))
        self.assertTrue(any("Invalid subnet mask" in err for err in res["errors"]))

    def test_mismatched_cidr_and_mask(self):
        data = {
            "hostname": "Mismatch-SW",
            "vlans": [
                {
                    "id": 10,
                    "name": "VLAN10",
                    "ip": "10.0.0.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 16,
                }
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("does not match CIDR" in err for err in res["errors"]))

    def test_invalid_wildcard_mask(self):
        valid, _ = _is_valid_wildcard("0.0.0.255")
        self.assertTrue(valid)

        invalid, _ = _is_valid_wildcard("0.0.2.255")
        self.assertFalse(invalid)

    def test_valid_edge_router_schema(self):
        data = {
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
                {
                    "name": "GigabitEthernet0/0/1",
                    "description": "LAN core link",
                    "ip": "10.1.1.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                    "shutdown": False,
                },
            ],
            "vlans": [],
            "routing": {
                "protocol": "bgp",
                "as_number": 65000,
                "router_id": "10.255.0.1",
                "neighbors": [
                    {
                        "ip": "198.51.100.1",
                        "remote_as": 65001,
                        "description": "Upstream ISP Gateway",
                    }
                ],
            },
            "acls": [],
        }
        res = validate_network_schema(data)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["errors"]), 0)

    def test_edge_router_interface_overlap(self):
        data = {
            "hostname": "Border-GW-West",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0",
                    "ip": "192.168.1.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                },
                {
                    "name": "GigabitEthernet0/1",
                    "ip": "192.168.1.10",
                    "subnet_mask": "255.255.255.128",
                    "cidr": 25,
                },
            ],
            "vlans": [],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("overlap" in err.lower() for err in res["errors"]))

    def test_schema_requires_at_least_one_interface_or_vlan(self):
        data = {
            "hostname": "Empty-Device",
            "interfaces": [],
            "vlans": [],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("At least one" in err for err in res["errors"]))

    def test_cli_command_injection_rejection_in_interface_name(self):
        data = {
            "hostname": "Test-Router",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0\nusername backdoor privilege 15 secret hacked",
                    "ip": "10.0.0.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                }
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("CLI injection risk" in err or "prohibited" in err or "invalid" in err for err in res["errors"]))

    def test_cli_command_injection_rejection_in_description(self):
        data = {
            "hostname": "Test-Router",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0",
                    "description": "Uplink\nno shutdown\nsnmp-server community public RW",
                    "ip": "10.0.0.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                }
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("CLI injection risk" in err or "prohibited" in err for err in res["errors"]))

    def test_cli_command_injection_rejection_in_vlan_name(self):
        data = {
            "hostname": "Test-Switch",
            "vlans": [
                {
                    "id": 10,
                    "name": "Management\nexit\nusername backdoor secret pass",
                    "ip": "192.168.10.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                }
            ],
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("CLI injection risk" in err or "prohibited" in err or "invalid" in err for err in res["errors"]))

    def test_cli_command_injection_rejection_in_security_fields(self):
        data = {
            "hostname": "Test-Router",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0",
                    "ip": "10.0.0.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                }
            ],
            "security": {
                "domain_name": "corp.local\nreload",
                "users": [
                    {
                        "username": "admin\nusername evil secret evil",
                        "secret": "Pass123\nexit",
                    }
                ],
            },
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("CLI injection risk" in err or "prohibited" in err for err in res["errors"]))

    def test_dos_protection_interface_limit(self):
        # 65 interfaces exceeds maximum of 64
        interfaces = [
            {
                "name": f"GigabitEthernet0/{i}",
                "ip": f"10.0.{i}.1",
                "subnet_mask": "255.255.255.0",
                "cidr": 24,
            }
            for i in range(65)
        ]
        data = {
            "hostname": "Huge-Switch",
            "interfaces": interfaces,
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("Maximum number of interfaces" in err for err in res["errors"]))

    def test_dos_protection_vlan_limit(self):
        # 65 VLANs exceeds maximum of 64
        vlans = [
            {
                "id": i,
                "name": f"VLAN_{i}",
                "ip": f"10.0.{i}.1",
                "subnet_mask": "255.255.255.0",
                "cidr": 24,
            }
            for i in range(1, 66)
        ]
        data = {
            "hostname": "Huge-Switch",
            "vlans": vlans,
        }
        res = validate_network_schema(data)
        self.assertFalse(res["valid"])
        self.assertTrue(any("Maximum number of VLANs" in err for err in res["errors"]))


if __name__ == "__main__":
    unittest.main()
