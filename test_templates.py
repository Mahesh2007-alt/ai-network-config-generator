"""Test Jinja2 CLI Template Rendering."""

import ipaddress
import re
import unittest
from pathlib import Path
import jinja2

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"


def to_junos_prefix(address_str: str) -> str:
    """Convert Cisco ACL address syntax to Junos CIDR prefix syntax."""
    if not address_str or address_str.strip().lower() in ["any", "all"]:
        return "0.0.0.0/0"

    addr = address_str.strip()
    if addr.lower().startswith("host "):
        return f"{addr[5:].strip()}/32"

    parts = addr.split()
    if len(parts) == 2:
        ip_part, wc_part = parts[0], parts[1]
        try:
            octets = [int(o) for o in wc_part.split(".")]
            if len(octets) == 4:
                inv_mask = ".".join(str(255 - o) for o in octets)
                prefix_len = bin(int(ipaddress.IPv4Address(inv_mask))).count("1")
                return f"{ip_part}/{prefix_len}"
        except Exception:
            pass
    return addr


def to_junos_interface(name: str) -> str:
    """Convert interface name to Junos interface syntax (e.g. Loopback0 -> lo0, GigabitEthernet0/0 -> ge-0/0/0)."""
    if not name:
        return "ge-0/0/0"
    n = str(name).strip()
    n_lower = n.lower()
    if re.match(r"^(?:ge|xe|fe|et)-\d+", n_lower) or re.match(r"^lo\d+", n_lower):
        return n
    if n_lower.startswith("loopback") or n_lower.startswith("lo"):
        num_match = re.search(r"\d+", n)
        unit = num_match.group(0) if num_match else "0"
        return f"lo{unit}"
    patterns = [
        (r"^(?:tengigabitethernet|te|xe)\s*", "xe-"),
        (r"^(?:gigabitethernet|gi|ge)\s*", "ge-"),
        (r"^(?:fastethernet|fa|fe)\s*", "fe-"),
        (r"^(?:ethernet|eth|et)\s*", "et-"),
    ]
    for pattern, prefix in patterns:
        m = re.match(pattern, n_lower)
        if m:
            rest = n_lower[m.end():]
            parts = [p for p in rest.split("/") if p]
            if len(parts) == 2:
                return f"{prefix}0/{parts[0]}/{parts[1]}"
            elif len(parts) == 3:
                return f"{prefix}{parts[0]}/{parts[1]}/{parts[2]}"
            return f"{prefix}{rest}"
    return n


def to_junos_port(name: str) -> str:
    """Extract physical port and convert to Junos syntax (e.g. GigabitEthernet0/0/0.10 -> ge-0/0/0)."""
    if not name:
        return "ge-0/0/0"
    base = str(name).strip().split(".")[0]
    return to_junos_interface(base)


def to_junos_unit(name: str) -> str:
    """Extract logical unit from interface name (e.g. GigabitEthernet0/0/0.10 -> 10, GigabitEthernet0/0 -> 0)."""
    parts = str(name).strip().split(".")
    if len(parts) > 1 and parts[-1].isdigit():
        return parts[-1]
    return "0"


jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=False,
)
jinja_env.filters["junos_prefix"] = to_junos_prefix
jinja_env.filters["junos_interface"] = to_junos_interface
jinja_env.filters["junos_port"] = to_junos_port
jinja_env.filters["junos_unit"] = to_junos_unit

SAMPLE_DATA = {
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
        "router_id": "192.168.10.1",
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
    "acls": [
        {
            "name": "BLOCK_GUEST",
            "type": "extended",
            "rules": [
                {
                    "action": "deny",
                    "protocol": "ip",
                    "source": "192.168.30.0 0.0.0.255",
                    "destination": "192.168.20.0 0.0.0.255",
                },
                {
                    "action": "permit",
                    "protocol": "ip",
                    "source": "any",
                    "destination": "any",
                },
            ],
        }
    ],
}

ROUTER_DATA = {
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


class TestTemplateRendering(unittest.TestCase):

    def test_cisco_ios_render(self):
        tmpl = jinja_env.get_template("cisco_ios.j2")
        out = tmpl.render(**SAMPLE_DATA)
        self.assertIn("hostname Core-Switch-01", out)
        self.assertIn("vlan 10", out)
        self.assertIn("name Management", out)
        self.assertIn("interface Vlan10", out)
        self.assertIn("ip address 192.168.10.1 255.255.255.0", out)
        self.assertIn("no shutdown", out)
        self.assertIn("router ospf 10", out)
        self.assertIn("network 192.168.10.0 0.0.0.255 area 0", out)
        self.assertIn("ip access-list extended BLOCK_GUEST", out)
        self.assertIn("deny ip 192.168.30.0 0.0.0.255 192.168.20.0 0.0.0.255", out)
        self.assertIn("permit ip any any", out)
        self.assertIn("end", out)
        self.assertIn("write memory", out)

    def test_junos_render(self):
        tmpl = jinja_env.get_template("junos.j2")
        out = tmpl.render(**SAMPLE_DATA)
        self.assertIn("set system host-name Core-Switch-01", out)
        self.assertIn("set vlans Management vlan-id 10", out)
        self.assertIn("set vlans Management l3-interface irb.10", out)
        self.assertIn("set interfaces irb unit 10 family inet address 192.168.10.1/24", out)
        self.assertIn("set protocols ospf area 0.0.0.0 interface irb.10", out)
        self.assertIn("set firewall family inet filter BLOCK_GUEST", out)
        # Verify Junos CIDR conversion
        self.assertIn("from source-address 192.168.30.0/24", out)
        self.assertIn("from destination-address 192.168.20.0/24", out)

    def test_edge_router_render(self):
        # Cisco IOS router
        tmpl_cisco = jinja_env.get_template("cisco_ios.j2")
        out_cisco = tmpl_cisco.render(**ROUTER_DATA)
        self.assertIn("hostname Border-GW-West", out_cisco)
        self.assertIn("interface Loopback0", out_cisco)
        self.assertIn("ip address 10.255.0.1 255.255.255.255", out_cisco)
        self.assertIn("interface GigabitEthernet0/0", out_cisco)
        self.assertIn("ip address 198.51.100.2 255.255.255.252", out_cisco)
        self.assertIn("router bgp 65000", out_cisco)
        self.assertIn("bgp router-id 10.255.0.1", out_cisco)
        self.assertIn("neighbor 198.51.100.1 remote-as 65001", out_cisco)

        # Juniper Junos router
        tmpl_junos = jinja_env.get_template("junos.j2")
        out_junos = tmpl_junos.render(**ROUTER_DATA)
        self.assertIn("set system host-name Border-GW-West", out_junos)
        self.assertIn("set interfaces lo0 unit 0 family inet address 10.255.0.1/32", out_junos)
        self.assertIn("set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.2/30", out_junos)
        self.assertIn("set interfaces ge-0/0/1 unit 0 family inet address 10.1.1.1/24", out_junos)
        self.assertIn("set routing-options autonomous-system 65000", out_junos)
        self.assertIn("set protocols bgp group EXTERNAL peer-as 65001", out_junos)

    def test_roas_render(self):
        roas_data = {
            "hostname": "RoAS-Core-Rtr",
            "interfaces": [
                {
                    "name": "GigabitEthernet0/0/0",
                    "description": "Physical trunk port to switch",
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
                {
                    "name": "GigabitEthernet0/0/0.20",
                    "description": "Operations department",
                    "ip": "10.1.20.1",
                    "subnet_mask": "255.255.255.0",
                    "cidr": 24,
                    "vlan_id": 20,
                    "encapsulation": "dot1Q 20",
                    "shutdown": False,
                },
            ],
            "vlans": [],
            "routing": {"protocol": "none"},
            "security": {
                "domain_name": "enterprise.local",
                "rsa_bits": 1024,
                "users": [
                    {
                        "username": "netadmin",
                        "privilege": 15,
                        "secret": "CiscoPass123",
                    }
                ],
                "ssh": {
                    "vty_lines": "0 4",
                    "transport_input": "ssh",
                    "login": "local",
                },
            },
            "acls": [],
        }

        # Cisco IOS
        tmpl_cisco = jinja_env.get_template("cisco_ios.j2")
        out_cisco = tmpl_cisco.render(**roas_data)
        self.assertIn("hostname RoAS-Core-Rtr", out_cisco)
        self.assertIn("ip domain-name enterprise.local", out_cisco)
        self.assertIn("username netadmin privilege 15 secret CiscoPass123", out_cisco)
        self.assertIn("crypto key generate rsa modulus 1024", out_cisco)
        self.assertIn("transport input ssh", out_cisco)
        self.assertIn("interface GigabitEthernet0/0/0\n description Physical trunk port to switch\n no ip address", out_cisco)
        self.assertIn("interface GigabitEthernet0/0/0.10", out_cisco)
        self.assertIn("encapsulation dot1Q 10", out_cisco)
        self.assertIn("ip address 10.1.10.1 255.255.255.0", out_cisco)
        self.assertIn("interface GigabitEthernet0/0/0.20", out_cisco)
        self.assertIn("encapsulation dot1Q 20", out_cisco)
        self.assertIn("ip address 10.1.20.1 255.255.255.0", out_cisco)

        # Juniper Junos
        tmpl_junos = jinja_env.get_template("junos.j2")
        out_junos = tmpl_junos.render(**roas_data)
        self.assertIn("set system host-name RoAS-Core-Rtr", out_junos)
        self.assertIn("set system domain-name enterprise.local", out_junos)
        self.assertIn("set system login user netadmin class super-user authentication plain-text-password CiscoPass123", out_junos)
        self.assertIn("set interfaces ge-0/0/0 vlan-tagging", out_junos)
        self.assertIn("set interfaces ge-0/0/0 unit 10 vlan-id 10", out_junos)
        self.assertIn("set interfaces ge-0/0/0 unit 10 family inet address 10.1.10.1/24", out_junos)
        self.assertIn("set interfaces ge-0/0/0 unit 20 vlan-id 20", out_junos)
        self.assertIn("set interfaces ge-0/0/0 unit 20 family inet address 10.1.20.1/24", out_junos)


if __name__ == "__main__":
    unittest.main()
