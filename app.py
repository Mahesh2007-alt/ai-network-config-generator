"""AI Network Configuration Generator.

Translates natural language network requirements into validated,
multi-vendor CLI configurations (Cisco IOS & Juniper Junos).
Supports OpenAI, Groq Cloud (Free Tier), and Google Gemini.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Dict

from dotenv import load_dotenv
import jinja2
import streamlit as st

from topology import (
    generate_mermaid_syntax,
    generate_routing_matrix,
    generate_topology_svg,
)
from validator import validate_network_schema

# Load local environment variables from .env
load_dotenv()

# Setup paths
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"


def to_junos_prefix(address_str: str) -> str:
    """Convert Cisco ACL address syntax to Junos CIDR prefix syntax.

    Examples:
        'host 10.1.1.1' -> '10.1.1.1/32'
        '192.168.30.0 0.0.0.255' -> '192.168.30.0/24'
        '192.168.30.0/24' -> '192.168.30.0/24'
        'any' -> '0.0.0.0/0'
    """
    if not address_str or str(address_str).strip().lower() in ["any", "all"]:
        return "0.0.0.0/0"

    addr = str(address_str).strip()
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


# Jinja2 environment with block whitespace trimming & custom filters
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

# Strict System Prompt for JSON object generation
SYSTEM_PROMPT = """You are a senior network automation engineer.
Your task is to parse natural language network requirements into a strictly formatted, valid JSON schema.
You MUST output ONLY a valid JSON object matching the following structure:

{
  "hostname": "STRING (e.g. Border-GW-West, RoAS-Core-Rtr, or Core-Switch-01)",
  "interfaces": [
    {
      "name": "STRING (e.g. GigabitEthernet0/0/0, GigabitEthernet0/0/0.10, Loopback0, ge-0/0/0)",
      "description": "STRING (optional, e.g. Accounts department)",
      "ip": "STRING or null (for physical carrier trunk port with no IP use null; for routed ports valid IPv4)",
      "subnet_mask": "STRING or null (e.g. 255.255.255.0, 255.255.255.252, or null)",
      "cidr": "INTEGER or null (e.g. 24, 30, 32, or null)",
      "vlan_id": "INTEGER or null (for 802.1Q subinterfaces, e.g. 10)",
      "encapsulation": "STRING or null (e.g. dot1Q 10)",
      "shutdown": false
    }
  ],
  "vlans": [
    {
      "id": INTEGER (1-4094),
      "name": "STRING (e.g. Management)",
      "ip": "STRING (valid IPv4 interface host IP, e.g. 192.168.10.1)",
      "subnet_mask": "STRING (e.g. 255.255.255.0)",
      "cidr": INTEGER (e.g. 24)
    }
  ],
  "routing": {
    "protocol": "STRING (e.g. ospf, bgp, static, or none)",
    "process_id": INTEGER (optional, for OSPF, e.g. 1),
    "as_number": INTEGER (optional, for BGP ASN, e.g. 65000),
    "router_id": "STRING (optional, e.g. 10.255.0.1)",
    "networks": [
      {
        "network_ip": "STRING (base network IP address, e.g. 192.168.10.0)",
        "wildcard_mask": "STRING (standard inverted subnet mask, e.g. 0.0.0.255)",
        "subnet_mask": "STRING (optional, e.g. 255.255.255.0)",
        "area": 0
      }
    ],
    "neighbors": [
      {
        "ip": "STRING (e.g. 198.51.100.1)",
        "remote_as": INTEGER (e.g. 65001),
        "description": "STRING (optional)"
      }
    ],
    "static_routes": [
      {
        "prefix": "STRING (e.g. 0.0.0.0)",
        "mask": "STRING (e.g. 0.0.0.0)",
        "cidr": 0,
        "next_hop": "STRING (e.g. 198.51.100.1)"
      }
    ]
  },
  "security": {
    "domain_name": "STRING (optional, e.g. enterprise.local)",
    "rsa_bits": "INTEGER (optional, e.g. 1024 or 2048)",
    "users": [
      {
        "username": "STRING (e.g. netadmin)",
        "privilege": "INTEGER (optional, e.g. 15)",
        "secret": "STRING (optional, e.g. CiscoPass123)"
      }
    ],
    "ssh": {
      "vty_lines": "STRING (e.g. 0 4)",
      "transport_input": "STRING (e.g. ssh)",
      "login": "STRING (e.g. local)"
    }
  },
  "acls": [
    {
      "name": "STRING (e.g. BLOCK_GUEST_CORP)",
      "type": "STRING (standard or extended)",
      "rules": [
        {
          "action": "permit | deny",
          "protocol": "STRING (e.g. ip, tcp, udp, icmp)",
          "source": "STRING (e.g. 192.168.30.0 0.0.0.255, host 192.168.10.5, or any)",
          "destination": "STRING (e.g. 192.168.20.0 0.0.0.255, or any)",
          "port": "STRING (optional, e.g. 80, 443, 22)"
        }
      ]
    }
  ]
}

CRITICAL RULES:
1. For routed interfaces, physical carrier ports, and 802.1Q subinterfaces (e.g. GigabitEthernet0/0/0, GigabitEthernet0/0/0.10), populate 'interfaces'.
2. For switched VLANs / SVIs (Layer 2 VLAN 10, VLAN 20, etc.), populate 'vlans'.
3. At least one interface OR one VLAN must be present. If the prompt describes a router with routed interfaces and no VLANs, 'vlans' should be an empty list [].
4. For Router-on-a-Stick (RoAS):
   - Physical port (e.g. GigabitEthernet0/0/0) with no IP address: "ip": null, "subnet_mask": null, "cidr": null, "shutdown": false.
   - Subinterfaces (e.g. GigabitEthernet0/0/0.10): specify "ip", "subnet_mask", "cidr", and "vlan_id" (e.g. 10) or "encapsulation": "dot1Q 10".
5. For /32 loopbacks, 'subnet_mask' is '255.255.255.255' and 'cidr' is 32.
6. For /30 point-to-point links, 'subnet_mask' is '255.255.255.252' and 'cidr' is 30.
7. If remote management, domain name, admin users, RSA keys, or SSH VTY lines are requested, populate the 'security' object.
8. Ensure 'cidr' matches 'subnet_mask' exactly when an IP is configured.
9. Do NOT include markdown code blocks, explanation, or notes. Output purely the JSON object.
"""


# Sample Presets
PRESET_CAMPUS = """Configure a core campus switch named 'Core-Switch-01' with 3 distinct VLANs:
- VLAN 10 named 'Management' with gateway IP 192.168.10.1 and subnet mask 255.255.255.0 (/24).
- VLAN 20 named 'Engineering' with gateway IP 192.168.20.1 and subnet mask 255.255.255.0 (/24).
- VLAN 30 named 'Guest-WiFi' with gateway IP 192.168.30.1 and subnet mask 255.255.255.0 (/24).

Enable OSPF routing process 10 in Area 0 covering all three subnets (192.168.10.0, 192.168.20.0, and 192.168.30.0 with wildcard mask 0.0.0.255).
Include an extended ACL named 'BLOCK_GUEST_CORP' denying traffic from Guest subnet (192.168.30.0 0.0.0.255) to Engineering subnet (192.168.20.0 0.0.0.255) and permitting all other IP traffic."""

PRESET_BRANCH = """Configure branch router 'Branch-Rtr-East' for a remote sales office.
Set up VLAN 100 for 'Data' with IP 10.50.1.1/24 (subnet mask 255.255.255.0).
Set up VLAN 200 for 'Voice' with IP 10.50.2.1/24 (subnet mask 255.255.255.0).
Configure single-area OSPF process 1 advertising both 10.50.1.0 and 10.50.2.0 in Area 0 with wildcard 0.0.0.255."""

PRESET_BORDER_GW = """Configure an autonomous edge border router named Border-GW-West:
- Loopback0 interface with IP 10.255.0.1/32 for router management and BGP router ID.
- WAN interface GigabitEthernet0/0 connecting to upstream ISP peer with IP 198.51.100.2/30.
- LAN core link GigabitEthernet0/0/1 with IP 10.1.1.1/24.
Configure BGP AS 65000 with router-id 10.255.0.1 and neighbor 198.51.100.1 remote-as 65001."""

PRESET_ROAS = """Configure an inter-VLAN core router named RoAS-Core-Rtr.
- On physical interface GigabitEthernet0/0/0, bring up the port with no IP address.
- Create subinterface GigabitEthernet0/0/0.10 for the Accounts department with 802.1Q encapsulation on VLAN 10 and gateway IP 10.1.10.1/24.
- Create subinterface GigabitEthernet0/0/0.20 for the Operations department with 802.1Q encapsulation on VLAN 20 and gateway IP 10.1.20.1/24.
- Secure device remote management: set local domain name to "enterprise.local", generate RSA keys with 1024 bits, configure a local admin user named "netadmin" with privilege 15 and secret "CiscoPass123", and restrict VTY lines 0 to 4 to SSH only using local authentication."""

PRESET_OVERLAP = """Configure switch 'Test-Overlap-SW' with 2 overlapping subnets to test validation error handling:
- VLAN 10 named 'HQ-LAN' with gateway IP 172.16.1.1 and subnet mask 255.255.255.0 (/24).
- VLAN 20 named 'Finance' with gateway IP 172.16.1.129 and subnet mask 255.255.255.128 (/25 - completely overlaps inside 172.16.1.0/24!).
Enable OSPF routing process 1 in Area 0."""

# Built-in fallback mock payloads for instant offline preview & resilience
MOCK_PAYLOADS = {
    "campus": {
        "hostname": "Core-Switch-01",
        "interfaces": [],
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
            {
                "id": 30,
                "name": "Guest-WiFi",
                "ip": "192.168.30.1",
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
                {
                    "network_ip": "192.168.30.0",
                    "wildcard_mask": "0.0.0.255",
                    "area": 0,
                },
            ],
        },
        "acls": [
            {
                "name": "BLOCK_GUEST_CORP",
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
    },
    "branch": {
        "hostname": "Branch-Rtr-East",
        "interfaces": [],
        "vlans": [
            {
                "id": 100,
                "name": "Data",
                "ip": "10.50.1.1",
                "subnet_mask": "255.255.255.0",
                "cidr": 24,
            },
            {
                "id": 200,
                "name": "Voice",
                "ip": "10.50.2.1",
                "subnet_mask": "255.255.255.0",
                "cidr": 24,
            },
        ],
        "routing": {
            "protocol": "ospf",
            "process_id": 1,
            "router_id": "10.50.1.1",
            "networks": [
                {
                    "network_ip": "10.50.1.0",
                    "wildcard_mask": "0.0.0.255",
                    "area": 0,
                },
                {
                    "network_ip": "10.50.2.0",
                    "wildcard_mask": "0.0.0.255",
                    "area": 0,
                },
            ],
        },
        "acls": [],
    },
    "edge_router": {
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
            "networks": [],
            "neighbors": [
                {
                    "ip": "198.51.100.1",
                    "remote_as": 65001,
                    "description": "Upstream ISP Gateway",
                }
            ],
            "static_routes": [],
        },
        "acls": [],
    },
    "overlap": {
        "hostname": "Test-Overlap-SW",
        "interfaces": [],
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
        "routing": {
            "protocol": "ospf",
            "process_id": 1,
            "networks": [
                {
                    "network_ip": "172.16.1.0",
                    "wildcard_mask": "0.0.0.255",
                    "area": 0,
                }
            ],
        },
        "acls": [],
    },
    "roas": {
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
        "routing": {
            "protocol": "none",
        },
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
    },
}

# Provider configurations
PROVIDERS_CONFIG = {
    "Groq Cloud (Free Tier)": {
        "base_url": "https://api.groq.com/openai/v1",
        "models": ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"],
        "env_key": "GROQ_API_KEY",
        "help": "Free ultra-fast cloud inference on Groq.",
    },
    "OpenAI (Official)": {
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo"],
        "env_key": "OPENAI_API_KEY",
        "help": "Official OpenAI models.",
    },
    "Google Gemini (Free Tier)": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "models": ["gemini-2.0-flash", "gemini-1.5-flash"],
        "env_key": "GEMINI_API_KEY",
        "help": "Free API access via Google AI Studio.",
    },
    "Custom / Local (Ollama)": {
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3.2", "mistral", "qwen2.5"],
        "env_key": "LOCAL_API_KEY",
        "help": "Local Ollama or custom OpenAI-compatible server.",
    },
}


def call_llm_extractor(
    prompt_text: str, api_key: str, model_name: str, base_url: str
) -> Dict[str, Any]:
    """Call OpenAI-compatible LLM endpoint using structured JSON Object mode."""
    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        temperature=0.1,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
    )
    raw_content = response.choices[0].message.content or "{}"
    return json.loads(raw_content)


def get_mock_fallback(prompt_text: str) -> Dict[str, Any]:
    """Provide realistic schema matching prompt contents when API key is not set."""
    p_lower = prompt_text.lower()
    if "overlap" in p_lower or "172.16.1" in p_lower:
        return MOCK_PAYLOADS["overlap"]
    if (
        "roas" in p_lower
        or "subinterface" in p_lower
        or "inter-vlan" in p_lower
        or "802.1q" in p_lower
        or "dot1q" in p_lower
        or "accounts" in p_lower
        or "0/0/0." in p_lower
    ):
        return MOCK_PAYLOADS["roas"]
    if (
        "border" in p_lower
        or "edge" in p_lower
        or "loopback" in p_lower
        or "wan" in p_lower
        or "bgp" in p_lower
    ):
        return MOCK_PAYLOADS["edge_router"]
    if "branch" in p_lower or "voice" in p_lower or "10.50." in p_lower:
        return MOCK_PAYLOADS["branch"]
    return MOCK_PAYLOADS["campus"]


def sanitize_error_message(err: Any) -> str:
    """Redact sensitive API keys, bearer tokens, and credentials from exception messages."""
    text = str(err)
    text = re.sub(r"(?:gsk_|sk-|AIza)[A-Za-z0-9_-]{10,}", "[REDACTED_API_KEY]", text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9_.-]+", "Bearer [REDACTED_TOKEN]", text, flags=re.IGNORECASE)
    text = re.sub(r"key=[A-Za-z0-9_-]+", "key=[REDACTED]", text, flags=re.IGNORECASE)
    return text


def _deep_sanitize_strings(obj: Any) -> Any:
    """Recursively strip newline and carriage return characters from data structures."""
    if isinstance(obj, str):
        return obj.replace("\r", "").replace("\n", " ").strip()
    elif isinstance(obj, dict):
        return {k: _deep_sanitize_strings(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_deep_sanitize_strings(x) for x in obj]
    return obj


def render_cli(schema: Dict[str, Any], vendor: str) -> str:
    """Render Jinja2 template for chosen vendor with defense-in-depth CLI string sanitization."""
    safe_schema = _deep_sanitize_strings(schema)
    if vendor == "Cisco IOS":
        template = jinja_env.get_template("cisco_ios.j2")
    else:
        template = jinja_env.get_template("junos.j2")
    return template.render(**safe_schema)


# ==============================================================================
# Streamlit Application Page
# ==============================================================================
st.set_page_config(
    page_title="AI Network Configuration Generator",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for polished, production-grade aesthetics
st.markdown(
    """
    <style>
    .metric-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-right: 6px;
        margin-bottom: 6px;
    }
    .badge-success {
        background-color: rgba(34, 197, 94, 0.15);
        color: #22c55e;
        border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .badge-error {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .badge-info {
        background-color: rgba(59, 130, 246, 0.15);
        color: #3b82f6;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }
    .stTextArea textarea {
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.95rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Determine default provider based on available environment keys
groq_env_val = os.getenv("GROQ_API_KEY", "")
openai_env_val = os.getenv("OPENAI_API_KEY", "")

default_provider_index = 0 if groq_env_val else (1 if openai_env_val else 0)

# Initialize Session State
if "requirement_text" not in st.session_state:
    st.session_state["requirement_text"] = PRESET_CAMPUS
if "target_vendor" not in st.session_state:
    st.session_state["target_vendor"] = "Cisco IOS"
if "parsed_schema" not in st.session_state:
    st.session_state["parsed_schema"] = None
if "validation_result" not in st.session_state:
    st.session_state["validation_result"] = None
if "generated_cli" not in st.session_state:
    st.session_state["generated_cli"] = None

# Sidebar Controls
with st.sidebar:
    st.title("⚙️ Engine Controls")
    st.caption("AI Provider & Network Architecture Setup")

    provider_choice = st.selectbox(
        "AI Provider",
        options=list(PROVIDERS_CONFIG.keys()),
        index=default_provider_index,
        help="Select your AI engine. Groq and Gemini offer free access.",
    )

    current_cfg = PROVIDERS_CONFIG[provider_choice]
    env_key_name = current_cfg["env_key"]
    detected_key = os.getenv(env_key_name, "") or (
        groq_env_val if provider_choice == "Groq Cloud (Free Tier)" else ""
    )

    api_key_input = st.text_input(
        f"{provider_choice.split()[0]} API Key",
        value=detected_key,
        type="password",
        help=f"Enter your API key or configure {env_key_name} in your .env file.",
    )

    model_option = st.selectbox(
        "Extraction Model",
        options=current_cfg["models"],
        index=0,
        help="Model optimized for structured JSON schema extraction.",
    )

    custom_base_url = None
    if provider_choice == "Custom / Local (Ollama)":
        custom_base_url = st.text_input("Base URL", value=current_cfg["base_url"])

    offline_mode = st.checkbox(
        "Simulation / Offline Mode",
        value=not bool(api_key_input),
        help="Run without API calls using built-in realistic mock data.",
    )

    st.divider()
    st.markdown("### 📋 Supported Target Platforms")
    st.markdown(
        "- **Cisco IOS**: L2 VLANs, SVI SVIs with `no shutdown`, OSPF process with wildcard masks, ACLs.\n"
        "- **Juniper Junos**: `set` commands, VLANs, IRB interfaces with CIDR, `protocols ospf`, and firewall filters."
    )

    st.divider()
    st.caption("AI Network Configuration Generator v1.2.0 • Powered by Groq & Streamlit")

# Main Header
st.title("🌐 AI Network Configuration Generator")

# Status alert bar
if api_key_input and not offline_mode:
    st.success(
        f"🟢 **Live AI Extraction Enabled**: Connected to **{provider_choice}** "
        f"using model `{model_option}` • Authenticated"
    )
else:
    st.info("ℹ️ Running in **Simulation / Offline Mode** (using built-in network schema parser).")

st.markdown(
    "Translate natural language campus and branch network requirements into **strictly validated**, "
    "**multi-vendor CLI configurations** with automated IP overlap checking."
)

st.markdown("---")

# Section 1: Input Prompts & Vendor Selection
st.subheader("1. Network Requirements & Target Platform")

# Preset Prompt Buttons
st.markdown("**Click a Sample Preset Prompt:**")
col_p1, col_p2, col_p3, col_p4, col_p5 = st.columns([1, 1, 1.1, 1.25, 1])

with col_p1:
    if st.button("🏢 Campus (VLANs)", use_container_width=True):
        st.session_state["requirement_text"] = PRESET_CAMPUS
        st.session_state["parsed_schema"] = None
        st.session_state["validation_result"] = None
        st.session_state["generated_cli"] = None
        st.rerun()

with col_p2:
    if st.button("🌲 Branch (OSPF)", use_container_width=True):
        st.session_state["requirement_text"] = PRESET_BRANCH
        st.session_state["parsed_schema"] = None
        st.session_state["validation_result"] = None
        st.session_state["generated_cli"] = None
        st.rerun()

with col_p3:
    if st.button("🌐 Border GW (BGP/WAN)", use_container_width=True):
        st.session_state["requirement_text"] = PRESET_BORDER_GW
        st.session_state["parsed_schema"] = None
        st.session_state["validation_result"] = None
        st.session_state["generated_cli"] = None
        st.rerun()

with col_p4:
    if st.button("🔀 RoAS Inter-VLAN", use_container_width=True):
        st.session_state["requirement_text"] = PRESET_ROAS
        st.session_state["parsed_schema"] = None
        st.session_state["validation_result"] = None
        st.session_state["generated_cli"] = None
        st.rerun()

with col_p5:
    if st.button("⚠️ Overlap Test", use_container_width=True):
        st.session_state["requirement_text"] = PRESET_OVERLAP
        st.session_state["parsed_schema"] = None
        st.session_state["validation_result"] = None
        st.session_state["generated_cli"] = None
        st.rerun()

# Text Area for Requirements
req_text = st.text_area(
    "Plain-English Network Requirements:",
    value=st.session_state["requirement_text"],
    height=160,
    help="Describe your VLANs, IP subnets, routing protocols, and access control lists in natural language.",
)

col_ctrl1, col_ctrl2 = st.columns([1, 2])
with col_ctrl1:
    vendor_selection = st.selectbox(
        "Target Vendor Platform:",
        options=["Cisco IOS", "Juniper Junos"],
        index=0 if st.session_state["target_vendor"] == "Cisco IOS" else 1,
        help="Choose the target network operating system syntax.",
    )
    st.session_state["target_vendor"] = vendor_selection

with col_ctrl2:
    st.markdown("<div style='height: 28px'></div>", unsafe_allow_html=True)
    generate_clicked = st.button(
        "🚀 Generate & Validate Network Configuration",
        type="primary",
        use_container_width=True,
    )

st.markdown("---")

# Section 2: Backend Logic Execution
if generate_clicked:
    st.session_state["requirement_text"] = req_text

    with st.spinner(f"Extracting network schema with {provider_choice}..."):
        try:
            if offline_mode or not api_key_input:
                extracted_data = get_mock_fallback(req_text)
            else:
                if provider_choice == "Custom / Local (Ollama)":
                    target_base_url = (custom_base_url or "").strip()
                    if not (target_base_url.startswith("http://") or target_base_url.startswith("https://")):
                        st.error("❌ Invalid Base URL: Custom Ollama endpoint must start with 'http://' or 'https://'.")
                        st.stop()
                else:
                    target_base_url = current_cfg["base_url"]

                extracted_data = call_llm_extractor(
                    req_text, api_key_input, model_option, target_base_url
                )
            st.session_state["parsed_schema"] = extracted_data
        except Exception as e:
            redacted_err = sanitize_error_message(e)
            st.error(f"❌ AI Schema Extraction Failed: {redacted_err}")
            st.session_state["parsed_schema"] = None
            st.stop()

    # Pass extracted schema to validator.py
    with st.spinner("Running deep IP, subnet, wildcard, and overlap validation..."):
        validation_status = validate_network_schema(st.session_state["parsed_schema"])
        st.session_state["validation_result"] = validation_status

    # If valid, render the Jinja2 template
    if validation_status["valid"]:
        rendered_output = render_cli(
            st.session_state["parsed_schema"], st.session_state["target_vendor"]
        )
        st.session_state["generated_cli"] = rendered_output
    else:
        st.session_state["generated_cli"] = None

# Section 3: Outputs Display (Validation Status, JSON Schema & Syntax-Highlighted CLI)
if st.session_state["parsed_schema"] is not None:
    validation = st.session_state["validation_result"]

    # Display Validation Status Header
    if validation and validation["valid"]:
        st.success(
            "✅ **Network Schema Validation Succeeded:** All IP addresses, masks, and subnets are well-formed with zero overlaps."
        )
    else:
        st.error(
            "❌ **Validation Failed:** The extracted schema contains networking errors. CLI generation halted."
        )
        for err in validation.get("errors", []):
            st.markdown(f"- 🔴 **Error:** {err}")

    # Side-by-Side Output Columns
    col_json, col_cli = st.columns(2)

    with col_json:
        st.subheader("📊 Extracted Network Schema")
        if validation and validation["valid"]:
            num_vlans = len(st.session_state["parsed_schema"].get("vlans", []))
            num_ifaces = len(st.session_state["parsed_schema"].get("interfaces", []))
            proto_val = (
                (st.session_state["parsed_schema"].get("routing", {}) or {})
                .get("protocol", "None")
                .upper()
            )
            badge_html = '<span class="metric-badge badge-success">✓ Schema Valid</span>'
            badge_html += f'<span class="metric-badge badge-info">Host: {st.session_state["parsed_schema"].get("hostname", "N/A")}</span>'
            if num_ifaces > 0:
                badge_html += f'<span class="metric-badge badge-info">Interfaces: {num_ifaces}</span>'
            if num_vlans > 0:
                badge_html += f'<span class="metric-badge badge-info">VLANs: {num_vlans}</span>'
            if proto_val and proto_val != "NONE":
                badge_html += f'<span class="metric-badge badge-info">Routing: {proto_val}</span>'
            st.markdown(badge_html, unsafe_allow_html=True)
        else:
            st.markdown(
                '<span class="metric-badge badge-error">✕ Validation Failed</span>'
                f'<span class="metric-badge badge-error">Errors: {len(validation.get("errors", []))}</span>',
                unsafe_allow_html=True,
            )

        st.json(st.session_state["parsed_schema"], expanded=True)

    with col_cli:
        st.subheader(f"💻 {st.session_state['target_vendor']} Configuration")

        if validation and validation["valid"]:
            cli_code = st.session_state["generated_cli"]
            st.code(cli_code, language="bash")

            # File download button
            hostname_val = st.session_state["parsed_schema"].get("hostname", "switch")
            vendor_slug = (
                "cisco_ios"
                if st.session_state["target_vendor"] == "Cisco IOS"
                else "junos"
            )
            file_extension = (
                "cfg" if st.session_state["target_vendor"] == "Cisco IOS" else "txt"
            )
            filename = f"{hostname_val}_{vendor_slug}.{file_extension}"

            st.download_button(
                label=f"📥 Download {filename}",
                data=cli_code,
                file_name=filename,
                mime="text/plain",
                use_container_width=True,
            )
        else:
            st.warning(
                "⚠️ CLI configuration cannot be rendered because the network specification failed validation checks. "
                "Fix the errors highlighted on the left to generate the deployment CLI."
            )

    # Visual Network Topology & Interconnection Routing Map
    if validation and validation["valid"]:
        st.markdown("---")
        st.subheader("🗺️ Network Topology & Routing Interconnections")
        st.caption(
            "Live hardware chassis representation, connected interface cards, "
            "subnets, and dynamic routing peering domains derived from the validated code."
        )

        topo_tab1, topo_tab2, topo_tab3 = st.tabs(
            [
                "🎨 Visual Topology Diagram (SVG)",
                "🔀 Component Interconnections & Routing Matrix",
                "📐 Architecture Graph (Mermaid)",
            ]
        )

        with topo_tab1:
            svg_markup = generate_topology_svg(st.session_state["parsed_schema"])
            st.markdown(svg_markup, unsafe_allow_html=True)
            st.caption(
                "💡 **Dark-Mode Vector Topology**: Displays central chassis node, color-coded interface cards "
                "(Loopbacks, WAN Transit, LAN, Switched SVIs), IP subnets, and routing peering domains."
            )

        with topo_tab2:
            matrix_data = generate_routing_matrix(st.session_state["parsed_schema"])
            st.dataframe(
                matrix_data,
                use_container_width=True,
                column_config={
                    "Component / Port": st.column_config.TextColumn(
                        "Component / Port", width="medium"
                    ),
                    "Link Type": st.column_config.TextColumn("Link Type", width="small"),
                    "IP / CIDR": st.column_config.TextColumn("IP / CIDR", width="small"),
                    "Network Address": st.column_config.TextColumn("Network", width="small"),
                    "Usable Host Range": st.column_config.TextColumn("Usable Range", width="medium"),
                    "Usable Hosts": st.column_config.TextColumn("Usable Hosts", width="small"),
                    "Routing Domain": st.column_config.TextColumn("Routing Domain", width="medium"),
                    "Description": st.column_config.TextColumn("Description", width="large"),
                },
                hide_index=True,
            )
            st.caption(
                "Automated subnet calculation: network boundaries, broadcast addresses, usable host capacities, and associated routing domains."
            )

        with topo_tab3:
            mermaid_code = generate_mermaid_syntax(st.session_state["parsed_schema"])
            st.code(mermaid_code, language="mermaid")
            st.caption(
                "Copy this Mermaid graph markup directly into Markdown documentation, GitHub READMEs, or Mermaid Live Editor."
            )

st.markdown("---")

# Section 4: Collapsible Packet Tracer Verification Guide
with st.expander("🔍 Packet Tracer / Lab Verification Guide", expanded=False):
    st.markdown("### Step-by-Step Lab Verification Commands")
    st.markdown(
        "After pasting the generated configuration into Cisco Packet Tracer, GNS3, or Eve-NG, "
        "execute these verification commands to ensure end-to-end interface state and routing convergence:"
    )

    tab_cisco, tab_junos = st.tabs(["Cisco IOS Commands", "Juniper Junos Commands"])

    with tab_cisco:
        st.markdown("#### 1. Verify Interfaces (SVIs & Physical Routed Ports)")
        st.code("Device# show ip interface brief", language="bash")
        st.caption(
            "Checks that all configured interfaces (SVIs, `Loopback0`, `GigabitEthernet0/0`, etc.) have their correct IP addresses assigned and Status/Protocol is `up/up`."
        )

        st.markdown("#### 2. Verify Layer 2 VLAN Database (if configured)")
        st.code("Switch# show vlan brief", language="bash")
        st.caption(
            "Ensures all VLAN IDs and names are created and active in the local VLAN database."
        )

        st.markdown("#### 3. Verify Dynamic Routing (OSPF & BGP)")
        st.code(
            "Router# show ip route\nRouter# show ip ospf neighbor\nRouter# show ip bgp summary",
            language="bash",
        )
        st.caption(
            "Verifies routing table routes (`C`, `L`, `O`, `B`), OSPF neighbor adjacencies, and BGP peering session states (`Established`)."
        )

        st.markdown("#### 4. Verify Access Control List (ACL) Hits")
        st.code("Device# show access-lists", language="bash")
        st.caption(
            "Displays configured permit/deny ACL rules and current packet match counters."
        )

    with tab_junos:
        st.markdown("#### 1. Verify Interfaces (Logical Units & Physical Ports)")
        st.code("user@router> show interfaces terse", language="bash")
        st.caption(
            "Verifies logical units and physical ports (e.g. `lo0.0`, `ge-0/0/0.0`, `irb.10`) are `up/up` with configured CIDR addresses."
        )

        st.markdown("#### 2. Verify Configured VLANs (if configured)")
        st.code("user@router> show vlans", language="bash")
        st.caption(
            "Displays active VLAN tags and associated Layer-3 IRB interfaces."
        )

        st.markdown("#### 3. Verify Routing Table & Protocols (OSPF & BGP)")
        st.code(
            "user@router> show route\nuser@router> show ospf neighbor\nuser@router> show bgp summary",
            language="bash",
        )
        st.caption(
            "Displays the `inet.0` routing table, OSPF state, and BGP peer session states."
        )

        st.markdown("#### 4. Verify Firewall Filter Counters")
        st.code("user@router> show firewall filter <filter-name>", language="bash")
        st.caption(
            "Monitors packet counters matching your configured firewall filter terms."
        )
