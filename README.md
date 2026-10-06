# 🌐 AI Network Configuration Generator

A production-ready network automation application built with **Python**, **Streamlit**, **OpenAI (`gpt-4o-mini`)**, and **Jinja2**. It translates natural language network requirements into strictly validated, multi-vendor CLI configurations (**Cisco IOS** & **Juniper Junos**), with built-in IP subnet overlap detection and Packet Tracer lab verification steps.

---

## 🚀 Features

- **Natural Language Parsing**: Uses structured JSON mode (Groq, OpenAI, Google Gemini, Ollama) to extract network parameters (`hostname`, `interfaces`, `vlans`, `routing`, `acls`).
- **Routed Interfaces & Switched VLANs**: Supports both switched access/distribution layers (VLANs/SVIs) and enterprise edge border routers (physical routed ports like `GigabitEthernet0/0`, `/30` WAN links, and `/32` Loopbacks).
- **Comprehensive Validation Module (`validator.py`)**:
  - Validates IPv4 host addresses, subnet masks, and wildcard masks using Python's standard library `ipaddress`.
  - Verifies CIDR prefix consistency against dotted-decimal subnet masks.
  - Automatically identifies and flags **overlapping subnets** across all interfaces and VLANs.
  - Supports `/32` loopbacks, `/30` point-to-point links, and unnumbered physical trunk carrier ports.
  - Returns a structured status: `{"valid": bool, "errors": list[str]}`.
- **Multi-Vendor CLI Generation**:
  - **Cisco IOS**: L2 VLANs, SVIs, physical routed interfaces, 802.1Q subinterfaces (`encapsulation dot1Q`), unnumbered trunk ports (`no ip address`), device security/remote management (`ip domain-name`, local users, RSA key generation, SSH VTY lines), OSPF & BGP dynamic routing, and ACLs.
  - **Juniper Junos**: `set` syntax for hostname, domain name, local admin users, VLANs, `irb` units, physical interfaces (`ge-0/0/0`, `lo0`), `vlan-tagging` subinterface units, `protocols ospf`, BGP, and firewall filters.
- **Visual Network Topology & Routing Interconnections (`topology.py`)**:
  - **Dynamic Dark-Mode SVG Diagram**: Renders the central hardware chassis, color-coded interface cards (Loopbacks, WAN /30 transit, LAN, VLAN SVIs, 802.1Q subinterfaces, trunk carrier ports), connection cables, and routing peering domains.
  - **Interconnection & Routing Matrix**: Computes network boundaries, broadcast addresses, usable host IP ranges, usable host counts, and associated routing domains (OSPF Area 0, BGP ASN, Local Router ID, Inter-VLAN Gateway).
  - **Architecture Graph (Mermaid Syntax)**: Generates exportable Mermaid diagram markup for GitHub/Notion documentation.
- **Side-by-Side Interactive Streamlit UI**:
  - Real-time status badges for schema validity, hostname, interfaces, VLANs, and routing protocol.
  - Column 1 displays the formatted JSON schema.
  - Column 2 provides syntax-highlighted CLI code with one-click `.cfg` / `.txt` file downloading.
  - Section 3 provides 3 interactive tabs: SVG Topology Diagram, Routing Interconnection Matrix, and Mermaid Graph.
  - Clickable sample prompt presets:
    - 🏢 *Campus Network (VLANs)*
    - 🌲 *Branch Office (OSPF)*
    - 🌐 *Edge Border Router (BGP/WAN)*
    - 🔀 *Router-on-a-Stick (RoAS)*
    - ⚠️ *Overlap Subnet Test (Validator Demo)*
- **Offline / Simulation Mode**: Built-in mock parser fallback allowing full offline testing even without an API key.
- **Packet Tracer / Lab Verification Guide**: Collapsible reference card with exact CLI verification commands (`show ip interface brief`, `show vlan brief`, `show ip route`, `show ip bgp summary`, etc.).

---

## 📁 Project Structure

```
├── app.py                  # Main Streamlit web application
├── validator.py            # ipaddress-based IP, subnet & overlap validation
├── topology.py             # SVG topology & routing interconnection engine
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variables template
├── templates/
│   ├── cisco_ios.j2        # Jinja2 template for Cisco IOS CLI syntax
│   └── junos.j2            # Jinja2 template for Juniper Junos set-commands
├── test_validator.py       # Unit tests for validator.py
├── test_templates.py       # Unit tests for Jinja2 template rendering
└── test_topology.py        # Unit tests for topology.py
```

---

## 🛠️ Installation & Setup

### 1. Clone or Navigate to the Project Directory

```bash
cd "c:\Users\Mahesh Kumar\Desktop\Web Development Projects\landing page"
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key (Optional)

Create a `.env` file in the root directory (or enter the key directly in the Streamlit sidebar):

```env
OPENAI_API_KEY=sk-...
```

*Note: If no API key is provided, the application runs seamlessly in **Simulation / Offline Mode** using realistic presets!*

---

## ▶️ Running the Application

Launch the Streamlit web application:

```bash
streamlit run app.py
```

The app will open automatically in your browser at `http://localhost:8501`.

---

## 🧪 Running Unit Tests

Run the validator and template test suites:

```bash
# Run all 23 unit tests at once
python -m unittest discover -s . -p "test_*.py"

# Or run individual test suites
python test_validator.py
python test_templates.py
python test_topology.py
```

---

## 🔍 Packet Tracer / GNS3 Verification Workflow

After generating and pasting the configuration into your lab device:

### Cisco IOS
1. **Interface State**: `Switch# show ip interface brief`
2. **VLAN Database**: `Switch# show vlan brief`
3. **OSPF Routing**: `Switch# show ip route` and `Switch# show ip ospf neighbor`
4. **ACL Hits**: `Switch# show access-lists`

### Juniper Junos
1. **Interface State**: `user@switch> show interfaces terse irb*`
2. **VLANs**: `user@switch> show vlans`
3. **Routing Table**: `user@switch> show route`
4. **OSPF Adjacency**: `user@switch> show ospf neighbor`
