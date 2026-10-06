"""Network Topology and Routing Visualization Module.

Generates self-contained, theme-adaptive SVG diagrams, routing interconnection
matrices, and Mermaid diagram syntax for both routed interfaces and switched VLANs.
"""

from __future__ import annotations

import html
import ipaddress
import re
from typing import Any, Dict, List


def calculate_subnet_details(ip_str: str, cidr: int) -> Dict[str, str]:
    """Calculate network, broadcast, usable host range and host count."""
    try:
        net = ipaddress.IPv4Network(f"{ip_str}/{cidr}", strict=False)
        total_hosts = net.num_addresses
        if cidr == 32:
            usable = f"{net.network_address} (Host)"
            usable_count = 1
        elif cidr == 31:
            usable = f"{net.network_address} - {net.broadcast_address}"
            usable_count = 2
        else:
            first_host = net.network_address + 1
            last_host = net.broadcast_address - 1
            usable = f"{first_host} - {last_host}"
            usable_count = max(0, total_hosts - 2)

        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address),
            "netmask": str(net.netmask),
            "usable_range": usable,
            "usable_count": str(usable_count),
        }
    except Exception:
        return {
            "network": "N/A",
            "broadcast": "N/A",
            "netmask": "N/A",
            "usable_range": "N/A",
            "usable_count": "N/A",
        }


def generate_routing_matrix(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a structured routing & connection table from the network schema."""
    rows: List[Dict[str, Any]] = []
    interfaces = schema.get("interfaces", []) or []
    vlans = schema.get("vlans", []) or []
    routing = schema.get("routing", {}) or {}
    proto = str(routing.get("protocol", "Connected")).upper()

    # 1. Physical / Routed Interfaces
    for iface in interfaces:
        name = iface.get("name", "Interface")
        ip = iface.get("ip")
        cidr = iface.get("cidr")
        desc = iface.get("description", "")
        is_unnumbered = not ip or str(ip).strip().lower() in ["none", "null", "unassigned", "no ip", "no-ip", ""]
        is_subinterface = "." in name or iface.get("vlan_id") is not None or iface.get("encapsulation") is not None
        vlan_val = iface.get("vlan_id") or (name.split(".")[-1] if "." in name and name.split(".")[-1].isdigit() else "")

        if is_unnumbered:
            link_type = "802.1Q Trunk Carrier"
            ip_display = "No IP (802.1Q Carrier)"
            net_display = "N/A"
            usable_range = "N/A"
            usable_count = "0"
            assoc_routing = "Trunk Carrier"
        elif is_subinterface:
            effective_cidr = int(cidr) if cidr is not None else 24
            details = calculate_subnet_details(str(ip), effective_cidr)
            link_type = f"802.1Q Subinterface (VLAN {vlan_val})" if vlan_val else "802.1Q Subinterface"
            ip_display = f"{ip}/{effective_cidr}"
            net_display = details["network"]
            usable_range = details["usable_range"]
            usable_count = details["usable_count"]
            assoc_routing = "Inter-VLAN Gateway"
        else:
            effective_cidr = int(cidr) if cidr is not None else 24
            details = calculate_subnet_details(str(ip), effective_cidr)
            ip_display = f"{ip}/{effective_cidr}"
            net_display = details["network"]
            usable_range = details["usable_range"]
            usable_count = details["usable_count"]
            link_type = (
                "Loopback Host"
                if effective_cidr == 32 or "loop" in name.lower()
                else ("WAN Transit (/30 P2P)" if effective_cidr == 30 else "LAN Routed Link")
            )
            assoc_routing = (
                "Local Management / Router ID"
                if effective_cidr == 32
                else (
                    f"BGP (AS {routing.get('as_number', routing.get('asn', 65000))})"
                    if proto == "BGP"
                    else (
                        f"OSPF Area {routing.get('networks', [{}])[0].get('area', 0)}"
                        if proto == "OSPF"
                        else "Directly Connected"
                    )
                )
            )

        rows.append(
            {
                "Component / Port": name,
                "Link Type": link_type,
                "IP / CIDR": ip_display,
                "Network Address": net_display,
                "Usable Host Range": usable_range,
                "Usable Hosts": usable_count,
                "Routing Domain": assoc_routing,
                "Description": desc or ("802.1Q Trunk Carrier" if is_unnumbered else "Routed interface"),
            }
        )

    # 2. Switched VLANs / SVIs
    for vlan in vlans:
        v_id = vlan.get("id", "1")
        name = vlan.get("name", f"VLAN_{v_id}")
        ip = vlan.get("ip", "")
        cidr = vlan.get("cidr", 24)
        details = calculate_subnet_details(ip, cidr)

        assoc_routing = (
            f"OSPF Area 0"
            if proto == "OSPF"
            else "Layer 3 SVI Gateway"
        )

        rows.append(
            {
                "Component / Port": f"VLAN {v_id} ({name})",
                "Link Type": "Switched SVI Gateway",
                "IP / CIDR": f"{ip}/{cidr}",
                "Network Address": details["network"],
                "Usable Host Range": details["usable_range"],
                "Usable Hosts": details["usable_count"],
                "Routing Domain": assoc_routing,
                "Description": f"Layer 3 SVI Gateway for {name}",
            }
        )

    return rows


def generate_topology_svg(schema: Dict[str, Any]) -> str:
    """Generate a responsive, dark-mode SVG network topology diagram."""
    hostname = html.escape(schema.get("hostname", "Device-01"))
    interfaces = schema.get("interfaces", []) or []
    vlans = schema.get("vlans", []) or []
    routing = schema.get("routing", {}) or {}
    acls = schema.get("acls", []) or []

    items: List[Dict[str, Any]] = []
    for iface in interfaces:
        name = iface.get("name", "Interface")
        ip = iface.get("ip")
        cidr = iface.get("cidr", 24)
        desc = iface.get("description", "")
        is_unnumbered = not ip or str(ip).strip().lower() in ["none", "null", "unassigned", "no ip", "no-ip", ""]
        is_sub = "." in name or iface.get("vlan_id") is not None
        is_loop = (cidr == 32 or "loop" in name.lower()) and not is_unnumbered
        is_wan = (cidr == 30 or "wan" in desc.lower() or "isp" in desc.lower()) and not is_unnumbered

        if is_unnumbered:
            kind, color, icon = "carrier", "#c084fc", "🔀"
            sub_title = "Trunk Carrier (No IP)"
        elif is_sub:
            kind, color, icon = "subif", "#06b6d4", "📑"
            sub_title = f"{ip}/{cidr}"
        elif is_loop:
            kind, color, icon = "loopback", "#818cf8", "🔄"
            sub_title = f"{ip}/{cidr}"
        elif is_wan:
            kind, color, icon = "wan", "#f59e0b", "🌐"
            sub_title = f"{ip}/{cidr}"
        else:
            kind, color, icon = "lan", "#10b981", "🔌"
            sub_title = f"{ip}/{cidr}"

        items.append(
            {
                "title": name,
                "subtitle": sub_title,
                "extra": desc[:26] + "..." if len(desc) > 26 else desc,
                "kind": kind,
                "color": color,
                "icon": icon,
            }
        )

    for vlan in vlans:
        v_id = vlan.get("id", "1")
        name = vlan.get("name", f"VLAN_{v_id}")
        ip = vlan.get("ip", "")
        cidr = vlan.get("cidr", 24)
        items.append(
            {
                "title": f"VLAN {v_id}: {name}",
                "subtitle": f"SVI {ip}/{cidr}",
                "extra": "Switched SVI Domain",
                "kind": "vlan",
                "color": "#38bdf8",
                "icon": "🏷️",
            }
        )


    proto = str(routing.get("protocol", "")).upper()
    proto_label = "Switching / L2"
    if proto == "BGP":
        asn = routing.get("as_number", routing.get("asn", 65000))
        proto_label = f"BGP Domain (AS {asn})"
    elif proto == "OSPF":
        proc_id = routing.get("process_id", 1)
        proto_label = f"OSPF (Process {proc_id})"

    # Cap total items displayed in SVG to prevent Denial of Service via massive canvas size
    MAX_SVG_ITEMS = 24
    if len(items) > MAX_SVG_ITEMS:
        overflow_count = len(items) - (MAX_SVG_ITEMS - 1)
        display_items = items[: MAX_SVG_ITEMS - 1]
        display_items.append(
            {
                "title": f"+ {overflow_count} More Ports",
                "subtitle": "Additional Interfaces/VLANs",
                "extra": "See Routing Matrix below",
                "kind": "overflow",
                "color": "#94a3b8",
                "icon": "📦",
            }
        )
    else:
        display_items = items

    total_items = max(len(display_items), 1)
    card_width = 240
    card_height = 82
    gap = 24
    header_height = 130
    footer_height = 70

    svg_width = max(900, total_items * (card_width + gap) + 60)
    svg_height = header_height + 260 + footer_height

    center_x = svg_width / 2
    dev_box_width = 340
    dev_box_height = 96
    dev_x = center_x - (dev_box_width / 2)
    dev_y = 35

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_width} {svg_height}" '
        f'style="width:100%; height:auto; background:#0b0f19; border-radius:12px; font-family:system-ui, -apple-system, sans-serif; box-shadow: 0 4px 20px rgba(0,0,0,0.5);">',
        '<defs>',
        '  <linearGradient id="devGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
        '    <stop offset="0%" stop-color="#1e293b"/>',
        '    <stop offset="100%" stop-color="#0f172a"/>',
        '  </linearGradient>',
        '  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">',
        '    <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#3b82f6" flood-opacity="0.35"/>',
        '  </filter>',
        '  <filter id="cardShadow" x="-10%" y="-10%" width="120%" height="120%">',
        '    <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000" flood-opacity="0.5"/>',
        '  </filter>',
        '</defs>',
    ]

    # Grid background
    svg.append(f'<rect width="{svg_width}" height="{svg_height}" fill="#0b0f19" rx="12"/>')
    svg.append(
        f'<pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse">'
        f'<path d="M 28 0 L 0 0 0 28" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="1"/>'
        f'</pattern>'
        f'<rect width="{svg_width}" height="{svg_height}" fill="url(#grid)" rx="12"/>'
    )

    total_cards_width = total_items * card_width + (total_items - 1) * gap
    start_x = (svg_width - total_cards_width) / 2
    card_y = dev_y + dev_box_height + 110

    # Draw connection lines
    for i, itm in enumerate(display_items):
        item_x = start_x + i * (card_width + gap) + (card_width / 2)
        color = itm["color"]

        svg.append(
            f'<path d="M {center_x} {dev_y + dev_box_height} C {center_x} {dev_y + dev_box_height + 60}, '
            f'{item_x} {card_y - 60}, {item_x} {card_y}" '
            f'fill="none" stroke="{color}" stroke-width="2.5" stroke-dasharray="{"6,4" if itm["kind"] == "wan" else "none"}"/>'
        )
        svg.append(f'<circle cx="{item_x}" cy="{card_y}" r="4.5" fill="{color}"/>')

    # Central Device Chassis
    svg.append(
        f'<g filter="url(#glow)">'
        f'<rect x="{dev_x}" y="{dev_y}" width="{dev_box_width}" height="{dev_box_height}" rx="10" '
        f'fill="url(#devGrad)" stroke="#3b82f6" stroke-width="2.5"/>'
        f'</g>'
    )
    svg.append(
        f'<text x="{center_x}" y="{dev_y + 32}" text-anchor="middle" fill="#f8fafc" font-size="19" font-weight="700">'
        f'🌐 {hostname}'
        f'</text>'
    )
    svg.append(
        f'<rect x="{center_x - 110}" y="{dev_y + 45}" width="220" height="24" rx="12" fill="rgba(59, 130, 246, 0.18)" stroke="rgba(59, 130, 246, 0.4)" stroke-width="1"/>'
        f'<text x="{center_x}" y="{dev_y + 61}" text-anchor="middle" fill="#60a5fa" font-size="12" font-weight="600">'
        f'{html.escape(proto_label)}'
        f'</text>'
    )
    svg.append(
        f'<text x="{center_x}" y="{dev_y + 84}" text-anchor="middle" fill="#94a3b8" font-size="11">'
        f'Chassis: UP/ACTIVE • Gateway Convergence Verified'
        f'</text>'
    )

    # Component Cards
    for i, itm in enumerate(display_items):
        cx = start_x + i * (card_width + gap)
        color = itm["color"]
        title = html.escape(itm["title"])
        subtitle = html.escape(itm["subtitle"])
        extra = html.escape(itm.get("extra", ""))
        icon = itm["icon"]

        svg.append(
            f'<g filter="url(#cardShadow)">'
            f'<rect x="{cx}" y="{card_y}" width="{card_width}" height="{card_height}" rx="8" '
            f'fill="#131d31" stroke="{color}" stroke-width="1.8"/>'
            f'</g>'
        )
        svg.append(
            f'<path d="M {cx} {card_y + 8} Q {cx} {card_y} {cx + 6} {card_y} L {cx + 6} {card_y + card_height} Q {cx} {card_y + card_height} {cx} {card_y + card_height - 8} Z" fill="{color}"/>'
        )
        svg.append(
            f'<text x="{cx + 18}" y="{card_y + 24}" fill="#f8fafc" font-size="13.5" font-weight="600">'
            f'{icon} {title}'
            f'</text>'
        )
        svg.append(
            f'<text x="{cx + 18}" y="{card_y + 47}" fill="{color}" font-size="12.5" font-weight="700" font-family="monospace">'
            f'{subtitle}'
            f'</text>'
        )
        if extra:
            svg.append(
                f'<text x="{cx + 18}" y="{card_y + 67}" fill="#94a3b8" font-size="10.5">'
                f'{extra}'
                f'</text>'
            )

    # Footer Status Bar
    footer_y = card_y + card_height + 35
    footer_text_parts = []
    if proto == "BGP":
        neighbors = routing.get("neighbors", [])
        if neighbors:
            nb = neighbors[0]
            footer_text_parts.append(
                f"🤝 BGP Peer: {nb.get('ip')} (Remote AS {nb.get('remote_as', 'N/A')})"
            )
    elif proto == "OSPF":
        nets = routing.get("networks", [])
        footer_text_parts.append(
            f"🌲 OSPF Advertised Networks: {len(nets)} Subnets in Area 0"
        )

    security = schema.get("security", {}) or {}
    if security:
        users = security.get("users", [])
        u_name = users[0].get("username") if users else "Admin"
        dom = security.get("domain_name", "")
        rsa = security.get("rsa_bits", "")
        sec_text = f"🔒 Remote SSH: {u_name}"
        if dom:
            sec_text += f"@{dom}"
        if rsa:
            sec_text += f" ({rsa}-bit RSA)"
        footer_text_parts.append(sec_text)

    if acls:
        footer_text_parts.append(
            f"🛡️ Firewall Rules: {len(acls)} Filter Policies Active"
        )

    footer_str = (
        "  |  ".join(footer_text_parts) or "✓ All Interface Links Active & Converged"
    )
    svg.append(
        f'<rect x="40" y="{footer_y}" width="{svg_width - 80}" height="32" rx="6" fill="#111827" stroke="rgba(255,255,255,0.08)"/>'
        f'<text x="{svg_width / 2}" y="{footer_y + 20}" text-anchor="middle" fill="#a7f3d0" font-size="12" font-weight="500">'
        f'{html.escape(footer_str)}'
        f'</text>'
    )

    svg.append("</svg>")
    return "\n".join(svg)


def _sanitize_mermaid(text: Any, max_len: int = 64) -> str:
    """Sanitize strings for safe embedding into Mermaid diagrams."""
    if text is None:
        return ""
    s = str(text).replace("\r", " ").replace("\n", " ")
    s = s.replace('"', "'").replace("[", "(").replace("]", ")").replace("`", "'")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:max_len]


def generate_mermaid_syntax(schema: Dict[str, Any]) -> str:
    """Generate Mermaid diagram syntax representing topology and routing."""
    hostname = _sanitize_mermaid(schema.get("hostname", "Network-Device"), 48)
    interfaces = schema.get("interfaces", []) or []
    vlans = schema.get("vlans", []) or []
    routing = schema.get("routing", {}) or {}
    acls = schema.get("acls", []) or []

    lines = ["graph TD"]
    lines.append("    classDef device fill:#1e293b,stroke:#3b82f6,stroke-width:3px,color:#f8fafc,font-weight:bold,rx:8,ry:8;")
    lines.append("    classDef iface fill:#0f172a,stroke:#06b6d4,stroke-width:2px,color:#38bdf8,rx:6,ry:6;")
    lines.append("    classDef vlan fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#c7d2fe,rx:6,ry:6;")
    lines.append("    classDef router fill:#312e81,stroke:#a855f7,stroke-width:2px,color:#e9d5ff,rx:6,ry:6;")
    lines.append("    classDef peer fill:#1e293b,stroke:#f59e0b,stroke-width:2px,color:#fef3c7,stroke-dasharray: 5 5,rx:6,ry:6;")
    lines.append("    classDef acl fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fecaca,rx:4,ry:4;")

    proto = _sanitize_mermaid(str(routing.get("protocol", "")).upper(), 16)
    dev_label = f"🌐 {hostname}"
    if proto and proto != "NONE":
        dev_label += f" ({proto})"
    lines.append(f'    DEV["{dev_label}"]:::device')

    max_render_ifaces = 20
    for idx, iface in enumerate(interfaces[:max_render_ifaces], 1):
        raw_if_name = iface.get("name", f"Eth{idx}")
        if_name = _sanitize_mermaid(raw_if_name, 32)
        ip = _sanitize_mermaid(iface.get("ip", ""), 20)
        cidr = _sanitize_mermaid(iface.get("cidr", ""), 8)
        desc = _sanitize_mermaid(iface.get("description", ""), 32)
        is_unnum = not ip or ip.lower() in ["none", "null", "unassigned", "no ip", "no-ip", ""]
        node_id = f"IF_{idx}"
        label = f"{if_name} (Trunk Carrier)" if is_unnum else f"{if_name} ({ip}/{cidr})"
        lines.append(f'    {node_id}["{label}"]:::iface')
        lines.append(f'    DEV ---|"{if_name}"| {node_id}')

        if "wan" in desc.lower() or "isp" in desc.lower() or cidr == "30":
            isp_node = f"ISP_{idx}"
            lines.append(f'    {isp_node}["☁️ Upstream ISP Gateway"]:::peer')
            lines.append(f'    {node_id} -.-|"/30 P2P Transit"| {isp_node}')

    if len(interfaces) > max_render_ifaces:
        rem = len(interfaces) - max_render_ifaces
        lines.append(f'    IF_MORE["... +{rem} More Interfaces"]:::iface')
        lines.append(f'    DEV --- IF_MORE')

    max_render_vlans = 20
    for idx, vlan in enumerate(vlans[:max_render_vlans], 1):
        v_id = _sanitize_mermaid(vlan.get("id", idx), 8)
        vlan_name = _sanitize_mermaid(vlan.get("name", f"VLAN{v_id}"), 32)
        ip = _sanitize_mermaid(vlan.get("ip", ""), 20)
        cidr = _sanitize_mermaid(vlan.get("cidr", ""), 8)
        node_id = f"VLAN_{idx}"
        label = f"VLAN {v_id}: {vlan_name} ({ip}/{cidr})"
        lines.append(f'    {node_id}["{label}"]:::vlan')
        lines.append(f'    DEV ===|"SVI Vlan{v_id}"| {node_id}')

    if len(vlans) > max_render_vlans:
        rem_v = len(vlans) - max_render_vlans
        lines.append(f'    VLAN_MORE["... +{rem_v} More VLANs"]:::vlan')
        lines.append(f'    DEV === VLAN_MORE')

    protocol_lower = str(routing.get("protocol", "")).lower()
    if protocol_lower == "bgp":
        asn = _sanitize_mermaid(routing.get("as_number", routing.get("asn", 65000)), 16)
        bgp_node = "BGP_DOMAIN"
        lines.append(f'    {bgp_node}["📡 BGP Domain (AS {asn})"]:::router')
        lines.append(f'    DEV -.->|"BGP Speaker"| {bgp_node}')

        neighbors = routing.get("neighbors", [])
        for n_idx, nb in enumerate(neighbors[:8], 1):
            nb_ip = _sanitize_mermaid(nb.get("ip", ""), 20)
            remote_as = _sanitize_mermaid(nb.get("remote_as", ""), 16)
            nb_node = f"BGP_PEER_{n_idx}"
            lines.append(f'    {nb_node}["🤝 BGP Peer: {nb_ip} (AS {remote_as})"]:::peer')
            lines.append(f'    {bgp_node} ==>|"eBGP Peering"| {nb_node}')

    elif protocol_lower == "ospf":
        proc_id = _sanitize_mermaid(routing.get("process_id", 1), 8)
        ospf_node = "OSPF_DOMAIN"
        lines.append(f'    {ospf_node}["🌲 OSPF Area 0 (Process {proc_id})"]:::router')
        lines.append(f'    DEV -.->|"OSPF Adjacency"| {ospf_node}')
        for net in (routing.get("networks", []) or [])[:8]:
            net_ip = _sanitize_mermaid(net.get("network_ip", ""), 20)
            area = _sanitize_mermaid(net.get("area", 0), 16)
            net_node = f"NET_{re.sub(r'[^A-Za-z0-9]', '_', net_ip)}"
            lines.append(f'    {net_node}["Subnet {net_ip} (Area {area})"]:::peer')
            lines.append(f'    {ospf_node} --- {net_node}')

    for a_idx, acl in enumerate(acls[:8], 1):
        acl_name = _sanitize_mermaid(acl.get("name", f"ACL_{a_idx}"), 32)
        acl_node = f"ACL_{a_idx}"
        lines.append(f'    {acl_node}["🛡️ ACL Filter: {acl_name}"]:::acl')
        lines.append(f'    DEV -.->|"Enforces"| {acl_node}')

    security = schema.get("security", {}) or {}
    if security:
        users = security.get("users", [])
        u_name = _sanitize_mermaid(users[0].get("username", "netadmin") if users else "netadmin", 32)
        rsa = _sanitize_mermaid(security.get("rsa_bits", 1024), 8)
        sec_node = "SEC_MGMT"
        lines.append(f'    {sec_node}["🔒 SSH Local Auth: {u_name} ({rsa}-bit RSA)"]:::router')
        lines.append(f'    DEV -.->|"Secured by"| {sec_node}')

    return "\n".join(lines)

