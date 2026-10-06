"""Network Configuration Validator Module.

Uses Python's built-in ipaddress library to validate network schemas extracted
from natural language prompts, including IP formats, subnet masks, wildcard masks,
and cross-VLAN subnet overlap detection.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Tuple


def _is_valid_netmask(mask_str: str) -> Tuple[bool, int | None]:
    """Check if mask_str is a valid dotted-decimal IPv4 subnet mask.

    Returns (is_valid, prefix_length).
    """
    try:
        mask_ip = ipaddress.IPv4Address(mask_str.strip())
        mask_int = int(mask_ip)

        # A valid netmask has contiguous 1s followed by contiguous 0s
        # When inverted and +1, it must be a power of 2 (or 0 for 255.255.255.255)
        if mask_int == 0:
            return True, 0

        inverted = (~mask_int) & 0xFFFFFFFF
        if (inverted & (inverted + 1)) == 0:
            prefix_len = bin(mask_int).count("1")
            return True, prefix_len
        return False, None
    except Exception:
        return False, None


def _is_valid_wildcard(wildcard_str: str) -> Tuple[bool, str | None]:
    """Check if wildcard_str is a valid IPv4 wildcard mask (inverse of subnet mask).

    Returns (is_valid, equivalent_netmask_str).
    """
    try:
        octets = [int(o) for o in wildcard_str.strip().split(".")]
        if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
            return False, None

        # Standard wildcard is inverted subnet mask
        inverted_octets = [255 - o for o in octets]
        netmask_str = ".".join(str(o) for o in inverted_octets)
        valid_netmask, _ = _is_valid_netmask(netmask_str)
        if valid_netmask:
            return True, netmask_str
        return False, None
    except Exception:
        return False, None


def _is_safe_single_line_str(
    val: Any,
    field_name: str,
    max_len: int = 128,
    pattern: str | None = None,
) -> Tuple[bool, str]:
    """Check that val is a string without newlines, control characters, or excessive length.

    Prevents multi-line CLI command injection and buffer exhaustion.
    """
    if not isinstance(val, str):
        return False, f"{field_name} must be a string."
    if len(val) > max_len:
        return False, f"{field_name} exceeds maximum length of {max_len} characters."
    if any(c in val for c in ("\r", "\n", "\0")):
        return False, f"{field_name} contains prohibited newline or null characters (CLI injection risk)."
    if any(ord(c) < 32 or ord(c) == 127 for c in val):
        return False, f"{field_name} contains prohibited control characters."
    if pattern and not re.match(pattern, val):
        return False, f"{field_name} '{val}' contains invalid characters or does not match format."
    return True, ""


def validate_network_schema(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate parsed JSON network configuration schema.

    Checks:
    - Hostname format
    - VLAN IDs (range 1-4094, uniqueness)
    - IP addresses and subnet masks
    - CIDR prefix consistency with subnet mask
    - Subnet overlaps across VLANs/interfaces
    - OSPF routing configuration (process-id, network IPs, wildcard masks, areas)
    - ACL rules (if defined)

    Returns:
        dict: {"valid": bool, "errors": list[str]}
    """
    errors: List[str] = []

    if not isinstance(data, dict):
        return {"valid": False, "errors": ["Root schema must be a valid JSON object."]}

    # 1. Validate Hostname
    hostname = data.get("hostname")
    if not hostname or not isinstance(hostname, str) or not hostname.strip():
        errors.append("Invalid or missing 'hostname'. Must be a non-empty string.")
    else:
        clean_hostname = hostname.strip()
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,62}$", clean_hostname):
            errors.append(
                f"Hostname '{clean_hostname}' is invalid. Must start with alphanumeric, "
                "contain only alphanumeric, hyphens or underscores, and be <= 63 characters."
            )

    # 2. Validate Routed Interfaces and VLANs
    interfaces = data.get("interfaces", [])
    vlans = data.get("vlans", [])

    has_interfaces = isinstance(interfaces, list) and len(interfaces) > 0
    has_vlans = isinstance(vlans, list) and len(vlans) > 0

    if not has_interfaces and not has_vlans:
        errors.append(
            "At least one routed interface in 'interfaces' or VLAN definition in 'vlans' is required."
        )

    parsed_networks: List[Tuple[ipaddress.IPv4Network, str, Dict[str, Any]]] = []

    # 2a. Validate Routed Interfaces
    if has_interfaces:
        if len(interfaces) > 64:
            errors.append(f"Maximum number of interfaces (64) exceeded: received {len(interfaces)}.")

        seen_if_names: set[str] = set()
        for idx, iface in enumerate(interfaces, start=1):
            if not isinstance(iface, dict):
                errors.append(f"Interface item #{idx} must be a dictionary.")
                continue

            if_name = iface.get("name")
            ip_str = iface.get("ip")
            subnet_mask = iface.get("subnet_mask")
            cidr_raw = iface.get("cidr")

            # Validate Interface Name
            if not if_name or not isinstance(if_name, str) or not if_name.strip():
                errors.append(f"Interface #{idx}: Name must be a non-empty string.")
            else:
                ok, msg = _is_safe_single_line_str(
                    if_name.strip(),
                    f"Interface #{idx} name",
                    max_len=64,
                    pattern=r"^[A-Za-z0-9][A-Za-z0-9/_.:-]{0,63}$",
                )
                if not ok:
                    errors.append(msg)
                else:
                    norm_if_name = if_name.strip().lower()
                    if norm_if_name in seen_if_names:
                        errors.append(f"Interface #{idx}: Duplicate interface name '{if_name}'.")
                    else:
                        seen_if_names.add(norm_if_name)

            # Validate optional description
            desc = iface.get("description")
            if desc is not None:
                ok, msg = _is_safe_single_line_str(
                    desc, f"Interface '{if_name or idx}' description", max_len=128
                )
                if not ok:
                    errors.append(msg)

            # Validate optional encapsulation
            encap = iface.get("encapsulation")
            if encap is not None:
                ok, msg = _is_safe_single_line_str(
                    str(encap), f"Interface '{if_name or idx}' encapsulation", max_len=64
                )
                if not ok:
                    errors.append(msg)

            # Check if interface is an unnumbered or physical trunk carrier port (no IP assigned)
            is_unnumbered = (
                ip_str is None
                or str(ip_str).strip().lower() in ["none", "null", "unassigned", "no ip", "no-ip", ""]
            )

            # Validate optional 802.1Q VLAN ID / Encapsulation
            vlan_id_raw = iface.get("vlan_id")
            if vlan_id_raw is not None:
                try:
                    vid = int(vlan_id_raw)
                    if vid < 1 or vid > 4094:
                        errors.append(
                            f"Interface '{if_name or idx}': VLAN ID '{vid}' out of valid range (1-4094)."
                        )
                except (ValueError, TypeError):
                    errors.append(
                        f"Interface '{if_name or idx}': Invalid VLAN ID '{vlan_id_raw}'."
                    )

            if is_unnumbered:
                # Unnumbered physical parent interface (e.g. GigabitEthernet0/0/0 in Router-on-a-Stick)
                # Does not require IP or subnet mask. Subinterfaces or other ports handle routing.
                continue

            # Validate CIDR
            cidr_int: int | None = None
            if cidr_raw is not None:
                try:
                    c_str = str(cidr_raw).strip().lstrip("/")
                    cidr_int = int(c_str)
                    if cidr_int < 0 or cidr_int > 32:
                        errors.append(
                            f"Interface '{if_name or idx}': CIDR /{cidr_int} out of range (0-32)."
                        )
                        cidr_int = None
                except ValueError:
                    errors.append(
                        f"Interface '{if_name or idx}': Invalid CIDR prefix '{cidr_raw}'."
                    )

            # Validate Subnet Mask
            mask_prefix: int | None = None
            if subnet_mask:
                valid_mask, mask_prefix = _is_valid_netmask(str(subnet_mask))
                if not valid_mask:
                    errors.append(
                        f"Interface '{if_name or idx}': Invalid subnet mask '{subnet_mask}'."
                    )
            else:
                errors.append(
                    f"Interface '{if_name or idx}': Missing 'subnet_mask'."
                )

            # Check CIDR vs Subnet Mask consistency
            if cidr_int is not None and mask_prefix is not None:
                if cidr_int != mask_prefix:
                    errors.append(
                        f"Interface '{if_name or idx}': Subnet mask '{subnet_mask}' "
                        f"(/ {mask_prefix}) does not match CIDR prefix /{cidr_int}."
                    )

            # Validate IP Address
            effective_prefix = cidr_int if cidr_int is not None else mask_prefix
            if not ip_str or not isinstance(ip_str, str):
                errors.append(
                    f"Interface '{if_name or idx}': Missing or invalid 'ip' address."
                )
            else:
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str.strip())
                    if ip_obj.is_multicast:
                        errors.append(
                            f"Interface '{if_name or idx}': IP '{ip_str}' is a multicast address."
                        )

                    # Build network and check host address usability
                    if effective_prefix is not None:
                        try:
                            network_obj = ipaddress.IPv4Network(
                                f"{ip_str.strip()}/{effective_prefix}", strict=False
                            )
                            # For standard subnets <= 30, cannot be network or broadcast IP
                            if effective_prefix <= 30:
                                if ip_obj == network_obj.network_address:
                                    errors.append(
                                        f"Interface '{if_name or idx}': IP '{ip_str}' is the network address for subnet {network_obj}."
                                    )
                                elif ip_obj == network_obj.broadcast_address:
                                    errors.append(
                                        f"Interface '{if_name or idx}': IP '{ip_str}' is the broadcast address for subnet {network_obj}."
                                    )

                            parsed_networks.append((network_obj, f"Interface '{if_name or idx}'", iface))
                        except Exception as net_err:
                            errors.append(
                                f"Interface '{if_name or idx}': Could not construct network: {net_err}"
                            )

                except ipaddress.AddressValueError:
                    errors.append(
                        f"Interface '{if_name or idx}': Invalid IPv4 address '{ip_str}'."
                    )

    # 2b. Validate VLANs
    if has_vlans:
        if len(vlans) > 64:
            errors.append(f"Maximum number of VLANs (64) exceeded: received {len(vlans)}.")

        seen_vlan_ids: set[int] = set()
        seen_vlan_names: set[str] = set()

        for idx, vlan in enumerate(vlans, start=1):
            if not isinstance(vlan, dict):
                errors.append(f"VLAN item #{idx} must be a dictionary.")
                continue

            vlan_id_raw = vlan.get("id")
            vlan_name = vlan.get("name")
            ip_str = vlan.get("ip")
            subnet_mask = vlan.get("subnet_mask")
            cidr_raw = vlan.get("cidr")

            # Validate VLAN ID
            try:
                vlan_id = int(vlan_id_raw)
                if vlan_id < 1 or vlan_id > 4094:
                    errors.append(
                        f"VLAN #{idx}: ID '{vlan_id_raw}' out of valid range (1-4094)."
                    )
                elif vlan_id in seen_vlan_ids:
                    errors.append(f"VLAN #{idx}: Duplicate VLAN ID '{vlan_id}'.")
                else:
                    seen_vlan_ids.add(vlan_id)
            except (ValueError, TypeError):
                errors.append(
                    f"VLAN #{idx}: ID '{vlan_id_raw}' must be an integer between 1 and 4094."
                )
                vlan_id = None

            # Validate VLAN Name
            if not vlan_name or not isinstance(vlan_name, str) or not vlan_name.strip():
                errors.append(f"VLAN #{idx}: Name must be a non-empty string.")
            else:
                ok, msg = _is_safe_single_line_str(
                    vlan_name.strip(),
                    f"VLAN #{idx} name",
                    max_len=64,
                    pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-\. ]{0,63}$",
                )
                if not ok:
                    errors.append(msg)
                else:
                    norm_name = vlan_name.strip().lower()
                    if norm_name in seen_vlan_names:
                        errors.append(f"VLAN #{idx}: Duplicate VLAN name '{vlan_name}'.")
                    else:
                        seen_vlan_names.add(norm_name)

            # Validate CIDR
            cidr_int: int | None = None
            if cidr_raw is not None:
                try:
                    c_str = str(cidr_raw).strip().lstrip("/")
                    cidr_int = int(c_str)
                    if cidr_int < 0 or cidr_int > 32:
                        errors.append(
                            f"VLAN #{idx} ({vlan_name or 'unnamed'}): CIDR /{cidr_int} out of range (0-32)."
                        )
                        cidr_int = None
                except ValueError:
                    errors.append(
                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): Invalid CIDR prefix '{cidr_raw}'."
                    )

            # Validate Subnet Mask
            mask_prefix: int | None = None
            if subnet_mask:
                valid_mask, mask_prefix = _is_valid_netmask(str(subnet_mask))
                if not valid_mask:
                    errors.append(
                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): Invalid subnet mask '{subnet_mask}'."
                    )
            else:
                errors.append(
                    f"VLAN #{idx} ({vlan_name or 'unnamed'}): Missing 'subnet_mask'."
                )

            # Check CIDR vs Subnet Mask consistency
            if cidr_int is not None and mask_prefix is not None:
                if cidr_int != mask_prefix:
                    errors.append(
                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): Subnet mask '{subnet_mask}' "
                        f"(/ {mask_prefix}) does not match CIDR prefix /{cidr_int}."
                    )

            # Validate IP Address
            effective_prefix = cidr_int if cidr_int is not None else mask_prefix
            if not ip_str or not isinstance(ip_str, str):
                errors.append(
                    f"VLAN #{idx} ({vlan_name or 'unnamed'}): Missing or invalid 'ip' address."
                )
            else:
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str.strip())

                    # Check multicast, loopback, or unspecified
                    if ip_obj.is_multicast:
                        errors.append(
                            f"VLAN #{idx} ({vlan_name or 'unnamed'}): IP '{ip_str}' is a multicast address, not valid for an interface."
                        )
                    if ip_obj.is_loopback:
                        errors.append(
                            f"VLAN #{idx} ({vlan_name or 'unnamed'}): IP '{ip_str}' is a loopback address."
                        )

                    # Build network and check host address usability
                    if effective_prefix is not None:
                        try:
                            network_obj = ipaddress.IPv4Network(
                                f"{ip_str.strip()}/{effective_prefix}", strict=False
                            )
                            # For subnets <= 30, cannot be network or broadcast IP
                            if effective_prefix <= 30:
                                if ip_obj == network_obj.network_address:
                                    errors.append(
                                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): IP '{ip_str}' is the network address for subnet {network_obj}."
                                    )
                                elif ip_obj == network_obj.broadcast_address:
                                    errors.append(
                                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): IP '{ip_str}' is the broadcast address for subnet {network_obj}."
                                    )

                            parsed_networks.append((network_obj, f"VLAN {vlan_id} ('{vlan_name}')", vlan))
                        except Exception as net_err:
                            errors.append(
                                f"VLAN #{idx} ({vlan_name or 'unnamed'}): Could not construct network: {net_err}"
                            )

                except ipaddress.AddressValueError:
                    errors.append(
                        f"VLAN #{idx} ({vlan_name or 'unnamed'}): Invalid IPv4 address '{ip_str}'."
                    )

    # Detect Subnet Overlaps across configured VLANs and Interfaces
    for i in range(len(parsed_networks)):
        for j in range(i + 1, len(parsed_networks)):
            net_a, label_a, _obj_a = parsed_networks[i]
            net_b, label_b, _obj_b = parsed_networks[j]
            if net_a.overlaps(net_b):
                errors.append(
                    f"Subnet overlap detected: {label_a} ({net_a}) "
                    f"overlaps with {label_b} ({net_b})."
                )

    # 3. Validate Routing Configuration
    routing = data.get("routing")
    if routing and isinstance(routing, dict):
        protocol = str(routing.get("protocol", "")).strip().lower()
        if protocol and protocol not in ["ospf", "none", "static", "bgp"]:
            errors.append(
                f"Routing protocol '{protocol}' is not supported. Use 'ospf', 'bgp', 'static', or 'none'."
            )

        if protocol == "ospf":
            # Process ID
            proc_id_raw = routing.get("process_id", 1)
            try:
                proc_id = int(proc_id_raw)
                if proc_id < 1 or proc_id > 65535:
                    errors.append(
                        f"OSPF process_id '{proc_id_raw}' must be between 1 and 65535."
                    )
            except (ValueError, TypeError):
                errors.append(
                    f"OSPF process_id '{proc_id_raw}' must be a valid integer."
                )

            # Networks
            networks = routing.get("networks", [])
            if not isinstance(networks, list):
                errors.append("OSPF 'networks' must be a list of network definitions.")
            elif len(networks) > 32:
                errors.append(f"Maximum number of OSPF networks (32) exceeded: received {len(networks)}.")
            else:
                for n_idx, net in enumerate(networks, start=1):
                    if not isinstance(net, dict):
                        errors.append(
                            f"OSPF network #{n_idx} must be a dictionary object."
                        )
                        continue

                    net_ip = net.get("network_ip")
                    wildcard = net.get("wildcard_mask")
                    area = net.get("area")

                    # Validate Network IP
                    if not net_ip or not isinstance(net_ip, str):
                        errors.append(
                            f"OSPF network #{n_idx}: Missing or invalid 'network_ip'."
                        )
                    else:
                        try:
                            ipaddress.IPv4Address(net_ip.strip())
                        except ipaddress.AddressValueError:
                            errors.append(
                                f"OSPF network #{n_idx}: Invalid IPv4 network IP '{net_ip}'."
                            )

                    # Validate Wildcard Mask
                    if not wildcard or not isinstance(wildcard, str):
                        errors.append(
                            f"OSPF network #{n_idx}: Missing or invalid 'wildcard_mask'."
                        )
                    else:
                        valid_wc, _ = _is_valid_wildcard(wildcard)
                        if not valid_wc:
                            errors.append(
                                f"OSPF network #{n_idx}: Invalid wildcard mask '{wildcard}'. "
                                "Must be a standard inverted IPv4 subnet mask (e.g., 0.0.0.255, 0.0.3.255)."
                            )

                    # Validate Area
                    if area is None:
                        errors.append(f"OSPF network #{n_idx}: Missing 'area'.")
                    else:
                        # Area can be integer or dotted decimal
                        area_str = str(area).strip()
                        is_int_area = False
                        try:
                            area_int = int(area_str)
                            if 0 <= area_int <= 4294967295:
                                is_int_area = True
                        except ValueError:
                            pass

                        if not is_int_area:
                            try:
                                ipaddress.IPv4Address(area_str)
                            except ipaddress.AddressValueError:
                                errors.append(
                                    f"OSPF network #{n_idx}: Invalid OSPF area '{area}'. "
                                    "Must be an integer (0-4294967295) or dotted-decimal format (e.g., '0.0.0.0')."
                                )

        elif protocol == "bgp":
            as_num = routing.get("as_number", routing.get("asn"))
            if as_num is not None:
                try:
                    asn_int = int(as_num)
                    if asn_int < 1 or asn_int > 4294967295:
                        errors.append(f"BGP AS number '{as_num}' must be between 1 and 4294967295.")
                except (ValueError, TypeError):
                    errors.append(f"BGP AS number '{as_num}' must be a valid integer.")
            router_id = routing.get("router_id")
            if router_id:
                try:
                    ipaddress.IPv4Address(str(router_id).strip())
                except ipaddress.AddressValueError:
                    errors.append(f"BGP router_id '{router_id}' is not a valid IPv4 address.")
            neighbors = routing.get("neighbors", [])
            if not isinstance(neighbors, list):
                errors.append("BGP 'neighbors' must be a list.")
            elif len(neighbors) > 32:
                errors.append(f"Maximum number of BGP neighbors (32) exceeded: received {len(neighbors)}.")
            else:
                for nb_idx, nb in enumerate(neighbors, start=1):
                    if not isinstance(nb, dict):
                        errors.append(f"BGP neighbor #{nb_idx} must be a dictionary.")
                        continue
                    nb_ip = nb.get("ip")
                    if not nb_ip:
                        errors.append(f"BGP neighbor #{nb_idx}: Missing 'ip'.")
                    else:
                        try:
                            ipaddress.IPv4Address(str(nb_ip).strip())
                        except ipaddress.AddressValueError:
                            errors.append(f"BGP neighbor #{nb_idx}: Invalid IP '{nb_ip}'.")
                    nb_as = nb.get("remote_as")
                    if nb_as is not None:
                        try:
                            nb_as_int = int(nb_as)
                            if nb_as_int < 1 or nb_as_int > 4294967295:
                                errors.append(f"BGP neighbor #{nb_idx}: remote_as '{nb_as}' out of range.")
                        except (ValueError, TypeError):
                            errors.append(f"BGP neighbor #{nb_idx}: remote_as must be an integer.")

                    nb_desc = nb.get("description")
                    if nb_desc is not None:
                        ok, msg = _is_safe_single_line_str(
                            nb_desc, f"BGP neighbor #{nb_idx} description", max_len=128
                        )
                        if not ok:
                            errors.append(msg)

        elif protocol == "static" or routing.get("static_routes"):
            routes = routing.get("static_routes", [])
            if not isinstance(routes, list):
                errors.append("Static routes must be a list.")
            elif len(routes) > 32:
                errors.append(f"Maximum number of static routes (32) exceeded: received {len(routes)}.")
            else:
                for r_idx, route in enumerate(routes, start=1):
                    if not isinstance(route, dict):
                        errors.append(f"Static route #{r_idx} must be a dictionary.")
                        continue
                    nh = route.get("next_hop")
                    if not nh:
                        errors.append(f"Static route #{r_idx}: Missing 'next_hop'.")
                    else:
                        try:
                            ipaddress.IPv4Address(str(nh).strip())
                        except ipaddress.AddressValueError:
                            errors.append(f"Static route #{r_idx}: Invalid next-hop IP '{nh}'.")
                    r_desc = route.get("description")
                    if r_desc is not None:
                        ok, msg = _is_safe_single_line_str(
                            r_desc, f"Static route #{r_idx} description", max_len=128
                        )
                        if not ok:
                            errors.append(msg)

    # 4. Validate Optional ACLs
    acls = data.get("acls")
    if acls is not None:
        if not isinstance(acls, list):
            errors.append("'acls' must be a list of access list configurations.")
        elif len(acls) > 32:
            errors.append(f"Maximum number of ACL configurations (32) exceeded: received {len(acls)}.")
        else:
            for a_idx, acl in enumerate(acls, start=1):
                if not isinstance(acl, dict):
                    errors.append(f"ACL #{a_idx} must be a dictionary object.")
                    continue
                acl_name = acl.get("name")
                if not acl_name:
                    errors.append(f"ACL #{a_idx}: Missing ACL 'name'.")
                else:
                    ok, msg = _is_safe_single_line_str(
                        str(acl_name).strip(),
                        f"ACL #{a_idx} name",
                        max_len=64,
                        pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$",
                    )
                    if not ok:
                        errors.append(msg)

                rules = acl.get("rules", [])
                if not isinstance(rules, list):
                    errors.append(f"ACL #{a_idx}: 'rules' must be a list.")
                elif len(rules) > 64:
                    errors.append(f"ACL #{a_idx}: Maximum allowed rules (64) exceeded.")
                else:
                    for r_idx, rule in enumerate(rules, start=1):
                        if not isinstance(rule, dict):
                            errors.append(
                                f"ACL #{a_idx} Rule #{r_idx} must be a dictionary."
                            )
                            continue
                        action = str(rule.get("action", "")).strip().lower()
                        if action not in ["permit", "deny"]:
                            errors.append(
                                f"ACL #{a_idx} Rule #{r_idx}: Action '{action}' must be 'permit' or 'deny'."
                            )
                        # Validate protocol, source, destination, port strings against CLI injection
                        for field_key in ["protocol", "source", "destination", "port"]:
                            field_val = rule.get(field_key)
                            if field_val is not None:
                                ok, msg = _is_safe_single_line_str(
                                    str(field_val),
                                    f"ACL #{a_idx} Rule #{r_idx} '{field_key}'",
                                    max_len=64,
                                )
                                if not ok:
                                    errors.append(msg)

    # 5. Validate Optional Security & Remote Management (domain_name, users, rsa_bits, ssh)
    security = data.get("security")
    if security is not None:
        if not isinstance(security, dict):
            errors.append("'security' must be a dictionary.")
        else:
            domain_name = security.get("domain_name")
            if domain_name is not None:
                ok, msg = _is_safe_single_line_str(
                    domain_name,
                    "Security 'domain_name'",
                    max_len=128,
                    pattern=r"^[A-Za-z0-9][A-Za-z0-9\.\-]{0,127}$",
                )
                if not ok:
                    errors.append(msg)

            rsa_bits = security.get("rsa_bits")
            if rsa_bits is not None:
                try:
                    bits = int(rsa_bits)
                    if bits not in [512, 768, 1024, 2048, 4096]:
                        errors.append(
                            f"Security 'rsa_bits' ({bits}) is non-standard (recommended: 1024, 2048, 4096)."
                        )
                except (ValueError, TypeError):
                    errors.append("Security 'rsa_bits' must be an integer.")

            users = security.get("users")
            if users is not None:
                if not isinstance(users, list):
                    errors.append("Security 'users' must be a list.")
                elif len(users) > 16:
                    errors.append(f"Maximum number of security users (16) exceeded: received {len(users)}.")
                else:
                    for u_idx, u in enumerate(users, start=1):
                        if not isinstance(u, dict):
                            errors.append(f"Security user #{u_idx} must be a dictionary.")
                        elif not u.get("username"):
                            errors.append(f"Security user #{u_idx}: Missing 'username'.")
                        else:
                            ok, msg = _is_safe_single_line_str(
                                str(u["username"]),
                                f"Security user #{u_idx} 'username'",
                                max_len=64,
                                pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,63}$",
                            )
                            if not ok:
                                errors.append(msg)

                            secret = u.get("secret") or u.get("password")
                            if secret is not None:
                                ok, msg = _is_safe_single_line_str(
                                    str(secret),
                                    f"Security user #{u_idx} secret",
                                    max_len=128,
                                )
                                if not ok:
                                    errors.append(msg)

                            priv = u.get("privilege")
                            if priv is not None:
                                try:
                                    priv_int = int(priv)
                                    if priv_int < 0 or priv_int > 15:
                                        errors.append(f"Security user #{u_idx} privilege '{priv}' must be 0-15.")
                                except (ValueError, TypeError):
                                    errors.append(f"Security user #{u_idx} privilege must be an integer.")

            ssh = security.get("ssh")
            if ssh is not None:
                if not isinstance(ssh, dict):
                    errors.append("Security 'ssh' configuration must be a dictionary.")
                else:
                    vty = ssh.get("vty_lines")
                    if vty is not None:
                        ok, msg = _is_safe_single_line_str(
                            str(vty),
                            "Security SSH 'vty_lines'",
                            max_len=32,
                            pattern=r"^[0-9 ]+$",
                        )
                        if not ok:
                            errors.append(msg)

                    ti = ssh.get("transport_input")
                    if ti is not None:
                        ok, msg = _is_safe_single_line_str(
                            str(ti),
                            "Security SSH 'transport_input'",
                            max_len=32,
                            pattern=r"^[A-Za-z0-9 ]+$",
                        )
                        if not ok:
                            errors.append(msg)

                    login_mode = ssh.get("login")
                    if login_mode is not None:
                        ok, msg = _is_safe_single_line_str(
                            str(login_mode),
                            "Security SSH 'login'",
                            max_len=32,
                            pattern=r"^[A-Za-z0-9 ]+$",
                        )
                        if not ok:
                            errors.append(msg)

    # 6. Ensure at least one routed interface, subinterface, or VLAN has an assigned IP
    if len(parsed_networks) == 0:
        errors.append(
            "At least one interface, subinterface, or VLAN must have an IP address configured."
        )

    return {"valid": len(errors) == 0, "errors": errors}
