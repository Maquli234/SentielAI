"""
SentinelAI Parser Module
=========================
Reads Nmap XML output files and converts them into clean Python
data structures ready for analysis and display.

Extracted data
--------------
• Scan metadata (start time, nmap version, command used)
• Per-host: state, hostnames, MAC address
• Per-port: protocol, port number, state, service name, version, extra info
• OS guesses: name, accuracy
• NSE script output (per-host and per-port)
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger("sentinelai.parser")


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    protocol:    str
    port:        int
    state:       str
    service:     str
    product:     str
    version:     str
    extra_info:  str
    script_output: dict[str, str] = field(default_factory=dict)

    @property
    def version_string(self) -> str:
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p).strip()

    @property
    def display_service(self) -> str:
        """Return service name; fall back to product name."""
        return self.service or self.product or "unknown"


@dataclass
class OSGuess:
    name:     str
    accuracy: int   # percentage, 0-100
    os_family: str = ""
    os_gen:    str = ""


@dataclass
class HostResult:
    address:     str
    hostname:    str
    state:       str
    mac_address: str
    mac_vendor:  str
    ports:       list[PortInfo]      = field(default_factory=list)
    os_guesses:  list[OSGuess]       = field(default_factory=list)
    host_scripts: dict[str, str]     = field(default_factory=dict)

    @property
    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    command:      str
    nmap_version: str
    start_time:   str
    hosts:        list[HostResult] = field(default_factory=list)
    source_file:  Optional[str]    = None


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_xml(xml_path: str | Path) -> ScanResult:
    """
    Parse an Nmap XML file and return a ScanResult.

    Raises
    ------
    FileNotFoundError  – if the XML file does not exist
    ValueError         – if the file is not valid Nmap XML
    """
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"XML file not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML file: {exc}") from exc

    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError("File does not appear to be Nmap XML output.")

    # ── Scan metadata ─────────────────────────────────────────────────────────
    command      = root.attrib.get("args", "")
    nmap_version = root.attrib.get("version", "")
    start_time   = root.attrib.get("startstr", "")

    scan_result = ScanResult(
        command=command,
        nmap_version=nmap_version,
        start_time=start_time,
        source_file=str(xml_path),
    )

    # ── Hosts ─────────────────────────────────────────────────────────────────
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        scan_result.hosts.append(host)

    logger.debug(
        "Parsed %d host(s) from %s", len(scan_result.hosts), xml_path.name
    )
    return scan_result


def _parse_host(host_elem: ET.Element) -> HostResult:
    """Extract all information for a single <host> element."""

    # Address (prefer IPv4; fall back to IPv6, then MAC)
    address     = ""
    mac_address = ""
    mac_vendor  = ""

    for addr_elem in host_elem.findall("address"):
        addr_type = addr_elem.attrib.get("addrtype", "")
        if addr_type in ("ipv4", "ipv6") and not address:
            address = addr_elem.attrib.get("addr", "")
        elif addr_type == "mac":
            mac_address = addr_elem.attrib.get("addr", "")
            mac_vendor  = addr_elem.attrib.get("vendor", "")

    # Hostname (first PTR record, or first hostname entry)
    hostname = ""
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            hostname = hn.attrib.get("name", "")
            break

    # Host state
    state = ""
    status_elem = host_elem.find("status")
    if status_elem is not None:
        state = status_elem.attrib.get("state", "")

    host = HostResult(
        address=address,
        hostname=hostname,
        state=state,
        mac_address=mac_address,
        mac_vendor=mac_vendor,
    )

    # ── Ports ─────────────────────────────────────────────────────────────────
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port_info = _parse_port(port_elem)
            host.ports.append(port_info)

    # ── OS detection ──────────────────────────────────────────────────────────
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match_elem in os_elem.findall("osmatch"):
            accuracy = int(match_elem.attrib.get("accuracy", "0"))
            name     = match_elem.attrib.get("name", "")
            os_family = ""
            os_gen    = ""
            osclass   = match_elem.find("osclass")
            if osclass is not None:
                os_family = osclass.attrib.get("osfamily", "")
                os_gen    = osclass.attrib.get("osgen", "")
            host.os_guesses.append(
                OSGuess(name=name, accuracy=accuracy, os_family=os_family, os_gen=os_gen)
            )
        # Sort best guess first
        host.os_guesses.sort(key=lambda o: o.accuracy, reverse=True)

    # ── Host-level scripts ────────────────────────────────────────────────────
    hostscript_elem = host_elem.find("hostscript")
    if hostscript_elem is not None:
        for script_elem in hostscript_elem.findall("script"):
            script_id     = script_elem.attrib.get("id", "")
            script_output = script_elem.attrib.get("output", "")
            host.host_scripts[script_id] = script_output.strip()

    return host


def _parse_port(port_elem: ET.Element) -> PortInfo:
    """Extract information for a single <port> element."""
    protocol = port_elem.attrib.get("protocol", "tcp")
    port_num  = int(port_elem.attrib.get("portid", "0"))

    # State
    state = ""
    state_elem = port_elem.find("state")
    if state_elem is not None:
        state = state_elem.attrib.get("state", "")

    # Service / version
    service    = ""
    product    = ""
    version    = ""
    extra_info = ""
    svc_elem   = port_elem.find("service")
    if svc_elem is not None:
        service    = svc_elem.attrib.get("name", "")
        product    = svc_elem.attrib.get("product", "")
        version    = svc_elem.attrib.get("version", "")
        extra_info = svc_elem.attrib.get("extrainfo", "")

    # NSE scripts for this port
    script_output: dict[str, str] = {}
    for script_elem in port_elem.findall("script"):
        script_id  = script_elem.attrib.get("id", "")
        script_out = script_elem.attrib.get("output", "")
        script_output[script_id] = script_out.strip()

    return PortInfo(
        protocol=protocol,
        port=port_num,
        state=state,
        service=service,
        product=product,
        version=version,
        extra_info=extra_info,
        script_output=script_output,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utility: parse from raw stdout (nmap -oX -)
# ─────────────────────────────────────────────────────────────────────────────

def parse_xml_string(xml_text: str) -> ScanResult:
    """
    Parse Nmap XML from a string (e.g. piped via -oX -).
    """
    import io
    try:
        tree = ET.parse(io.StringIO(xml_text))
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML string: {exc}") from exc

    root = tree.getroot()

    command      = root.attrib.get("args", "")
    nmap_version = root.attrib.get("version", "")
    start_time   = root.attrib.get("startstr", "")

    scan_result = ScanResult(
        command=command,
        nmap_version=nmap_version,
        start_time=start_time,
    )

    for host_elem in root.findall("host"):
        scan_result.hosts.append(_parse_host(host_elem))

    return scan_result
