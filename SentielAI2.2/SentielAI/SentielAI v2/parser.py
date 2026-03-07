"""
SentinelAI Parser Module
=========================
Converts Nmap XML output into typed Python dataclasses.
No network I/O — pure file/string parsing.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger("sentinelai.parser")


@dataclass
class ScriptResult:
    script_id: str
    output:    str
    elements:  dict[str, str] = field(default_factory=dict)


@dataclass
class PortInfo:
    protocol:      str
    port:          int
    state:         str
    service:       str           # service name (e.g. "http")
    product:       str           # product name (e.g. "Apache httpd")
    version:       str           # version string
    extra_info:    str
    tunnel:        str           # ssl/tls tunnel if present
    scripts:       list[ScriptResult] = field(default_factory=list)

    @property
    def version_string(self) -> str:
        return " ".join(p for p in [self.product, self.version, self.extra_info] if p).strip()

    @property
    def display_service(self) -> str:
        return self.service or self.product or "unknown"

    @property
    def full_label(self) -> str:
        vs = self.version_string
        return f"{self.display_service}{' / ' + vs if vs else ''}"


@dataclass
class OSGuess:
    name:      str
    accuracy:  int
    os_family: str = ""
    os_gen:    str = ""
    os_type:   str = ""


@dataclass
class HostResult:
    address:       str
    hostname:      str
    state:         str
    mac_address:   str
    mac_vendor:    str
    ports:         list[PortInfo]    = field(default_factory=list)
    os_guesses:    list[OSGuess]     = field(default_factory=list)
    host_scripts:  list[ScriptResult]= field(default_factory=list)

    @property
    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def best_os(self) -> Optional[OSGuess]:
        return self.os_guesses[0] if self.os_guesses else None

    @property
    def display_name(self) -> str:
        return self.hostname or self.address


@dataclass
class ScanResult:
    command:      str
    nmap_version: str
    start_time:   str
    elapsed:      str
    hosts:        list[HostResult] = field(default_factory=list)
    source_file:  Optional[str]    = None

    @property
    def all_open_ports(self) -> list[tuple[HostResult, PortInfo]]:
        pairs = []
        for h in self.hosts:
            for p in h.open_ports:
                pairs.append((h, p))
        return pairs


# ─────────────────────────────────────────────────────────────────────────────

def parse_xml(xml_path: str | Path) -> ScanResult:
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"XML not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}") from e

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise ValueError("Not valid Nmap XML output.")

    elapsed = ""
    run_stats = root.find("runstats/finished")
    if run_stats is not None:
        elapsed = run_stats.attrib.get("elapsed", "")

    result = ScanResult(
        command=root.attrib.get("args", ""),
        nmap_version=root.attrib.get("version", ""),
        start_time=root.attrib.get("startstr", ""),
        elapsed=elapsed,
        source_file=str(xml_path),
    )

    for host_elem in root.findall("host"):
        result.hosts.append(_parse_host(host_elem))

    logger.debug("Parsed %d host(s) from %s", len(result.hosts), xml_path.name)
    return result


def parse_xml_string(text: str) -> ScanResult:
    import io
    try:
        tree = ET.parse(io.StringIO(text))
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML string: {e}") from e
    root = tree.getroot()
    result = ScanResult(
        command=root.attrib.get("args", ""),
        nmap_version=root.attrib.get("version", ""),
        start_time=root.attrib.get("startstr", ""),
        elapsed="",
    )
    for host_elem in root.findall("host"):
        result.hosts.append(_parse_host(host_elem))
    return result


def _parse_host(elem: ET.Element) -> HostResult:
    address = mac = mac_vendor = hostname = state = ""

    for addr in elem.findall("address"):
        t = addr.attrib.get("addrtype", "")
        if t in ("ipv4", "ipv6") and not address:
            address = addr.attrib.get("addr", "")
        elif t == "mac":
            mac = addr.attrib.get("addr", "")
            mac_vendor = addr.attrib.get("vendor", "")

    hostnames = elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            hostname = hn.attrib.get("name", "")
            break

    status = elem.find("status")
    if status is not None:
        state = status.attrib.get("state", "")

    host = HostResult(
        address=address, hostname=hostname, state=state,
        mac_address=mac, mac_vendor=mac_vendor,
    )

    ports_elem = elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            host.ports.append(_parse_port(port_elem))

    os_elem = elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            name     = match.attrib.get("name", "")
            accuracy = int(match.attrib.get("accuracy", "0"))
            family = gen = os_type = ""
            cls = match.find("osclass")
            if cls is not None:
                family  = cls.attrib.get("osfamily", "")
                gen     = cls.attrib.get("osgen", "")
                os_type = cls.attrib.get("type", "")
            host.os_guesses.append(OSGuess(name, accuracy, family, gen, os_type))
        host.os_guesses.sort(key=lambda o: o.accuracy, reverse=True)

    hostscript = elem.find("hostscript")
    if hostscript is not None:
        for s in hostscript.findall("script"):
            host.host_scripts.append(_parse_script(s))

    return host


def _parse_port(elem: ET.Element) -> PortInfo:
    protocol = elem.attrib.get("protocol", "tcp")
    port_num = int(elem.attrib.get("portid", "0"))
    state = service = product = version = extra = tunnel = ""

    s = elem.find("state")
    if s is not None:
        state = s.attrib.get("state", "")

    svc = elem.find("service")
    if svc is not None:
        service = svc.attrib.get("name", "")
        product = svc.attrib.get("product", "")
        version = svc.attrib.get("version", "")
        extra   = svc.attrib.get("extrainfo", "")
        tunnel  = svc.attrib.get("tunnel", "")

    scripts = [_parse_script(s) for s in elem.findall("script")]

    return PortInfo(
        protocol=protocol, port=port_num, state=state,
        service=service, product=product, version=version,
        extra_info=extra, tunnel=tunnel, scripts=scripts,
    )


def _parse_script(elem: ET.Element) -> ScriptResult:
    script_id = elem.attrib.get("id", "")
    output    = elem.attrib.get("output", "").strip()
    elements  = {}
    for el in elem.findall("elem"):
        key = el.attrib.get("key", "")
        if key:
            elements[key] = el.text or ""
    return ScriptResult(script_id=script_id, output=output, elements=elements)
