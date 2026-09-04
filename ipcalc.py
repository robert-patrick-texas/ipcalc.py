#!/usr/bin/env python3
"""ipcalc — IPv4 and IPv6 subnet calculator.

Released to the public domain

Produced by Robert Patrick, Sept 3, 2026

A single argument is a host (/32 or /128) or an address in CIDR form.
Two arguments are ADDRESS plus a mask: /CIDR, numeric prefix, dotted
quad netmask, or Cisco ACL wildcard (inverse) mask.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Optional, Union

__version__ = "1.0.0"

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

IPV4_BITS = 32
IPV6_BITS = 128


class CalcError(Exception):
    """Invalid address or mask."""


# ---------------------------------------------------------------------------
# Color
# ---------------------------------------------------------------------------

class Palette:
    def __init__(self, enabled: bool, theme: str) -> None:
        self.enabled = enabled
        self.theme = theme  # "dark" | "light"
        if not enabled:
            self.reset = self.label = self.address = self.mask = ""
            self.wildcard = self.network = self.binary = self.hostbits = ""
            self.error = self.arrow = self.meta = ""
            return
        self.reset = "\033[0m"
        if theme == "light":
            # Darker, higher-contrast colors for bright backgrounds.
            self.label = "\033[38;5;238m"
            self.address = "\033[38;5;25m"      # navy
            self.mask = "\033[38;5;160m"        # red
            self.wildcard = "\033[38;5;94m"     # olive
            self.network = "\033[38;5;28m"      # green
            self.binary = "\033[38;5;24m"       # deep teal
            self.hostbits = "\033[38;5;244m"    # gray
            self.error = "\033[38;5;160m"
            self.arrow = "\033[38;5;238m"
            self.meta = "\033[38;5;96m"         # plum-gray
        else:
            # Tuned for dark terminals (default console theme).
            self.label = "\033[38;5;250m"
            self.address = "\033[38;5;81m"      # sky
            self.mask = "\033[38;5;203m"        # coral
            self.wildcard = "\033[38;5;180m"    # tan
            self.network = "\033[38;5;114m"     # green
            self.binary = "\033[38;5;80m"       # aqua
            self.hostbits = "\033[38;5;240m"    # dim
            self.error = "\033[38;5;203m"
            self.arrow = "\033[38;5;244m"
            self.meta = "\033[38;5;183m"        # soft lilac for class notes


def stdout_is_console() -> bool:
    if not sys.stdout.isatty():
        return False
    term = os.environ.get("TERM", "")
    if not term or term.lower() == "dumb":
        return False
    if os.environ.get("INSIDE_EMACS"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return True


def resolve_color(nocolor: bool, dark: bool, light: bool, force_color: bool) -> Palette:
    if nocolor:
        return Palette(False, "dark")
    theme = "light" if light and not dark else "dark"
    if dark or light or force_color:
        return Palette(True, theme)
    if stdout_is_console():
        return Palette(True, "dark")
    return Palette(False, "dark")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _split_addr_mask(token: str) -> tuple[str, Optional[str]]:
    """Split ADDRESS/MASK. IPv6 uses the last slash only."""
    if token.startswith("["):
        end = token.find("]")
        if end != -1:
            addr = token[1:end]
            rest = token[end + 1 :]
            if rest.startswith("/"):
                return addr, rest[1:]
            if rest == "":
                return addr, None
            raise CalcError(f"invalid address: {token}")
    if token.count(":") >= 2:
        if "/" in token:
            addr, mask = token.rsplit("/", 1)
            return addr, mask
        return token, None
    if "/" in token:
        addr, mask = token.split("/", 1)
        return addr, mask
    return token, None


def parse_ip(text: str) -> IPAddress:
    raw = text.strip()
    if not raw:
        raise CalcError("empty address")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw and ":" in raw:
        raw = raw.split("%", 1)[0]
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise CalcError(f"invalid address: {text}") from exc


def _prefix_from_length(length: int, version: int) -> int:
    max_len = IPV4_BITS if version == 4 else IPV6_BITS
    if length < 0 or length > max_len:
        raise CalcError(
            f"invalid prefix length /{length} for IPv{version} (0–{max_len})"
        )
    return length


def _is_contiguous_ones_then_zeros(value: int, bits: int) -> bool:
    host = ((1 << bits) - 1) ^ value
    return host & (host + 1) == 0


def _is_contiguous_zeros_then_ones(value: int, bits: int) -> bool:
    return _is_contiguous_ones_then_zeros(((1 << bits) - 1) ^ value, bits)


def parse_ipv4_mask_quad(text: str) -> tuple[int, bool]:
    """Return (prefixlen, was_wildcard)."""
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError as exc:
        raise CalcError(f"invalid subnet mask: {text}") from exc
    value = int(addr)
    is_net = _is_contiguous_ones_then_zeros(value, IPV4_BITS)
    is_wild = value != 0 and not (value & 0x80000000) and _is_contiguous_zeros_then_ones(
        value, IPV4_BITS
    )
    if is_wild and not (value == 0xFFFFFFFF and is_net):
        prefix = bin(((~value) & 0xFFFFFFFF)).count("1")
        return prefix, True
    if is_net:
        prefix = bin(value).count("1")
        return prefix, False
    raise CalcError(
        f"invalid subnet mask (not contiguous): {text}"
    )


def parse_ipv6_mask_addr(text: str) -> int:
    try:
        addr = ipaddress.IPv6Address(text)
    except ValueError as exc:
        raise CalcError(f"invalid IPv6 mask: {text}") from exc
    value = int(addr)
    if not _is_contiguous_ones_then_zeros(value, IPV6_BITS):
        raise CalcError(f"invalid IPv6 mask (not contiguous): {text}")
    return bin(value).count("1")


def parse_mask(text: str, version: int) -> tuple[int, bool]:
    """Parse mask as prefix, dotted quad, wildcard, or IPv6 mask address.

    Returns (prefixlen, was_wildcard).
    """
    raw = text.strip()
    if not raw:
        raise CalcError("empty subnet mask")
    if raw.startswith("/"):
        raw = raw[1:].strip()
        if not raw:
            raise CalcError("empty prefix length")
    if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
        return _prefix_from_length(int(raw), version), False
    if version == 4:
        if ":" in raw:
            raise CalcError("IPv6 mask given for an IPv4 address")
        return parse_ipv4_mask_quad(raw)
    if "." in raw and raw.replace(".", "").isdigit():
        raise CalcError("IPv4 mask given for an IPv6 address")
    return parse_ipv6_mask_addr(raw), False


def parse_query(positional: list[str]) -> tuple[IPAddress, int, bool]:
    """Return (address, prefixlen, wildcard_input)."""
    if not positional:
        raise CalcError("no address given")
    if len(positional) > 2:
        raise CalcError("too many arguments; expected ADDRESS [MASK]")

    if len(positional) == 1:
        addr_s, mask_s = _split_addr_mask(positional[0].strip())
        addr = parse_ip(addr_s)
        if mask_s is None or mask_s == "":
            prefix = IPV4_BITS if addr.version == 4 else IPV6_BITS
            return addr, prefix, False
        prefix, wild = parse_mask(mask_s, addr.version)
        return addr, prefix, wild

    addr_s, embedded = _split_addr_mask(positional[0].strip())
    addr = parse_ip(addr_s)
    prefix, wild = parse_mask(positional[1], addr.version)
    return addr, prefix, wild


# ---------------------------------------------------------------------------
# Calculation
# ---------------------------------------------------------------------------

@dataclass
class CalcResult:
    version: int
    address: str
    address_cidr: str
    prefixlen: int
    netmask: Optional[str]
    wildcard: Optional[str]
    network: str
    network_cidr: str
    broadcast: Optional[str]
    hostmin: str
    hostmax: str
    num_addresses: int
    usable_hosts: int
    is_single: bool
    prefix_address: str
    class_name: Optional[str]
    description: str
    reverse_ptr: str
    wildcard_input: bool
    hex_address: str
    hex_netmask: Optional[str]


def _ipv4_class(addr: ipaddress.IPv4Address) -> str:
    first = int(addr) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D"
    return "E"


def _describe(addr: IPAddress, network: IPNetwork) -> str:
    notes: list[str] = []
    if addr.version == 4:
        notes.append(f"Class {_ipv4_class(addr)}")  # type: ignore[arg-type]
        n = int(addr)
        if addr.is_unspecified:
            notes.append("Unspecified")
        elif addr.is_loopback:
            notes.append("Loopback")
        elif addr.is_link_local:
            notes.append("Link-Local")
        elif addr.is_multicast:
            notes.append("Multicast")
        elif (n >> 24) == 100 and ((n >> 16) & 0xC0) == 0x40:
            notes.append("Shared Address Space (RFC 6598 / CGNAT)")
        elif (
            (n >> 24) in (10,)
            or (n >> 20) == 0xAC1
            or (n >> 16) == 0xC0A8
        ):
            notes.append("Private Internet (RFC 1918)")
        elif (n >> 8) in (0xC00002, 0xC63364, 0xCB0071):
            notes.append("Documentation (RFC 5737)")
        elif addr.is_reserved:
            notes.append("Reserved")
        elif addr.is_global:
            notes.append("Public Internet")
    else:
        n = int(addr)
        if addr.is_unspecified:
            notes.append("Unspecified")
        elif addr.is_loopback:
            notes.append("Loopback")
        elif addr.ipv4_mapped is not None:
            notes.append(f"IPv4-mapped ({addr.ipv4_mapped})")
        elif addr.is_link_local:
            notes.append("Link-Local")
        elif addr.is_multicast:
            notes.append("Multicast")
        elif (n >> 121) == 0x7E:
            notes.append("Unique Local (RFC 4193)")
        elif (n >> 96) == 0x20010DB8:
            notes.append("Documentation (RFC 3849)")
        elif addr.is_reserved:
            notes.append("Reserved")
        elif addr.is_global:
            notes.append("Global Unicast")
    return ", ".join(notes)


def calculate(address: IPAddress, prefixlen: int, wildcard_input: bool = False) -> CalcResult:
    bits = IPV4_BITS if address.version == 4 else IPV6_BITS
    if prefixlen < 0 or prefixlen > bits:
        raise CalcError(f"invalid prefix length /{prefixlen}")

    iface = ipaddress.ip_interface(f"{address}/{prefixlen}")
    net = iface.network
    is_single = prefixlen == bits
    hostmask_int = int(net.hostmask)

    if address.version == 4:
        netmask_s = str(net.netmask)
        wildcard_s = str(net.hostmask)
        broadcast_s: Optional[str] = str(net.broadcast_address) if prefixlen < 31 else None
        if prefixlen == 32:
            hostmin = hostmax = str(address)
            usable = 1
        elif prefixlen == 31:
            hostmin = str(net.network_address)
            hostmax = str(net.broadcast_address)
            usable = 2
        else:
            hostmin = str(net.network_address + 1)
            hostmax = str(net.broadcast_address - 1)
            usable = max(int(net.num_addresses) - 2, 0)
        class_name = _ipv4_class(address)  # type: ignore[arg-type]
        hex_mask = f"{int(net.netmask):08x}"
    else:
        netmask_s = None
        wildcard_s = None
        broadcast_s = None
        hostmin = str(net.network_address)
        hostmax = str(ipaddress.IPv6Address(int(net.network_address) | hostmask_int))
        usable = int(net.num_addresses)
        class_name = None
        hex_mask = None

    prefix_addr = str(net.network_address)
    # IPv6 compressed form is the default str() of ipaddress.

    return CalcResult(
        version=address.version,
        address=str(address),
        address_cidr=f"{address}/{prefixlen}",
        prefixlen=prefixlen,
        netmask=netmask_s,
        wildcard=wildcard_s,
        network=prefix_addr,
        network_cidr=f"{prefix_addr}/{prefixlen}",
        broadcast=broadcast_s,
        hostmin=hostmin,
        hostmax=hostmax,
        num_addresses=int(net.num_addresses),
        usable_hosts=usable,
        is_single=is_single,
        prefix_address=prefix_addr,
        class_name=class_name,
        description=_describe(address, net),
        reverse_ptr=address.reverse_pointer,
        wildcard_input=wildcard_input,
        hex_address=address.exploded.replace(":", "") if address.version == 6 else f"{int(address):08x}",
        hex_netmask=hex_mask,
    )


def calculate_from_args(positional: list[str]) -> CalcResult:
    addr, prefix, wild = parse_query(positional)
    return calculate(addr, prefix, wild)


# ---------------------------------------------------------------------------
# Binary rendering
# ---------------------------------------------------------------------------

def _dotted_bits(bits: str, prefixlen: int, group: int) -> tuple[str, str]:
    """Return (plain, with-markers) binary grouped by `group` bits.

    A space marks the network/host boundary. Dots mark group boundaries.
    """
    out: list[str] = []
    for i, bit in enumerate(bits):
        out.append(bit)
        pos = i + 1
        if pos == len(bits):
            break
        at_prefix = pos == prefixlen
        at_group = pos % group == 0
        if at_prefix and at_group:
            out.append(". ")
        elif at_prefix:
            out.append(" ")
        elif at_group:
            out.append(".")
    return "".join(out), "".join(out)


def ipv4_binary(value: int, prefixlen: int) -> str:
    return _dotted_bits(f"{value:032b}", prefixlen, 8)[0]


def ipv6_binary(value: int, prefixlen: int) -> str:
    return _dotted_bits(f"{value:0128b}", prefixlen, 16)[0]


def ipv6_binary_lines(value: int, prefixlen: int) -> list[tuple[str, int]]:
    """Two 64-bit rows of IPv6 binary, each with a prefixlen relative to that row."""
    hi = value >> 64
    lo = value & ((1 << 64) - 1)
    line1 = _dotted_bits(f"{hi:064b}", min(prefixlen, 64), 16)[0]
    rel2 = 0 if prefixlen <= 64 else prefixlen - 64
    line2 = _dotted_bits(f"{lo:064b}", rel2, 16)[0]
    return [(line1, min(prefixlen, 64)), (line2, rel2)]


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _c(p: Palette, color: str, text: str) -> str:
    if not p.enabled or not color:
        return text
    return f"{color}{text}{p.reset}"


def _num_addresses_label(n: int) -> str:
    if n >= 1 << 16 and (n & (n - 1)) == 0:
        exp = n.bit_length() - 1
        return f"{n}  (2^{exp})"
    return f"{n:,}"


def format_report(
    result: CalcResult,
    palette: Palette,
    *,
    binary: bool = False,
) -> str:
    p = palette
    lines: list[str] = []

    def row(label: str, value: str, bits: Optional[str] = None, value_color: str = "", ipv6_val: Optional[int] = None) -> None:
        lab = _c(p, p.label, f"{label:<11}")
        val = _c(p, value_color or p.address, f"{value:<22}" if result.version == 4 else f"{value:<40}")
        if binary and result.version == 6 and ipv6_val is not None:
            lines.append(f"{lab}{val.rstrip()}")
            for bitline, rel_prefix in ipv6_binary_lines(ipv6_val, result.prefixlen):
                pad = " " * 11
                lines.append(f"{pad}{_colorize_binary(p, bitline, rel_prefix)}")
        elif binary and bits is not None:
            rendered = _colorize_binary(p, bits, result.prefixlen)
            lines.append(f"{lab}{val}{rendered}")
        else:
            lines.append(f"{lab}{val.rstrip()}")

    if result.version == 4:
        addr_int = int(ipaddress.IPv4Address(result.address))
        mask_int = int(ipaddress.IPv4Address(result.netmask)) if result.netmask else 0
        wild_int = int(ipaddress.IPv4Address(result.wildcard)) if result.wildcard else 0
        net_int = int(ipaddress.IPv4Address(result.network))
        bcast_int = int(ipaddress.IPv4Address(result.broadcast)) if result.broadcast else None

        row("Address:", result.address_cidr, ipv4_binary(addr_int, result.prefixlen), p.address)
        row(
            "Netmask:",
            f"{result.netmask} = {result.prefixlen}",
            ipv4_binary(mask_int, result.prefixlen),
            p.mask,
        )
        wild_label = result.wildcard or ""
        if result.wildcard_input:
            wild_label += "  (from wildcard)"
        row("Wildcard:", wild_label, ipv4_binary(wild_int, result.prefixlen), p.wildcard)
        row("CIDR:", f"/{result.prefixlen}", None, p.mask)

        lines.append(_c(p, p.arrow, "=>"))

        if result.is_single:
            row("Hostroute:", result.network_cidr, ipv4_binary(net_int, result.prefixlen), p.network)
        else:
            row("Network:", result.network_cidr, ipv4_binary(net_int, result.prefixlen), p.network)
            if result.broadcast is not None:
                row(
                    "Broadcast:",
                    result.broadcast,
                    ipv4_binary(bcast_int or 0, result.prefixlen),
                    p.network,
                )
            hmin = int(ipaddress.IPv4Address(result.hostmin))
            hmax = int(ipaddress.IPv4Address(result.hostmax))
            row("HostMin:", result.hostmin, ipv4_binary(hmin, result.prefixlen), p.address)
            row("HostMax:", result.hostmax, ipv4_binary(hmax, result.prefixlen), p.address)

        lab = _c(p, p.label, f"{'Addresses:':<11}")
        val = _c(p, p.address, f"{_num_addresses_label(result.num_addresses):<22}")
        meta = _c(p, p.meta, result.description)
        lines.append(f"{lab}{val}{meta}")
        if not result.is_single:
            lab = _c(p, p.label, f"{'Usable:':<11}")
            extra = ""
            if result.prefixlen == 31:
                extra = _c(p, p.meta, "RFC 3021 point-to-point")
            lines.append(f"{lab}{_c(p, p.address, f'{result.usable_hosts:<22}')}{extra}")
        lab = _c(p, p.label, f"{'Ptr:':<11}")
        lines.append(f"{lab}{_c(p, p.address, result.reverse_ptr)}")
    else:
        addr = ipaddress.IPv6Address(result.address)
        net = ipaddress.IPv6Address(result.network)
        hmin = ipaddress.IPv6Address(result.hostmin)
        hmax = ipaddress.IPv6Address(result.hostmax)
        row("Address:", result.address_cidr, ipv6_val=int(addr), value_color=p.address)
        row("Prefixlen:", f"/{result.prefixlen}", value_color=p.mask)
        row(
            "Prefix:",
            f"{result.prefix_address}/{result.prefixlen}",
            ipv6_val=int(net),
            value_color=p.network,
        )
        if not result.is_single:
            row("HostMin:", result.hostmin, ipv6_val=int(hmin), value_color=p.address)
            row("HostMax:", result.hostmax, ipv6_val=int(hmax), value_color=p.address)
        lab = _c(p, p.label, f"{'Addresses:':<11}")
        val = _c(p, p.address, f"{_num_addresses_label(result.num_addresses):<40}")
        meta = _c(p, p.meta, result.description)
        lines.append(f"{lab}{val}{meta}")
        lab = _c(p, p.label, f"{'Ptr:':<11}")
        lines.append(f"{lab}{_c(p, p.address, result.reverse_ptr)}")

    return "\n".join(lines) + "\n"


def _colorize_binary(p: Palette, bits: str, prefixlen: int) -> str:
    if not p.enabled:
        return bits
    net_bits = 0
    out: list[str] = []
    current = ""
    mode: Optional[str] = None

    def flush(next_mode: Optional[str]) -> None:
        nonlocal current, mode
        if current:
            color = p.binary if mode == "net" else p.hostbits if mode == "host" else p.label
            out.append(_c(p, color, current))
            current = ""
        mode = next_mode

    for ch in bits:
        if ch in "01":
            net_bits += 1
            want = "net" if net_bits <= prefixlen else "host"
            if mode != want:
                flush(want)
            current += ch
        else:
            if mode != "punct":
                flush("punct")
            current += ch
    flush(None)
    return "".join(out)


def result_to_json(result: CalcResult) -> str:
    data = asdict(result)
    data["num_addresses"] = str(result.num_addresses)
    return json.dumps(data, indent=2) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

USAGE = """\
Usage: ipcalc [options] <ADDRESS>[/MASK] [MASK]

Calculate network, broadcast, Cisco wildcard, host range and address
count for IPv4 and IPv6.

A single argument is a host (IPv4 /32, IPv6 /128) or CIDR notation.
Two arguments are ADDRESS and MASK. MASK may be:

  /24                 CIDR prefix (slash optional)
  24                  numeric prefix length
  255.255.255.0       dotted-quad subnet mask (IPv4)
  0.0.0.255           Cisco ACL wildcard / inverse mask (IPv4)

Options:
  -n, --nocolor       Disable ANSI color
      --dark          Colors for a dark terminal background
      --light         Colors for a light / bright background
  -c, --color         Force color even when stdout is not a TTY
  -b, --binary        Show the binary bit column
  -j, --json          Machine-readable JSON (implies --nocolor)
  -v, --version       Print version and exit
      --help          This help

Color is on by default in an interactive terminal (dark theme), and off
when output is piped to another program. --nocolor always wins.
Binary bits are hidden unless --binary is given.

Examples:
  ipcalc 192.168.1.1
  ipcalc 192.168.1.1/24
  ipcalc 192.168.1.1 255.255.255.0
  ipcalc 192.168.1.1 24
  ipcalc 192.168.1.1 /24
  ipcalc 192.168.1.1 0.0.0.255
  ipcalc 2001:db8::1/64
  ipcalc 2001:db8::1 64
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipcalc",
        add_help=False,
        usage="ipcalc [options] <ADDRESS>[/MASK] [MASK]",
    )
    parser.add_argument("-n", "--nocolor", action="store_true")
    parser.add_argument("--dark", action="store_true")
    parser.add_argument("--light", action="store_true")
    parser.add_argument("-c", "--color", action="store_true")
    parser.add_argument("-b", "--binary", action="store_true")
    parser.add_argument("-j", "--json", action="store_true", dest="json_out")
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("--help", action="store_true")
    parser.add_argument("tokens", nargs="*")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2

    if args.help:
        sys.stdout.write(USAGE)
        return 0
    if args.version:
        sys.stdout.write(f"{__version__}\n")
        return 0
    if not args.tokens:
        sys.stderr.write(USAGE)
        return 2

    palette = resolve_color(args.nocolor or args.json_out, args.dark, args.light, args.color)

    try:
        result = calculate_from_args(args.tokens)
    except CalcError as exc:
        err = _c(palette, palette.error, f"error: {exc}")
        sys.stderr.write(err + "\n")
        return 1

    if args.json_out:
        sys.stdout.write(result_to_json(result))
        return 0

    sys.stdout.write(format_report(result, palette, binary=args.binary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
