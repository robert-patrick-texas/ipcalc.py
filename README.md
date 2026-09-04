# ipcalc.py
IP address CLI calculator for IPv4 and IPv6 in Python

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
  ipcalc 192.168.1.1/23
  ipcalc 192.168.1.1 255.255.254.0
  ipcalc 192.168.1.1 23
  ipcalc 192.168.1.1 /23
  ipcalc 192.168.1.1 0.0.1.255
  ipcalc 2001:db8::1/64
  ipcalc 2001:db8::1 64
