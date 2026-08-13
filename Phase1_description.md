Phase 1: Core MITM + Detection Engine

Goal: Build the underlying interception and traffic-analysis engine — ARP spoofing, transparent forwarding, packet capture, and insecure-protocol detection — as a working backend, before any terminal UI is layered on top (UI moves to Phase 2).

Features to implement

1. ARP spoofing module

Continuously send forged ARP replies to both the target device (laptop) and the router, each claiming to be the other
Configurable target IP/MAC and gateway IP/MAC (currently hardcoded to one laptop; multi-device support is a later phase)
Re-send forged replies on an interval (~every 2–3 seconds) to survive ARP cache expiry on both ends
Graceful shutdown handler: on exit (Ctrl+C or SIGTERM), send corrective ARP replies restoring the real MAC mappings so the laptop and router can talk to each other again without waiting for cache timeout

2. IP forwarding

Enable Linux kernel IP forwarding on the Pi (/proc/sys/net/ipv4/ip_forward) so redirected traffic actually reaches the internet instead of dead-ending at the Pi
Verify forwarding is disabled/restored on shutdown, consistent with the ARP cleanup

3. Packet capture + parsing

Sniff traffic on the Pi's active interface using scapy (sniff() with a callback, store=False to avoid unbounded memory growth)
Parse each packet into its relevant layers (Ethernet/IP/TCP/UDP + payload)

4. Insecure-protocol detection engine

Rule-based checks run against each captured packet, flagging:
Plaintext HTTP traffic (port 80 / no TLS)
FTP login sequences (USER/PASS in cleartext)
Telnet sessions
Unencrypted SMTP/IMAP/POP3
Unencrypted DNS queries (plain port 53)
Weak/deprecated TLS versions visible in ClientHello/ServerHello (TLS 1.0/1.1)
Each detection includes a short reason string (why it's flagged/exploitable) for later display
