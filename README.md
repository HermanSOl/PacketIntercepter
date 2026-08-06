<h1 style = 'color:teal'>Local network packet interceptor (MITM) through Raspberry Pi 5</h1>

<h1>Goal:</h1>
Build a tool on the Pi that performs active ARP spoofing (MITM) against one target device — my laptop — routing its traffic through the Pi to the real router, so I can inspect live traffic and flag insecure/exploitable protocols (plaintext HTTP, FTP, Telnet, unencrypted SMTP/IMAP/POP3, unencrypted DNS, weak/deprecated TLS versions in handshakes).

<h3>Testing environment:</h3>
I will be using my own laptop (Debian OS), my own network router and the target device which is the Raspberry Pi 5 with 8GB of RAM.

<h3>Home network:</h3>
Nokia WiFi router, which has no built-in ARP-spoofing protection.
The purpose is only in security research on my own network and my own devices only.

<h2>Architercture flow that will be used:</h2>

[Laptop] <--ARP spoofed--> [Pi, fake gateway] <---> [Router] <---> Internet

- Pi enables IP forwarding so laptop's internet keeps working transparently
- Pi continuously sends forged ARP replies to both laptop and router (which needs no target side setup)
- Pi sniffs traffic passing through it and inspects payloads/handshakes against a "insecure protocol" ruleset

Phased build plan:

- Phase 1 (current target): single Python script — enable IP forwarding, ARP-spoof laptop↔router continuously (~every 2-3s to survive ARP cache expiry), sniff + parse with scapy
- Phase 2: externalize detection rules into a config file instead of hardcoded checks
- Phase 3: multi-device spoofing support
- Phase 4: localhost web dashboard (Flask/FastAPI + websocket) replacing/extending the terminal UI
