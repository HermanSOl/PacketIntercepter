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
  l


<h2>Big challenge faced:</h2>
The big challenge is SPEED (I know kind of obvious). I mean, at first I set up IP forwarding wrong completely and the target's device couldn't even reach the internet, so that was very apparent. When I run my app for now it is very apparent for the target to notice a drop in connection. After I fixed it, as well as enabled the FORWARD policy so that the FIREWALL level wouldn't block it it became a bit better but was still very slow. However, I think I know what is responsible for the big speed drop. By testing the sniffer and spoofer independently I realized that the problem is the SNIFFER THREAD. It has a delay of 5.27 ms on average no matter how many rules it checks. It is the BPF filter, meaning my device was capturing and processing to many packets on the sniffer. By making a tighter BPF filter it should speed up the process, so wish me luck. Wanted to write this down since it was very fun.
Edit 1: After doing the bpf, the runtime dropped by about 90 ms !!! That's a win. However, the app is still having trouble handling new big fresh packets, like Youtube flow, where a lot of packets flow through a single click. :( . I honestly don't know what to do with that yet but I'll try to figure it out.
Edit 2: I honestly just asked AI for this. A possible solution was building a packet FlowTracker that checks what packets need to be checked and what not. So if a packet is already a part of the flow we can skip the checks. This adds more time for the FIRST checked packets but is faster for all subsequent ones.
