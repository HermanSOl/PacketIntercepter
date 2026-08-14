# UI

A local web page showing every captured packet as a Wireshark-style row list, flagged
packets highlighted in red. Click a row to see the full packet (addresses, MACs,
header detail, hex dump of the payload, and any alerts) below the table. Deliberately
plain - no CSS framework, no build step.

Packets beyond a flow's `FlowTracker` inspection budget (see `pkt_capture_parse.py`)
still get a row - protocol/addresses/ports, always cheap to know - but no header
detail/payload, since that flow was never fully dissected past its budget. That
budget is the same optimization that fixed the jitter/video-stalling problem a few
sessions back; this UI never bypasses it. Their detail view says so explicitly
instead of showing blank fields.

Where a hostname can be recovered (an HTTP `Host:` header, or a TLS ClientHello's SNI
extension - see `hostname.py`), it's shown next to the destination IP, e.g.
`93.184.216.34 (example.com)`. This is display-only enrichment - it never changes
what `WeakTlsRule`/`HttpRule` flag, only adds a hostname to what's already flagged.

## Run it against real traffic

The UI runs by default - one command starts spoofing, sniffing, and the UI together:

```
sudo /usr/bin/python3 main.py eth0 <target_ip> <gateway_ip>
```

Then open `http://127.0.0.1:5000` (or whatever `--ui-port` you passed). The page
connects over Server-Sent Events (`/api/packets/stream`) and gets every packet
`PacketLog` already collects, alerts included - no separate process, no polling on
your end.

Needs Flask (`pip install -r ui/requirements.txt`). Pass `--no-ui` to skip it and go
back to a terminal-only run with no Flask dependency at all - useful if it's not
installed, or the default port (5000) collides with something else on the box.

## Run it standalone (no root, no interface, fake data)

For working on the frontend itself without a live capture:

```
python3 ui/server.py
```

Seeds a mix of ordinary and flagged demo traffic (one flagged packet per rule type,
plus plain HTTPS/DNS-shaped packets, plus one packet with `has_detail: false`) and
serves it at `http://127.0.0.1:5000`.

## The structure of the app :))

- `server.py` - Flask app. `create_app(handler, packet_log)` wires routes to whatever
  `AlertHandler`/`PacketLog` it's given; `run_ui(handler, packet_log, ...)` runs that
  app in a background thread. One-way dependency on `Phase1/` (imports
  `detection_engine`/`pkt_capture_parse`), never the other way - `main.py` only
  imports this module unless `--no-ui` is passed, so a `--no-ui` run never needs
  Flask installed.
  - `/api/packets` and `/api/packets/stream` (JSON snapshot / SSE) are what the page
    actually uses - every logged packet, `flagged`/`alerts`/`has_detail` included.
  - `/api/alerts` and `/api/stream` still exist too (alerts only, no plain packets) -
    kept for curl/debugging, not used by the page itself.
- `hostname.py` - best-effort HTTP Host / TLS SNI extraction from a packet's payload.
  Pure function of `(protocol, payload)`, no state, never raises (malformed/truncated
  payloads just mean no hostname found).
- `static/` - the page itself: `index.html` (table + detail pane), `app.js` (SSE
  client, row rendering, hex dump), `style.css` (borders, a monospace font, and the
  `.flagged` row highlight - nothing more).

Tests live in `ui/tests/`, run the same way as `Phase1/`'s: `cd ui && python3 -m pytest tests/`.
