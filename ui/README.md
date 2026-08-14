# UI

A local web page showing flagged packets as a Wireshark-style row list: one row per
alert, click a row to see the full packet (addresses, MACs, reason, hex dump of the
payload) below the table. Deliberately plain - no CSS framework, no build step.

## Run it against real traffic

The UI runs by default - one command starts spoofing, sniffing, and the UI together:

```
sudo /usr/bin/python3 main.py eth0 <target_ip> <gateway_ip>
```

Then open `http://127.0.0.1:5000` (or whatever `--ui-port` you passed). The page
connects over Server-Sent Events (`/api/stream`) and gets every alert `AlertHandler`
already collects - no separate process, no polling on your end.

Needs Flask (`pip install -r ui/requirements.txt`). Pass `--no-ui` to skip it and go
back to a terminal-only run with no Flask dependency at all - useful if it's not
installed, or the default port (5000) collides with something else on the box.

## Run it standalone (no root, no interface, fake data)

For working on the frontend itself without a live capture:

```
python3 ui/server.py
```

Seeds a handful of demo alerts (one per rule type) and serves them at
`http://127.0.0.1:5000`.

## The structure of the app :))

- `server.py` - Flask app. `create_app(handler)` wires routes to whatever
  `AlertHandler` it's given; `run_ui(handler, ...)` runs that app in a background
  thread. One-way dependency on `Phase1/` (imports `detection_engine`), never the
  other way - `main.py` only imports this module unless `--no-ui` is passed, so a
  `--no-ui` run never needs Flask installed.
- `static/` - the page itself: `index.html` (table + detail pane), `app.js` (SSE
  client, row rendering, hex dump), `style.css` (borders and a monospace font, nothing
  more).
