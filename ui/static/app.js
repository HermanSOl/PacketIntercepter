// Wireshark-style row list: every alert from /api/stream becomes a row, appended in
// order. Clicking a row shows the full packet in the detail pane below the table.

const rowsEl = document.getElementById("alert-rows");
const statusEl = document.getElementById("status");
const detailEl = document.getElementById("detail");
const detailTitleEl = document.getElementById("detail-title");
const detailFieldsEl = document.getElementById("detail-fields");
const detailHexdumpEl = document.getElementById("detail-hexdump");

const alertsById = new Map(); // id -> alert dict, so a row click can look up its full data
let selectedRow = null;

function formatTime(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function addressOf(ip, port) {
  return port === null || port === undefined ? ip : `${ip}:${port}`;
}

function hexDump(hex) {
  const bytes = hex.match(/../g) || [];
  if (bytes.length === 0) return "(empty payload)";
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const hexPart = chunk.join(" ").padEnd(16 * 3 - 1, " ");
    const asciiPart = chunk
      .map((b) => {
        const code = parseInt(b, 16);
        return code >= 0x20 && code < 0x7f ? String.fromCharCode(code) : ".";
      })
      .join("");
    lines.push(`${offset.toString(16).padStart(4, "0")}  ${hexPart}  ${asciiPart}`);
  }
  return lines.join("\n");
}

function renderRow(alert) {
  const tr = document.createElement("tr");
  tr.dataset.id = alert.id;
  tr.innerHTML = `
    <td>${alert.id}</td>
    <td>${formatTime(alert.timestamp)}</td>
    <td>${addressOf(alert.ip_src, alert.sport)}</td>
    <td>${addressOf(alert.ip_dst, alert.dport)}</td>
    <td>${alert.type}</td>
    <td class="info">${alert.reason}</td>
  `;
  tr.addEventListener("click", () => selectAlert(alert.id));
  rowsEl.appendChild(tr);
}

function selectAlert(id) {
  const alert = alertsById.get(id);
  if (!alert) return;

  if (selectedRow) selectedRow.classList.remove("selected");
  selectedRow = rowsEl.querySelector(`tr[data-id="${id}"]`);
  if (selectedRow) selectedRow.classList.add("selected");

  detailTitleEl.textContent = `#${alert.id} - ${alert.type}`;
  const fields = [
    ["Time", new Date(alert.timestamp * 1000).toISOString()],
    ["Source", addressOf(alert.ip_src, alert.sport)],
    ["Destination", addressOf(alert.ip_dst, alert.dport)],
    ["Protocol", alert.protocol],
    ["Source MAC", alert.mac_src],
    ["Destination MAC", alert.mac_dst],
    ["Reason", alert.reason],
    ["Payload length", `${alert.payload_len} bytes`],
  ];
  detailFieldsEl.innerHTML = fields.map(([label, value]) => `<tr><td>${label}</td><td>${value}</td></tr>`).join("");
  detailHexdumpEl.textContent = hexDump(alert.payload_hex);
  detailEl.hidden = false;
}

document.getElementById("detail-close").addEventListener("click", () => {
  detailEl.hidden = true;
  if (selectedRow) selectedRow.classList.remove("selected");
  selectedRow = null;
});

function connect() {
  const source = new EventSource("/api/stream");

  source.onopen = () => {
    statusEl.textContent = "live";
  };

  source.onerror = () => {
    statusEl.textContent = "reconnecting…";
  };

  source.onmessage = (event) => {
    const alert = JSON.parse(event.data);
    if (alertsById.has(alert.id)) return; // reconnects replay the current backlog
    alertsById.set(alert.id, alert);
    renderRow(alert);
  };
}

connect();
