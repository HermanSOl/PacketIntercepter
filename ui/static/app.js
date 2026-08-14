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
	return (
		d.toLocaleTimeString(undefined, { hour12: false }) +
		"." +
		String(d.getMilliseconds()).padStart(3, "0")
	);
}

function addressOf(ip, port, hostname) {
	const base = port === null || port === undefined ? ip : `${ip}:${port}`;
	return hostname ? `${base} (${hostname})` : base;
}

function formatHex(n, width = 4) {
	return n === null || n === undefined
		? ""
		: "0x" + n.toString(16).padStart(width, "0");
}

const TCP_FLAG_NAMES = {
	F: "FIN",
	S: "SYN",
	R: "RST",
	P: "PSH",
	A: "ACK",
	U: "URG",
	E: "ECE",
	C: "CWR",
	N: "NS",
};
function expandFlags(letters, names) {
	if (!letters) return "";
	return [...letters].map((c) => names[c] || c).join(", ");
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
		lines.push(
			`${offset.toString(16).padStart(4, "0")}  ${hexPart}  ${asciiPart}`,
		);
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
    <td>${addressOf(alert.ip_dst, alert.dport, alert.hostname)}</td>
    <td>${alert.type}</td>
    <td>${alert.length}</td>
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

	const section = (label) => ({ section: label });
	const rows = [
		section("Alert"),
		["Reason", alert.reason],
		["Time", new Date(alert.timestamp * 1000).toISOString()],
		section("Frame"),
		["Length", `${alert.length} bytes`],
		section("Ethernet"),
		["Source", alert.mac_src],
		["Destination", alert.mac_dst],
		[
			"Type",
			`${formatHex(alert.eth_type)} (${alert.eth_type === 0x0800 ? "IPv4" : "?"})`,
		],
		section("Internet Protocol"),
		["Source", alert.ip_src],
		["Destination", addressOf(alert.ip_dst, null, alert.hostname)],
		["Time to live", alert.ip_ttl],
		["Identification", formatHex(alert.ip_id)],
		["Flags", alert.ip_flags || "(none)"],
		["Protocol", `${alert.ip_proto_num} (${alert.protocol})`],
		["Header checksum", formatHex(alert.ip_checksum)],
	];

	if (alert.protocol === "TCP") {
		rows.push(
			section("Transmission Control Protocol"),
			["Source port", alert.sport],
			["Destination port", alert.dport],
			["Sequence number", alert.tcp_seq],
			["Acknowledgment number", alert.tcp_ack],
			[
				"Flags",
				`${alert.tcp_flags} (${expandFlags(alert.tcp_flags, TCP_FLAG_NAMES)})`,
			],
			["Window size", alert.tcp_window],
		);
	} else if (alert.protocol === "UDP") {
		rows.push(
			section("User Datagram Protocol"),
			["Source port", alert.sport],
			["Destination port", alert.dport],
		);
	}

	rows.push(section("Payload"), ["Length", `${alert.payload_len} bytes`]);

	detailFieldsEl.innerHTML = rows
		.map((row) =>
			"section" in row
				? `<tr class="section"><td colspan="2">${row.section}</td></tr>`
				: `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`,
		)
		.join("");
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
