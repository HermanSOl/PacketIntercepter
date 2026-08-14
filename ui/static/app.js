// Wireshark-style row list: every captured packet from /api/packets/stream becomes a
// row, in order. Flagged packets (anything a DetectionRule fired on) are highlighted.
// Clicking a row shows the full packet in the detail pane below the table - packets
// beyond their flow's inspection budget (see PacketLog/LoggedPacket on the backend)
// only ever get an identity, never full header detail, so their detail view is shorter.

const rowsEl = document.getElementById("packet-rows");
const statusEl = document.getElementById("status");
const detailEl = document.getElementById("detail");
const detailTitleEl = document.getElementById("detail-title");
const detailFieldsEl = document.getElementById("detail-fields");
const detailHexdumpEl = document.getElementById("detail-hexdump");

const packetsById = new Map(); // id -> packet dict, so a row click can look up its full data
let selectedRow = null;
let totalCount = 0;
let flaggedCount = 0;

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

function updateStatus() {
	statusEl.textContent = `live - ${totalCount} packet${totalCount === 1 ? "" : "s"}, ${flaggedCount} flagged`;
}

function renderRow(packet) {
	const tr = document.createElement("tr");
	tr.dataset.id = packet.id;
	if (packet.flagged) tr.classList.add("flagged");
	const info = packet.flagged ? packet.alerts.map((a) => a.reason).join("; ") : "";
	tr.innerHTML = `
    <td>${packet.id}</td>
    <td>${formatTime(packet.timestamp)}</td>
    <td>${addressOf(packet.ip_src, packet.sport)}</td>
    <td>${addressOf(packet.ip_dst, packet.dport, packet.hostname)}</td>
    <td>${packet.protocol}</td>
    <td>${packet.length ?? "-"}</td>
    <td class="info">${info}</td>
  `;
	tr.addEventListener("click", () => selectPacket(packet.id));
	rowsEl.appendChild(tr);
}

function selectPacket(id) {
	const packet = packetsById.get(id);
	if (!packet) return;

	if (selectedRow) selectedRow.classList.remove("selected");
	selectedRow = rowsEl.querySelector(`tr[data-id="${id}"]`);
	if (selectedRow) selectedRow.classList.add("selected");

	const titleSuffix = packet.flagged ? packet.alerts.map((a) => a.type).join(", ") : packet.protocol;
	detailTitleEl.textContent = `#${packet.id} - ${titleSuffix}`;

	const section = (label) => ({ section: label });
	const rows = [];

	if (packet.flagged) {
		rows.push(section("Alerts"));
		for (const alert of packet.alerts) {
			rows.push([alert.type, alert.reason]);
		}
	}

	rows.push(
		section("Identity"),
		["Time", new Date(packet.timestamp * 1000).toISOString()],
		["Source", addressOf(packet.ip_src, packet.sport)],
		["Destination", addressOf(packet.ip_dst, packet.dport, packet.hostname)],
		["Protocol", packet.protocol],
	);

	if (!packet.has_detail) {
		detailFieldsEl.innerHTML = rows
			.map((row) =>
				"section" in row
					? `<tr class="section"><td colspan="2">${row.section}</td></tr>`
					: `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`,
			)
			.join("");
		detailHexdumpEl.textContent =
			"(no further detail - this packet arrived after its flow's inspection budget was spent, so it was never fully dissected)";
		detailEl.hidden = false;
		return;
	}

	rows.push(
		section("Frame"),
		["Length", `${packet.length} bytes`],
		section("Ethernet"),
		["Source", packet.mac_src],
		["Destination", packet.mac_dst],
		[
			"Type",
			`${formatHex(packet.eth_type)} (${packet.eth_type === 0x0800 ? "IPv4" : "?"})`,
		],
		section("Internet Protocol"),
		["Time to live", packet.ip_ttl],
		["Identification", formatHex(packet.ip_id)],
		["Flags", packet.ip_flags || "(none)"],
		["Protocol number", `${packet.ip_proto_num} (${packet.protocol})`],
		["Header checksum", formatHex(packet.ip_checksum)],
	);

	if (packet.protocol === "TCP") {
		rows.push(
			section("Transmission Control Protocol"),
			["Sequence number", packet.tcp_seq],
			["Acknowledgment number", packet.tcp_ack],
			[
				"Flags",
				`${packet.tcp_flags} (${expandFlags(packet.tcp_flags, TCP_FLAG_NAMES)})`,
			],
			["Window size", packet.tcp_window],
		);
	}

	rows.push(section("Payload"), ["Length", `${packet.payload_len} bytes`]);

	detailFieldsEl.innerHTML = rows
		.map((row) =>
			"section" in row
				? `<tr class="section"><td colspan="2">${row.section}</td></tr>`
				: `<tr><td>${row[0]}</td><td>${row[1]}</td></tr>`,
		)
		.join("");
	detailHexdumpEl.textContent = hexDump(packet.payload_hex);
	detailEl.hidden = false;
}

document.getElementById("detail-close").addEventListener("click", () => {
	detailEl.hidden = true;
	if (selectedRow) selectedRow.classList.remove("selected");
	selectedRow = null;
});

function connect() {
	const source = new EventSource("/api/packets/stream");

	source.onopen = () => {
		updateStatus();
	};

	source.onerror = () => {
		statusEl.textContent = "reconnecting…";
	};

	source.onmessage = (event) => {
		const packet = JSON.parse(event.data);
		if (packetsById.has(packet.id)) return; // reconnects replay the current backlog
		packetsById.set(packet.id, packet);
		totalCount++;
		if (packet.flagged) flaggedCount++;
		renderRow(packet);
		updateStatus();
	};
}

connect();
