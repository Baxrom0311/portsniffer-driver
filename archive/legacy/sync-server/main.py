# app.py - YAKUNIY MUKAMMALLASHTIRILGAN KOD (C++ TUZATISHI BILAN)

from flask import Flask, request, jsonify, render_template_string
from collections import deque
import json
import time
import binascii
from decimal import Decimal, getcontext
import requests
import threading

getcontext().prec = 10

# --- Sozlamalar va Global O'zgaruvchilar ---
API_ENDPOINT = "http://mms.amusoft.uz/api/texnouz/transactions/"
dispenser_states = {}
read_log = deque(maxlen=100)
write_log = deque(maxlen=100)
error_log = deque(maxlen=20)
last_logs = {"read": {}, "write": {}}

# --- APIga Yuborish va CRC Funksiyalari (o'zgarishsiz) ---
def send_transaction_to_api(data: dict):
    def task():
        try:
            print(f"TRANSACTION >> Sending to API: {data}")
            response = requests.post(API_ENDPOINT, json=data, timeout=15)
            response.raise_for_status()
            error_log.appendleft(f"{time.strftime('%H:%M:%S')} - SUCCESS: Transaction for Dispenser {data['dispenser_id']} sent.")
        except requests.exceptions.RequestException as e:
            error_log.appendleft(f"{time.strftime('%H:%M:%S')} - API Error: {e}")
    threading.Thread(target=task).start()

def calculate_checksum(d: bytes) -> int:
    crc=0xFFFF; [setattr(locals(),'crc',locals()['crc']^b) or [setattr(locals(),'crc',(locals()['crc']>>1)^0xA001 if locals()['crc']&1 else locals()['crc']>>1) for _ in range(8)] for b in d]; return crc&0xFFFF

def check_packet_crc(data: bytes) -> bool:
    if len(data) < 2: return False
    payload, expected = data[:-2], int.from_bytes(data[-2:], "little")
    return expected == calculate_checksum(payload)

# --- MUKAMMALLASHTIRILGAN TAHLIL FUNKSIYASI ---
def parse_dispenser_packet(packet: bytes, packet_type: int) -> dict:
    analysis = {"description": "Unknown", "meaning": "Could not determine meaning", "details": {}, "crc_valid": False}
    if not check_packet_crc(packet):
        analysis["description"] = "Invalid CRC"
        return analysis
    analysis["crc_valid"] = True
    payload = packet[:-2]
    if len(payload) < 2: return analysis
    device_id, func_code = payload[0], payload[1]
    analysis["details"]["Device ID"] = device_id
    
    try:
        if packet_type == 2: # WRITE
            analysis["description"] = "WRITE Command"
            if func_code == 0x03 and len(payload) == 6:
                addr = int.from_bytes(payload[2:4], "big")
                analysis["meaning"] = {0x9C44: "ST (Request General Status)", 0x9C4D: "STP (Request Detailed Status)"}.get(addr, f"Read Registers at 0x{addr:04X}")
        elif packet_type == 1: # READ
            analysis["description"] = "READ Response"
            if func_code == 0x03 and len(payload) > 2:
                byte_count = payload[2]
                if byte_count == 14: # General Status Response
                    status_code = payload[8]
                    STATE_MAP = {
                        0x20: "FINISHED", 0x21: "IDLE", 0x40: "PAUSED", 0x41: "PAUSED", 0x60: "PAUSED", 0x61: "PAUSED",
                        0x80: "FILLING", 0xA0: "FILLING", 0xA1: "FILLING", 0xA2: "FILLING", 0xA3: "FILLING"
                    }
                    state_text = STATE_MAP.get(status_code, f'State 0x{status_code:02X}')
                    analysis["meaning"] = f"General Status is '{state_text}'"
                    analysis["details"]["_internal_state"] = state_text
                    analysis["details"]["Transaction Volume"] = f"{Decimal(int.from_bytes(payload[9:11], 'big'))/100:.2f}"
                    analysis["details"]["Transaction Amount"] = f"{Decimal((payload[13]<<24)|(payload[14]<<16)|(payload[11]<<8)|payload[12])}"
                elif byte_count == 10: # Detailed Status Response
                    analysis["meaning"] = "Detailed Status (Pressure & Temp)"
                    analysis["details"]["Pressure"] = f"{Decimal(int.from_bytes(payload[3:5], 'big'))}"
                    analysis["details"]["Temperature"] = f"{Decimal(int.from_bytes(payload[11:13], 'big'))}"
    except Exception as e:
        analysis["meaning"] = f"Parsing Error: {e}"
    return analysis

# --- MUKAMMALLASHTIRILGAN TRANZAKSIYA MANTIG'I ---
def process_transaction_logic(analysis: dict):
    details = analysis.get("details", {})
    device_id = details.get("Device ID")
    if not device_id: return

    if device_id not in dispenser_states:
        dispenser_states[device_id] = {"state": "IDLE"}
    state_data = dispenser_states[device_id]

    for key in ["Temperature", "Pressure"]:
        if key in details:
            state_data[key.lower()] = details[key]

    new_state_str = details.get("_internal_state")
    if not new_state_str: return
    
    current_state_str = state_data.get("state", "IDLE")

    if "FILLING" in new_state_str:
        if current_state_str != "FILLING":
            print(f"TRANSACTION >> START for dispenser {device_id}")
        state_data["state"] = "FILLING"
        state_data["current_volume"] = details.get("Transaction Volume", "0.00")
        state_data["current_amount"] = details.get("Transaction Amount", "0")
        state_data["last_good_volume"] = details.get("Transaction Volume")
        state_data["last_good_amount"] = details.get("Transaction Amount")
    
    elif new_state_str == "FINISHED" and current_state_str in ["FILLING", "PAUSED"]:
        print(f"TRANSACTION >> FINISH for dispenser {device_id}")
        final_volume = state_data.get("last_good_volume", "0.00")
        final_amount = state_data.get("last_good_amount", "0")
        tx_volume_dec, tx_amount_dec = Decimal(final_volume), Decimal(final_amount)
        if tx_volume_dec > 0.01:
            price = tx_amount_dec / tx_volume_dec if tx_volume_dec else Decimal(0)
            state_data["last_tx_volume"] = f"{tx_volume_dec:.2f}"
            state_data["last_tx_amount"] = f"{tx_amount_dec:.0f}"
            payload = {'dispenser_id': device_id, 'price': f"{price:.3f}", 'amount': f"{tx_amount_dec:.3f}",'volume': f"{tx_volume_dec:.3f}",'total_volume': "N/A", 'total_amount': "N/A",'temperature': state_data.get("temperature", "N/A"), 'pressure': state_data.get("pressure", "N/A")}
            send_transaction_to_api(payload)
        state_data.clear(); state_data["state"] = "IDLE"

    elif "PAUSED" in new_state_str:
        state_data["state"] = "PAUSED"
    elif "IDLE" in new_state_str:
        state_data["state"] = "IDLE"
        state_data["current_volume"] = "0.00"
        state_data["current_amount"] = "0"

# --- Flask ilovasi va Marshrutlar ---
app = Flask(__name__)
PAGE = """
<!-- Avvalgi ochiq rangli, jadvalli dizayn -->
<!doctype html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Real-time Dispenser Monitor & Logger</title>
  <style>:root{--bg-color:#f8f9fa;--card-bg:#ffffff;--text-color:#212529;--label-color:#6c757d;--border-color:#dee2e6;--shadow-color:rgba(0,0,0,0.06);--status-idle:#6c757d;--status-filling:#0d6efd;--status-finished:#198754;--status-paused:#ffc107;--status-error:#dc3545;--font-sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--font-mono:"SF Mono","Consolas","Menlo",monospace}body{font-family:var(--font-sans);margin:0;background-color:var(--bg-color)}.container{max-width:1800px;margin:20px auto;padding:10px}header{padding:0 10px 15px;border-bottom:1px solid var(--border-color);margin-bottom:20px}h3,h4{color:var(--text-color)}.dispenser-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}.dispenser-card{background-color:var(--card-bg);border-radius:12px;border:1px solid var(--border-color);box-shadow:0 4px 12px var(--shadow-color);overflow:hidden}.card-header{display:flex;justify-content:space-between;align-items:center;padding:12px 18px;border-bottom:1px solid var(--border-color)}.dispenser-id{font-size:22px;font-weight:600}.status-badge{padding:5px 12px;border-radius:15px;font-size:13px;font-weight:500;color:#fff}.status-IDLE{background-color:var(--status-idle)}.status-FILLING{background-color:var(--status-filling)}.status-PAUSED{background-color:var(--status-paused);color:#000}.card-body,.card-footer{padding:12px 18px}.live-filling .value{font-size:48px;font-weight:700;color:var(--status-filling)}.metrics-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.metric-label{font-size:13px;color:var(--label-color)}.metric-value{font-size:18px;font-weight:500}.log-section{margin-top:30px;background:#fff;border-radius:8px;padding:20px;box-shadow:0 4px 12px var(--shadow-color)}.tabs{display:flex;border-bottom:1px solid var(--border-color);margin-bottom:15px}.tab{padding:10px 20px;cursor:pointer;background:#f8f9fa;border:1px solid var(--border-color);border-bottom:none;margin-bottom:-1px;border-radius:6px 6px 0 0}.tab.active{background:#fff;border-bottom:1px solid #fff;font-weight:600}.log-table-container{max-height:400px;overflow-y:auto}table{width:100%;border-collapse:collapse}th,td{padding:8px;border:1px solid var(--border-color);font-size:12px;vertical-align:top}th{background-color:#f8f9fa;position:sticky;top:0}code{font-family:var(--font-mono);background:#e9ecef;padding:2px 4px;border-radius:3px;word-break:break-all}#error-log:empty{display:none}</style>
</head>
<body>
  <div class="container">
    <header><h3>Dispensers Real-time Monitor</h3></header>
    <div class="dispenser-grid" id="dispenser-grid"></div>
    <div class="log-section">
      <h4>Packet Log</h4>
      <div class="tabs">
        <div class="tab active" onclick="showTab('read')">READ Log (Only changed packets)</div>
        <div class="tab" onclick="showTab('error')">Error Log</div>
      </div>
      <div id="read-log-container" class="log-table-container"></div>
      <div id="error-log-container" class="log-table-container" style="display:none;"></div>
    </div>
  </div>
<script>
    const grid = document.getElementById('dispenser-grid');
    const readLogContainer = document.getElementById('read-log-container');
    const errorLogContainer = document.getElementById('error-log-container');

    function createCardHTML(id) { return `<div class="card-header"><div class="dispenser-id">№ ${id}</div><div class="status-badge" data-field="state">IDLE</div></div><div class="card-body"><div class="live-filling"><div class="label">Hozirgi Hajm</div><div class="value"><span data-field="current_volume">0.00</span></div></div><div class="metrics-grid"><div><div class="metric-label">Temperatura</div><div class="metric-value" data-field="temperature">N/A</div></div><div><div class="metric-label">Bosim</div><div class="metric-value" data-field="pressure">N/A</div></div></div></div><div class="card-footer"><div class="footer-title">SO'NGGI TRANZAKSIYA</div><div class="metrics-grid"><div><div class="metric-label">Hajm</div><div class="metric-value" data-field="last_tx_volume">N/A</div></div><div><div class="metric-label">Summa</div><div class="metric-value" data-field="last_tx_amount">N/A</div></div></div></div>`; }
    function createLogTable(logData) {
        let tableHTML = '<table><thead><tr><th>Time</th><th>Packet</th><th>Meaning</th><th>Details</th></tr></thead><tbody>';
        logData.forEach(e => {
            let detailsHTML = Object.entries(e.analysis.details).filter(([k]) => !k.startsWith('_')).map(([k, v]) => `<b>${k}:</b> ${v}`).join('<br>');
            tableHTML += `<tr><td><code>${e.timestamp.split('T')[1].replace('Z','')}</code></td><td><code>${e.raw_hex}</code></td><td>${e.analysis.meaning}</td><td>${detailsHTML}</td></tr>`;
        });
        return tableHTML + '</tbody></table>';
    }

    async function updateData() {
        try {
            const response = await fetch('/data');
            const data = await response.json();
            for (const id in data.dispensers) {
                let card = document.getElementById(`dispenser-${id}`);
                if (!card) {
                    card = document.createElement('div'); card.className = 'dispenser-card'; card.id = `dispenser-${id}`;
                    grid.appendChild(card); card.innerHTML = createCardHTML(id);
                }
                const dispenserData = data.dispensers[id];
                for (const field in dispenserData) {
                    const el = card.querySelector(`[data-field="${field}"]`);
                    if (el && el.textContent !== (dispenserData[field] || 'N/A')) {
                        el.textContent = dispenserData[field] || 'N/A';
                    }
                }
                const stateEl = card.querySelector(`[data-field="state"]`);
                if (stateEl) { stateEl.className = `status-badge status-${dispenserData.state || 'IDLE'}`; }
            }
            readLogContainer.innerHTML = createLogTable(data.read_log);
            errorLogContainer.innerHTML = `<div style="padding:10px;font-family:monospace;color:#c0392b;">${data.errors.join("<br>")}</div>`;
        } catch (error) { console.error('Failed to fetch data:', error); }
    }

    function showTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`.tab[onclick="showTab('${tabName}')"]`).classList.add('active');
        readLogContainer.style.display = (tabName === 'read') ? 'block' : 'none';
        errorLogContainer.style.display = (tabName === 'error') ? 'block' : 'none';
    }
    
    setInterval(updateData, 1000);
    updateData();
</script>
</body>
</html>
"""
@app.route("/data")
def data(): return jsonify({"dispensers": dispenser_states, "read_log": list(read_log), "errors": list(error_log)})
@app.route("/")
def index(): return render_template_string(PAGE)
@app.route("/ingest", methods=["POST"])
def ingest():
    global last_logs
    try:
        raw_bytes = request.data
        if not raw_bytes: return "OK", 200
        decoded_string = raw_bytes.decode("utf-16-le")
        payload = json.loads(decoded_string)
        hex_data, packet_type = payload.get("data_hex"), payload.get("type")
        if not hex_data or not packet_type: return "OK", 200
        packet_bytes = binascii.unhexlify(hex_data)

        if packet_type == 1: # READ
            analysis = parse_dispenser_packet(packet_bytes, 1)
            if not analysis["crc_valid"]: return "OK", 200 # Ignore invalid CRC packets
            
            device_id = analysis.get("details", {}).get("Device ID")
            if device_id:
                # Faqat STP javoblarini yoki o'zgargan paketlarni logga yozamiz
                is_stp = "Detailed Status" in analysis.get("meaning", "")
                
                # Agar STP bo'lmasa va paket avvalgisidan farq qilsa, logga yozamiz
                if not is_stp and last_logs["read"].get(device_id) != packet_bytes:
                    read_log.appendleft({"timestamp": payload.get("timestamp"), "raw_hex": hex_data, "analysis": analysis})
                    last_logs["read"][device_id] = packet_bytes

                process_transaction_logic(analysis)
                
    except Exception as e:
        error_log.appendleft(f"INGEST Error: {e}")
    return "OK", 200

if __name__ == "__main__":
    print(f"Server is running at http://127.0.0.1:8000")
    print(f"Transactions will be sent to: {API_ENDPOINT}")
    app.run(host="0.0.0.0", port=8000, debug=False)