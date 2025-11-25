# pip install flask
from flask import Flask, request, jsonify, render_template_string
from collections import deque
import json
import time
import binascii
import html
import threading
from typing import Dict, Any, List

app = Flask(__name__)
# Thread-safe event storage with proper locking
events_lock = threading.RLock()
events = deque(maxlen=1000)  # Limit memory usage

PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PortSniffer Logs</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 16px; color: #1a1a1a; }
    table { border-collapse: collapse; width: 100%; background: #fff; }
    th, td { border: 1px solid #e6e6e6; padding: 6px 8px; font-size: 12px; }
    thead th { background: #f9fafb; position: sticky; top: 0; z-index: 1; }
    tbody tr:nth-child(even) { background: #fcfcfc; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .pre { white-space: pre-wrap; word-break: break-word; }
    .controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
    .controls label { font-size: 12px; }
    .stats { margin: 8px 0; font-size: 12px; color: #374151; display: flex; gap: 12px; flex-wrap: wrap; }
    .legend { margin: 8px 0 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    .legend .item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; border: 1px solid #e6e6e6; padding: 2px 6px; border-radius: 4px; background: #fff; }
    .legend .swatch { width: 12px; height: 12px; border: 1px solid rgba(0,0,0,0.1); }
    .muted { color: #6b7280; }
  </style>
</head>
<body>
  <h3>PortSniffer Logs</h3>
  <div class="controls">
    <label>Auto-refresh (ms): <input id="interval" type="number" value="1000" min="250" style="width:90px"></label>
    <label>Port: <input id="flt_port" placeholder="e.g. COM3" style="width:120px"></label>
    <label>Type:
      <select id="flt_type">
        <option value="">Any</option>
        <option value="1">READ</option>
        <option value="2">WRITE</option>
        <option value="4">IOCTL</option>
      </select>
    </label>
    <label>Limit: <input id="flt_limit" type="number" min="1" max="1000" value="200" style="width:80px"></label>
    <label><input id="flt_combine" type="checkbox" checked> Combine</label>
    <label>Gap (ms): <input id="flt_gap" type="number" min="5" max="2000" value="300" style="width:80px"></label>
    <label>UTF-16 view: <input id="flt_utf16" type="checkbox"></label>
    <button onclick="start()">Apply</button>
    <button onclick="reloadNow()">Reload</button>
  </div>
  <div class="stats" id="stats"></div>
  <div id="legend" class="legend"></div>
  <table id="tbl">
    <thead>
      <tr>
        <th>#</th>
        <th>port</th>
        <th>timestamp</th>
        <th>type</th>
        <th>length</th>
        <th>data_hex</th>
        <th>volume_l</th>
        <th>amount</th>
        <th>pressure</th>
        <th>temperature</th>
        <th>data_text</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
<script>
let timer;
const portColors = new Map();
function hashToHsl(str){
  let h = 0;
  for (let i=0;i<str.length;i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  h = Math.abs(h) % 360;
  const s = 70; // saturation
  const l = 90; // lightness (pastel)
  return `hsl(${h} ${s}% ${l}%)`;
}
function colorForPort(port){
  if (!port) return "transparent";
  if (!portColors.has(port)) portColors.set(port, hashToHsl(port));
  return portColors.get(port);
}
function renderLegend(){
  const legend = document.getElementById("legend");
  if (!legend) return;
  legend.innerHTML = "";
  Array.from(portColors.keys()).sort().forEach(p => {
    const div = document.createElement("div");
    div.className = "item";
    const sw = document.createElement("span");
    sw.className = "swatch";
    sw.style.backgroundColor = colorForPort(p);
    const text = document.createElement("span");
    text.textContent = p;
    div.appendChild(sw);
    div.appendChild(text);
    legend.appendChild(div);
  });
}
function render(rows) {
  const tb = document.querySelector("#tbl tbody");
  tb.innerHTML = "";
  rows.forEach((e, idx) => {
    const tr = document.createElement("tr");
    const bg = colorForPort(e.port||"");
    tr.style.backgroundColor = bg;
    tr.innerHTML = `
      <td>${idx+1}</td>
      <td>${e.port||""}</td>
      <td>${e.timestamp||""}</td>
      <td>${e.type}</td>
      <td>${e.length}</td>
      <td><code class="muted">${e.data_hex||""}</code></td>
      <td>${e.volume_l!==undefined? e.volume_l : ""}</td>
      <td>${e.amount!==undefined? e.amount : ""}</td>
      <td>${e.pressure!==undefined? e.pressure : ""}</td>
      <td>${e.temperature!==undefined? e.temperature : ""}</td>
      <td><code class="pre">${e.data_text||""}</code></td>`;
    tb.appendChild(tr);
  });
  renderLegend();
}
async function load() {
  try {
    const t0 = performance.now();
    const p = new URLSearchParams();
    const port = document.getElementById("flt_port").value.trim();
    const type = document.getElementById("flt_type").value;
    const limit = parseInt(document.getElementById("flt_limit").value || "200", 10);
    const combine = document.getElementById("flt_combine").checked;
    const gap = parseInt(document.getElementById("flt_gap").value || "300", 10);
    const utf16 = document.getElementById("flt_utf16").checked;
    if (port) p.set("port", port);
    if (type) p.set("type", type);
    if (limit) p.set("limit", String(Math.max(1, Math.min(1000, limit))));
    if (combine) p.set("combine", "1");
    if (gap) p.set("gap_ms", String(Math.max(5, Math.min(2000, gap))));
    if (utf16) p.set("utf16", "1");
    const r = await fetch("/data?" + p.toString());
    if (!r.ok) return;
    const j = await r.json();
    render(j);
    const t1 = performance.now();
    const stats = document.getElementById("stats");
    if (stats) stats.textContent = `rows: ${j.length}, fetch+render: ${Math.round(t1 - t0)} ms`;
  } catch(e) {
    console.error('Error loading data:', e);
    const stats = document.getElementById("stats");
    if (stats) stats.textContent = `Error: ${e.message}`;
  }
}
function start() {
  clearInterval(timer);
  load();
  const ms = Math.max(250, parseInt(document.getElementById("interval").value || "1000", 10));
  timer = setInterval(load, ms);
}
function reloadNow(){ load(); }
start();
</script>
</body>
</html>
"""

def hex_to_text(hex_str: str) -> str:
  try:
    raw = binascii.unhexlify(hex_str)
  except (binascii.Error, ValueError):
    return "<invalid-hex>"
  out = []
  for b in raw:
    if 32 <= b <= 126 or b in (9, 10, 13):
      out.append(chr(b))
    else:
      out.append(".")
  return html.escape("".join(out), quote=False)

# --- Texno UZ decoding helpers ---
def _crc16_texno(data: bytes) -> int:
  crc = 0xFFFF
  for byte in data:
    crc ^= byte
    for _ in range(8):
      if (crc & 0x0001) != 0:
        crc = (crc >> 1) ^ 0xA001
      else:
        crc >>= 1
  return crc & 0xFFFF

def _check_packet(data: bytes) -> bool:
  if len(data) < 3:
    return False
  # Fix: Use big-endian to match C code
  expected = int.from_bytes(data[-2:], byteorder="big", signed=False)
  calc = _crc16_texno(data[:-2])
  return expected == calc

def _decode_texno_uz_fields(data: bytes) -> dict:
  result = {}
  if not data or len(data) < 3:
    result["proto"] = "unknown"
    return result
  result["proto"] = "texno_uz"
  result["device_id"] = int(data[0])
  result["crc_ok"] = _check_packet(data)
  # Try common response layouts observed in ugaz-django texno_uz_v1
  try:
    # Status/flow frames with volume/amount at offsets when data[1]==0x03
    if len(data) >= 17 and data[1] == 0x03 and data[10] in (0xA3, 0xB3, 0xB1, 0xA1, 0xA2, 0xA0, 0x82, 0x83, 0x93, 0x80):
      volume_raw = int.from_bytes(data[11:13], byteorder="big", signed=False)
      amount_raw = ((data[15] << 24) | (data[16] << 16) | (data[13] << 8) | data[14])
      result["volume_l"] = volume_raw / 100.0
      result["amount"] = amount_raw
      result["frame_type"] = "flow"
    # Pressure/temperature snapshot when data[1]==0x03 and marker 0x0A at [2]
    elif len(data) >= 13 and data[1] == 0x03 and data[2] == 0x0A:
      pressure_raw = int.from_bytes(data[3:5], byteorder="big", signed=False)
      temperature_raw = int.from_bytes(data[11:13], byteorder="big", signed=False)
      result["pressure"] = pressure_raw
      result["temperature"] = temperature_raw
      result["frame_type"] = "env"
    else:
      result["frame_type"] = "unknown"
  except Exception:
    # Best-effort decode; keep base fields
    result.setdefault("frame_type", "unknown")
  return result

def _compose_human_text(fields: dict) -> str:
  if not fields or fields.get("proto") != "texno_uz":
    return ""
  parts = []
  idv = fields.get("device_id")
  if idv is not None:
    parts.append(f"ID={idv}")
  ft = fields.get("frame_type")
  if ft:
    parts.append(f"type={ft}")
  if "volume_l" in fields:
    parts.append(f"V={fields['volume_l']:.2f}L")
  if "amount" in fields:
    parts.append(f"A={fields['amount']}")
  if "pressure" in fields:
    parts.append(f"P={fields['pressure']}")
  if "temperature" in fields:
    parts.append(f"T={fields['temperature']}")
  if "crc_ok" in fields:
    parts.append("CRC=OK" if fields["crc_ok"] else "CRC=BAD")
  return " ".join(parts)

@app.route("/")
def index():
  # XSS zaifligini oldini olish uchun template'ni xavfsiz qilish
  return render_template_string(PAGE, safe_mode=True)

@app.route("/data")
def data():
  try:
    # Filtrlar: port, type, limit, combine, gap_ms
    q_port = (request.args.get("port") or "").strip()
    q_type = request.args.get("type")
    q_limit = request.args.get("limit", type=int) or 200
    q_limit = max(1, min(1000, q_limit))
    q_combine = request.args.get("combine") in ("1", "true", "yes")
    q_gap = request.args.get("gap_ms", type=int) or 50
    q_gap = max(5, min(1000, q_gap))

    # Thread-safe data access
    with events_lock:
      src = list(events)
    
    # Chronological processing for combine
    src_chrono = list(src)
    
    # Filter early to speed
    if q_port:
      src_chrono = [e for e in src_chrono if str(e.get("port", "")).lower() == q_port.lower()]
    if q_type and q_type.isdigit():
      try:
        tval = int(q_type)
        src_chrono = [e for e in src_chrono if int(e.get("type", -1)) == tval]
      except Exception:
        pass

    if q_combine:
      out = []
      cur = None
      last_ts = None
      for e in src_chrono:
      try:
        ts_val = e.get("ts_received") or 0
        if isinstance(ts_val, str):
          ts = int(float(ts_val))
        else:
          ts = int(ts_val)
      except (ValueError, TypeError):
        ts = 0
      if not cur:
        cur = dict(e)
        # normalize
        cur["data_hex"] = cur.get("data_hex", "")
        cur["data_text"] = cur.get("data_text", "")
        try:
          cur["length"] = int(cur.get("length") or 0)
        except Exception:
          cur["length"] = 0
        last_ts = ts
        continue

      same_group = (e.get("port") == cur.get("port") and e.get("type") == cur.get("type"))
      close_in_time = (ts - last_ts) <= q_gap if (ts and last_ts) else True

      # If different group or gap too large -> flush
      if not same_group or not close_in_time:
        out.append(cur)
        cur = dict(e)
        cur["data_hex"] = cur.get("data_hex", "")
        cur["data_text"] = cur.get("data_text", "")
        try:
          cur["length"] = int(cur.get("length") or 0)
        except Exception:
          cur["length"] = 0
        last_ts = ts
        continue

      # Merge into current with buffer overflow protection
      new_hex = cur.get("data_hex", "") + e.get("data_hex", "")
      new_text = cur.get("data_text", "") + e.get("data_text", "")
      
      # Limit buffer size to prevent memory issues
      if len(new_hex) > 10000:  # 10KB limit
        new_hex = new_hex[:10000] + "...[truncated]"
      if len(new_text) > 10000:  # 10KB limit
        new_text = new_text[:10000] + "...[truncated]"
        
      cur["data_hex"] = new_hex
      cur["data_text"] = new_text
      
      try:
        cur["length"] = int(cur.get("length") or 0) + int(e.get("length") or 0)
      except (ValueError, TypeError):
        cur["length"] = len(new_hex) // 2  # Approximate byte length
      # Keep the latest timestamp string
      if e.get("timestamp"):
        cur["timestamp"] = e.get("timestamp")
      last_ts = ts

    if cur:
      out.append(cur)
  else:
    out = src_chrono

    # Newest first for UI
    out.reverse()
    out = out[:q_limit]
    return jsonify(out)
    
  except Exception as e:
    app.logger.error(f"Error in /data endpoint: {e}")
    return jsonify({"error": "Internal server error"}), 500

def _normalize_one(obj: dict):
  data_hex = obj.get("data_hex", "")
  obj["data_text"] = hex_to_text(data_hex)
  # Enrich with Texno UZ decoding if hex present
  try:
    if data_hex:
      raw = binascii.unhexlify(data_hex)
      fields = _decode_texno_uz_fields(raw)
      if fields.get("proto") == "texno_uz":
        # attach parsed fields and human-readable summary
        for k, v in fields.items():
          obj.setdefault(k, v)
        text = _compose_human_text(fields)
        if text:
          sep = ("\n" if obj.get("data_text") else "")
          obj["data_text"] = f"{obj.get('data_text','')}{sep}{text}"
  except Exception:
    pass
  obj.setdefault("ts_received", int(time.time()*1000))
  return obj

@app.route("/ingest", methods=["POST"])
def ingest():
  try:
    payload = request.get_json(force=True, silent=True)
    if payload is None:
      # UTF-16LE bo'lib kelishi mumkin, sinab ko'ramiz
      raw = request.data
      try:
        payload = json.loads(raw.decode("utf-16-le"))
      except Exception:
        payload = {"raw": raw.decode("utf-8", "ignore")}

    # Thread-safe event addition
    with events_lock:
      if isinstance(payload, list):
        for obj in payload:
          if isinstance(obj, dict):
            events.append(_normalize_one(obj))
      elif isinstance(payload, dict):
        events.append(_normalize_one(payload))
      else:
        events.append(_normalize_one({"raw": str(payload)}))
    
    return "OK", 200
  except Exception as e:
    app.logger.error(f"Error in /ingest endpoint: {e}")
    return f"ERR: {e}", 400

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8000, debug=False)