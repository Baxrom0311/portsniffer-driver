# pip install flask
from flask import Flask, request, jsonify, render_template_string
from collections import deque
import json
import time
import binascii
import html
import threading

app = Flask(__name__)
events = deque(maxlen=1000)
events_lock = threading.RLock()

PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PortSniffer Logs</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 6px; font-size: 12px; }
    th { background: #f5f5f5; position: sticky; top: 0; }
    code { font-family: Menlo, Consolas, monospace; }
    .pre { white-space: pre-wrap; word-break: break-word; }
    .controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .controls label { font-size: 12px; }
    .legend { margin: 8px 0 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    .legend .item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; border: 1px solid #ddd; padding: 2px 6px; border-radius: 4px; }
    .legend .swatch { width: 12px; height: 12px; border: 1px solid rgba(0,0,0,0.2); }
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
    <label>Gap (ms): <input id="flt_gap" type="number" min="5" max="1000" value="50" style="width:80px"></label>
    <button onclick="start()">Apply</button>
    <button onclick="reloadNow()">Reload</button>
  </div>
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
      <td><code>${e.data_hex||""}</code></td>
      <td><code class="pre">${e.data_text||""}</code></td>`;
    tb.appendChild(tr);
  });
  renderLegend();
}
async function load() {
  try {
    const p = new URLSearchParams();
    const port = document.getElementById("flt_port").value.trim();
    const type = document.getElementById("flt_type").value;
    const limit = parseInt(document.getElementById("flt_limit").value || "200", 10);
    const combine = document.getElementById("flt_combine").checked;
    const gap = parseInt(document.getElementById("flt_gap").value || "50", 10);
    if (port) p.set("port", port);
    if (type) p.set("type", type);
    if (limit) p.set("limit", String(Math.max(1, Math.min(1000, limit))));
    if (combine) p.set("combine", "1");
    if (gap) p.set("gap_ms", String(Math.max(5, Math.min(1000, gap))));
    const r = await fetch("/data?" + p.toString());
    if (!r.ok) return;
    const j = await r.json();
    render(j);
  } catch(e) {}
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

@app.route("/")
def index():
  return render_template_string(PAGE)

def decode_request_payload():
  raw = request.get_data(cache=True)
  payload = request.get_json(silent=True)
  if payload is not None:
    return payload
  if not raw:
    return {}
  for encoding in ("utf-8", "utf-16-le"):
    try:
      return json.loads(raw.decode(encoding))
    except Exception:
      pass
  return {"raw": raw.decode("utf-8", "ignore")}

@app.route("/data")
def data():
  # Filtrlar: port, type, limit, combine, gap_ms
  q_port = (request.args.get("port") or "").strip()
  q_type = request.args.get("type")
  q_limit = request.args.get("limit", type=int) or 200
  q_limit = max(1, min(1000, q_limit))
  q_combine = request.args.get("combine") in ("1", "true", "yes")
  q_gap = request.args.get("gap_ms", type=int) or 50
  q_gap = max(5, min(1000, q_gap))

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
        ts = int(e.get("ts_received") or 0)
      except Exception:
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

      # Merge into current with output size guards.
      new_hex = cur.get("data_hex", "") + e.get("data_hex", "")
      new_text = cur.get("data_text", "") + e.get("data_text", "")
      if len(new_hex) > 10000:
        new_hex = new_hex[:10000] + "...[truncated]"
      if len(new_text) > 10000:
        new_text = new_text[:10000] + "...[truncated]"
      cur["data_hex"] = new_hex
      cur["data_text"] = new_text
      try:
        cur["length"] = int(cur.get("length") or 0) + int(e.get("length") or 0)
      except Exception:
        cur["length"] = len(cur["data_hex"]) // 2
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

def _normalize_one(obj: dict):
  data_hex = obj.get("data_hex", "")
  obj["data_text"] = hex_to_text(data_hex)
  obj.setdefault("ts_received", int(time.time()*1000))
  return obj

@app.route("/ingest", methods=["POST"])
def ingest():
  try:
    payload = decode_request_payload()
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
    app.logger.error("Error in /ingest endpoint: %s", e)
    return f"ERR: {e}", 400

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8000, debug=False)
