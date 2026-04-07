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
  </style>
</head>
<body>
  <h3>PortSniffer Logs</h3>
  <div>
    <label>Auto-refresh (ms): <input id="interval" type="number" value="1000" min="250" style="width:80px"></label>
    <button onclick="start()">Apply</button>
    <button onclick="reloadNow()">Reload</button>
  </div>
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
function addCell(tr, value, {code=false, pre=false} = {}) {
  const td = document.createElement("td");
  if (code) {
    const c = document.createElement("code");
    if (pre) c.className = "pre";
    c.textContent = value == null ? "" : String(value);
    td.appendChild(c);
  } else {
    td.textContent = value == null ? "" : String(value);
  }
  tr.appendChild(td);
}
function render(rows) {
  const tb = document.querySelector("#tbl tbody");
  tb.innerHTML = "";
  rows.forEach((e, idx) => {
    const tr = document.createElement("tr");
    addCell(tr, idx + 1);
    addCell(tr, e.port || "");
    addCell(tr, e.timestamp || "");
    addCell(tr, e.type);
    addCell(tr, e.length);
    addCell(tr, e.data_hex || "", {code: true});
    addCell(tr, e.data_text || "", {code: true, pre: true});
    tb.appendChild(tr);
  });
}
async function load() {
  try {
    const r = await fetch("/data");
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

def normalize_event(obj):
  item = dict(obj)
  data_hex = item.get("data_hex", "")
  item["data_text"] = hex_to_text(data_hex)
  item.setdefault("ts_received", int(time.time() * 1000))
  return item

@app.route("/data")
def data():
  # Oxirgi 1000 yozuv
  with events_lock:
    return jsonify(list(reversed(events)))

@app.route("/ingest", methods=["POST"])
def ingest():
  try:
    payload = decode_request_payload()
    with events_lock:
      if isinstance(payload, list):
        for obj in payload:
          if isinstance(obj, dict):
            events.append(normalize_event(obj))
      elif isinstance(payload, dict):
        events.append(normalize_event(payload))
      else:
        events.append(normalize_event({"raw": str(payload)}))
    return "OK", 200
  except Exception as e:
    app.logger.error("Error in /ingest endpoint: %s", e)
    return f"ERR: {e}", 400

if __name__ == "__main__":
  # Bind to loopback by default — the ingest endpoint has no auth and must
  # not be exposed on the network. Override via a reverse proxy if needed.
  app.run(host="127.0.0.1", port=8000, debug=False)
