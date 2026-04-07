import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, render_template_string
from collections import deque
import json
import time
import binascii
import html
import threading
import os

app = Flask(__name__)
events = deque(maxlen=1000)
events_lock = threading.RLock()

# Database Configuration
DB_CONFIG = {
    "dbname": "portsniffer_db",
    "user": "baxrom",
    "host": "localhost",
    "port": 5432
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS port_logs (
                id SERIAL PRIMARY KEY,
                port TEXT NOT NULL,
                timestamp TEXT,
                type INTEGER,
                length INTEGER,
                data_hex TEXT,
                data_text TEXT,
                ts_received BIGINT
            );
            CREATE INDEX IF NOT EXISTS idx_port_logs_port ON port_logs(port);
            CREATE INDEX IF NOT EXISTS idx_port_logs_ts ON port_logs(ts_received DESC);
        """)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize the database table
init_db()

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
    const bg = colorForPort(e.port||"");
    tr.style.backgroundColor = bg;
    addCell(tr, idx + 1);
    addCell(tr, e.port || "");
    addCell(tr, e.timestamp || "");
    addCell(tr, e.type);
    addCell(tr, e.length);
    addCell(tr, e.data_hex || "", {code: true});
    addCell(tr, e.data_text || "", {code: true, pre: true});
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
    q_limit = max(1, min(10000, q_limit))  # Allow higher limit for DB
    q_combine = request.args.get("combine") in ("1", "true", "yes")
    q_gap = request.args.get("gap_ms", type=int) or 50
    q_gap = max(5, min(1000, q_gap))

    # Query from Database
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        query = "SELECT port, timestamp, type, length, data_hex, data_text, ts_received FROM port_logs WHERE 1=1"
        params = []
        
        if q_port:
            query += " AND LOWER(port) = LOWER(%s)"
            params.append(q_port)
            
        if q_type and q_type.isdigit():
            query += " AND type = %s"
            params.append(int(q_type))
            
        query += " ORDER BY ts_received DESC LIMIT %s"
        params.append(q_limit)
        
        cur.execute(query, params)
        src = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error("Database query error: %s", e)
        with events_lock:
            src = list(events)

    # Chronological processing for combine (DB returns newest first, so reverse to process)
    src.reverse() 
    src_chrono = src

    if q_combine:
        out = []
        cur_row = None
        last_ts = None
        for e in src_chrono:
            try:
                ts = int(e.get("ts_received") or 0)
            except Exception:
                ts = 0
            if not cur_row:
                cur_row = dict(e)
                cur_row["data_hex"] = cur_row.get("data_hex", "")
                cur_row["data_text"] = cur_row.get("data_text", "")
                try:
                    cur_row["length"] = int(cur_row.get("length") or 0)
                except Exception:
                    cur_row["length"] = 0
                last_ts = ts
                continue

            same_group = (e.get("port") == cur_row.get("port") and e.get("type") == cur_row.get("type"))
            close_in_time = (ts - last_ts) <= q_gap if (ts and last_ts) else True

            if not same_group or not close_in_time:
                out.append(cur_row)
                cur_row = dict(e)
                cur_row["data_hex"] = cur_row.get("data_hex", "")
                cur_row["data_text"] = cur_row.get("data_text", "")
                try:
                    cur_row["length"] = int(cur_row.get("length") or 0)
                except Exception:
                    cur_row["length"] = 0
                last_ts = ts
                continue

            new_hex = cur_row.get("data_hex", "") + e.get("data_hex", "")
            new_text = cur_row.get("data_text", "") + e.get("data_text", "")
            if len(new_hex) > 10000:
                new_hex = new_hex[:10000] + "...[truncated]"
            if len(new_text) > 10000:
                new_text = new_text[:10000] + "...[truncated]"
            cur_row["data_hex"] = new_hex
            cur_row["data_text"] = new_text
            try:
                cur_row["length"] = int(cur_row.get("length") or 0) + int(e.get("length") or 0)
            except Exception:
                cur_row["length"] = len(cur_row["data_hex"]) // 2
            if e.get("timestamp"):
                cur_row["timestamp"] = e.get("timestamp")
            last_ts = ts

        if cur_row:
            out.append(cur_row)
    else:
        out = src_chrono

    # Newest first for UI
    out.reverse()
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
        objs = []
        if isinstance(payload, list):
            objs = [_normalize_one(obj) for obj in payload if isinstance(obj, dict)]
        elif isinstance(payload, dict):
            objs = [_normalize_one(payload)]
        else:
            objs = [_normalize_one({"raw": str(payload)})]

        # Single transaction for the batch
        conn = get_db_connection()
        cur = conn.cursor()
        for obj in objs:
            cur.execute("""
                INSERT INTO port_logs (port, timestamp, type, length, data_hex, data_text, ts_received)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                obj.get("port"),
                obj.get("timestamp"),
                obj.get("type"),
                obj.get("length"),
                obj.get("data_hex"),
                obj.get("data_text"),
                obj.get("ts_received")
            ))
            # Also keep in memory for "Live Feed" if UI is open and polling
            with events_lock:
                events.append(obj)
        
        conn.commit()
        cur.close()
        conn.close()
        
        return "OK", 200
    except Exception as e:
        app.logger.error("Error in /ingest endpoint: %s", e)
        return f"ERR: {e}", 400

if __name__ == "__main__":
  # Bind to 0.0.0.0 to allow incoming connections from the target Windows machine.
  # Note: The /ingest endpoint has no authentication; use a firewall or proxy in production.
  app.run(host="0.0.0.0", port=8005, debug=False)
