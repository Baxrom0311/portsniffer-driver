# api_test_server.py

from flask import Flask, request, jsonify, render_template_string
from collections import deque
from datetime import datetime

app = Flask(__name__)
# Oxirgi 50 ta tranzaksiyani saqlaymiz
transactions = deque(maxlen=50)

PAGE = """
<!doctype html>
<html>
<head>
  <title>API Test Server - Received Transactions</title>
  <meta http-equiv="refresh" content="2">
  <style>
    body { font-family: system-ui, sans-serif; background-color: #f0f2f5; color: #333; margin: 20px; }
    h3 { color: #0056b3; }
    .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .transaction { border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 15px; }
    .tx-header { background-color: #f8f9fa; padding: 10px 15px; border-bottom: 1px solid #dee2e6; font-weight: bold; }
    .tx-header span { float: right; font-weight: normal; color: #6c757d; }
    .tx-body { padding: 15px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .tx-body div { background-color: #f8f9fa; padding: 8px; border-radius: 4px; }
    .tx-body .label { font-size: 12px; color: #6c757d; }
    .tx-body .value { font-size: 16px; font-weight: 500; }
  </style>
</head>
<body>
  <div class="container">
    <h3>API Test Server</h3>
    <p>Waiting for transactions from the main server. This page auto-refreshes every 2 seconds.</p>
    <div id="transactions-list">
      {% for tx in transactions %}
        <div class="transaction">
          <div class="tx-header">Dispenser ID: {{ tx.data.dispenser_id }} <span>{{ tx.time }}</span></div>
          <div class="tx-body">
            <div><div class="label">Volume</div><div class="value">{{ tx.data.volume }} L</div></div>
            <div><div class="label">Amount</div><div class="value">{{ tx.data.amount }} so'm</div></div>
            <div><div class="label">Price</div><div class="value">{{ tx.data.price }}</div></div>
            <div><div class="label">Temperature</div><div class="value">{{ tx.data.temperature }} °C</div></div>
            <div><div class="label">Pressure</div><div class="value">{{ tx.data.pressure }} kPa</div></div>
            <div><div class="label">Total Volume</div><div class="value">{{ tx.data.total_volume }} L</div></div>
          </div>
        </div>
      {% endfor %}
    </div>
  </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE, transactions=list(transactions))

@app.route('/api/texnouz/transactions/', methods=['POST'])
def receive_transaction():
    data = request.get_json()
    if data:
        transactions.appendleft({
            "time": datetime.now().strftime('%H:%M:%S'),
            "data": data
        })
    return jsonify({"status": "success"}), 201

if __name__ == '__main__':
    print("API Test Server is running at http://127.0.0.1:8001")
    app.run(port=8001, debug=False)