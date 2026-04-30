from flask import Flask, request, jsonify, render_template_string
import hashlib
import os

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CWE-400 Target Server</title>
    <style>
        body { font-family: monospace; max-width: 600px; margin: 40px auto; padding: 20px; background: #1e1e1e; color: #d4d4d4;}
        h2 { text-align: center; color: #ff5555; }
        button { display: block; margin: 0 auto; padding: 12px 24px; font-size: 16px; cursor: pointer; background: #007acc; color: white; border: none; border-radius: 4px; }
        button:hover { background: #005999; }
        button:disabled { background: #555; cursor: not-allowed; }
        #output { margin-top: 20px; padding: 15px; background: #2d2d2d; border-radius: 4px; min-height: 80px; }
        .success { color: #4ec9b0; }
        .error { color: #f14c4c; }
    </style>
</head>
<body>
    <h2>Mock API Target (CPU/RAM Heavy)</h2>
    <p style="text-align: center; color: #888;">This endpoint performs real cryptographic calculations.</p>
    <button id="sendBtn">Send 1 Request (Baseline)</button>
    <div id="output">
        <div id="status">Status: Ready.</div>
        <div id="time"></div>
        <div id="data"></div>
    </div>

    <script>
        document.getElementById('sendBtn').addEventListener('click', async () => {
            const statusEl = document.getElementById('status');
            const timeEl = document.getElementById('time');
            const dataEl = document.getElementById('data');
            const btn = document.getElementById('sendBtn');
            
            btn.disabled = true;
            statusEl.textContent = 'Status: Processing heavy task...';
            statusEl.className = '';
            timeEl.textContent = '';
            dataEl.textContent = '';

            const start = Date.now();
            try {
                const res = await fetch('/api/search?q=manual_test_' + start);
                const data = await res.json();
                const end = Date.now();
                
                statusEl.textContent = 'Status: HTTP ' + res.status;
                statusEl.className = res.ok ? 'success' : 'error';
                timeEl.textContent = 'Time taken: ' + (end - start) + 'ms';
                dataEl.textContent = 'Response: ' + JSON.stringify(data);
            } catch (err) {
                const end = Date.now();
                statusEl.textContent = 'Status: Error - ' + err.message;
                statusEl.className = 'error';
                timeEl.textContent = 'Time taken: ' + (end - start) + 'ms';
            }
            btn.disabled = false;
        });
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', 'default')
    
    # 1. Gây áp lực lên RAM (Memory Allocation)
    # Tạo ra một mảng chứa 1 triệu số nguyên (Ngốn khoảng 8-10MB RAM mỗi request)
    # Nếu 100 requests tới cùng lúc, RAM sẽ bị trừ đi ~1GB, tiệm cận mức OOM (Out of memory) của Docker.
    dummy_memory_load = [x for x in range(1000000)]
    
    # 2. Gây áp lực lên CPU (CPU Intensive Calculation)
    # Thay vì sleep, ta bắt CPU phải băm chuỗi (hashing) 500,000 lần.
    # Quá trình này không thể bị bỏ qua và ép CPU phải chạy 100% công suất.
    # Tốn khoảng 200ms - 400ms trên CPU thực tế.
    salt = os.urandom(16)
    hash_result = hashlib.pbkdf2_hmac(
        'sha256', 
        query.encode('utf-8'), 
        salt, 
        500000  # Số vòng lặp băm cường độ cao
    )
    
    # Tính toán xong thì giải phóng RAM giả lập
    del dummy_memory_load 

    return jsonify({
        "status": "success",
        "message": f"Processed heavy query: {query}",
        "hash_preview": hash_result.hex()[:10] + "..."
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)