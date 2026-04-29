from flask import Flask, request, jsonify, render_template_string
import time

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CWE-400 Test UI</title>
    <style>
        body { font-family: monospace; max-width: 600px; margin: 40px auto; padding: 20px; background: #1e1e1e; color: #d4d4d4;}
        h2 { text-align: center; }
        button { display: block; margin: 0 auto; padding: 12px 24px; font-size: 16px; cursor: pointer; background: #007acc; color: white; border: none; border-radius: 4px; }
        button:hover { background: #005999; }
        button:disabled { background: #555; cursor: not-allowed; }
        #output { margin-top: 20px; padding: 15px; background: #2d2d2d; border-radius: 4px; min-height: 80px; }
        .success { color: #4ec9b0; }
        .error { color: #f14c4c; }
    </style>
</head>
<body>
    <h2>Mock API Test UI</h2>
    <p style="text-align: center; color: #888;">Test the response time of the baseline request</p>
    <button id="sendBtn">Send 1 Request</button>
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
            statusEl.textContent = 'Status: Sending...';
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
    
    # Giả lập thời gian xử lý nghiệp vụ, database query...
    # Baseline này mất khoảng 300ms.
    time.sleep(0.3) 
    
    return jsonify({
        "status": "success",
        "message": f"Results for: {query}"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
