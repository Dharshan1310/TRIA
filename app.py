"""
Transaction Risk Detection System
A Flask-based application for analyzing customer transactions and detecting unusual activity patterns.
"""

from flask import Flask, render_template_string, request, jsonify
import csv
from datetime import datetime
from collections import Counter
import io
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
API_KEY = os.getenv('API_KEY', 'not-configured')

# Minimalistic HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Detector</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f9fafb; color: #1f2937; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        header { text-align: center; padding: 30px 0; border-bottom: 2px solid #e5e7eb; margin-bottom: 30px; }
        h1 { font-size: 28px; font-weight: 700; }
        p { font-size: 14px; color: #6b7280; margin-top: 5px; }
        .card { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 25px; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        textarea { width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-family: monospace; font-size: 13px; resize: vertical; min-height: 120px; }
        input[type="file"] { width: 100%; padding: 8px; border: 1px solid #d1d5db; border-radius: 6px; }
        .button-group { display: flex; gap: 10px; margin-top: 20px; }
        button { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; transition: 0.2s; }
        .btn-primary { background: #3b82f6; color: white; }
        .btn-primary:hover { background: #2563eb; }
        .btn-secondary { background: #e5e7eb; color: #374151; }
        .btn-secondary:hover { background: #d1d5db; }
        .note { background: #eff6ff; border-left: 3px solid #3b82f6; padding: 12px; border-radius: 4px; font-size: 13px; margin-top: 15px; color: #1e40af; }
        .error { background: #fee2e2; border-left: 3px solid #dc2626; padding: 12px; border-radius: 4px; color: #991b1b; display: none; margin-top: 10px; font-size: 13px; }
        .error.show { display: block; }
        .hidden { display: none; }
        .summary { padding: 15px; border-radius: 6px; font-weight: 600; margin-bottom: 20px; }
        .safe { background: #dcfce7; color: #166534; border-left: 3px solid #22c55e; }
        .alert { background: #fef3c7; color: #92400e; border-left: 3px solid #f59e0b; }
        .issue { background: #fff7ed; border: 1px solid #fed7aa; border-radius: 6px; padding: 15px; margin-bottom: 15px; }
        .issue h3 { font-size: 16px; margin-bottom: 10px; color: #92400e; }
        .txn-table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 10px 0; }
        .txn-table th { background: #f3f4f6; padding: 8px; text-align: left; border-bottom: 1px solid #d1d5db; }
        .txn-table td { padding: 8px; border-bottom: 1px solid #e5e7eb; }
        .rule-label { background: #fef3c7; padding: 6px 10px; border-radius: 4px; font-size: 12px; margin: 8px 0; display: inline-block; }
        .explanation { font-size: 13px; color: #4b5563; margin: 8px 0; line-height: 1.5; }
        .investigation { background: #dbeafe; padding: 10px; border-radius: 4px; font-size: 13px; color: #0c4a6e; margin-top: 10px; }
        .back-btn { margin-bottom: 15px; }
        .loading { display: none; text-align: center; padding: 20px; }
        .spinner { display: inline-block; width: 24px; height: 24px; border: 3px solid #e5e7eb; border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Risk Detector</h1>
            <p>Analyze transactions for unusual patterns</p>
        </header>

        <div id="input-section" class="card">
            <div>
                <label for="csv-file">Upload CSV File</label>
                <input type="file" id="csv-file" accept=".csv">
            </div>
            
            <div class="form-group">
                <label for="csv-text">Or Paste CSV Data</label>
                <textarea id="csv-text" placeholder="date,description,payee,amount,channel&#10;2024-01-15,Transfer,John Smith,500.00,online&#10;2024-01-16,Payment,Utility Co,125.50,online"></textarea>
            </div>

            <div class="note">
                <strong>Format:</strong> date (YYYY-MM-DD), description, payee, amount, channel
            </div>

            <div class="button-group">
                <button class="btn-primary" onclick="analyzeTransactions()">Analyze</button>
                <button class="btn-secondary" onclick="clearForm()">Clear</button>
            </div>

            <div class="error" id="error-msg"></div>
            <div class="loading" id="loading"><div class="spinner"></div></div>
        </div>

        <div id="report-section" class="hidden">
            <div class="card">
                <div class="back-btn">
                    <button class="btn-secondary" onclick="backToForm()">← Back</button>
                </div>
                <div id="report-content"></div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('csv-file').addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    document.getElementById('csv-text').value = e.target.result;
                };
                reader.readAsText(file);
            }
        });

        function analyzeTransactions() {
            const csvData = document.getElementById('csv-text').value.trim();
            const errorDiv = document.getElementById('error-msg');
            errorDiv.classList.remove('show');

            if (!csvData) {
                errorDiv.textContent = 'Please provide CSV data';
                errorDiv.classList.add('show');
                return;
            }

            document.getElementById('loading').style.display = 'block';
            
            fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ csv_data: csvData })
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                if (data.error) {
                    errorDiv.textContent = data.error;
                    errorDiv.classList.add('show');
                } else {
                    document.getElementById('report-content').innerHTML = data.report;
                    document.getElementById('input-section').classList.add('hidden');
                    document.getElementById('report-section').classList.remove('hidden');
                    window.scrollTo(0, 0);
                }
            })
            .catch(err => {
                document.getElementById('loading').style.display = 'none';
                errorDiv.textContent = 'Error: ' + err.message;
                errorDiv.classList.add('show');
            });
        }

        function clearForm() {
            document.getElementById('csv-text').value = '';
            document.getElementById('csv-file').value = '';
            document.getElementById('error-msg').classList.remove('show');
        }

        function backToForm() {
            document.getElementById('report-section').classList.add('hidden');
            document.getElementById('input-section').classList.remove('hidden');
            clearForm();
            window.scrollTo(0, 0);
        }
    </script>
</body>
</html>
"""


class TransactionAnalyzer:
    """
    Analyzes customer transactions for unusual risk patterns.
    
    Detects anomalies including:
    - Large transfers compared to customer baseline
    - Burst payments to new payees
    - Odd-hour transactions (midnight to 6 AM)
    - Unusual transaction channels
    """
    
    def __init__(self, transactions):
        """Initialize analyzer with transaction data."""
        self.transactions = transactions
        self.issues = []
        self.stats = self._calculate_stats()
    
    def _calculate_stats(self):
        """Calculate customer behavior baseline statistics."""
        if not self.transactions:
            return {}
        
        amounts = [t['amount'] for t in self.transactions]
        hours = [t['hour'] for t in self.transactions]
        channels = [t['channel'] for t in self.transactions]
        payees = [t['payee'] for t in self.transactions]
        
        sorted_amounts = sorted(amounts)
        
        return {
            'avg_amount': sum(amounts) / len(amounts),
            'median_amount': sorted_amounts[len(sorted_amounts) // 2],
            'max_amount': max(amounts),
            'min_amount': min(amounts),
            'common_hours': Counter(hours).most_common(3),
            'common_channels': Counter(channels),
            'total_payees': len(set(payees)),
            'payee_frequency': Counter(payees),
        }
    
    def detect_large_transfers(self):
        """Flag transfers significantly larger than customer's average."""
        if not self.transactions:
            return
            
        avg = self.stats['avg_amount']
        median = self.stats['median_amount']
        threshold = max(avg * 2.5, median * 3)
        
        flagged = [t for t in self.transactions if t['amount'] > threshold]
        
        if flagged:
            pct_above_avg = ((flagged[0]['amount'] / avg - 1) * 100) if avg > 0 else 0
            self.issues.append({
                'rule': 'Large Transfer Detected',
                'severity': 'high',
                'transactions': flagged,
                'explanation': f"Transactions exceed typical amount by {pct_above_avg:.0f}%. Customer average: ${avg:.2f}, flagged amount: ${flagged[0]['amount']:.2f}.",
                'investigation': 'Verify legitimacy of large transfers. Check if payee is known and transaction aligns with customer profile.'
            })
    
    def detect_burst_to_new_payees(self):
        """Flag sudden payments to newly added payees."""
        if not self.transactions:
            return
            
        payee_freq = self.stats['payee_frequency']
        one_time_payees = {payee: count for payee, count in payee_freq.items() if count <= 1}
        
        if len(one_time_payees) >= 2:
            flagged = [t for t in self.transactions if t['payee'] in one_time_payees]
            if flagged:
                self.issues.append({
                    'rule': 'Burst to New Payees',
                    'severity': 'high',
                    'transactions': flagged,
                    'explanation': f"{len(one_time_payees)} new payees in this period. Typical payee count: {self.stats['total_payees']}.",
                    'investigation': 'Verify customer added these payees and authorized payments. Check if payee names are suspicious.'
                })
    
    def detect_odd_hour_transactions(self):
        """Flag transactions during unusual hours (midnight to 6 AM)."""
        if not self.transactions:
            return
            
        odd_hours = [t for t in self.transactions if t['hour'] < 6]
        
        if odd_hours:
            common_hours = [h for h, count in self.stats['common_hours']]
            self.issues.append({
                'rule': 'Odd-Hour Transactions',
                'severity': 'medium',
                'transactions': odd_hours,
                'explanation': f"Transactions at {len(odd_hours)} unusual hour(s) (midnight-6 AM). Customer typically transacts at: {common_hours if common_hours else 'various times'}.",
                'investigation': 'Confirm customer was awake and authorized these transactions. Check for account access via VPN or unusual location.'
            })
    
    def detect_unusual_channels(self):
        """Flag transactions using uncommon channels."""
        if not self.transactions:
            return
            
        common_channels = dict(self.stats['common_channels'])
        if not common_channels:
            return
            
        most_common = max(common_channels.items(), key=lambda x: x[1])[0]
        flagged = [t for t in self.transactions if t['channel'] != most_common]
        
        if flagged and len(self.transactions) > 0:
            pct_different = (len(flagged) / len(self.transactions)) * 100
            if pct_different > 20:
                self.issues.append({
                    'rule': 'Unusual Channel Usage',
                    'severity': 'low',
                    'transactions': flagged,
                    'explanation': f"{len(flagged)} transactions ({pct_different:.0f}%) use different channel. Usual: {most_common}.",
                    'investigation': 'Verify if customer intentionally changed their preferred transaction method.'
                })
    
    def analyze(self):
        """Run all risk detection rules and return issues found."""
        self.detect_large_transfers()
        self.detect_burst_to_new_payees()
        self.detect_odd_hour_transactions()
        self.detect_unusual_channels()
        return self.issues


def parse_csv(csv_data):
    """
    Parse CSV data into transaction list.
    
    Args:
        csv_data (str): CSV formatted transaction data
        
    Returns:
        list: Parsed transactions with computed fields
        
    Raises:
        ValueError: If CSV format is invalid or data is malformed
    """
    try:
        reader = csv.DictReader(io.StringIO(csv_data))
        transactions = []
        required_fields = ['date', 'description', 'payee', 'amount', 'channel']
        
        for idx, row in enumerate(reader, 1):
            if not row or not any(row.values()):
                continue
                
            if not all(field in row for field in required_fields):
                missing = [f for f in required_fields if f not in row]
                raise ValueError(f"Row {idx}: Missing fields: {', '.join(missing)}")
            
            try:
                date_obj = datetime.strptime(row['date'].strip(), '%Y-%m-%d')
                amount = float(row['amount'].strip())
            except ValueError as e:
                raise ValueError(f"Row {idx}: Invalid date or amount format - {str(e)}")
            
            transactions.append({
                'date': row['date'].strip(),
                'description': row['description'].strip(),
                'payee': row['payee'].strip(),
                'amount': amount,
                'channel': row['channel'].strip(),
                'hour': date_obj.hour,
                'dow': date_obj.strftime('%A'),
            })
        
        if not transactions:
            raise ValueError("No valid transactions found in CSV data")
        
        return transactions
        
    except csv.Error as e:
        raise ValueError(f"CSV parsing error: {str(e)}")
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Unexpected error parsing CSV: {str(e)}")


def generate_report(issues, transactions):
    """
    Generate HTML investigation report from analysis results.
    
    Args:
        issues (list): List of detected risk issues
        transactions (list): Original transaction data
        
    Returns:
        str: HTML formatted report
    """
    from html import escape
    
    html = ""
    
    # Summary
    if not issues:
        html += '<div class="summary safe">✓ No issues found – activity appears routine</div>'
    else:
        html += '<div class="summary alert">⚠ Activity requires attention – see details below</div>'
    
    # Issue details
    for issue in issues:
        html += '<div class="issue">'
        html += f'<h3>{escape(issue["rule"])}</h3>'
        
        # Transactions table
        html += '<table class="txn-table"><tr><th>Date</th><th>Payee</th><th>Amount</th><th>Channel</th><th>Time</th></tr>'
        for txn in issue['transactions']:
            html += f'<tr><td>{escape(txn["date"])}</td><td>{escape(txn["payee"])}</td><td>${txn["amount"]:.2f}</td><td>{escape(txn["channel"])}</td><td>{txn["hour"]:02d}:00</td></tr>'
        html += '</table>'
        
        # Rule and explanation
        html += f'<div class="rule-label">Rule: {escape(issue["rule"])}</div>'
        html += f'<div class="explanation"><strong>Analysis:</strong> {escape(issue["explanation"])}</div>'
        html += f'<div class="investigation"><strong>Next Steps:</strong> {escape(issue["investigation"])}</div>'
        
        html += '</div>'
    
    return html


@app.route('/')
def index():
    """Serve the main application page."""
    return render_template_string(HTML_TEMPLATE)


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    API endpoint for transaction analysis.
    
    Expected JSON body: { "csv_data": "date,payee,..." }
    Returns: { "report": "<html>" } or { "error": "message" }
    """
    try:
        # Get and validate request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON request'}), 400
            
        csv_data = data.get('csv_data', '').strip()
        
        if not csv_data:
            return jsonify({'error': 'No CSV data provided'}), 400
        
        # Parse transactions
        transactions = parse_csv(csv_data)
        
        # Run analysis
        analyzer = TransactionAnalyzer(transactions)
        issues = analyzer.analyze()
        
        # Generate report
        report_html = generate_report(issues, transactions)
        
        return jsonify({'report': report_html}), 200
    
    except ValueError as e:
        # CSV parsing or validation error
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        # Unexpected server error
        app.logger.error(f"Analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred during analysis'}), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors."""
    app.logger.error(f"Server error: {str(error)}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("Transaction Risk Detection System")
    print("=" * 60)
    print(f"Starting Flask application...")
    print(f"Access the app at: http://localhost:8000")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    app.run(
        host='localhost',
        port=8000,
        debug=False,
        use_reloader=False
    )
