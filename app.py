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
import re
from html import escape
from pypdf import PdfReader
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
        .container { max-width: 980px; margin: 0 auto; padding: 28px 20px; }
        header { text-align: left; padding: 24px 0 28px; border-bottom: 2px solid #e5e7eb; margin-bottom: 30px; }
        h1 { font-size: 34px; font-weight: 800; color: #12304a; }
        p { font-size: 14px; color: #6b7280; margin-top: 5px; }
        .card { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 28px; margin-bottom: 20px; box-shadow: 0 10px 24px rgba(18, 48, 74, 0.06); }
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
        .note { background: #eef8f7; border-left: 3px solid #0f766e; padding: 12px; border-radius: 4px; font-size: 13px; margin-top: 15px; color: #115e59; }
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
        .report-heading { display: flex; justify-content: space-between; gap: 24px; align-items: center; margin-bottom: 22px; }
        .report-heading h2 { font-size: 26px; color: #12304a; margin-top: 4px; }
        .eyebrow { color: #0f766e; font-size: 11px; font-weight: 800; letter-spacing: 1.4px; }
        .report-intro { margin-top: 8px; }
        .risk-score { min-width: 190px; padding: 18px 22px; border-radius: 10px; text-align: center; border: 1px solid #d1d5db; }
        .risk-score span, .risk-score small { display: block; font-size: 12px; font-weight: 700; }
        .risk-score strong { display: block; font-size: 52px; line-height: 1; margin: 7px 0; font-weight: 900; }
        .risk-score.safe { background: #ecfdf5; color: #166534; border-color: #86efac; }
        .risk-score.alert { background: #fff7ed; color: #9a3412; border-color: #fdba74; }
        .key-info { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 18px 0; }
        .key-info div { background: #f8fafc; border: 1px solid #e2e8f0; padding: 14px; border-radius: 6px; }
        .key-info span { display: block; color: #64748b; font-size: 12px; margin-bottom: 8px; }
        .key-info strong { font-size: 20px; color: #12304a; }
        .rules-broken { background: #f1f5f9; padding: 13px 15px; border-radius: 6px; font-size: 13px; margin-bottom: 22px; color: #334155; }
        .issue-title { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .severity { font-size: 11px; font-weight: 700; padding: 5px 8px; border-radius: 12px; text-transform: uppercase; }
        .severity.high { background: #fee2e2; color: #991b1b; }
        .severity.medium { background: #fef3c7; color: #92400e; }
        .severity.low { background: #dbeafe; color: #1e40af; }
        .back-btn { margin-bottom: 15px; }
        .loading { display: none; text-align: center; padding: 20px; }
        .spinner { display: inline-block; width: 24px; height: 24px; border: 3px solid #e5e7eb; border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (max-width: 650px) { .report-heading { align-items: stretch; flex-direction: column; } .risk-score { min-width: 0; } .key-info { grid-template-columns: repeat(2, 1fr); } .card { padding: 20px; } }
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
                <label for="csv-file">Upload a CSV, PDF, or text file</label>
                <input type="file" id="csv-file" accept=".csv,.pdf,.txt,text/csv,text/plain,application/pdf">
            </div>
            
            <div class="form-group">
                <label for="csv-text">Or paste transaction text</label>
                <textarea id="csv-text" placeholder="date,description,payee,amount,channel&#10;2024-01-15,Transfer,John Smith,500.00,online&#10;2024-01-16,Payment,Utility Co,125.50,online"></textarea>
            </div>

            <div class="note">
                <strong>Accepted:</strong> CSV, PDF, or plain text with date, description, payee, amount, and channel columns.
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
        function analyzeTransactions() {
            const pastedText = document.getElementById('csv-text').value.trim();
            const selectedFile = document.getElementById('csv-file').files[0];
            const errorDiv = document.getElementById('error-msg');
            errorDiv.classList.remove('show');

            if (!pastedText && !selectedFile) {
                errorDiv.textContent = 'Please upload a CSV, PDF, or text file, or paste transaction data.';
                errorDiv.classList.add('show');
                return;
            }

            document.getElementById('loading').style.display = 'block';
            const formData = new FormData();
            if (selectedFile) formData.append('file', selectedFile);
            if (pastedText) formData.append('text_data', pastedText);

            fetch('/analyze', {
                method: 'POST',
                body: formData
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
                errorDiv.textContent = 'We could not complete the analysis. Please check the input and try again.';
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
                date_value = row['date'].strip()
                date_obj = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
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


def parse_text(text_data):
    """Parse CSV, tab-separated, or pipe-separated transaction text."""
    cleaned = text_data.strip()
    if not cleaned:
        raise ValueError("The uploaded text is empty")

    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    if lines and ',' not in lines[0]:
        if '\t' in lines[0] or '|' in lines[0]:
            delimiter = '\t' if '\t' in lines[0] else '|'
            cleaned = '\n'.join(line.replace(delimiter, ',') for line in lines)
        elif any(re.search(r'\s{2,}', line) for line in lines):
            cleaned = '\n'.join(re.sub(r'\s{2,}', ',', line) for line in lines)
    return parse_csv(cleaned)


def parse_pdf(pdf_file):
    """Extract transaction text from a PDF and parse it as delimited data."""
    try:
        reader = PdfReader(pdf_file)
        text = '\n'.join(page.extract_text() or '' for page in reader.pages)
    except Exception as exc:
        raise ValueError(f"Could not read the PDF: {exc}") from exc

    if not text.strip():
        raise ValueError("The PDF does not contain readable transaction text")
    return parse_text(text)


def calculate_risk_percentage(issues):
    """Return a transparent, capped score from the rules that were broken."""
    severity_points = {'high': 35, 'medium': 20, 'low': 10}
    return min(100, sum(severity_points.get(issue.get('severity'), 0) for issue in issues))


def generate_report(issues, transactions):
    """
    Generate HTML investigation report from analysis results.
    
    Args:
        issues (list): List of detected risk issues
        transactions (list): Original transaction data
        
    Returns:
        str: HTML formatted report
    """
    risk_percentage = calculate_risk_percentage(issues)
    flagged_transactions = {id(txn) for issue in issues for txn in issue['transactions']}
    total_amount = sum(txn['amount'] for txn in transactions)
    rules = ', '.join(issue['rule'] for issue in issues) or 'None'
    status_class = 'safe' if not issues else 'alert'
    status_text = 'No rules were broken. Activity appears routine.' if not issues else 'Some activity needs attention. Please review the rules below.'

    html = f'''
    <div class="report-heading">
        <div><span class="eyebrow">FINAL RISK REPORT</span><h2>Transaction review</h2>
        <p class="report-intro">A clear summary of the submitted activity and the checks that were triggered.</p></div>
        <div class="risk-score {status_class}"><span>Total risk</span><strong>{risk_percentage}%</strong><small>Based on triggered rules</small></div>
    </div>
    <div class="summary {status_class}">{escape(status_text)}</div>
    <div class="key-info">
        <div><span>Transactions reviewed</span><strong>{len(transactions)}</strong></div>
        <div><span>Flagged transactions</span><strong>{len(flagged_transactions)}</strong></div>
        <div><span>Total amount</span><strong>${total_amount:,.2f}</strong></div>
        <div><span>Rules broken</span><strong>{len(issues)}</strong></div>
    </div>
    <div class="rules-broken"><strong>Rules broken:</strong> {escape(rules)}</div>
    '''
    
    # Summary
    if not issues:
        html += '<div class="summary safe">✓ No issues found – activity appears routine</div>'
    else:
        html += '<div class="summary alert">⚠ Activity requires attention – see details below</div>'
    
    # Issue details
    for issue in issues:
        html += '<div class="issue">'
        html += f'<div class="issue-title"><h3>{escape(issue["rule"])}</h3><span class="severity {escape(issue["severity"])}">{escape(issue["severity"].title())} priority</span></div>'
        
        # Transactions table
        html += '<table class="txn-table"><tr><th>Date</th><th>Payee</th><th>Amount</th><th>Channel</th><th>Time</th></tr>'
        for txn in issue['transactions']:
            html += f'<tr><td>{escape(txn["date"])}</td><td>{escape(txn["payee"])}</td><td>${txn["amount"]:.2f}</td><td>{escape(txn["channel"])}</td><td>{txn["hour"]:02d}:00</td></tr>'
        html += '</table>'
        
        # Rule and explanation
        html += f'<div class="rule-label">Rule: {escape(issue["rule"])}</div>'
        html += f'<div class="explanation"><strong>What we found:</strong> {escape(issue["explanation"])}</div>'
        html += f'<div class="investigation"><strong>Recommended next step:</strong> {escape(issue["investigation"])}</div>'
        
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
    
    Accepts multipart file uploads or JSON/text input.
    Returns: { "report": "<html>" } or { "error": "message" }
    """
    try:
        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename.lower()
            if filename.endswith('.pdf'):
                transactions = parse_pdf(uploaded_file)
            else:
                transactions = parse_text(uploaded_file.read().decode('utf-8-sig'))
        else:
            data = request.get_json(silent=True) or {}
            text_data = request.form.get('text_data', '') or data.get('csv_data', '')
            if not text_data.strip():
                return jsonify({'error': 'Please provide a CSV, PDF, or text file, or paste transaction data.'}), 400
            transactions = parse_text(text_data)
        
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
