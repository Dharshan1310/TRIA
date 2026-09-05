"""
Transaction Risk Detection System
A Flask-based application for analyzing customer transactions and detecting unusual activity patterns.
"""

from flask import Flask, render_template_string, request, jsonify, send_file, session, redirect, url_for
import csv
import json
from datetime import datetime, date
from collections import Counter
import io
import os
import re
from html import escape
from pypdf import PdfReader
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'tria-development-secret-change-me')
EMPLOYEE_USERNAME = os.getenv('EMPLOYEE_USERNAME', 'employee')
EMPLOYEE_PASSWORD = os.getenv('EMPLOYEE_PASSWORD', 'tria2024')
EMPLOYEES_FILE = os.path.join(os.path.dirname(__file__), 'employees.json')
API_KEY = os.getenv('API_KEY', 'not-configured')
DEFAULT_RULES = {
    'large_transfer_multiplier': 2.5,
    'odd_hour_end': 6,
    'new_payee_count': 2,
    'enabled_rules': ['large_transfer', 'new_payee', 'odd_hour', 'channel'],
}
RULES = DEFAULT_RULES.copy()
RULES_UPDATED_AT = None


def load_employee_accounts():
    """Load registered employees, falling back to the configured initial account."""
    try:
        with open(EMPLOYEES_FILE, 'r', encoding='utf-8') as employee_file:
            accounts = json.load(employee_file)
            return accounts if isinstance(accounts, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {EMPLOYEE_USERNAME: generate_password_hash(EMPLOYEE_PASSWORD)}


def save_employee_accounts(accounts):
    """Persist only password hashes, never plaintext passwords."""
    with open(EMPLOYEES_FILE, 'w', encoding='utf-8') as employee_file:
        json.dump(accounts, employee_file, indent=2)

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TRIA | Employee access</title>
    <style>
        :root { color-scheme: dark; font-family: Georgia, 'Times New Roman', serif; background: #111916; color: #edf4ef; }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: radial-gradient(circle at 15% 15%, #20453c, transparent 36%), linear-gradient(135deg, #111916, #1c2c29); }
        main { width: min(440px, 100%); padding: 42px; border: 1px solid #48695e; background: rgba(20, 33, 29, .92); box-shadow: 0 24px 70px rgba(0,0,0,.3); }
        .mark { color: #b9d66f; font: 700 12px Arial, sans-serif; letter-spacing: .2em; }
        h1 { font-size: 40px; line-height: 1; margin: 28px 0 10px; }
        p { color: #b8c8c0; font: 14px Arial, sans-serif; line-height: 1.6; }
        label { display: block; margin: 24px 0 8px; color: #dce9df; font: 700 12px Arial, sans-serif; text-transform: uppercase; letter-spacing: .08em; }
        input { width: 100%; padding: 14px; color: #f4fbf5; background: #0d1513; border: 1px solid #527267; font: 15px Arial, sans-serif; }
        input:focus { outline: 2px solid #b9d66f; outline-offset: 2px; }
        button { width: 100%; margin-top: 28px; padding: 15px; border: 0; background: #b9d66f; color: #142019; font: 700 13px Arial, sans-serif; letter-spacing: .08em; text-transform: uppercase; cursor: pointer; transition: transform .2s, background .2s; }
        button:hover { transform: translateY(-2px); background: #d5ed8e; }
        .error { margin-top: 18px; padding: 12px; border-left: 3px solid #f0a078; background: #3b2521; color: #ffc4a9; font: 13px Arial, sans-serif; }
        .success { margin-top: 18px; padding: 12px; border-left: 3px solid #b9d66f; background: #263d2c; color: #d5ed8e; font: 13px Arial, sans-serif; }
        .hint { margin-top: 24px; font-size: 12px; color: #829a8f; }
    </style>
</head>
<body><main>
    <div class="mark">TRIA / OPERATIONS</div>
    <h1>Welcome back.</h1>
    <p>Sign in to review transaction activity and move the next investigation forward.</p>
    <form method="post">
        <label for="username">Employee ID</label><input id="username" name="username" autocomplete="username" required autofocus>
        <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Enter workspace</button>
    </form>
    {% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}
    {% if created %}<div class="success" role="status">Account created. You can sign in now.</div>{% endif %}
    <p class="hint"><a href="{{ url_for('register') }}">Create a new employee account</a></p>
    <p class="hint">Protected employee workspace · Authorized access only</p>
</main></body>
</html>
"""

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>TRIA | Create account</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: linear-gradient(135deg, #111916, #1c2c29); color: #edf4ef; font-family: Arial, sans-serif; }
main { width: min(440px, 100%); padding: 42px; border: 1px solid #48695e; background: #14211d; box-shadow: 0 24px 70px rgba(0,0,0,.3); } h1 { font: 700 36px Georgia, serif; margin: 22px 0 8px; } p { color: #b8c8c0; line-height: 1.5; } label { display: block; margin: 20px 0 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; } input { width: 100%; padding: 14px; box-sizing: border-box; background: #0d1513; border: 1px solid #527267; color: white; } button { width: 100%; margin-top: 26px; padding: 15px; border: 0; background: #b9d66f; color: #142019; font-weight: 700; cursor: pointer; } a { color: #b9d66f; } .error { padding: 12px; margin-top: 18px; border-left: 3px solid #f0a078; background: #3b2521; color: #ffc4a9; }
</style></head><body><main><div style="color:#b9d66f;font-size:12px;font-weight:700;letter-spacing:.2em">TRIA / OPERATIONS</div><h1>Create employee account.</h1><p>Set up a secure ID for the transaction intelligence workspace.</p><form method="post"><label for="username">Employee ID</label><input id="username" name="username" minlength="3" maxlength="40" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" minlength="8" required><label for="confirm_password">Confirm password</label><input id="confirm_password" name="confirm_password" type="password" minlength="8" required><button type="submit">Create account</button></form>{% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}<p><a href="{{ url_for('login') }}">Back to employee login</a></p></main></body></html>
"""

# Minimalistic HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRIA | Operations overview</title>
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
        .baseline-panel { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 16px 0; }
        .baseline-panel div { background: #ecfeff; border: 1px solid #a5f3fc; padding: 13px; border-radius: 6px; }
        .baseline-panel span, .baseline-panel strong { display: block; }
        .baseline-panel span { color: #155e75; font-size: 12px; margin-bottom: 7px; }
        .baseline-panel strong { color: #164e63; font-size: 15px; }
        .rule-grid, .filter-bar { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
        .rule-grid input, .filter-bar input, .filter-bar select { width: 100%; padding: 9px; border: 1px solid #d1d5db; border-radius: 6px; }
        .rule-help, .history { font-size: 12px; color: #64748b; margin-top: 9px; }
        .report-tools { display: flex; justify-content: space-between; gap: 12px; align-items: end; margin: 0 0 20px; }
        .filter-bar { flex: 1; }
        .history-item { padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
        @media (max-width: 650px) { .baseline-panel, .rule-grid, .filter-bar { grid-template-columns: 1fr; } .report-tools { align-items: stretch; flex-direction: column; } }
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
        :root { --ink: #17231f; --muted: #687872; --paper: #f5f7f2; --panel: #ffffff; --line: #dce4dc; --green: #286b59; --lime: #b8d96a; --coral: #e67d5f; }
        body { font-family: Arial, sans-serif; background: var(--paper); color: var(--ink); transition: background .25s, color .25s; }
        .app-shell { display: flex; min-height: 100vh; }
        .sidebar { width: 248px; flex: 0 0 248px; padding: 28px 18px; background: #18352e; color: #dcebe2; display: flex; flex-direction: column; }
        .brand { padding: 0 14px 30px; border-bottom: 1px solid #3d6155; }
        .brand strong { display: block; font: 800 28px Georgia, serif; letter-spacing: .08em; color: #f2f7eb; }
        .brand span { display: block; margin-top: 7px; font-size: 10px; letter-spacing: .18em; color: var(--lime); }
        .menu-label { margin: 28px 14px 10px; font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: #91afa2; }
        .nav-btn { width: 100%; padding: 12px 14px; border: 0; border-left: 3px solid transparent; text-align: left; color: #bdd0c6; background: transparent; font-weight: 700; cursor: pointer; transition: background .2s, color .2s, border .2s; }
        .nav-btn:hover, .nav-btn.active { background: #285247; border-left-color: var(--lime); color: white; }
        .sidebar-footer { margin-top: auto; padding: 16px 14px 0; border-top: 1px solid #3d6155; font-size: 12px; color: #9ab4a8; }
        .sidebar-footer strong { display: block; color: #edf5e9; margin-bottom: 12px; }
        .sidebar-footer form { margin: 0; }
        .logout { padding: 0; color: #b9d66f; background: none; font-size: 12px; }
        .container { width: min(1180px, 100%); max-width: none; margin: 0; padding: 0 44px 60px; }
        header { display: flex; justify-content: space-between; align-items: end; padding: 42px 0 26px; margin-bottom: 30px; border-bottom: 1px solid var(--line); }
        header h1 { color: var(--ink); font: 800 38px Georgia, serif; letter-spacing: -.02em; }
        header p { color: var(--muted); }
        .top-actions { display: flex; gap: 8px; align-items: center; }
        .icon-btn { width: 38px; height: 38px; padding: 0; background: var(--panel); border: 1px solid var(--line); color: var(--ink); }
        .icon-btn:hover { background: #e7efe3; }
        .hero-strip { display: grid; grid-template-columns: 1fr 1.25fr; gap: 16px; margin-bottom: 18px; }
        .welcome-panel, .next-panel { padding: 25px; border: 1px solid var(--line); background: var(--panel); box-shadow: 0 12px 28px rgba(31, 67, 53, .07); }
        .welcome-panel { background: #dcebd6; }
        .welcome-panel h2, .next-panel h2 { margin: 7px 0 8px; font: 700 25px Georgia, serif; }
        .welcome-panel p, .next-panel p { margin: 0; line-height: 1.5; }
        .next-panel { display: flex; align-items: center; gap: 18px; }
        .next-number { display: grid; place-items: center; flex: 0 0 48px; height: 48px; border-radius: 50%; background: var(--coral); color: white; font: 800 21px Georgia, serif; }
        .next-panel .eyebrow { color: var(--green); }
        .card { border: 1px solid var(--line); border-radius: 2px; background: var(--panel); box-shadow: 0 12px 28px rgba(31, 67, 53, .07); }
        .btn-primary { background: var(--green); }
        .btn-primary:hover { background: #1e5546; }
        .btn-secondary { background: #edf2eb; color: var(--ink); }
        textarea, input[type=file], .rule-grid input, .filter-bar input, .filter-bar select { background: var(--panel); color: var(--ink); border-color: var(--line); }
        .eyebrow { color: var(--green); }
        .mobile-menu { display: none; }
        @media (max-width: 820px) { .sidebar { width: 210px; flex-basis: 210px; } .container { padding: 0 24px 40px; } .hero-strip { grid-template-columns: 1fr; } }
        @media (max-width: 650px) { .app-shell { display: block; } .sidebar { display: none; position: fixed; z-index: 5; inset: 0 auto 0 0; width: 250px; } .sidebar.open { display: flex; } .mobile-menu { display: inline-block; } .container { padding: 0 16px 36px; } header { align-items: start; padding: 24px 0 20px; } header h1 { font-size: 30px; } .top-actions { flex-shrink: 0; } }
        body.dark { --ink: #e9f2e9; --muted: #a2b5aa; --paper: #101916; --panel: #192620; --line: #34483f; --green: #78b79f; --lime: #c8e47a; }
        body.dark .sidebar { background: #0a1210; } body.dark .welcome-panel { background: #203a31; } body.dark .btn-secondary, body.dark .icon-btn { background: #22332d; color: var(--ink); }
    </style>
</head>
<body>
    <div class="app-shell">
    <aside class="sidebar" id="sidebar">
        <div class="brand"><strong>TRIA</strong><span>TRANSACTION INTELLIGENCE</span></div>
        <div class="menu-label">Workspace</div>
        <button class="nav-btn active" onclick="showWorkspace('input-section', this)">Overview</button>
        <button class="nav-btn" onclick="focusInput('csv-file', this)">New investigation</button>
        <button class="nav-btn" onclick="showWorkspace('history-anchor', this)">Investigation history</button>
        <div class="menu-label">System</div>
        <button class="nav-btn" onclick="toggleTheme()">Appearance <span id="theme-label">Light</span></button>
        <div class="sidebar-footer"><strong>{{ session.get('employee_username', 'Employee') }}</strong><span>Risk operations desk</span><form method="post" action="{{ url_for('logout') }}"><button class="logout" type="submit">Sign out</button></form></div>
    </aside>
    <main class="container">
        <header>
            <div><button class="icon-btn mobile-menu" onclick="toggleMenu()" aria-label="Open menu">☰</button><h1>Operations overview</h1><p>Review activity, surface risk, and decide what happens next.</p></div>
            <div class="top-actions"><button class="icon-btn" onclick="toggleTheme()" aria-label="Toggle dark mode" title="Toggle dark mode">◐</button></div>
        </header>
        <div class="hero-strip">
            <section class="welcome-panel"><span class="eyebrow">TODAY'S DESK</span><h2>Clarity before action.</h2><p>Use the review engine to turn raw transaction activity into a defensible next step.</p></section>
            <section class="next-panel"><div class="next-number">1</div><div><span class="eyebrow">RECOMMENDED NEXT ACTION</span><h2>Start a new investigation</h2><p>Upload a transaction file or paste activity to establish a customer baseline.</p></div></section>
        </div>
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

            <div class="form-group">
                <label>Rule modification</label>
                <div class="rule-grid">
                    <div><label><input id="rule-large" type="checkbox" checked> Large transfer rule</label><input id="large-rule" type="number" min="1.1" max="10" step="0.1" value="2.5"></div>
                    <div><label><input id="rule-payee" type="checkbox" checked> New payee rule</label><input id="payee-rule" type="number" min="2" max="10" step="1" value="2"></div>
                    <div><label><input id="rule-odd" type="checkbox" checked> Odd-hour rule</label><input id="odd-rule" type="number" min="1" max="12" step="1" value="6"></div>
                </div>
                <div class="rule-grid"><div><label><input id="rule-channel" type="checkbox" checked> Unusual channel rule</label><input value="Uses the customer’s most common channel" disabled></div></div>
                <div class="rule-help">Enable or disable complete fraud rules and edit their criteria. Rules can be changed once per day.</div>
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
                    <button class="btn-primary" onclick="newInvestigation()">+ New investigation</button>
                </div>
                <div class="report-tools">
                    <div class="filter-bar">
                        <input id="filter-date" type="date" onchange="filterReport()" aria-label="Filter by date">
                        <input id="filter-amount" type="number" min="0" placeholder="Minimum amount" oninput="filterReport()" aria-label="Filter by amount">
                        <select id="filter-rule" onchange="filterReport()"><option value="">All risk rules</option></select>
                    </div>
                    <button class="btn-secondary" onclick="rerunWithRules()">Rerun with new rules</button>
                    <button class="btn-secondary" onclick="exportReport()">Export PDF</button>
                </div>
                <div id="report-content"></div>
                <div class="history" id="history-anchor"><strong>Investigation history</strong><div id="history-list"></div></div>
            </div>
        </div>
    </main></div>

    <script>
        let currentCsvData = '';
        let currentRules = {};
        let investigations = [];

        function toggleTheme() {
            document.body.classList.toggle('dark');
            const isDark = document.body.classList.contains('dark');
            localStorage.setItem('tria-theme', isDark ? 'dark' : 'light');
            document.getElementById('theme-label').textContent = isDark ? 'Dark' : 'Light';
        }

        function toggleMenu() {
            document.getElementById('sidebar').classList.toggle('open');
        }

        function showWorkspace(sectionId, button) {
            if (sectionId === 'history-anchor' && document.getElementById('report-section').classList.contains('hidden')) {
                showError('Complete an investigation first to view its history.');
                return;
            }
            document.querySelectorAll('.nav-btn').forEach(item => item.classList.remove('active'));
            button.classList.add('active');
            document.getElementById(sectionId).scrollIntoView({behavior: 'smooth', block: 'start'});
            toggleMenu();
        }

        function focusInput(inputId, button) {
            showWorkspace('input-section', button);
            document.getElementById(inputId).focus();
        }

        function showError(message) {
            const errorDiv = document.getElementById('error-msg');
            errorDiv.textContent = message;
            errorDiv.classList.add('show');
            errorDiv.scrollIntoView({behavior: 'smooth', block: 'center'});
        }

        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('tria-theme') === 'dark') toggleTheme();
        });

        function readRules() {
            return {
                large_transfer_multiplier: Number(document.getElementById('large-rule').value),
                odd_hour_end: Number(document.getElementById('odd-rule').value),
                new_payee_count: Number(document.getElementById('payee-rule').value),
                enabled_rules: ['large', 'payee', 'odd', 'channel'].filter(rule => document.getElementById('rule-' + rule).checked).map(rule => ({large: 'large_transfer', payee: 'new_payee', odd: 'odd_hour', channel: 'channel'})[rule])
            };
        }

        function showReport(data) {
            currentRules = data.rules || readRules();
            if (!currentCsvData && data.transactions) {
                currentCsvData = 'date,description,payee,amount,channel\\n' + data.transactions.map(txn => [txn.date, txn.description, txn.payee, txn.amount, txn.channel].map(value => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\\n');
            }
            investigations.push({time: data.generated_at, report: data.report, issues: data.issues || []});
            document.getElementById('report-content').innerHTML = data.report;
            document.getElementById('input-section').classList.add('hidden');
            document.getElementById('report-section').classList.remove('hidden');
            const ruleSelect = document.getElementById('filter-rule');
            ruleSelect.innerHTML = '<option value="">All risk rules</option>' + (data.issues || []).map(issue => `<option value="${issue.rule}">${issue.rule}</option>`).join('');
            renderHistory();
            window.scrollTo(0, 0);
        }

        function analyzeTransactions() {
            const pastedText = document.getElementById('csv-text').value.trim();
            const selectedFile = document.getElementById('csv-file').files[0];
            const errorDiv = document.getElementById('error-msg');
            errorDiv.classList.remove('show');

            if (!pastedText && !selectedFile) {
                showError('Please upload a CSV, PDF, or text file, or paste transaction data.');
                return;
            }

            document.getElementById('loading').style.display = 'block';
            const formData = new FormData();
            if (selectedFile) formData.append('file', selectedFile);
            if (pastedText) formData.append('text_data', pastedText);
            formData.append('rules', JSON.stringify(readRules()));
            currentCsvData = pastedText;

            fetch('/analyze', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                if (data.error) {
                    showError(data.error);
                } else {
                    showReport(data);
                }
            })
            .catch(err => {
                document.getElementById('loading').style.display = 'none';
                showError('We could not complete the analysis. Please check the input and try again.');
            });
        }

        function filterReport() {
            const date = document.getElementById('filter-date').value;
            const minimum = Number(document.getElementById('filter-amount').value || 0);
            const rule = document.getElementById('filter-rule').value;
            document.querySelectorAll('#report-content .issue').forEach(issue => {
                const matchesRule = !rule || issue.querySelector('h3').textContent === rule;
                const rows = [...issue.querySelectorAll('tbody tr, tr')].slice(1);
                const matchesTransaction = !date && !minimum || rows.some(row => {
                    const cells = row.querySelectorAll('td');
                    return cells.length && (!date || cells[0].textContent.startsWith(date)) && (!minimum || Number(cells[2].textContent.replace(/[^0-9.-]/g, '')) >= minimum);
                });
                issue.style.display = matchesRule && matchesTransaction ? '' : 'none';
            });
        }

        function exportReport() {
            const form = new FormData();
            form.append('text_data', currentCsvData);
            form.append('rules', JSON.stringify(currentRules));
            fetch('/export-pdf', {method: 'POST', body: form}).then(response => response.blob()).then(blob => {
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a'); link.href = url; link.download = 'tria-risk-report.pdf'; link.click(); URL.revokeObjectURL(url);
            });
        }

        function newInvestigation() {
            document.getElementById('report-section').classList.add('hidden');
            document.getElementById('input-section').classList.remove('hidden');
            clearForm();
        }

        function rerunWithRules() {
            fetch('/rerun', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csv_data: currentCsvData, rules: readRules()})})
                .then(r => r.json()).then(data => data.error ? alert(data.error) : showReport(data));
        }

        function renderHistory() {
            const stored = JSON.parse(localStorage.getItem('tria-history') || '[]');
            const all = [...stored, ...investigations.map(item => ({time: item.time}))].slice(-8).reverse();
            localStorage.setItem('tria-history', JSON.stringify(all));
            document.getElementById('history-list').innerHTML = all.map(item => `<div class="history-item">${item.time || 'Unknown time'}</div>`).join('');
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
    
    def __init__(self, transactions, rules=None):
        """Initialize analyzer with transaction data."""
        self.transactions = transactions
        self.rules = {**DEFAULT_RULES, **(rules or {})}
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
        threshold = max(avg * self.rules['large_transfer_multiplier'], median * 3)
        
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
        
        if len(one_time_payees) >= self.rules['new_payee_count']:
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
            
        odd_hours = [t for t in self.transactions if t['hour'] < self.rules['odd_hour_end']]
        
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
        if 'large_transfer' in self.rules['enabled_rules']:
            self.detect_large_transfers()
        if 'new_payee' in self.rules['enabled_rules']:
            self.detect_burst_to_new_payees()
        if 'odd_hour' in self.rules['enabled_rules']:
            self.detect_odd_hour_transactions()
        if 'channel' in self.rules['enabled_rules']:
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
    normal_average = (sum(txn['amount'] for txn in transactions) / len(transactions)) if transactions else 0
    normal_channel = Counter(txn['channel'] for txn in transactions).most_common(1)
    normal_channel = normal_channel[0][0] if normal_channel else 'n/a'

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
    <div class="baseline-panel"><div><span>Normal activity baseline</span><strong>Average ${normal_average:,.2f}</strong></div><div><span>Typical channel</span><strong>{escape(normal_channel)}</strong></div><div><span>Comparison</span><strong>Flagged items are shown against this baseline</strong></div></div>
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
    if not session.get('employee_authenticated'):
        return redirect(url_for('login'))
    return render_template_string(HTML_TEMPLATE)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate an employee before opening the investigation workspace."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        accounts = load_employee_accounts()
        valid_password = username in accounts and check_password_hash(accounts[username], password)
        if valid_password or (username == EMPLOYEE_USERNAME and password == EMPLOYEE_PASSWORD):
            session['employee_authenticated'] = True
            session['employee_username'] = username
            return redirect(url_for('index'))
        return render_template_string(LOGIN_TEMPLATE, error='The employee ID or password is incorrect.', created=False), 401
    return render_template_string(LOGIN_TEMPLATE, error=None, created=request.args.get('created') == '1')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Create a persistent employee account with a hashed password."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirmation = request.form.get('confirm_password', '')
        if not re.fullmatch(r'[A-Za-z0-9._-]{3,40}', username):
            error = 'Employee ID must be 3-40 characters and use letters, numbers, dots, underscores, or hyphens.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif password != confirmation:
            error = 'Passwords do not match.'
        else:
            accounts = load_employee_accounts()
            if username in accounts or username == EMPLOYEE_USERNAME:
                error = 'That employee ID is already registered.'
            else:
                accounts[username] = generate_password_hash(password)
                save_employee_accounts(accounts)
                return redirect(url_for('login', created='1'))
        return render_template_string(REGISTER_TEMPLATE, error=error), 400
    return render_template_string(REGISTER_TEMPLATE, error=None)


@app.route('/logout', methods=['POST'])
def logout():
    """End the employee session."""
    session.clear()
    return redirect(url_for('login'))


@app.before_request
def require_employee_for_api():
    """Keep direct analysis and export calls inside the employee session."""
    protected_api_paths = {'/analyze', '/rerun', '/export-pdf'}
    if request.path in protected_api_paths and not session.get('employee_authenticated'):
        return jsonify({'error': 'Employee login required.'}), 401


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
        
        rules = request.form.get('rules')
        rules = parse_rules(rules) if rules else RULES
        issues = TransactionAnalyzer(transactions, rules).analyze()
        
        # Generate report
        report_html = generate_report(issues, transactions)
        
        return jsonify({'report': report_html, 'transactions': transactions, 'issues': issues, 'generated_at': datetime.now().isoformat(timespec='seconds'), 'rules': rules}), 200
    
    except ValueError as e:
        # CSV parsing or validation error
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        # Unexpected server error
        app.logger.error(f"Analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred during analysis'}), 500


def parse_rules(raw_rules):
    """Validate the small set of user-editable rules."""
    if isinstance(raw_rules, dict):
        values = raw_rules
    else:
        values = json.loads(raw_rules or '{}')
    rules = DEFAULT_RULES.copy()
    rules['large_transfer_multiplier'] = min(10, max(1.1, float(values.get('large_transfer_multiplier', rules['large_transfer_multiplier']))))
    rules['odd_hour_end'] = min(12, max(1, int(values.get('odd_hour_end', rules['odd_hour_end']))))
    rules['new_payee_count'] = min(10, max(2, int(values.get('new_payee_count', rules['new_payee_count']))))
    enabled_rules = values.get('enabled_rules', rules['enabled_rules'])
    rules['enabled_rules'] = [rule for rule in enabled_rules if rule in {'large_transfer', 'new_payee', 'odd_hour', 'channel'}]
    return rules


def parse_request_transactions():
    """Read the same multipart or JSON input accepted by /analyze."""
    uploaded_file = request.files.get('file')
    if uploaded_file and uploaded_file.filename:
        if uploaded_file.filename.lower().endswith('.pdf'):
            return parse_pdf(uploaded_file)
        return parse_text(uploaded_file.read().decode('utf-8-sig'))
    data = request.get_json(silent=True) or {}
    text_data = request.form.get('text_data', '') or data.get('csv_data', '')
    if not text_data.strip():
        raise ValueError('Please provide transaction data.')
    return parse_text(text_data)


def build_pdf(transactions, issues):
    """Create a dependency-free, readable PDF summary for export."""
    lines = ['TRIA TRANSACTION RISK REPORT', f'Generated: {datetime.now().isoformat(timespec="seconds")}',
             f'Transactions reviewed: {len(transactions)}', f'Flagged transactions: {len({id(transaction) for issue in issues for transaction in issue["transactions"]})}',
             f'Total risk: {calculate_risk_percentage(issues)}%', '']
    for issue in issues:
        lines.append(f'{issue["severity"].upper()}: {issue["rule"]}')
        lines.append(issue['explanation'])
    if not issues:
        lines.append('No rules were broken. Activity appears routine.')
    lines = [line[:115] for line in lines]
    stream = 'BT /F1 10 Tf 50 760 Td ' + ' '.join(f'({line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")}) Tj 0 -16 Td' for line in lines) + ' ET'
    objects = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>', f'<< /Length {len(stream.encode("latin-1"))} >>\nstream\n{stream}\nendstream']
    pdf = b'%PDF-1.4\n'
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f'{index} 0 obj\n{obj}\nendobj\n'.encode('latin-1')
    xref = len(pdf)
    pdf += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode('latin-1')
    pdf += ''.join(f'{offset:010d} 00000 n \n' for offset in offsets[1:]).encode('latin-1')
    pdf += f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF'.encode('latin-1')
    return io.BytesIO(pdf)


@app.route('/rerun', methods=['POST'])
def rerun():
    """Re-analyze the current case with rules changed at most once per day."""
    global RULES, RULES_UPDATED_AT
    try:
        data = request.get_json(silent=True) or {}
        requested_rules = parse_rules(data.get('rules', {}))
        today = date.today().isoformat()
        if RULES_UPDATED_AT and RULES_UPDATED_AT != today:
            RULES_UPDATED_AT = None
        if RULES_UPDATED_AT == today and requested_rules != RULES:
            return jsonify({'error': 'Rules can be changed once per day. You can still rerun with today\'s rules.'}), 429
        if requested_rules != RULES:
            RULES = requested_rules
            RULES_UPDATED_AT = today
        transactions = parse_text(data.get('csv_data', ''))
        issues = TransactionAnalyzer(transactions, RULES).analyze()
        return jsonify({'report': generate_report(issues, transactions), 'transactions': transactions, 'issues': issues, 'generated_at': datetime.now().isoformat(timespec='seconds'), 'rules': RULES})
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/export-pdf', methods=['POST'])
def export_pdf():
    try:
        transactions = parse_request_transactions()
        rules = parse_rules(request.form.get('rules', '{}'))
        issues = TransactionAnalyzer(transactions, rules).analyze()
        return send_file(build_pdf(transactions, issues), mimetype='application/pdf', as_attachment=True, download_name='tria-risk-report.pdf')
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


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
