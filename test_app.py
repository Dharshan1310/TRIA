"""
Quick functional tests for the transaction analysis system.
"""
import os
import tempfile
import app as app_module
from app import parse_csv, parse_text, TransactionAnalyzer, calculate_risk_percentage, generate_report, app

# Test CSV data
test_csv = """date,description,payee,amount,channel
2024-01-15,Transfer,John Smith,500.00,online
2024-01-15,Payment,Sarah Lee,100.00,online
2024-01-16,Withdrawal,ATM,5000.00,atm
2024-01-17,Payment,Unknown Vendor,3500.00,online
2024-01-17,Payment,Another New,2800.00,online
2024-01-18,Payment,Utility Co,125.50,branch
2024-01-18,Transfer,John Smith,520.00,online
2024-01-19,Payment,New Payee 1,1500.00,online
2024-01-20,Deposit,Employer,5500.00,online
2024-01-21,Payment,Regular Vendor,250.00,mobile"""

def run_tests():
    """Run functional tests."""
    print("=" * 60)
    print("Running Functional Tests")
    print("=" * 60)
    
    try:
        # Test 1: CSV Parsing
        print("\n[Test 1] CSV Parsing...")
        transactions = parse_csv(test_csv)
        assert len(transactions) == 10, f"Expected 10 transactions, got {len(transactions)}"
        assert all('date' in t for t in transactions), "Missing 'date' in transactions"
        assert all('amount' in t for t in transactions), "Missing 'amount' in transactions"
        print(f"✅ Successfully parsed {len(transactions)} transactions")
        
        # Test 2: Analysis
        print("\n[Test 2] Transaction Analysis...")
        analyzer = TransactionAnalyzer(transactions)
        issues = analyzer.analyze()
        print(f"✅ Analysis complete: {len(issues)} issues detected")
        
        # Test 3: Report Generation
        print("\n[Test 3] Report Generation...")
        report = generate_report(issues, transactions)
        assert isinstance(report, str), "Report should be a string"
        assert len(report) > 0, "Report should not be empty"
        assert "Activity requires attention" in report or "No issues found" in report, "Report format incorrect"
        print(f"✅ Report generated: {len(report)} characters")
        assert "Total risk" in report, "Report should show the total risk score"
        assert "Rules broken" in report, "Report should show the broken rules"
        
        # Test 4: Issue Details
        print("\n[Test 4] Issue Details...")
        if issues:
            issue = issues[0]
            assert 'rule' in issue, "Missing 'rule' in issue"
            assert 'transactions' in issue, "Missing 'transactions' in issue"
            assert 'explanation' in issue, "Missing 'explanation' in issue"
            assert 'investigation' in issue, "Missing 'investigation' in issue"
            print(f"✅ First issue details: {issue['rule']}")
        
        # Test 5: Error Handling
        print("\n[Test 5] Error Handling...")
        try:
            parse_csv("invalid,csv\nno dates here")
            print("❌ Should have raised ValueError for invalid CSV")
        except ValueError:
            print("✅ Correctly raises ValueError for invalid CSV")

        print("\n[Test 6] Alternate Input Formats...")
        text_transactions = parse_text("date\tdescription\tpayee\tamount\tchannel\n2024-01-15T03:30:00\tPayment\tNight Shop\t20\tonline")
        assert text_transactions[0]['hour'] == 3, "Timestamp hour should be preserved"
        pdf_style_transactions = parse_text("date  description  payee  amount  channel\n2024-01-15  Payment  Night Shop  20  online")
        assert len(pdf_style_transactions) == 1, "Fixed-width text should be parsed"
        assert calculate_risk_percentage([{'severity': 'high'}, {'severity': 'medium'}]) == 55
        assert calculate_risk_percentage([{'severity': 'high'}] * 4) == 100
        print("✅ Text parsing and risk score checks passed")

        print("\n[Test 7] Employee Authentication...")
        client = app.test_client()
        response = client.get('/', follow_redirects=False)
        assert response.status_code == 302 and response.headers['Location'].endswith('/login'), "Anonymous users should be sent to login"
        response = client.post('/login', data={'username': 'employee', 'password': 'wrong'}, follow_redirects=False)
        assert response.status_code == 401, "Invalid credentials should be rejected"
        response = client.post('/login', data={'username': 'employee', 'password': 'tria2024'}, follow_redirects=False)
        assert response.status_code == 302 and response.headers['Location'].endswith('/'), "Valid credentials should open workspace"
        response = client.get('/')
        assert b'Operations overview' in response.data and b'RECOMMENDED NEXT ACTION' in response.data, "Workspace shell should render"
        print("✅ Employee login and protected workspace work")

        print("\n[Test 8] Employee Registration...")
        original_employee_file = app_module.EMPLOYEES_FILE
        with tempfile.TemporaryDirectory() as temporary_directory:
            app_module.EMPLOYEES_FILE = os.path.join(temporary_directory, 'employees.json')
            response = client.post('/register', data={'username': 'new.employee', 'password': 'securepass', 'confirm_password': 'different'})
            assert response.status_code == 400 and b'Passwords do not match' in response.data, "Mismatched passwords should be rejected"
            response = client.post('/register', data={'username': 'new.employee', 'password': 'securepass', 'confirm_password': 'securepass'})
            assert response.status_code == 302 and response.headers['Location'].endswith('/login?created=1'), "Valid registration should redirect to login"
            client.post('/logout')
            response = client.post('/login', data={'username': 'new.employee', 'password': 'securepass'}, follow_redirects=False)
            assert response.status_code == 302, "New employee should be able to log in"
        app_module.EMPLOYEES_FILE = original_employee_file
        print("✅ New employee registration and login work")

        print("\n[Test 9] Multipart Text Upload...")
        response = client.post('/analyze', data={'text_data': test_csv}, content_type='multipart/form-data')
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.get_json()['report'], "Multipart report should not be empty"
        print("✅ Multipart upload works")
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return True
        
    except AssertionError as e:
        print(f"❌ Assertion failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
