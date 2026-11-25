"""
Live HTTP Probe and Health Check Script for Satark Setu.
Checks all pages, APIs, and error routes.
"""

import urllib.request
import urllib.error
import json
import time

BASE = 'http://127.0.0.1:5000'
results = []

def test_get(path, name):
    t0 = time.perf_counter()
    try:
        resp = urllib.request.urlopen(f'{BASE}{path}')
        ms = (time.perf_counter() - t0) * 1000
        code = resp.getcode()
        results.append((name, code, f'{ms:.1f}ms', 'PASS' if code == 200 else 'FAIL'))
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        is_pass = (e.code == 404 and '404' in name)
        results.append((name, e.code, f'{ms:.1f}ms', 'PASS' if is_pass else 'FAIL'))
    except Exception as e:
        results.append((name, 'ERR', str(e), 'FAIL'))

def test_post(path, name, payload):
    t0 = time.perf_counter()
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(f'{BASE}{path}', data=data, headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req)
        ms = (time.perf_counter() - t0) * 1000
        code = resp.getcode()
        body = json.loads(resp.read().decode('utf-8'))
        ok = body.get('success', False)
        results.append((name, code, f'{ms:.1f}ms', 'PASS' if code == 200 and ok else 'FAIL'))
        return body
    except Exception as e:
        results.append((name, 'ERR', str(e), 'FAIL'))
        return None

def main():
    # Test Views
    test_get('/', 'Page: Home')
    test_get('/detector', 'Page: Detector')
    test_get('/upi-guard', 'Page: UPI Guard')
    test_get('/url-scanner', 'Page: URL Scanner')
    test_get('/emergency', 'Page: Emergency')
    test_get('/dashboard', 'Page: Dashboard')
    test_get('/about', 'Page: About')
    test_get('/nonexistent-test-404', 'Page: Custom 404')

    # Test APIs
    body1 = test_post('/api/detect', 'API: Detect Legit DLT Bank', {
        'sender': 'AD-HDFCBK',
        'text': 'Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank',
        'lang': 'en'
    })

    body2 = test_post('/api/detect', 'API: Detect Mobile Scam', {
        'sender': '+91 9876543210',
        'text': 'Your bank account will be blocked today. Update your KYC immediately using this link: http://sbi-kyc-verify.top',
        'lang': 'en'
    })

    body3 = test_post('/api/upi-guard', 'API: UPI PIN Trap Check', {
        'text': 'Enter your UPI PIN to claim cashback of Rs 2500 in PhonePe',
        'vpa': 'cashback@paytm',
        'amount': '2500',
        'lang': 'en'
    })

    body4 = test_post('/api/url-scan', 'API: URL Phishing Scan', {
        'url': 'http://sbi-kyc-verify.top/update.php',
        'lang': 'en'
    })

    body5 = test_post('/api/emergency', 'API: Emergency Triage', {
        'scenario': 'shared_otp',
        'lang': 'en'
    })

    test_get('/api/dashboard', 'API: Dashboard Metrics')
    test_get('/api/sample-messages', 'API: Sample Messages')

    print('=' * 68)
    print(f'{"TARGET":<30} {"STATUS":<8} {"LATENCY":<12} {"RESULT"}')
    print('=' * 68)
    for name, code, lat, res in results:
        print(f'{name:<30} {str(code):<8} {lat:<12} {res}')
    print('=' * 68)

    if body1:
        d1 = body1['data']
        bm1 = d1.get('bank_metadata') or {}
        print(f'Legit Bank Test: Risk={d1["risk_level"]} ({d1["risk_score"]}/100) | Classification={bm1.get("classification")} | IsSpam={bm1.get("is_spam")}')

    if body2:
        d2 = body2['data']
        bm2 = d2.get('bank_metadata') or {}
        print(f'Mobile Scam Test: Risk={d2["risk_level"]} ({d2["risk_score"]}/100) | Classification={bm2.get("classification")} | IsSpam={bm2.get("is_spam")}')

if __name__ == '__main__':
    main()

