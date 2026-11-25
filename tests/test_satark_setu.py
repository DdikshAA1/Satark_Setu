"""
Comprehensive Automated Test Suite for SATARK SETU.
Validates all 5 mandatory hackathon test scenarios (Section 10)
plus edge cases, privacy masking, Next Best Action plans, and Flask endpoints.
"""

import unittest
import json
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.detector import SmartScamDetector
from services.upi_guard import UPIFraudGuard
from services.url_scanner import URLSafetyScanner
from services.emergency import EmergencyResponseAssistant
from services.nba_engine import NextBestActionEngine
import database
from app import create_app

class TestSatarkSetu(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.app = create_app()
        cls.client = cls.app.test_client()

    # =========================================================================
    # MANDATORY HACKATHON TEST 1: Fake KYC & Account Block Threat
    # =========================================================================
    def test_01_urgent_kyc_and_block_threat(self):
        msg = "Your bank account will be blocked today. Update your KYC immediately using this link."
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH', "Test 1 must be HIGH risk")
        self.assertGreaterEqual(res['risk_score'], 65, "Score must be >= 65 for urgent KYC threat")
        self.assertIn('urgent_block_threat', res['indicators'])
        self.assertIn('kyc_update_demand', res['indicators'])
        self.assertEqual(res['category_key'], 'fake_kyc')
        self.assertIn('what_to_avoid', res['action_plan'])
        self.assertIn('immediate_actions', res['action_plan'])
        self.assertIn('if_already_interacted', res['action_plan'])

    # =========================================================================
    # MANDATORY HACKATHON TEST 2: Lottery & Advance Fee Fraud
    # =========================================================================
    def test_02_lottery_and_advance_fee(self):
        msg = "Congratulations! You won a lottery. Pay a processing fee to receive your prize."
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH', "Test 2 must be HIGH risk")
        self.assertGreaterEqual(res['risk_score'], 65)
        self.assertTrue('lottery_claim' in res['indicators'] or 'advance_fee_fraud' in res['indicators'])
        self.assertEqual(res['category_key'], 'lottery_prize')
        self.assertTrue(len(res['action_plan']['what_to_avoid']) > 0)

    # =========================================================================
    # MANDATORY HACKATHON TEST 3: UPI PIN to Receive Money
    # =========================================================================
    def test_03_upi_pin_to_receive_cashback(self):
        msg = "Enter your UPI PIN to receive your cashback."
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH', "Test 3 must be HIGH risk")
        self.assertIn('pin_to_receive', res['indicators'])
        self.assertEqual(res['category_key'], 'upi_pin_trap')

        # Also test via UPIFraudGuard service
        upi_res = UPIFraudGuard.evaluate_upi_request(msg, lang='en')
        self.assertEqual(upi_res['risk_level'], 'HIGH')
        self.assertIn('pin_to_receive', upi_res['indicators'])
        self.assertIn('CRITICAL SAFETY RULE', upi_res['golden_rule'])

    # =========================================================================
    # MANDATORY HACKATHON TEST 4: Legitimate Bank Notification (NO False Positive)
    # =========================================================================
    def test_04_legitimate_bank_transaction_alert(self):
        msg = "Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank"
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'LOW', "Legitimate transactional alerts must NOT be HIGH risk!")
        self.assertLessEqual(res['risk_score'], 35, "Score must remain in the LOW risk band (<= 35)")
        self.assertEqual(res['category_key'], 'legitimate_bank')

    # =========================================================================
    # MANDATORY HACKATHON TEST 5: Suspicious Misspelled URL / Typosquatting
    # =========================================================================
    def test_05_suspicious_url_typosquatting(self):
        url = "http://sbi-kyc-verify.top/login.php"
        res = URLSafetyScanner.scan_url(url, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH', "Typosquatted domain on .top must be HIGH risk")
        self.assertIn('brand_typosquatting', res['indicators'])
        self.assertIn('suspicious_tld', res['indicators'])
        self.assertIn('no_https', res['indicators'])

    # =========================================================================
    # ADDITIONAL TESTS: IP Hostname, Legitimate Domain, Digital Arrest
    # =========================================================================
    def test_06_url_ip_hostname(self):
        url = "http://192.168.1.105/paytm-rewards.apk"
        res = URLSafetyScanner.scan_url(url, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH')
        self.assertIn('ip_host', res['indicators'])
        self.assertIn('apk_download_prompt', res['indicators'])

    def test_07_legitimate_bank_url(self):
        url = "https://www.onlinesbi.sbi/portal/personal.html"
        res = URLSafetyScanner.scan_url(url, lang='en')

        self.assertEqual(res['risk_level'], 'LOW')
        self.assertLessEqual(res['risk_score'], 10)

    def test_08_digital_arrest_detection(self):
        msg = "Police notice: You are under digital arrest for money laundering. Join Skype interrogation immediately."
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH')
        self.assertEqual(res['category_key'], 'digital_arrest')
        self.assertIn('digital_arrest_claim', res['indicators'])

    def test_09_electricity_disconnection_threat(self):
        msg = "Dear consumer your electricity power will be disconnected tonight at 9.30 pm from electricity office. Call 9876543210."
        res = SmartScamDetector.analyze_message(msg, lang='en')

        self.assertEqual(res['risk_level'], 'HIGH')
        self.assertEqual(res['category_key'], 'electricity_threat')
        self.assertIn('utility_threat', res['indicators'])

    def test_10_empty_and_whitespace_inputs(self):
        res1 = SmartScamDetector.analyze_message("", lang='en')
        self.assertEqual(res1['risk_level'], 'LOW')

        res2 = UPIFraudGuard.evaluate_upi_request("   ", lang='en')
        self.assertEqual(res2['risk_level'], 'LOW')

        res3 = URLSafetyScanner.scan_url("", lang='en')
        self.assertEqual(res3['risk_level'], 'LOW')

    def test_11_hindi_localization(self):
        msg = "आपका बैंक खाता आज बंद हो जाएगा। तुरंत पैन कार्ड अपडेट करें।"
        res = SmartScamDetector.analyze_message(msg, lang='hi')

        self.assertEqual(res['risk_level'], 'HIGH')
        # Check that explanation and action plan contain Hindi text
        self.assertTrue(any('\u0900' <= char <= '\u097F' for char in res['explanation']))
        self.assertTrue(any('\u0900' <= char <= '\u097F' for char in res['action_plan']['why_suspicious']))

    def test_12_privacy_redaction_in_database(self):
        raw_msg = "Send OTP 948210 for card 4111 2222 3333 4444 to 9876543210"
        masked = database.mask_sensitive_text(raw_msg)

        self.assertNotIn('948210', masked)
        self.assertNotIn('4111 2222 3333 4444', masked)
        self.assertNotIn('9876543210', masked)
        self.assertIn('[REDACTED_CODE]', masked)

    def test_13_emergency_triage_all_scenarios(self):
        scenarios = ['clicked_link', 'shared_otp', 'shared_banking_info', 'approved_upi', 'money_lost', 'threat_call']
        for sc in scenarios:
            triage = EmergencyResponseAssistant.get_incident_triage(sc, lang='en')
            self.assertIn('step_by_step', triage)
            self.assertIn('evidence_checklist', triage)
            self.assertIn('official_hotlines', triage)
            self.assertGreaterEqual(len(triage['step_by_step']), 3)

    # =========================================================================
    # REST API INTEGRATION TESTS
    # =========================================================================
    def test_14_api_detect_endpoint(self):
        response = self.client.post('/api/detect', json={
            'text': 'Your bank account will be blocked today. Update your KYC immediately using this link.',
            'lang': 'en'
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['risk_level'], 'HIGH')

    def test_15_api_upi_guard_endpoint(self):
        response = self.client.post('/api/upi-guard', json={
            'text': 'Enter UPI PIN to receive cashback',
            'vpa': 'cashback@paytm',
            'amount': '500',
            'lang': 'en'
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['risk_level'], 'HIGH')

    def test_16_api_url_scan_endpoint(self):
        response = self.client.post('/api/url-scan', json={
            'url': 'http://sbi-kyc-verify.top',
            'lang': 'en'
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['risk_level'], 'HIGH')

    def test_17_api_dashboard_endpoint(self):
        response = self.client.get('/api/dashboard')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('total', data['data'])
        self.assertIn('high_risk', data['data'])
        self.assertIn('top_categories', data['data'])

    def test_18_html_views_render_successfully(self):
        routes = ['/', '/detector', '/upi-guard', '/url-scanner', '/emergency', '/dashboard', '/about']
        for route in routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed to render")

    # =========================================================================
    # BANK METADATA & TRAI DLT SENDER VERIFICATION TESTS (Spam vs Non-Spam)
    # =========================================================================
    def test_19_bank_metadata_dlt_legitimate_alert(self):
        sender = 'AD-HDFCBK'
        msg = 'Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank'
        res = SmartScamDetector.analyze_message(msg, lang='en', sender=sender)

        self.assertEqual(res['risk_level'], 'LOW', "Legitimate bank with verified DLT header must be LOW risk")
        self.assertLessEqual(res['risk_score'], 10, "Risk score must be minimal (<= 10)")
        self.assertIsNotNone(res['bank_metadata'])
        self.assertEqual(res['bank_metadata']['classification'], 'VERIFIED_LEGITIMATE_BANK_ALERT')
        self.assertFalse(res['bank_metadata']['is_spam'], "Legitimate DLT alert must be classified as Non-Spam")
        self.assertTrue(res['bank_metadata']['sender_analysis']['is_registered_bank_header'])
        self.assertEqual(res['bank_metadata']['sender_analysis']['bank_name'], 'HDFC Bank')
        self.assertTrue(res['bank_metadata']['extracted_metadata']['has_masked_account'])
        self.assertEqual(res['bank_metadata']['extracted_metadata']['account_number'], 'XX4589')
        self.assertEqual(res['bank_metadata']['extracted_metadata']['transaction_type'], 'DEBIT')
        self.assertTrue(res['bank_metadata']['extracted_metadata']['has_balance'])

    def test_20_bank_metadata_personal_mobile_scam(self):
        sender = '+91 9876543210'
        msg = 'Dear SBI User, your A/C has been suspended. Click http://sbi-kyc-verify.top or call manager at 9876543210 to resume service.'
        res = SmartScamDetector.analyze_message(msg, lang='en', sender=sender)

        self.assertEqual(res['risk_level'], 'HIGH', "Scam from personal mobile number must be HIGH risk")
        self.assertGreaterEqual(res['risk_score'], 85, "Risk score must be >= 85 for personal mobile bank alert")
        self.assertIsNotNone(res['bank_metadata'])
        self.assertEqual(res['bank_metadata']['classification'], 'CONFIRMED_FINANCIAL_SPAM_OR_PHISHING')
        self.assertTrue(res['bank_metadata']['is_spam'], "Must be confirmed Spam")
        self.assertEqual(res['bank_metadata']['sender_analysis']['sender_type'], 'PERSONAL_MOBILE_NUMBER')
        self.assertIn('unofficial_sender_mobile', res['indicators'])

    def test_21_bank_metadata_international_number_spoof(self):
        sender = '+44 7911 123456'
        msg = 'Your bank account will be blocked today. Update your KYC immediately.'
        res = SmartScamDetector.analyze_message(msg, lang='en', sender=sender)

        self.assertEqual(res['risk_level'], 'HIGH')
        self.assertEqual(res['bank_metadata']['sender_analysis']['sender_type'], 'INTERNATIONAL_NUMBER')
        self.assertTrue(res['bank_metadata']['is_spam'])

    def test_22_api_detect_with_sender_metadata(self):
        payload = {
            'sender': 'VK-SBIINB',
            'text': 'Your A/C ...9876 credited with INR 5,000.00 on 24-Nov-26 by UPI. Avail Bal: INR 12,000.00. - SBI',
            'lang': 'en'
        }
        response = self.client.post('/api/detect', json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['risk_level'], 'LOW')
        self.assertEqual(data['data']['bank_metadata']['classification'], 'VERIFIED_LEGITIMATE_BANK_ALERT')
        self.assertFalse(data['data']['bank_metadata']['is_spam'])

if __name__ == '__main__':
    unittest.main()

