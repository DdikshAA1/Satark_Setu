"""
Performance & Bank Metadata Accuracy Benchmark for Satark Setu.
Evaluates:
1. Bank Account Metadata & TRAI DLT Header identification accuracy.
2. Authentic Non-Spam vs Fraudulent Spam classification precision.
3. System latency across heuristic, metadata, ML, and cached AI pathways.
"""

import time
import os
import sys

# Ensure root directory on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.detector import SmartScamDetector
from services.bank_metadata import BankMetadataAnalyzer

TEST_CORPUS = [
    # --- LEGITIMATE BANK ALERTS (Verified Non-Spam) ---
    {
        'id': 'legit_hdfc_debit',
        'sender': 'AD-HDFCBK',
        'text': 'Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank',
        'expected_spam': False,
        'expected_category': 'legitimate_bank',
        'expected_risk': 'LOW'
    },
    {
        'id': 'legit_sbi_credit',
        'sender': 'VK-SBIINB',
        'text': 'Dear Customer, your A/C ...9876 has been credited with INR 25,000.00 on 24-Nov-26 by salary transfer. Updated Bal: INR 48,210.00. Call 18001234 for queries.',
        'expected_spam': False,
        'expected_category': 'legitimate_bank',
        'expected_risk': 'LOW'
    },
    {
        'id': 'legit_icici_atm',
        'sender': 'AX-ICICIB',
        'text': 'INR 2,000.00 withdrawn from ATM using Card ending 3214. Avail Bal INR 14,890.00. If not done by you SMS BLOCK to 9215676766. ICICI Bank',
        'expected_spam': False,
        'expected_category': 'legitimate_bank',
        'expected_risk': 'LOW'
    },
    {
        'id': 'legit_axis_otp',
        'sender': 'AX-AXISBK',
        'text': 'Your OTP for transaction of INR 3,200.00 at Amazon on Card XX8765 is 849201. Valid for 5 mins. Do not share with anyone. Axis Bank',
        'expected_spam': False,
        'expected_category': 'legitimate_bank',
        'expected_risk': 'LOW'
    },

    # --- FRAUDULENT / SPAM MESSAGES (Confirmed Spam) ---
    {
        'id': 'spam_fake_kyc_mobile',
        'sender': '+91 9876543210',
        'text': 'Dear SBI User, your bank account will be blocked today. Update your KYC immediately using this link: http://sbi-kyc-verify.top',
        'expected_spam': True,
        'expected_category': 'fake_kyc',
        'expected_risk': 'HIGH'
    },
    {
        'id': 'spam_electricity_cut',
        'sender': '+91 9988776655',
        'text': 'Dear consumer your electricity power will be disconnected tonight at 9.30 pm from electricity office. Call officer at 9876543210 immediately.',
        'expected_spam': True,
        'expected_category': 'electricity_threat',
        'expected_risk': 'HIGH'
    },
    {
        'id': 'spam_digital_arrest',
        'sender': '+91 9123456789',
        'text': 'Cyber Crime Branch: A digital arrest warrant has been issued in your name for illegal parcel. Connect on WhatsApp video call immediately or police will arrive.',
        'expected_spam': True,
        'expected_category': 'digital_arrest',
        'expected_risk': 'HIGH'
    },
    {
        'id': 'spam_upi_cashback_trap',
        'sender': '+91 8877665544',
        'text': 'Congratulations! You received Rs 3,500 cashback. Enter your UPI PIN to claim money directly to bank.',
        'expected_spam': True,
        'expected_category': 'upi_pin_trap',
        'expected_risk': 'HIGH'
    },
    {
        'id': 'spam_intl_spoof',
        'sender': '+44 7911 123456',
        'text': 'Your Bank Account blocked due to pending KYC. Click http://hdfc-update.live/kyc to verify PAN card.',
        'expected_spam': True,
        'expected_category': 'fake_kyc',
        'expected_risk': 'HIGH'
    }
]

def run_benchmark():
    print("=" * 72)
    print("SATARK SETU: BANK METADATA & FRAUD DETECTION BENCHMARK")
    print("=" * 72)

    passed_accuracy = 0
    total = len(TEST_CORPUS)
    latencies = []

    for item in TEST_CORPUS:
        t0 = time.perf_counter()
        res = SmartScamDetector.analyze_message(item['text'], lang='en', sender=item['sender'])
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)

        bm = res.get('bank_metadata') or {}
        is_spam = bm.get('is_spam')
        risk_level = res['risk_level']
        category = res['category_key']

        # Evaluation criteria
        is_correct_spam = (is_spam == item['expected_spam'])
        is_correct_risk = (risk_level == item['expected_risk'])

        if is_correct_spam and is_correct_risk:
            passed_accuracy += 1
            status = "PASS [OK]"
        else:
            status = f"FAIL (Spam: {is_spam} vs {item['expected_spam']}, Risk: {risk_level} vs {item['expected_risk']})"

        print(f"[{item['id'][:24]:<24}] {status:<12} Latency: {elapsed_ms:6.2f} ms | Score: {res['risk_score']:3d}/100 | Risk: {risk_level:<6}")

    print("-" * 72)
    print(f"ACCURACY VERDICT: {passed_accuracy}/{total} ({passed_accuracy/total*100:.1f}%) Passed Classification Requirements")
    avg_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)
    print(f"LATENCY: Avg: {avg_latency:.2f} ms | Min: {min_latency:.2f} ms | Max: {max_latency:.2f} ms")

    # In-memory cache benchmark on repeated queries
    print("-" * 72)
    print("CACHE PERFORMANCE BENCHMARK (Repeated Evaluations):")
    cache_latencies = []
    for item in TEST_CORPUS[:5]:
        t0 = time.perf_counter()
        _ = SmartScamDetector.analyze_message(item['text'], lang='en', sender=item['sender'])
        cache_latencies.append((time.perf_counter() - t0) * 1000)

    avg_cached = sum(cache_latencies) / len(cache_latencies)
    print(f"Cached Avg Latency: {avg_cached:.3f} ms (Throughput: ~{int(1000 / max(0.001, avg_cached)):,} req/sec)")
    print("=" * 72)

if __name__ == '__main__':
    run_benchmark()

