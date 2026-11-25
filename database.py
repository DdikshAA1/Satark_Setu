import sqlite3
import json
import re
from datetime import datetime
from config import Config

def get_db_connection():
    """Create and return a database connection with dict-like row access."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def mask_sensitive_text(text: str) -> str:
    """
    Privacy guard: Redact phone numbers, account numbers, card numbers,
    and potential OTPs before logging to the database.
    """
    if not text:
        return ""
    # Mask 10-digit Indian phone numbers
    masked = re.sub(r'\b[6-9]\d{9}\b', lambda m: m.group(0)[:3] + 'XXXX' + m.group(0)[7:], text)
    # Mask 12-16 digit bank accounts or card numbers
    masked = re.sub(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}([ -]?\d{4})?\b', '[REDACTED_ACCOUNT/CARD]', masked)
    # Mask OTP mentions
    masked = re.sub(r'(?i)(otp|code|pin)\s*(?:is|:|-)?\s*([0-9]{4,8})', r'\1: [REDACTED_CODE]', masked)
    # Limit length for storage
    if len(masked) > 280:
        masked = masked[:280] + "..."
    return masked

def init_db():
    """Initialize database tables and seed baseline demonstration data if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_type TEXT NOT NULL, -- 'message', 'upi', 'url', 'emergency'
            snippet_masked TEXT,
            risk_level TEXT NOT NULL,    -- 'LOW', 'MEDIUM', 'HIGH'
            risk_score INTEGER NOT NULL, -- 0 to 100
            category TEXT NOT NULL,
            indicators TEXT,             -- JSON string of indicators
            language TEXT DEFAULT 'en',  -- 'en' or 'hi'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emergency_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT NOT NULL,
            time_elapsed TEXT,
            amount_lost TEXT,
            bank_name TEXT,
            status TEXT DEFAULT 'GUIDANCE_PROVIDED',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Check if we should seed realistic demonstration telemetry
    cursor.execute('SELECT COUNT(*) as count FROM analysis_logs')
    count = cursor.fetchone()['count']

    if count == 0:
        # Seed realistic sample data reflecting Indian digital payment threat patterns
        sample_records = [
            ('message', 'Dear Customer, your SBI account will be blocked today. Click http://sbi-kyc-verify.top to update PAN immediately.', 'HIGH', 92, 'Fake KYC / Account Suspension', json.dumps(['urgent_block_threat', 'kyc_update_demand', 'suspicious_link', 'brand_impersonation']), 'en', '2026-11-20 09:15:00'),
            ('message', 'Congratulations! You won Rs 25,00,000 in KBC Lottery. Deposit Rs 5,000 security fee to claim.', 'HIGH', 95, 'Lottery & Prize Scam', json.dumps(['lottery_claim', 'advance_fee_fraud', 'unrealistic_prize']), 'en', '2026-11-20 11:30:00'),
            ('upi', 'Ramesh Jewellers requests Rs 4,500. Message: Enter your UPI PIN to receive cashback from PhonePe.', 'HIGH', 88, 'UPI PIN to Receive Trap', json.dumps(['pin_to_receive', 'fake_cashback', 'collect_request']), 'en', '2026-11-21 14:20:00'),
            ('url', 'http://192.168.1.105/paytm-rewards-claim.apk', 'HIGH', 94, 'Suspicious APK Download', json.dumps(['ip_host', 'dangerous_apk_extension', 'brand_impersonation']), 'en', '2026-11-21 17:05:00'),
            ('message', 'Dear consumer, your electricity will be disconnected tonight at 9:30 PM due to unpaid bill. Call 98765XXXXX.', 'HIGH', 89, 'Electricity Disconnection Threat', json.dumps(['utility_threat', 'disconnection_urgency', 'personal_number_callback']), 'hi', '2026-11-22 10:45:00'),
            ('message', 'Rs 450.00 debited from A/C XX1234 on 22-Nov-26 at Zomato UPI. Bal: Rs 14,250. Helpline: 1800112211.', 'LOW', 8, 'Legitimate Bank Alert', json.dumps(['normal_debit_notification', 'has_balance', 'has_official_tollfree']), 'en', '2026-11-22 13:10:00'),
            ('upi', 'Collect request for Rs 120 from BigBasket at payment gateway checkout.', 'LOW', 12, 'Legitimate Collect Request', json.dumps(['merchant_collect', 'reasonable_amount']), 'en', '2026-11-23 08:40:00'),
            ('url', 'https://www.onlinesbi.sbi/portal/personal.html', 'LOW', 5, 'Legitimate Bank Portal', json.dumps(['official_tld', 'valid_https', 'known_banking_domain']), 'en', '2026-11-23 11:15:00'),
            ('message', 'Work from Home: Earn Rs 3,000 to 5,000 daily by liking YouTube videos and rating hotels on Telegram.', 'HIGH', 85, 'Task / Job Fraud', json.dumps(['unrealistic_earning', 'task_fraud', 'telegram_redirect']), 'en', '2026-11-23 16:20:00'),
            ('message', 'Dear customer, your credit card reward points worth Rs 9,850 are expiring today. Redeem cash at bit.ly/points-claim.', 'HIGH', 90, 'Reward Points Phishing', json.dumps(['reward_expiry_urgency', 'shortened_url', 'credential_harvesting']), 'en', '2026-11-24 12:00:00'),
            ('url', 'http://hdfcbank-security-kyc-login.xyz', 'HIGH', 91, 'Typosquatting & Phishing', json.dumps(['suspicious_tld', 'no_https', 'brand_typosquatting']), 'en', '2026-11-24 15:45:00'),
            ('message', 'Police Dept: Digital arrest warrant issued in your name for money laundering. Join Skype call immediately.', 'HIGH', 98, 'Digital Arrest & Law Enforcement Impersonation', json.dumps(['digital_arrest_claim', 'law_enforcement_impersonation', 'intimidation_urgency']), 'en', '2026-11-24 18:30:00'),
            ('message', 'Part payment of Rs 1,200 received via PhonePe from Sharma Kirana Store.', 'LOW', 5, 'Legitimate Merchant Credit', json.dumps(['merchant_credit', 'no_call_to_action']), 'hi', '2026-11-25 01:10:00'),
        ]

        cursor.executemany('''
            INSERT INTO analysis_logs (analysis_type, snippet_masked, risk_level, risk_score, category, indicators, language, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_records)

    conn.commit()
    conn.close()

def log_analysis(analysis_type: str, snippet: str, risk_level: str, risk_score: int, category: str, indicators: list, language: str = 'en'):
    """Log an analysis query safely with masked content."""
    conn = get_db_connection()
    cursor = conn.cursor()
    masked = mask_sensitive_text(snippet)
    indicators_json = json.dumps(indicators) if isinstance(indicators, list) else str(indicators)

    cursor.execute('''
        INSERT INTO analysis_logs (analysis_type, snippet_masked, risk_level, risk_score, category, indicators, language)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (analysis_type, masked, risk_level, risk_score, category, indicators_json, language))
    
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def get_dashboard_stats():
    """Compute aggregate analytics for the Safety Dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total counts and risk breakdown
    cursor.execute('SELECT COUNT(*) as total FROM analysis_logs')
    total = cursor.fetchone()['total']

    cursor.execute('''
        SELECT 
            SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk
        FROM analysis_logs
    ''')
    breakdown = cursor.fetchone()

    # Breakdown by category
    cursor.execute('''
        SELECT category, COUNT(*) as count 
        FROM analysis_logs 
        GROUP BY category 
        ORDER BY count DESC 
        LIMIT 6
    ''')
    top_categories = [dict(row) for row in cursor.fetchall()]

    # Breakdown by analysis type
    cursor.execute('''
        SELECT analysis_type, COUNT(*) as count
        FROM analysis_logs
        GROUP BY analysis_type
    ''')
    by_type = [dict(row) for row in cursor.fetchall()]

    # Recent history
    cursor.execute('''
        SELECT id, analysis_type, snippet_masked, risk_level, risk_score, category, created_at
        FROM analysis_logs
        ORDER BY created_at DESC
        LIMIT 8
    ''')
    recent_history = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        'total': total,
        'high_risk': breakdown['high_risk'] or 0,
        'medium_risk': breakdown['medium_risk'] or 0,
        'low_risk': breakdown['low_risk'] or 0,
        'top_categories': top_categories,
        'by_type': by_type,
        'recent_history': recent_history
    }

