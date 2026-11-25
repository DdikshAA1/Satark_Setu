"""
REST API Blueprint for Satark Setu.
Provides structured, JSON endpoints for:
- /api/detect (Message text analysis)
- /api/upi-guard (UPI payment request analysis)
- /api/url-scan (URL structural safety check)
- /api/emergency (Emergency incident triage)
- /api/dashboard (Analytics & metrics)
- /api/sample-messages (Curated testing samples)
"""

from flask import Blueprint, request, jsonify
from services.detector import SmartScamDetector
from services.upi_guard import UPIFraudGuard
from services.url_scanner import URLSafetyScanner
from services.emergency import EmergencyResponseAssistant
from services.localization import TRANSLATIONS, get_text
import database

api_bp = Blueprint('api', __name__, url_prefix='/api')

SAMPLE_MESSAGES = [
    {
        'id': 'sample_kyc',
        'title': 'Fake Bank KYC Threat (Mobile Sender)',
        'category': 'fake_kyc',
        'sender': '+91 9876543210',
        'text': 'Your bank account will be blocked today. Update your KYC immediately using this link: http://sbi-kyc-verify.top',
        'lang': 'en'
    },
    {
        'id': 'sample_lottery',
        'title': 'KBC Lottery Advance Fee',
        'category': 'lottery_prize',
        'sender': '+91 8877665544',
        'text': 'Congratulations! You won a lottery. Pay a processing fee to receive your prize.',
        'lang': 'en'
    },
    {
        'id': 'sample_upi_pin',
        'title': 'UPI PIN to Receive Cashback',
        'category': 'upi_pin_trap',
        'sender': 'PAYTMB',
        'text': 'Enter your UPI PIN to receive your cashback of Rs 2,500 directly in PhonePe.',
        'lang': 'en'
    },
    {
        'id': 'sample_electricity',
        'title': 'Electricity Power Cut Threat',
        'category': 'electricity_threat',
        'sender': '+91 9988776655',
        'text': 'Dear consumer, your electricity power will be disconnected tonight at 9.30 pm from electricity office. Please call officer at 9876543210 immediately.',
        'lang': 'en'
    },
    {
        'id': 'sample_digital_arrest',
        'title': 'Digital Arrest & Police Call',
        'category': 'digital_arrest',
        'sender': '+91 9123456789',
        'text': 'Cyber Crime Branch: A digital arrest warrant has been issued in your name for illegal parcel. Connect on WhatsApp video call immediately or police will arrive.',
        'lang': 'en'
    },
    {
        'id': 'sample_legit_bank',
        'title': 'Legitimate Bank Transaction (DLT Verified)',
        'category': 'legitimate_bank',
        'sender': 'AD-HDFCBK',
        'text': 'Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank',
        'lang': 'en'
    },
    {
        'id': 'sample_hindi_kyc',
        'title': 'केवाईसी खाता ब्लॉक चेतावनी (हिंदी)',
        'category': 'fake_kyc',
        'sender': '+91 9876543210',
        'text': 'प्रिय ग्राहक, आपका बैंक खाता आज बंद कर दिया जाएगा। तुरंत इस लिंक http://pnb-kyc.top पर जाकर पैन कार्ड अपडेट करें।',
        'lang': 'hi'
    },
    {
        'id': 'sample_hindi_upi',
        'title': 'पैसे पाने के लिए पिन (हिंदी)',
        'category': 'upi_pin_trap',
        'sender': 'PAYTMB',
        'text': 'रुपये 4,000 कैशबैक प्राप्त करने के लिए अपना यूपीआई पिन दर्ज करें।',
        'lang': 'hi'
    }
]

@api_bp.route('/detect', methods=['POST'])
def detect_scam():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    sender = data.get('sender', '').strip() if data.get('sender') else None
    lang = data.get('lang', 'en')

    result = SmartScamDetector.analyze_message(text, lang=lang, sender=sender)

    # Safely log analysis to database if there was actual input
    if text and text.strip():
        try:
            log_snippet = f"[{sender}] {text}" if sender else text
            database.log_analysis(
                analysis_type='message',
                snippet=log_snippet,
                risk_level=result['risk_level'],
                risk_score=result['risk_score'],
                category=result['category_label'],
                indicators=result['indicators'],
                language=lang
            )
        except Exception as e:
            # Database logging error should never fail the user's scan request
            pass

    return jsonify({'success': True, 'data': result})

@api_bp.route('/upi-guard', methods=['POST'])
def check_upi():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    vpa = data.get('vpa', '')
    amount = data.get('amount', '')
    lang = data.get('lang', 'en')

    result = UPIFraudGuard.evaluate_upi_request(text=text, vpa=vpa, amount=amount, lang=lang)

    combined = f"UPI Check: {text} | VPA: {vpa} | Amt: {amount}".strip()
    if combined:
        try:
            database.log_analysis(
                analysis_type='upi',
                snippet=combined,
                risk_level=result['risk_level'],
                risk_score=result['risk_score'],
                category=result['category_label'],
                indicators=result['indicators'],
                language=lang
            )
        except Exception:
            pass

    return jsonify({'success': True, 'data': result})

@api_bp.route('/url-scan', methods=['POST'])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    lang = data.get('lang', 'en')

    result = URLSafetyScanner.scan_url(url, lang=lang)

    if url and url.strip():
        try:
            database.log_analysis(
                analysis_type='url',
                snippet=url,
                risk_level=result['risk_level'],
                risk_score=result['risk_score'],
                category=result['category_label'],
                indicators=result['indicators'],
                language=lang
            )
        except Exception:
            pass

    return jsonify({'success': True, 'data': result})

@api_bp.route('/emergency', methods=['GET', 'POST'])
def get_emergency_guidance():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        incident = data.get('incident') or data.get('scenario') or 'clicked_link'
        lang = data.get('lang', 'en')
    else:
        incident = request.args.get('incident') or request.args.get('scenario') or 'clicked_link'
        lang = request.args.get('lang', 'en')
    triage = EmergencyResponseAssistant.get_incident_triage(incident, lang=lang)
    return jsonify({'success': True, 'data': triage})

@api_bp.route('/dashboard', methods=['GET'])
def get_dashboard_metrics():
    stats = database.get_dashboard_stats()
    return jsonify({'success': True, 'data': stats})

@api_bp.route('/sample-messages', methods=['GET'])
def get_sample_messages():
    lang = request.args.get('lang', 'en')
    if lang == 'hi':
        # Prioritize hindi samples
        samples = sorted(SAMPLE_MESSAGES, key=lambda s: 0 if s['lang'] == 'hi' else 1)
    else:
        samples = SAMPLE_MESSAGES
    return jsonify({'success': True, 'samples': samples})

@api_bp.route('/translations', methods=['GET'])
def get_translations():
    lang = request.args.get('lang', 'en')
    lang = 'hi' if lang == 'hi' else 'en'
    return jsonify({'success': True, 'lang': lang, 'translations': TRANSLATIONS.get(lang, TRANSLATIONS['en'])})

