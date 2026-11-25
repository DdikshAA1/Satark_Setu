"""
UPI Fraud Guard Service for Satark Setu.
Dedicated safety analysis for UPI payment requests, collect alerts,
QR code instructions, and merchant VPA verification.
Reinforces the foundational UPI Safety Golden Rule:
'You NEVER enter your UPI PIN to receive money.'
"""

import re
from typing import Dict, Any, List
from services.nba_engine import NextBestActionEngine
from services.localization import get_text, get_indicator_label, get_category_label

class UPIFraudGuard:

    UPI_WARNING_PATTERNS = {
        'pin_to_receive': [
            r'(?i)\b(enter|type|submit|put)\s*(your)?\s*(upi\s*pin|pin|secret\s*pin)\s*(to|for)?\s*(receive|get|claim|accept|credit|collect)\b',
            r'(?i)\b(receive|get|claim|collect)\s*(cashback|refund|money|amount|funds)\s*(by\s*entering|using|enter)\s*(upi\s*pin|pin)\b',
            r'(?i)\b(pin\s*(daalein|daalo|darj\s*karein))\b',
            r'(?i)\b(enter\s*pin\s*to\s*receive)\b'
        ],
        'fake_cashback': [
            r'(?i)\b(cashback|reward|scratch\s*card|refund|bonus|won|congratulations)\b',
            r'(?i)\b(flipkart|phonepe|paytm|gpay|googlepay)\s*(reward|cashback|prize)\b'
        ],
        'collect_request': [
            r'(?i)\b(collect\s*request|request\s*to\s*pay|approve\s*request|pull\s*request|debit\s*request)\b',
            r'(?i)\b(approve\s*payment|pay\s*request)\b'
        ],
        'qr_to_receive': [
            r'(?i)\b(scan\s*(this|the)?\s*qr\s*(code)?\s*(to)?\s*(receive|accept|get)\s*(money|payment|cashback))\b',
            r'(?i)\b(qr\s*code\s*scan\s*karke\s*paise\s*lo)\b'
        ],
        'urgency_pressure': [
            r'(?i)\b(immediately|within\s*\d+\s*(mins|minutes)|urgently|now\s*or\s*never|expires\s*in)\b',
            r'(?i)\b(jaldi|turant|abhi\s*karo)\b'
        ],
        'remote_screen_share': [
            r'(?i)\b(screen\s*share|anydesk|teamviewer|share\s*screen|video\s*call)\b'
        ]
    }

    LEGIT_UPI_PATTERNS = {
        'merchant_checkout': [
            r'(?i)\b(swiggy|zomato|amazon|flipkart|uber|ola|bigbasket|blinkit|zepto|irctc)\b',
            r'(?i)\b(paying\s*for\s*order|e-commerce\s*checkout)\b'
        ],
        'direct_peer_transfer': [
            r'(?i)\b(sending\s*money\s*to\s*(friend|family|brother|sister|shopkeeper))\b',
            r'(?i)\b(paying\s*bill|grocery\s*payment)\b'
        ]
    }

    @classmethod
    def evaluate_upi_request(cls, text: str, vpa: str = '', amount: str = '', lang: str = 'en') -> Dict[str, Any]:
        """
        Evaluate a UPI payment scenario or collect request for fraud indicators.
        """
        combined_text = f"{text} {vpa} {amount}".strip()
        if not combined_text:
            return {
                'risk_level': 'LOW',
                'risk_score': 0,
                'category_key': 'legitimate_upi',
                'category_label': get_category_label('legitimate_upi', lang),
                'indicators': [],
                'indicator_details': [],
                'explanation': 'No UPI request details entered.',
                'action_plan': NextBestActionEngine.generate_action_plan('upi_pin_trap', 'LOW', [], lang),
                'golden_rule': get_text('upi_pin_golden_rule', lang)
            }

        detected_indicators = []
        for ind, patterns in cls.UPI_WARNING_PATTERNS.items():
            for p in patterns:
                if re.search(p, combined_text):
                    detected_indicators.append(ind)
                    break

        # Check VPA structure if provided
        vpa_clean = vpa.strip().lower()
        if vpa_clean:
            if not re.match(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$', vpa_clean):
                detected_indicators.append('unrecognized_upi_handle')
            elif any(s in vpa_clean for s in ['refund', 'helpdesk', 'support', 'customercare', 'cashback', 'kyc']):
                detected_indicators.append('brand_impersonation')

        score = 0
        if 'pin_to_receive' in detected_indicators:
            score += 55
        if 'qr_to_receive' in detected_indicators:
            score += 45
        if 'fake_cashback' in detected_indicators:
            score += 25
        if 'collect_request' in detected_indicators:
            score += 20
        if 'urgency_pressure' in detected_indicators:
            score += 15
        if 'remote_screen_share' in detected_indicators:
            score += 40
        if 'brand_impersonation' in detected_indicators:
            score += 30

        # Legitimate check
        legit_found = any(re.search(p, combined_text) for p in cls.LEGIT_UPI_PATTERNS['merchant_checkout'])
        if legit_found and not ('pin_to_receive' in detected_indicators or 'qr_to_receive' in detected_indicators):
            score = max(5, score - 25)

        score = max(0, min(100, score))

        if score >= 65:
            risk_level = 'HIGH'
            category_key = 'upi_pin_trap'
        elif score >= 35:
            risk_level = 'MEDIUM'
            category_key = 'upi_pin_trap'
        else:
            risk_level = 'LOW'
            category_key = 'legitimate_upi'

        # Indicators localized
        indicator_details = [
            {
                'code': ind,
                'label': get_indicator_label(ind, lang),
                'type': 'warning'
            }
            for ind in detected_indicators
        ]

        # Plain language explanation
        if lang == 'hi':
            if 'pin_to_receive' in detected_indicators or 'qr_to_receive' in detected_indicators:
                explanation = "चेतावनी! इस अनुरोध में आपको पैसे पाने के लिए यूपीआई पिन डालने या क्यूआर कोड स्कैन करने को कहा जा रहा है। यह 100% फ्रॉड है। पैसे प्राप्त करने के लिए कभी भी पिन डालने की आवश्यकता नहीं होती।"
            elif 'collect_request' in detected_indicators and 'fake_cashback' in detected_indicators:
                explanation = "यह एक अज्ञात कलेक्ट रिक्वेस्ट है जिसे कैशबैक या लॉटरी के नाम पर भेजा गया है। इसे अप्रूव करने पर आपके खाते से पैसे कट जाएंगे।"
            elif risk_level == 'LOW':
                explanation = "यह एक सामान्य यूपीआई भुगतान या सुरक्षित लेनदेन प्रतीत होता है। याद रखें कि केवल सामान खरीदते समय ही पिन डालें, पैसे लेते समय नहीं।"
            else:
                explanation = "इस यूपीआई अनुरोध में असामान्य संकेत पाए गए हैं। भुगतान स्वीकार करने से पहले प्राप्तकर्ता का नाम ठीक से जांच लें।"
        else:
            if 'pin_to_receive' in detected_indicators or 'qr_to_receive' in detected_indicators:
                explanation = "CRITICAL WARNING: The request asks you to enter your UPI PIN or scan a QR code to 'receive' money. Under the Unified Payments Interface (UPI) protocol, entering a PIN is ONLY used to AUTHORIZE MONEY LEAVING YOUR ACCOUNT."
            elif 'collect_request' in detected_indicators and 'fake_cashback' in detected_indicators:
                explanation = "This is an unprompted collect request disguised as cashback or prize money. Approving this request will immediately transfer your money to the requester."
            elif risk_level == 'LOW':
                explanation = "This appears to be a standard payment checkout or transfer. Follow standard payment hygiene and verify the beneficiary name before entering your PIN."
            else:
                explanation = "Suspicious attributes detected in this payment request. Proceed with caution and verify the recipient's identity independently."

        action_plan = NextBestActionEngine.generate_action_plan(category_key, risk_level, detected_indicators, lang)

        return {
            'risk_level': risk_level,
            'risk_score': score,
            'category_key': category_key,
            'category_label': get_category_label(category_key, lang),
            'indicators': detected_indicators,
            'indicator_details': indicator_details,
            'explanation': explanation,
            'action_plan': action_plan,
            'golden_rule': get_text('upi_pin_golden_rule', lang)
        }

