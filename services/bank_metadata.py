"""
Bank Metadata & TRAI DLT Header Verification Service for Satark Setu.
Analyzes telecom sender IDs, TRAI DLT alphanumeric headers, masked bank account numbers,
transaction references (UTR/IMPS/NEFT), balance indicators, and official contact channels
to accurately distinguish authentic bank communications (Non-Spam) from fraudulent phishing (Spam).
"""

import re
from typing import Dict, Any, List, Optional

class BankMetadataAnalyzer:

    # Recognized Indian Bank TRAI DLT 6-character sender codes
    # Prefix format: 2 letters indicating telecom circle/operator (e.g. AD, VK, BW, VM, BZ, CP, JM)
    RECOGNIZED_BANK_HEADERS = {
        'SBIINB': {'bank': 'State Bank of India', 'type': 'NetBanking'},
        'SBISMS': {'bank': 'State Bank of India', 'type': 'Transactional'},
        'ATMSBI': {'bank': 'State Bank of India', 'type': 'ATM / Card'},
        'SBIUPI': {'bank': 'State Bank of India', 'type': 'UPI'},
        'SBICRD': {'bank': 'SBI Card', 'type': 'Credit Card'},
        'HDFCBK': {'bank': 'HDFC Bank', 'type': 'Core Banking'},
        'HDFCCC': {'bank': 'HDFC Bank', 'type': 'Credit Card'},
        'HDFCAL': {'bank': 'HDFC Bank', 'type': 'Alerts'},
        'HDFCUP': {'bank': 'HDFC Bank', 'type': 'UPI'},
        'ICICIB': {'bank': 'ICICI Bank', 'type': 'Core Banking'},
        'ICICIT': {'bank': 'ICICI Bank', 'type': 'Transactional'},
        'ICICIN': {'bank': 'ICICI Bank', 'type': 'NetBanking'},
        'ICICIP': {'bank': 'ICICI Bank', 'type': 'iMobile / UPI'},
        'AXISBK': {'bank': 'Axis Bank', 'type': 'Core Banking'},
        'AXISBC': {'bank': 'Axis Bank', 'type': 'Credit Card'},
        'AXISCD': {'bank': 'Axis Bank', 'type': 'Cards'},
        'PNBSMS': {'bank': 'Punjab National Bank', 'type': 'Transactional'},
        'PNBATN': {'bank': 'Punjab National Bank', 'type': 'ATM'},
        'PNBBNK': {'bank': 'Punjab National Bank', 'type': 'Core Banking'},
        'BOBTXN': {'bank': 'Bank of Baroda', 'type': 'Transactional'},
        'BOBSMS': {'bank': 'Bank of Baroda', 'type': 'SMS Alerts'},
        'KOTAKB': {'bank': 'Kotak Mahindra Bank', 'type': 'Core Banking'},
        'KOTAKS': {'bank': 'Kotak Mahindra Bank', 'type': 'Alerts'},
        'CANBNK': {'bank': 'Canara Bank', 'type': 'Core Banking'},
        'CANOTP': {'bank': 'Canara Bank', 'type': 'OTP Service'},
        'UBINBK': {'bank': 'Union Bank of India', 'type': 'Core Banking'},
        'INDBNK': {'bank': 'Indian Bank', 'type': 'Core Banking'},
        'IDFCFB': {'bank': 'IDFC FIRST Bank', 'type': 'Core Banking'},
        'YESBNK': {'bank': 'Yes Bank', 'type': 'Core Banking'},
        'PAYTMB': {'bank': 'Paytm Payments Bank', 'type': 'Payments'},
        'PHNPAY': {'bank': 'PhonePe', 'type': 'UPI Payments'},
        'BHIMUP': {'bank': 'NPCI / BHIM', 'type': 'UPI Official'},
        'GOOGLE': {'bank': 'Google Pay', 'type': 'UPI Payments'}
    }

    OFFICIAL_BANK_DOMAINS = {
        'sbi': ['onlinesbi.sbi', 'sbi.co.in'],
        'hdfc': ['hdfcbank.com'],
        'icici': ['icicibank.com'],
        'axis': ['axisbank.com'],
        'pnb': ['pnbindia.in', 'punjabnationalbank.in'],
        'bob': ['bankofbaroda.in'],
        'kotak': ['kotak.com'],
        'canara': ['canarabank.com'],
        'paytm': ['paytm.com'],
        'phonepe': ['phonepe.com']
    }

    OFFICIAL_BANK_HELPLINES = [
        '18001234', '18002100', '1800112211', '18004253800', # SBI
        '18001600', '18002600', '18002026161',               # HDFC
        '18001080', '18001024242',                           # ICICI
        '18004195959', '18001035577',                       # Axis
        '18001802222', '18001032222',                       # PNB
        '18005700', '18002584455'                            # Bank of Baroda
    ]

    @classmethod
    def verify_sender_header(cls, sender: str) -> Dict[str, Any]:
        """
        Analyze the SMS sender identifier according to TRAI DLT regulations.
        Indian banks use registered 6-character alphanumeric headers prefixed with telecom circle codes.
        Personal 10-digit mobile numbers are NEVER used by legitimate banks.
        """
        if not sender or not sender.strip():
            return {
                'provided': False,
                'sender_type': 'NOT_PROVIDED',
                'is_registered_bank_header': False,
                'bank_name': None,
                'threat_assessment': 'NEUTRAL',
                'explanation': 'Sender ID was not provided.'
            }

        s_clean = sender.strip().upper()
        # Remove common separators (e.g. AD-SBIINB or AD_SBIINB -> AD-SBIINB)
        s_clean = re.sub(r'[\s_]+', '-', s_clean)

        # 1. Check for International phone number (e.g. +44 7911 123456, +1-800-...)
        raw_digits = re.sub(r'[\s\-\(\)\.]', '', sender.strip())
        if raw_digits.startswith('+') and not raw_digits.startswith('+91') and len(raw_digits) >= 8:
            return {
                'provided': True,
                'raw_sender': sender,
                'sender_type': 'INTERNATIONAL_NUMBER',
                'is_registered_bank_header': False,
                'bank_name': None,
                'threat_assessment': 'SEVERE_SUSPICION',
                'explanation': 'Sender is an international phone number. Legitimate Indian banks exclusively operate through domestic telecom headers.'
            }

        # 2. Check if sender is a personal 10-digit Indian phone number
        phone_match = re.search(r'(\+?91)?[- ]?([6-9]\d{9})\b', s_clean)
        if phone_match and not re.search(r'[A-Z]{3,}', s_clean):
            return {
                'provided': True,
                'raw_sender': sender,
                'sender_type': 'PERSONAL_MOBILE_NUMBER',
                'is_registered_bank_header': False,
                'bank_name': None,
                'threat_assessment': 'HIGH_SUSPICION',
                'explanation': 'Sender is a personal 10-digit mobile number. Indian banks and utility DISCOMs NEVER send official banking, KYC, or disconnection notices from personal mobile numbers under TRAI regulations.'
            }

        # 3. Check for TRAI DLT Alphanumeric Header (e.g. AD-SBIINB, VK-HDFCBK, AX-ICICIB)
        # Standard format: 2-letter operator prefix + hyphen + 6-character entity code
        dlt_match = re.match(r'^([A-Z]{2})-([A-Z0-9]{5,6})$', s_clean)
        if dlt_match:
            operator_circle = dlt_match.group(1)
            entity_code = dlt_match.group(2)

            if entity_code in cls.RECOGNIZED_BANK_HEADERS:
                bank_info = cls.RECOGNIZED_BANK_HEADERS[entity_code]
                return {
                    'provided': True,
                    'raw_sender': sender,
                    'sender_type': 'VERIFIED_TRAI_DLT_HEADER',
                    'is_registered_bank_header': True,
                    'operator_circle': operator_circle,
                    'entity_code': entity_code,
                    'bank_name': bank_info['bank'],
                    'header_type': bank_info['type'],
                    'threat_assessment': 'AUTHENTIC_SENDER',
                    'explanation': f'Sender matches verified TRAI DLT registered header for {bank_info["bank"]} ({bank_info["type"]}).'
                }
            else:
                return {
                    'provided': True,
                    'raw_sender': sender,
                    'sender_type': 'STANDARD_TRAI_DLT_HEADER',
                    'is_registered_bank_header': False,
                    'operator_circle': operator_circle,
                    'entity_code': entity_code,
                    'bank_name': None,
                    'threat_assessment': 'UNVERIFIED_CORPORATE_HEADER',
                    'explanation': f'Formatted as a TRAI corporate sender ({entity_code}), but not recognized in our trusted bank registry.'
                }

        # 4. Check for direct 6-letter bank code without operator prefix (e.g. HDFCBK, SBIINB)
        if s_clean in cls.RECOGNIZED_BANK_HEADERS:
            bank_info = cls.RECOGNIZED_BANK_HEADERS[s_clean]
            return {
                'provided': True,
                'raw_sender': sender,
                'sender_type': 'REGISTERED_BANK_CODE',
                'is_registered_bank_header': True,
                'bank_name': bank_info['bank'],
                'header_type': bank_info['type'],
                'threat_assessment': 'AUTHENTIC_SENDER',
                'explanation': f'Matches recognized bank sender code for {bank_info["bank"]}.'
            }

        # 5. Non-standard sender
        return {
            'provided': True,
            'raw_sender': sender,
            'sender_type': 'CUSTOM_SENDER_TAG',
            'is_registered_bank_header': False,
            'bank_name': None,
            'threat_assessment': 'UNVERIFIED',
            'explanation': 'Sender tag does not match standard TRAI telecom bank format.'
        }

    @classmethod
    def extract_bank_metadata(cls, text: str) -> Dict[str, Any]:
        """
        Extract financial entity metadata from the message text:
        - Masked Account numbers (A/C XX1234)
        - Transaction classification (DEBIT / CREDIT / OTP / NONE)
        - Amounts & Balances
        - Transaction reference numbers (UTR / UPI / IMPS / NEFT)
        - Official vs personal contact channels
        """
        if not text:
            return {}

        clean_text = text.strip()
        metadata = {
            'has_masked_account': False,
            'account_number': None,
            'transaction_type': 'UNKNOWN',
            'amount_extracted': None,
            'balance_extracted': None,
            'has_balance': False,
            'reference_no': None,
            'has_reference': False,
            'official_tollfree': None,
            'personal_callback_number': None,
            'bank_name_mentioned': None
        }

        # 1. Masked Account Number Detection
        # Authentic bank pattern: A/C XX1234, Account No ending in 4589, A/C ...9876
        acct_match = re.search(r'(?i)\b(a\/c|acct|account|card)\s*(no\.?|ending|number)?\s*[:\-\s]?([X\*]{2,8}\d{3,4}|\.\.\.\d{3,4}|\d{4})\b', clean_text)
        if acct_match:
            metadata['has_masked_account'] = True
            metadata['account_number'] = acct_match.group(3)

        # 2. Transaction Type & Amount Detection
        debit_match = re.search(r'(?i)\b(debited|spent|paid|withdrawn)\s*(for|with|by|amount\s*of)?\s*(inr|rs\.?)\s*(\d{1,3}(?:,\d{2,3})*(?:\.\d{2})?)\b', clean_text)
        credit_match = re.search(r'(?i)\b(credited|received|deposited)\s*(with|for|by|amount\s*of)?\s*(inr|rs\.?)\s*(\d{1,3}(?:,\d{2,3})*(?:\.\d{2})?)\b', clean_text)
        otp_match = re.search(r'(?i)\b(your\s*otp|one\s*time\s*password|verification\s*code)\s*(is|for\s*login)?\s*[:\-]?\s*(\d{4,8})\b', clean_text)

        if debit_match:
            metadata['transaction_type'] = 'DEBIT'
            metadata['amount_extracted'] = f"INR {debit_match.group(4)}"
        elif credit_match:
            metadata['transaction_type'] = 'CREDIT'
            metadata['amount_extracted'] = f"INR {credit_match.group(4)}"
        elif otp_match:
            metadata['transaction_type'] = 'OTP'
        else:
            # Check generic INR mention
            generic_amt = re.search(r'(?i)\b(inr|rs\.?)\s*(\d{1,3}(?:,\d{2,3})*(?:\.\d{2})?)\b', clean_text)
            if generic_amt:
                metadata['amount_extracted'] = f"INR {generic_amt.group(2)}"

        # 3. Available Balance Metadata
        bal_match = re.search(r'(?i)\b(avail(able)?\s*bal(ance)?|total\s*bal|updated\s*bal(ance)?)\s*[:\-]?\s*(inr|rs\.?)\s*(\d{1,3}(?:,\d{2,3})*(?:\.\d{2})?)\b', clean_text)
        if bal_match:
            metadata['has_balance'] = True
            metadata['balance_extracted'] = f"INR {bal_match.group(6)}"

        # 4. Transaction Reference / UTR Metadata
        ref_match = re.search(r'(?i)\b(upi\/\d{12}|utr\s*[:\-]?\s*[A-Za-z0-9]{10,16}|ref\s*[:\-]?\s*[A-Za-z0-9\/\-]{8,20})\b', clean_text)
        if ref_match:
            metadata['has_reference'] = True
            metadata['reference_no'] = ref_match.group(0)

        # 5. Bank Mention Identification
        for bank_short, info in cls.RECOGNIZED_BANK_HEADERS.items():
            b_name = info['bank']
            if re.search(rf'(?i)\b{b_name}\b', clean_text) or re.search(rf'(?i)\b{bank_short[:4]}\b', clean_text):
                metadata['bank_name_mentioned'] = b_name
                break

        # 6. Official Toll-Free Helpline vs Personal Callback Number
        for tollfree in cls.OFFICIAL_BANK_HELPLINES:
            if tollfree in re.sub(r'[\s\-]+', '', clean_text):
                metadata['official_tollfree'] = tollfree
                break

        # Check for suspicious personal callback mobile numbers inside message text
        call_match = re.search(r'(?i)\b(call|contact|dial)\s*(on|at|our\s*officer)?\s*[:\-]?\s*([6-9]\d{9})\b', clean_text)
        if call_match:
            metadata['personal_callback_number'] = call_match.group(3)

        return metadata

    @classmethod
    def evaluate_spam_authenticity(
        cls,
        text: str,
        sender: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluate full authenticity score (0-100) separating genuine bank alerts from spam/phishing.
        Returns detailed telemetry verdict and metadata signals.
        """
        sender_analysis = cls.verify_sender_header(sender or '')
        msg_metadata = cls.extract_bank_metadata(text)

        # Authenticity Signals
        auth_score = 0
        spam_signals = []
        legit_signals = []

        # 1. Sender Header Checks
        if sender_analysis['is_registered_bank_header']:
            auth_score += 40
            legit_signals.append(f"Sender ID matches official TRAI DLT header ({sender_analysis.get('raw_sender')})")
        elif sender_analysis['sender_type'] == 'PERSONAL_MOBILE_NUMBER':
            auth_score -= 50
            spam_signals.append(f"Sender is a personal 10-digit mobile number ({sender_analysis.get('raw_sender')}), not a registered bank channel")
        elif sender_analysis['sender_type'] == 'INTERNATIONAL_NUMBER':
            auth_score -= 60
            spam_signals.append("Sender uses an international calling code claiming to represent an Indian bank")

        # 2. Account Metadata Checks
        if msg_metadata['has_masked_account']:
            auth_score += 25
            legit_signals.append(f"Message references masked account metadata: {msg_metadata['account_number']}")
        
        if msg_metadata['has_balance']:
            auth_score += 20
            legit_signals.append(f"Includes updated available account balance: {msg_metadata['balance_extracted']}")

        if msg_metadata['has_reference']:
            auth_score += 15
            legit_signals.append(f"Includes verifiable transaction reference/UTR: {msg_metadata['reference_no']}")

        if msg_metadata['official_tollfree']:
            auth_score += 10
            legit_signals.append(f"Features verified bank toll-free helpline: {msg_metadata['official_tollfree']}")

        # 3. Scam Red Flags in Metadata
        if msg_metadata['personal_callback_number']:
            auth_score -= 40
            spam_signals.append(f"Prompts user to call an unverified personal mobile number: {msg_metadata['personal_callback_number']}")

        # Classification
        if auth_score >= 45 and not spam_signals:
            classification = 'VERIFIED_LEGITIMATE_BANK_ALERT'
            is_spam = False
        elif auth_score <= 0 or len(spam_signals) >= 2:
            classification = 'CONFIRMED_FINANCIAL_SPAM_OR_PHISHING'
            is_spam = True
        else:
            classification = 'UNVERIFIED_COMMUNICATION'
            is_spam = None

        return {
            'is_spam': is_spam,
            'authenticity_score': max(0, min(100, auth_score)),
            'classification': classification,
            'sender_analysis': sender_analysis,
            'extracted_metadata': msg_metadata,
            'legitimate_signals': legit_signals,
            'spam_signals': spam_signals
        }
