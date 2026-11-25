"""
Smart Scam Detector Service for Satark Setu.
Combines rule-based explainable heuristic indicators with an NLP / TF-IDF
Machine Learning model to produce calibrated, explainable scam detection.
Supports English, Hindi, and transliterated Hinglish scam patterns.
"""

import re
from typing import Dict, Any, List, Optional
from services.ml_classifier import ScamClassifier
from services.nba_engine import NextBestActionEngine
from services.localization import get_text, get_indicator_label, get_category_label
from services.gemini_service import GeminiScamAnalyzer
from services.bank_metadata import BankMetadataAnalyzer

class SmartScamDetector:

    PATTERNS = {
        'urgent_block_threat': [
            r'(?i)\b(account|a\/c|sim|card|service|netbanking)\s*(will be|has been|is)?\s*(blocked|suspended|deactivated|frozen|stopped|closed|terminated)\b',
            r'(?i)\b(block|suspend|freeze|deactivate)\s*(today|tonight|within\s*\d+\s*(hours|hrs|mins)|immediately|urgently)\b',
            r'(?i)\b(avoid\s*(block|suspension|deactivation))\b',
            r'(?i)(खाता|अकाउंट|सिम|कार्ड)\s*(आज\s*(ही)?\s*)?(बंद|ब्लॉक|सस्पेंड|फ्रीज)\s*(हो\s*जाएगा|कर\s*दिया\s*जाएगा|हो\s*चुका\s*है)',
            r'(?i)(बंद\s*होने\s*से\s*बचाएं|तुरंत\s*शुरू\s*कराएं)'
        ],
        'kyc_update_demand': [
            r'(?i)\b(update|complete|verify|submit|link)\s*(your)?\s*(kyc|pan|aadhar|aadhaar|documents|biometric)\b',
            r'(?i)\b(kyc\s*(pending|incomplete|failed|suspended|verification|required|update))\b',
            r'(?i)\b(pan\s*card\s*(update|link|blocked|verification))\b',
            r'(?i)(पैन\s*कार्ड|केवाईसी|आधार|दस्तावेज)\s*(तुरंत\s*)?(अपडेट|लिंक|सत्यापित|वेरिफाई|जमा)\s*(करें|करो|कीजिए)',
            r'(?i)(केवाईसी\s*(लंबित|अधूरा|अपडेट\s*करें))'
        ],
        'pin_to_receive': [
            r'(?i)\b(enter|type|input)\s*(your)?\s*(upi\s*pin|pin|secret\s*pin)\s*(to)?\s*(receive|claim|accept|credit|get|collect)\b',
            r'(?i)\b(receive|get|claim)\s*(money|cashback|refund|prize|amount)\s*(by\s*entering|using|enter)\s*(upi\s*pin|pin)\b',
            r'(?i)\b(pin\s*(daalein|daalo|darj\s*karein|to\s*receive))\b',
            r'(?i)\b(enter\s*(your\s*)?upi\s*pin\s*to\s*receive)\b',
            r'(?i)(पैसे|कैशबैक|रुपये|राशि|इनाम)\s*(प्राप्त\s*करने|पाने|लेने)\s*(के\s*लिए)?\s*(अपना\s*)?(यूपीआई\s*पिन|पिन|upi\s*pin)\s*(दर्ज\s*करें|डालें|डाले)'
        ],
        'fake_cashback': [
            r'(?i)\b(won|win|credited|claim|receive)\s*(rs\.?|inr|cashback|reward|scratch\s*card)\s*(\d{2,6})\b',
            r'(?i)\b(festive|special|exclusive|congratulations)\s*(cashback|reward|bonus)\b',
            r'(?i)\b(flat\s*cashback|scratch\s*and\s*win)\b',
            r'(?i)(कैशबैक|रिवॉर्ड|इनाम|बोनस)\s*(जीत\s*चुके|पाएं|क्लेम\s*करें)'
        ],
        'lottery_claim': [
            r'(?i)\b(lottery|lucky\s*draw|kbc|congratulations|selected\s*for|won\s*(a\s*)?(car|iphone|cash|lakhs?|crores?))\b',
            r'(?i)\b(won\s*(rs\.?|inr)?\s*\d+\s*(lakh|crore|million))\b',
            r'(?i)(लॉटरी|लकी\s*ड्रॉ|केबीसी|बधाई|कार\s*जीती|लाख\s*रुपये\s*जीते)'
        ],
        'advance_fee_fraud': [
            r'(?i)\b(pay|deposit|transfer|send)\s*(a\s*)?(processing\s*fee|registration\s*fee|gst|security\s*deposit|clearance\s*charge|refundable)\b',
            r'(?i)\b(before\s*receiving|to\s*claim|to\s*release|file\s*charge)\b',
            r'(?i)(प्रोसेसिंग\s*फीस|रजिस्ट्रेशन\s*शुल्क|जीएसटी\s*चार्ज|सिक्योरिटी\s*डिपॉजिट)\s*(जमा\s*करें|दें|भेजें)'
        ],
        'digital_arrest_claim': [
            r'(?i)\b(digital\s*arrest|arrest\s*warrant|interrogation|money\s*laundering|narcotics|customs\s*parcel|illegal\s*parcel|drugs\s*found)\b',
            r'(?i)\b(cbi|ed\s*notice|police\s*department|supreme\s*court|crime\s*branch|trai)\s*(notice|case|investigation|officer)\b',
            r'(?i)\b(join\s*(skype|zoom|whatsapp\s*video)|stay\s*on\s*call|do\s*not\s*disconnect)\b',
            r'(?i)(डिजिटल\s*अरेस्ट|वारंट|मनी\s*लॉन्ड्रिंग|नारकोटिक्स|अवैध\s*पार्सल|सीबीआई|क्राइम\s*ब्रांच)'
        ],
        'utility_threat': [
            r'(?i)\b(electricity|power|bijli|bses|mahavitaran|bescom|uppcl|tneb|gas)\s*(power\s*)?(will\s*be\s*)?(disconnect|cut|stop)\b',
            r'(?i)\b(disconnected\s*tonight|tonight\s*at\s*\d+[\.:]\d+|\d+\s*pm\s*from\s*electricity\s*office)\b',
            r'(?i)\b(previous\s*month\s*bill\s*(not\s*updated|unpaid))\b',
            r'(?i)(बिजली\s*(काट\s*दी\s*जाएगी|काट\s*देंगे|बंद\s*हो\s*जाएगी)|आज\s*रात\s*बिजली\s*कट)'
        ],
        'personal_number_callback': [
            r'(?i)\b(call|contact|dial)\s*(on\s*)?(our\s*)?(officer|manager|helpline|support|number)?\s*[:\-]?\s*([6-9]\d{9})\b'
        ],
        'task_fraud': [
            r'(?i)\b(work\s*from\s*home|part\s*time\s*job|earn\s*(rs\.?|inr)?\s*\d+\s*(to|-)?\s*\d+\s*(daily|per\s*day))\b',
            r'(?i)\b(like\s*youtube\s*videos|rate\s*hotels|google\s*maps\s*review|subscribe\s*channel\s*and\s*earn)\b',
            r'(?i)\b(telegram\s*group|telegram\s*channel|prepaid\s*task|vip\s*tier)\b'
        ],
        'remote_access_app': [
            r'(?i)\b(install|download)\s*(anydesk|teamviewer|quicksupport|rustdesk|alpemix)\b',
            r'(?i)\b(share\s*(9|10)\s*digit\s*code|remote\s*access)\b'
        ],
        'apk_download_prompt': [
            r'(?i)\b(download|install)\s*(.*)?\.(apk)\b',
            r'(?i)https?:\/\/[^\s]+\.apk\b'
        ],
        'otp_request': [
            r'(?i)\b(share|tell|send|read\s*out|forward)\s*(your)?\s*(otp|one\s*time\s*password|verification\s*code)\b',
            r'(?i)\b(otp\s*bhejo|otp\s*batao|share\s*otp)\b'
        ],
        'suspicious_link': [
            r'(?i)https?:\/\/(?!www\.(onlinesbi\.sbi|hdfcbank\.com|icicibank\.com|axisbank\.com|punjabnationalbank\.in|bankofbaroda\.in|canarabank\.com|paytm\.com|phonepe\.com|bhimupi\.org\.in|npci\.org\.in|sbi\.co\.in))[a-zA-Z0-9\.\-\_\/]+\.(top|xyz|click|live|club|site|online|pw|vip|apk|link|work|loan|support|cc)\b',
            r'(?i)https?:\/\/bit\.ly\/[^\s]+',
            r'(?i)https?:\/\/tinyurl\.com\/[^\s]+',
            r'(?i)https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s]*'
        ]
    }

    # Legitimate markers commonly found in standard Indian transactional alerts
    LEGITIMATE_PATTERNS = {
        'normal_debit_notification': [
            r'(?i)\b(debited\s*(for|by|with)?\s*(inr|rs\.?)\s*\d+[\.,]?\d*)\b',
            r'(?i)\b(paid\s*(rs\.?|inr)\s*\d+[\.,]?\d*\s*to)\b',
            r'(?i)\b(spent\s*(rs\.?|inr)\s*\d+)\b'
        ],
        'normal_credit_notification': [
            r'(?i)\b(credited\s*(with|for|by)?\s*(inr|rs\.?)\s*\d+[\.,]?\d*)\b',
            r'(?i)\b(received\s*(rs\.?|inr)\s*\d+[\.,]?\d*\s*from)\b'
        ],
        'has_balance': [
            r'(?i)\b(avail(able)?\s*bal(ance)?|total\s*bal|updated\s*bal(ance)?)\s*[:\-]?\s*(inr|rs\.?)\s*\d+[\.,]?\d*\b'
        ],
        'has_official_tollfree': [
            r'(?i)\b(1800\d{6,8}|1860\d{6,8}|helpline|customer\s*care\s*1800)\b',
            r'(?i)\b(if\s*not\s*done\s*by\s*you|sms\s*block\s*to\s*\d{5,6})\b'
        ]
    }

    # Critical scam indicators that carry severe threat status in Indian cybercrime
    SEVERE_INDICATORS = {
        'pin_to_receive': 88,
        'digital_arrest_claim': 92,
        'urgent_block_threat': 80,
        'kyc_update_demand': 78,
        'utility_threat': 82,
        'advance_fee_fraud': 85,
        'lottery_claim': 80,
        'remote_access_app': 86,
        'otp_request': 85,
        'apk_download_prompt': 82
    }

    @classmethod
    def analyze_message(cls, text: str, lang: str = 'en', sender: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze an input text for fraud indicators and return an explainable risk dossier.
        Supports optional sender ID / TRAI DLT header for bank metadata verification.
        """
        if not text or not text.strip():
            return {
                'risk_level': 'LOW',
                'risk_score': 0,
                'category_key': 'general_suspicious',
                'category_label': get_category_label('general_suspicious', lang),
                'indicators': [],
                'indicator_details': [],
                'explanation': 'Empty or blank input provided. Please enter a valid SMS, WhatsApp, or payment message.',
                'action_plan': NextBestActionEngine.generate_action_plan('legitimate_bank', 'LOW', [], lang),
                'confidence': 'heuristic_fallback',
                'bank_metadata': None
            }

        cleaned_text = text.strip()
        detected_indicators = []

        # Run Bank Metadata & TRAI DLT Header Evaluation
        bank_eval = BankMetadataAnalyzer.evaluate_spam_authenticity(cleaned_text, sender)
        sender_analysis = bank_eval.get('sender_analysis', {})
        extracted_metadata = bank_eval.get('extracted_metadata', {})

        # Check suspicious rules
        for indicator, regex_list in cls.PATTERNS.items():
            for pattern in regex_list:
                if re.search(pattern, cleaned_text):
                    detected_indicators.append(indicator)
                    break

        # Check legitimate markers
        legit_indicators = []
        for legit_code, regex_list in cls.LEGITIMATE_PATTERNS.items():
            for pattern in regex_list:
                if re.search(pattern, cleaned_text):
                    legit_indicators.append(legit_code)
                    break

        # Incorporate Bank Metadata red flags and green flags
        if extracted_metadata.get('personal_callback_number') and 'personal_number_callback' not in detected_indicators:
            detected_indicators.append('personal_number_callback')

        sender_type = sender_analysis.get('sender_type')
        if sender_type in ('PERSONAL_MOBILE_NUMBER', 'INTERNATIONAL_NUMBER'):
            # If sender is a personal mobile number, sending bank alerts, KYC demands, or utility disconnection threats is illegal under TRAI
            if detected_indicators or any(word in cleaned_text.lower() for word in ['bank', 'kyc', 'electricity', 'power', 'bijli', 'account', 'blocked', 'arrest']):
                if 'unofficial_sender_mobile' not in detected_indicators:
                    detected_indicators.append('unofficial_sender_mobile')

        if sender_analysis.get('is_registered_bank_header'):
            if 'dlt_verified_header' not in legit_indicators:
                legit_indicators.append('dlt_verified_header')

        if extracted_metadata.get('has_masked_account'):
            if 'masked_account_verified' not in legit_indicators:
                legit_indicators.append('masked_account_verified')

        # ML inference
        classifier = ScamClassifier.get_instance()
        ml_fraud_prob = classifier.predict_fraud_probability(cleaned_text)
        ml_score = int(ml_fraud_prob * 100)

        # Determine if severe scam indicator is present
        severe_matches = [cls.SEVERE_INDICATORS[ind] for ind in detected_indicators if ind in cls.SEVERE_INDICATORS]
        if 'unofficial_sender_mobile' in detected_indicators:
            severe_matches.append(86)

        # Legitimate dampening: If message looks like standard transaction alert with balance and no suspicious calls to action
        is_transactional = ('normal_debit_notification' in legit_indicators or 'normal_credit_notification' in legit_indicators)
        has_balance = 'has_balance' in legit_indicators or extracted_metadata.get('has_balance')
        is_dlt_verified = sender_analysis.get('is_registered_bank_header', False)

        if bank_eval.get('classification') == 'VERIFIED_LEGITIMATE_BANK_ALERT' and not detected_indicators:
            # TRAI DLT header + masked account + transaction info + no red flags
            final_score = min(ml_score, 5)
            category_key = 'legitimate_bank'
        elif is_transactional and has_balance and not detected_indicators:
            final_score = min(ml_score, 10 if is_dlt_verified else 12)
            category_key = 'legitimate_bank'
        elif is_transactional and not detected_indicators:
            final_score = min(ml_score, 18)
            category_key = 'legitimate_bank'
        elif severe_matches:
            # Anchor to the highest severe indicator detected + add boost for secondary indicators
            base_severe = max(severe_matches)
            secondary_bonus = min(12, (len(detected_indicators) - 1) * 4)
            combined = int(0.7 * (base_severe + secondary_bonus) + 0.3 * ml_score)
            # Ensure severe scam patterns remain firmly in HIGH band (>= 75)
            final_score = max(combined, base_severe)

            # Determine specific scam category
            if 'pin_to_receive' in detected_indicators:
                category_key = 'upi_pin_trap'
            elif 'digital_arrest_claim' in detected_indicators:
                category_key = 'digital_arrest'
            elif 'utility_threat' in detected_indicators:
                category_key = 'electricity_threat'
            elif 'kyc_update_demand' in detected_indicators or 'urgent_block_threat' in detected_indicators:
                category_key = 'fake_kyc'
            elif 'lottery_claim' in detected_indicators or 'advance_fee_fraud' in detected_indicators:
                category_key = 'lottery_prize'
            elif 'task_fraud' in detected_indicators:
                category_key = 'task_scam'
            elif 'remote_access_app' in detected_indicators or 'apk_download_prompt' in detected_indicators:
                category_key = 'remote_access_apk'
            elif 'fake_cashback' in detected_indicators:
                category_key = 'reward_points'
            else:
                category_key = 'general_suspicious'
        elif detected_indicators:
            # Moderate indicators
            heuristic_score = len(detected_indicators) * 25
            combined = int(0.6 * heuristic_score + 0.4 * ml_score)
            final_score = max(45, min(combined, 95))
            category_key = 'general_suspicious'
        else:
            # Rely on ML classifier
            final_score = ml_score
            category_key = 'general_suspicious' if final_score >= 60 else 'legitimate_bank'

        final_score = max(0, min(100, final_score))

        # Risk Classification
        if final_score >= 65:
            risk_level = 'HIGH'
        elif final_score >= 35:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # Generate localized indicator details
        indicator_details = [
            {
                'code': ind,
                'label': get_indicator_label(ind, lang),
                'type': 'warning'
            }
            for ind in detected_indicators
        ]
        for legit in legit_indicators:
            indicator_details.append({
                'code': legit,
                'label': get_indicator_label(legit, lang),
                'type': 'safe'
            })

        # Generate plain-language explanation
        explanation = cls._generate_explanation(risk_level, category_key, detected_indicators, legit_indicators, lang, bank_eval)

        # Generate Next Best Action Plan
        action_plan = NextBestActionEngine.generate_action_plan(category_key, risk_level, detected_indicators, lang)

        # AI LLM Deep Analysis Layer (Google Gemini)
        gemini_result = None
        psychological_tactics = []
        ai_enhanced = False
        try:
            gemini_result = GeminiScamAnalyzer.analyze_threat(cleaned_text, lang)
        except Exception:
            gemini_result = None

        if gemini_result and isinstance(gemini_result, dict):
            ai_enhanced = True
            psychological_tactics = gemini_result.get('psychological_tactics', [])
            gemini_score = int(gemini_result.get('risk_score', final_score))
            if severe_matches:
                final_score = max(final_score, gemini_score)
            elif not is_transactional:
                final_score = max(final_score, int(0.4 * final_score + 0.6 * gemini_score))
            
            final_score = max(0, min(100, final_score))
            if final_score >= 65:
                risk_level = 'HIGH'
            elif final_score >= 35:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'

            if gemini_result.get('explanation') and not (bank_eval.get('classification') == 'VERIFIED_LEGITIMATE_BANK_ALERT'):
                explanation = gemini_result['explanation']
            
            if gemini_result.get('what_to_avoid') and len(gemini_result['what_to_avoid']) > 0:
                action_plan['what_to_avoid'] = gemini_result['what_to_avoid']
            if gemini_result.get('immediate_actions') and len(gemini_result['immediate_actions']) > 0:
                action_plan['immediate_actions'] = gemini_result['immediate_actions']

        return {
            'risk_level': risk_level,
            'risk_score': final_score,
            'category_key': category_key,
            'category_label': get_category_label(category_key, lang),
            'indicators': detected_indicators,
            'indicator_details': indicator_details,
            'explanation': explanation,
            'action_plan': action_plan,
            'ml_confidence': round(ml_fraud_prob, 2),
            'ai_enhanced': ai_enhanced,
            'psychological_tactics': psychological_tactics,
            'ai_model': 'Gemini AI (Flash-Lite)' if ai_enhanced else None,
            'bank_metadata': bank_eval
        }

    @staticmethod
    def _generate_explanation(risk: str, cat: str, suspicious: List[str], legit: List[str], lang: str, bank_eval: Optional[Dict[str, Any]] = None) -> str:
        sender_analysis = (bank_eval or {}).get('sender_analysis', {})
        if bank_eval and bank_eval.get('classification') == 'VERIFIED_LEGITIMATE_BANK_ALERT':
            bank_name = sender_analysis.get('bank_name') or 'Bank'
            header = sender_analysis.get('raw_sender') or 'TRAI DLT'
            if lang == 'hi':
                return f"यह संदेश {bank_name} के ट्राई (TRAI) पंजीकृत आधिकारिक हेडर ({header}) और सुरक्षित मास्क किए गए खाते से भेजा गया वैध लेनदेन अलर्ट है।"
            return f"Verified authentic financial alert sent via TRAI DLT registered header ({header}) for {bank_name} referencing legitimate masked account metadata."
        
        if 'unofficial_sender_mobile' in suspicious:
            raw_sender = sender_analysis.get('raw_sender', 'personal mobile number')
            if lang == 'hi':
                return f"संदेश एक व्यक्तिगत 10-अंकों के मोबाइल नंबर ({raw_sender}) से भेजा गया है। भारतीय बैंक या बिजली विभाग कभी भी निजी मोबाइल से बैंक खाता बंद होने या केवाईसी का नोटिस नहीं भेजते।"
            return f"The message was dispatched from an unofficial personal mobile number ({raw_sender}). Under TRAI regulations, Indian banks and utilities never send official account notices from personal phone numbers."
        if lang == 'hi':
            if risk == 'LOW':
                return "यह संदेश एक सामान्य बैंक या सेवा प्रदाता के नियमित लेनदेन जैसा प्रतीत होता है। इसमें कोई धमकी, गोपनीय पिन मांगने या संदिग्ध लिंक का उपयोग नहीं किया गया है।"
            elif cat == 'fake_kyc':
                return "इस संदेश में आपके खाते को तुरंत बंद करने का डर दिखाया गया है और केवाईसी के नाम पर असत्यापित लिंक या नंबर दिया गया है। बैंक कभी एसएमएस पर ऐसा अल्टीमेटम नहीं देते।"
            elif cat == 'upi_pin_trap':
                return "संदेश में पैसे या कैशबैक प्राप्त करने के लिए पिन डालने की बात कही गई है। यह धोखाधड़ी की सबसे आम तकनीक है; यूपीआई में पैसे पाने के लिए कभी पिन नहीं लगता।"
            elif cat == 'digital_arrest':
                return "संदेश या कॉल में कानूनी कार्रवाई, डिजिटल अरेस्ट या पुलिस केस का फर्जी डर दिखाकर तुरंत पैसे मांगने के स्पष्ट संकेत हैं। भारत में 'डिजिटल अरेस्ट' का कोई कानून नहीं है।"
            elif cat == 'electricity_threat':
                return "संदेश में आज रात बिजली काटने की फर्जी चेतावनी दी गई है और पर्सनल मोबाइल नंबर पर बात करने को कहा गया है। यह बिजली विभाग का आधिकारिक तरीका नहीं है।"
            elif cat == 'lottery_prize':
                return "संदेश में बिना किसी लॉटरी टिकट के भारी नकद इनाम का झांसा दिया गया है, जिसके लिए आपसे प्रोसेसिंग फीस या शुल्क मांगा जा सकता है।"
            elif cat == 'task_scam':
                return "घर बैठे यूट्यूब लाइक या होटल रेटिंग से अवास्तविक रूप से अधिक कमाई का लालच दिया जा रहा है।"
            else:
                return "इस संदेश में कई ऐसे संकेत मौजूद हैं जिनका उपयोग साइबर ठग बैंक उपभोक्ताओं को गुमराह करने के लिए करते हैं।"
        else:
            if risk == 'LOW':
                return "This message aligns with standard financial transaction alerts. It does not exhibit psychological pressure, urgent deadlines, or requests for PIN/OTP."
            elif cat == 'fake_kyc':
                return "Identified urgent account suspension threats and unsolicited KYC update prompts. Legitimate financial institutions do not issue sudden suspension deadlines via SMS links."
            elif cat == 'upi_pin_trap':
                return "Identified instructions prompting the user to enter a UPI PIN or approve a collect request to receive funds. This violates the core design of UPI."
            elif cat == 'digital_arrest':
                return "Identified severe intimidation involving fabricated legal warrants, police or CBI impersonation, and pressure to join unmonitored video calls or transfer funds."
            elif cat == 'electricity_threat':
                return "Identified simulated utility disconnection notices with arbitrary evening deadlines sent from unofficial personal contact numbers."
            elif cat == 'lottery_prize':
                return "Identified unrealistic prize claims combined with upfront fee or personal detail requests."
            elif cat == 'task_scam':
                return "Identified unrealistic part-time earning claims and invitations to unverified social tasks or investment groups."
            else:
                return "The text contains patterns characteristic of financial engineering tactics intended to induce hasty decisions."
