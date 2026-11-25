"""
Localization service for Satark Setu.
Provides English and Hindi dictionary mappings for UI labels, risk categories,
warning indicators, and actionable guidance in simple, respectful language.
"""

TRANSLATIONS = {
    'en': {
        'brand_name': 'Satark Setu',
        'tagline': 'Think Before You Trust.',
        'sub_tagline': 'Intelligent Digital Payment Fraud Prevention & Awareness Platform for India',
        'risk_low': 'Low Risk',
        'risk_medium': 'Medium Risk',
        'risk_high': 'High Risk / Severe Warning',
        'risk_score': 'Heuristic Risk Score',
        'detected_category': 'Detected Pattern',
        'key_indicators': 'Detected Warning Indicators',
        'why_suspicious': 'Why This Looks Suspicious',
        'what_to_avoid': 'What You Must AVOID Doing',
        'immediate_actions': 'What You Should Do Immediately',
        'if_already_interacted': 'If You Already Interacted or Sent Money',
        'upi_pin_golden_rule': 'CRITICAL SAFETY RULE: You NEVER enter your UPI PIN to receive money or claim cashback. UPI PIN is exclusively for authorizing money to LEAVE your account.',
        'disclaimer': 'Disclaimer: Satark Setu uses explainable heuristic rules and machine learning indicators to guide users. A low-risk assessment does not guarantee complete legitimacy. Never share passwords or PINs.',
        'nav': {
            'home': 'Home',
            'scam_detector': 'Scam Detector',
            'upi_guard': 'UPI Fraud Guard',
            'url_scanner': 'URL Scanner',
            'emergency': 'Emergency Help',
            'dashboard': 'Safety Dashboard',
            'language': 'Language'
        },
        'actions': {
            'analyse_message': 'Analyze Message',
            'check_upi': 'Verify UPI Request',
            'scan_url': 'Scan URL Safety',
            'get_emergency_steps': 'Get Emergency Steps',
            'copy_advice': 'Copy Safety Steps',
            'clear': 'Clear Input',
            'try_sample': 'Load Sample'
        }
    },
    'hi': {
        'brand_name': 'सतर्क सेतु (Satark Setu)',
        'tagline': 'विश्वास करने से पहले, एक बार सोचें।',
        'sub_tagline': 'भारत के लिए डिजिटल भुगतान धोखाधड़ी रोकथाम एवं सुरक्षा मंच',
        'risk_low': 'कम जोखिम (सामान्य)',
        'risk_medium': 'मध्यम जोखिम (सावधानी जरूरी)',
        'risk_high': 'अत्यधिक जोखिम (सावधान! धोखाधड़ी का खतरा)',
        'risk_score': 'सुरक्षा जोखिम स्कोर',
        'detected_category': 'पहचाना गया फ्रॉड प्रकार',
        'key_indicators': 'पहचाने गए चेतावनी संकेत',
        'why_suspicious': 'यह संदेश संदिग्ध क्यों लग रहा है?',
        'what_to_avoid': 'आपको क्या बिल्कुल नहीं करना है',
        'immediate_actions': 'तुरंत क्या सुरक्षित कदम उठाएं',
        'if_already_interacted': 'यदि आप पहले ही लिंक खोल चुके हैं या पैसे कट गए हैं',
        'upi_pin_golden_rule': 'सबसे जरूरी सुरक्षा नियम: पैसे प्राप्त करने या कैशबैक लेने के लिए कभी भी UPI PIN दर्ज नहीं किया जाता। UPI PIN केवल आपके खाते से पैसे भेजने (कटने) के लिए होता है।',
        'disclaimer': 'अस्वीकरण: सतर्क सेतु आपको धोखाधड़ी से सावधान करने के लिए नियमों और संकेतकों पर आधारित सुझाव देता है। कम जोखिम का अर्थ यह नहीं कि कोई जोखिम नहीं है। कभी भी अपना पिन या ओटीपी किसी को न दें।',
        'nav': {
            'home': 'मुख्य पृष्ठ',
            'scam_detector': 'मैसेज जांचें',
            'upi_guard': 'यूपीआई सुरक्षा कवच',
            'url_scanner': 'वेबसाइट लिंक जांचें',
            'emergency': 'आपातकालीन सहायता',
            'dashboard': 'सुरक्षा डैशबोर्ड',
            'language': 'भाषा (Language)'
        },
        'actions': {
            'analyse_message': 'मैसेज की जांच करें',
            'check_upi': 'यूपीआई अनुरोध जांचें',
            'scan_url': 'वेबसाइट लिंक जांचें',
            'get_emergency_steps': 'आपातकालीन सहायता प्राप्त करें',
            'copy_advice': 'सुरक्षा उपाय कॉपी करें',
            'clear': 'हटाएं (Clear)',
            'try_sample': 'उदाहरण लोड करें'
        }
    }
}

INDICATOR_LABELS = {
    'en': {
        'urgent_block_threat': 'Account Block / Suspension Threat',
        'kyc_update_demand': 'Unsolicited KYC Update Requirement',
        'suspicious_link': 'Unverified External Web Link',
        'brand_impersonation': 'Bank or Official Brand Impersonation',
        'pin_to_receive': 'Request to Enter UPI PIN to Receive Money',
        'fake_cashback': 'Unrealistic Reward / Cashback Promise',
        'collect_request': 'Unexpected UPI Collect / Pull Request',
        'lottery_claim': 'Lottery or Prize Money Claim',
        'advance_fee_fraud': 'Demand for Advance Fee / Processing Charge',
        'digital_arrest_claim': 'Threat of "Digital Arrest" / Police Case',
        'law_enforcement_impersonation': 'Impersonation of Police, CBI, ED, or TRAI',
        'utility_threat': 'Electricity / Gas Disconnection Warning',
        'disconnection_urgency': 'Immediate Disconnection Deadline (Tonight/Within Hours)',
        'personal_number_callback': 'Callback to a Personal Mobile Number for Official Work',
        'unofficial_sender_mobile': 'Unofficial 10-Digit Mobile Sender (TRAI Violation)',
        'dlt_verified_header': 'TRAI DLT Verified Bank Header',
        'masked_account_verified': 'Legitimate Masked Account Reference (A/C XX1234)',
        'task_fraud': 'Work from Home / Paid YouTube Likes Scam',
        'unrealistic_earning': 'Unrealistic Daily Earnings Promise (Rs 2000-5000/day)',
        'telegram_redirect': 'Redirection to Telegram or WhatsApp Group',
        'apk_download_prompt': 'Instruction to Download an APK File',
        'remote_access_app': 'Request to Install Remote Control App (AnyDesk/TeamViewer/RustDesk)',
        'otp_request': 'Request to Share or Read Out OTP',
        'reward_expiry_urgency': 'Credit Card / Reward Points Expiry Urgency',
        'shortened_url': 'Shortened URL (bit.ly, tinyurl, etc.) Hiding Real Destination',
        'ip_host': 'URL Uses Direct IP Address Instead of Registered Domain',
        'suspicious_tld': 'Suspicious or Low-Cost TLD (.xyz, .top, .live, .click)',
        'brand_typosquatting': 'Misspelled Brand or Bank Domain',
        'no_https': 'Unencrypted Plain HTTP Connection',
        'normal_debit_notification': 'Standard Bank Debit Transaction Alert',
        'has_balance': 'Includes Available Account Balance',
        'has_official_tollfree': 'Includes Standard Bank Helpline Contact',
        'merchant_credit': 'Legitimate Merchant Settlement or Credit Alert',
        'unrecognized_upi_handle': 'Unrecognized or Random UPI Handle (@xyz, @okrandom)'
    },
    'hi': {
        'urgent_block_threat': 'बैंक खाता या सिम तुरंत बंद करने की धमकी',
        'kyc_update_demand': 'केवाईसी (KYC) तुरंत अपडेट करने का दबाव',
        'suspicious_link': 'अज्ञात या असुरक्षित वेब लिंक',
        'brand_impersonation': 'प्रसिद्ध बैंक या सरकारी विभाग का फर्जी नाम',
        'pin_to_receive': 'पैसे प्राप्त करने के लिए UPI PIN डालने की मांग',
        'fake_cashback': 'फर्जी इनाम या कैशबैक का लालच',
        'collect_request': 'अचानक आया यूपीआई कलेक्ट अनुरोध',
        'lottery_claim': 'लॉटरी या ईनाम जीतने का झूठा दावा',
        'advance_fee_fraud': 'इनाम पाने के लिए पहले प्रोसेसिंग फीस की मांग',
        'digital_arrest_claim': 'फर्जी "डिजिटल अरेस्ट" या कोर्ट केस की धमकी',
        'law_enforcement_impersonation': 'पुलिस, सीबीआई, ट्राई (TRAI) का फर्जी अधिकारी बनना',
        'utility_threat': 'बिजली या गैस कनेक्शन काटने की चेतावनी',
        'disconnection_urgency': 'आज रात ही बिजली काटने का फर्जी अल्टीमेटम',
        'personal_number_callback': 'सरकारी काम के लिए पर्सनल मोबाइल नंबर पर कॉल करने को कहना',
        'unofficial_sender_mobile': 'व्यक्तिगत मोबाइल नंबर से बैंक/केवाईसी संदेश (ट्राई नियमों का उल्लंघन)',
        'dlt_verified_header': 'ट्राई द्वारा पंजीकृत आधिकारिक बैंक हेडर',
        'masked_account_verified': 'सुरक्षित मास्क किया गया बैंक खाता (जैसे A/C XX1234)',
        'task_fraud': 'घर बैठे यूट्यूब लाइक कर पैसे कमाने का झांसा',
        'unrealistic_earning': 'रोजाना 2000-5000 रुपये कमाने का अवास्तविक लालच',
        'telegram_redirect': 'टेलीग्राम या व्हाट्सएप ग्रुप में जुड़ने का निर्देश',
        'apk_download_prompt': 'फर्जी मोबाइल ऐप (APK) डाउनलोड करने का दबाव',
        'remote_access_app': 'AnyDesk या TeamViewer जैसे रिमोट ऐप डाउनलोड कराने की कोशिश',
        'otp_request': 'ओटीपी (OTP) पूछने या शेयर करने की मांग',
        'reward_expiry_urgency': 'क्रेडिट कार्ड रिवॉर्ड पॉइंट्स आज ही खत्म होने की झूठी सूचना',
        'shortened_url': 'छोटा किया गया लिंक जो असली वेबसाइट छुपाता है',
        'ip_host': 'वेबसाइट नाम की जगह सीधा आईपी नंबर का उपयोग',
        'suspicious_tld': 'संदिग्ध एक्सटेंशन (.xyz, .top, .live)',
        'brand_typosquatting': 'बैंक के नाम से मिलती-जुलती फर्जी स्पेलिंग',
        'no_https': 'असुरक्षित (HTTP) कनेक्शन',
        'normal_debit_notification': 'बैंक खाते से सामान्य पैसे कटने की सूचना',
        'has_balance': 'खाते का उपलब्ध बैलेंस प्रदर्शित है',
        'has_official_tollfree': 'बैंक का आधिकारिक हेल्पलाइन नंबर मौजूद है',
        'merchant_credit': 'व्यापारी खाते में सामान्य पैसे आने की सूचना',
        'unrecognized_upi_handle': 'अज्ञात या अजीब यूपीआई हैंडल'
    }
}

CATEGORY_LABELS = {
    'en': {
        'fake_kyc': 'Fake KYC / Account Suspension Threat',
        'lottery_prize': 'Lottery & Prize Scam',
        'upi_pin_trap': 'UPI PIN to Receive Trap',
        'electricity_threat': 'Utility / Electricity Disconnection Threat',
        'digital_arrest': 'Digital Arrest & Law Enforcement Impersonation',
        'task_scam': 'Task / Work From Home Fraud',
        'remote_access_apk': 'Remote App / Malicious APK Scam',
        'reward_points': 'Credit Card / Reward Points Phishing',
        'legitimate_bank': 'Legitimate Bank Transaction Notification',
        'legitimate_upi': 'Standard UPI Transaction Alert',
        'suspicious_url': 'Suspicious URL / Phishing Domain',
        'general_suspicious': 'Potentially Deceptive Payment Communication'
    },
    'hi': {
        'fake_kyc': 'फर्जी केवाईसी / खाता बंद होने का डर',
        'lottery_prize': 'लॉटरी और ईनाम का झांसा (Lottery Scam)',
        'upi_pin_trap': 'पैसे पाने के लिए यूपीआई पिन मांगने का धोखा',
        'electricity_threat': 'बिजली कनेक्शन काटने की फर्जी चेतावनी',
        'digital_arrest': 'डिजिटल अरेस्ट व पुलिस का फर्जी डर',
        'task_scam': 'घर बैठे पैसे कमाने / टास्क फ्रॉड',
        'remote_access_apk': 'फर्जी ऐप (APK) या रिमोट एक्सेस फ्रॉड',
        'reward_points': 'क्रेडिट कार्ड रिवॉर्ड पॉइंट्स फर्जीवाड़ा',
        'legitimate_bank': 'सामान्य बैंक लेनदेन सूचना (सुरक्षित)',
        'legitimate_upi': 'सामान्य यूपीआई भुगतान सूचना',
        'suspicious_url': 'संदिग्ध वेबसाइट लिंक (Phishing)',
        'general_suspicious': 'संदिग्ध भुगतान संबंधी संदेश'
    }
}

def get_text(key: str, lang: str = 'en') -> str:
    """Retrieve localized top-level text."""
    lang = 'hi' if lang == 'hi' else 'en'
    return TRANSLATIONS.get(lang, {}).get(key, TRANSLATIONS['en'].get(key, key))

def get_indicator_label(code: str, lang: str = 'en') -> str:
    """Retrieve human-friendly localized indicator label."""
    lang = 'hi' if lang == 'hi' else 'en'
    return INDICATOR_LABELS.get(lang, {}).get(code, INDICATOR_LABELS['en'].get(code, code))

def get_category_label(cat_key: str, lang: str = 'en') -> str:
    """Retrieve human-friendly localized category label."""
    lang = 'hi' if lang == 'hi' else 'en'
    return CATEGORY_LABELS.get(lang, {}).get(cat_key, CATEGORY_LABELS['en'].get(cat_key, cat_key))

