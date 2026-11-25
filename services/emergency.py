"""
Emergency Fraud Response Assistant for Satark Setu.
Provides an interactive, calm, decisive triage workflow for citizens
who have interacted with a scam, shared credentials, or suffered unauthorized debits.
Integrates with India's 1930 Cyber Helpline, Sanchar Saathi Chakshu,
and official bank freeze protocols.
"""

from typing import Dict, Any, List
from services.localization import get_text

class EmergencyResponseAssistant:

    INCIDENT_TYPES = {
        'clicked_link': {
            'en': 'I clicked a suspicious link or opened a strange webpage',
            'hi': 'मैंने किसी संदिग्ध लिंक पर क्लिक किया या अनजान वेबसाइट खोली'
        },
        'shared_otp': {
            'en': 'I accidentally shared an OTP or verification code',
            'hi': 'मैंने गलती से किसी को अपना ओटीपी (OTP) बता दिया'
        },
        'shared_banking_info': {
            'en': 'I entered my NetBanking password, PIN, or card details',
            'hi': 'मैंने बैंक पासवर्ड, कार्ड नंबर या यूपीआई पिन किसी पेज पर भर दिया'
        },
        'approved_upi': {
            'en': 'I approved a suspicious UPI collect request or scanned a QR code',
            'hi': 'मैंने कोई अनजान यूपीआई कलेक्ट रिक्वेस्ट स्वीकार कर ली या क्यूआर स्कैन किया'
        },
        'money_lost': {
            'en': 'Money was debited / transferred from my bank account',
            'hi': 'मेरे बैंक खाते से पैसे कट चुके हैं / ट्रांसफर हो चुके हैं'
        },
        'threat_call': {
            'en': 'I received a threatening call (Digital Arrest / Police / Power Cut)',
            'hi': 'मुझे धमकी भरा कॉल आया (डिजिटल अरेस्ट / पुलिस / बिजली काटने की धमकी)'
        }
    }

    BANK_DIRECTORIES = [
        {'name': 'State Bank of India (SBI)', 'toll_free': '1800 1234 / 1800 2100', 'block_sms': 'SMS "BLOCK" to 567676', 'app': 'YONO SBI'},
        {'name': 'HDFC Bank', 'toll_free': '1800 1600 / 1800 2600', 'block_sms': 'SMS "BLOCK" to 5676712', 'app': 'HDFC MobileBanking'},
        {'name': 'ICICI Bank', 'toll_free': '1800 1080', 'block_sms': 'SMS "BLOCK" to 5676766', 'app': 'iMobile Pay'},
        {'name': 'Punjab National Bank (PNB)', 'toll_free': '1800 180 2222 / 1800 103 2222', 'block_sms': 'SMS "HOT <CardNo>" to 5607040', 'app': 'PNB ONE'},
        {'name': 'Axis Bank', 'toll_free': '1800 419 5959 / 1800 103 5577', 'block_sms': 'SMS "BLOCKCARD" to 5676782', 'app': 'Axis Mobile'},
        {'name': 'Bank of Baroda', 'toll_free': '1800 5700', 'block_sms': 'SMS "BLOCK <Last4Digits>" to 8422009988', 'app': 'bob World'},
        {'name': 'Paytm Payments Bank / Wallet', 'toll_free': '0120 4456 456', 'block_sms': 'In-App 24x7 Helpdesk', 'app': 'Paytm App'},
        {'name': 'PhonePe', 'toll_free': '080 6872 7374 / 022 6872 7374', 'block_sms': 'In-App Support', 'app': 'PhonePe App'}
    ]

    @classmethod
    def get_incident_triage(cls, incident_key: str, lang: str = 'en') -> Dict[str, Any]:
        """
        Generate detailed triage recommendations for the selected emergency incident.
        """
        lang = 'hi' if lang == 'hi' else 'en'

        if incident_key not in cls.INCIDENT_TYPES:
            incident_key = 'clicked_link'

        incident_title = cls.INCIDENT_TYPES[incident_key].get(lang, cls.INCIDENT_TYPES[incident_key]['en'])

        if lang == 'hi':
            return cls._get_hindi_triage(incident_key, incident_title)
        else:
            return cls._get_english_triage(incident_key, incident_title)

    @staticmethod
    def _get_english_triage(key: str, title: str) -> Dict[str, Any]:
        golden_hour_alert = "CRITICAL: The first 2 hours after financial fraud are known as the 'Golden Hour'. Immediate reporting to 1930 and your bank maximizes the chances of freezing stolen funds before scammers cash out."

        if key == 'money_lost':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': golden_hour_alert,
                'severity': 'CRITICAL',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'Call 1930 Cyber Crime Helpline Immediately',
                        'detail': 'Dial 1930 right now from your phone. Explain the fraudulent transaction, provide your bank name, account number, amount debited, and the recipient details/transaction ID. The 1930 system communicates directly with bank nodal officers to place an immediate hold on the suspect beneficiary account.'
                    },
                    {
                        'step_number': 2,
                        'title': 'Contact Your Bank’s 24x7 Fraud Desk',
                        'detail': 'Call your bank\'s official customer care helpline. State clearly: "I am reporting an unauthorized fraudulent debit." Request an immediate block on your debit/credit card, UPI access, and NetBanking, and demand a Formal Dispute/Complaint Ticket Number.'
                    },
                    {
                        'step_number': 3,
                        'title': 'Preserve Evidence Thoroughly',
                        'detail': 'Take screenshots of: the debit SMS notification showing UTR / reference number, the message or WhatsApp chat with the scammer, the scammer\'s phone number or UPI VPA, and bank account statement.'
                    },
                    {
                        'step_number': 4,
                        'title': 'Register an FIR on National Cyber Crime Portal',
                        'detail': 'Visit https://cybercrime.gov.in and register an official complaint under "Financial Fraud". Upload the screenshots and mention your 1930 complaint acknowledgment number.'
                    },
                    {
                        'step_number': 5,
                        'title': 'Beware of Secondary Recovery Scams',
                        'detail': 'NEVER pay anyone on Instagram, Telegram, or Twitter claiming to be a "hacker who can recover lost money". Only banks and police have the legal authority to freeze and refund stolen funds.'
                    }
                ],
                'evidence_checklist': [
                    'SMS alert showing debit amount and 12-digit UTR / Transaction ID',
                    'Bank account statement showing date, time, and recipient account/VPA',
                    'Screenshots of chat / call logs with the scammer',
                    'Scammer\'s UPI ID, phone number, or bank details'
                ],
                'official_hotlines': {
                    'primary': '1930 (National Cyber Crime Helpline - 24x7)',
                    'portal': 'https://cybercrime.gov.in',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        elif key == 'shared_otp':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "URGENT: Scammers use captured OTPs to authorize immediate money transfers, card charges, or SIM swaps.",
                'severity': 'HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'Block All NetBanking & Debit Cards Immediately',
                        'detail': 'Open your official banking app and instantly freeze your debit/credit cards and disable international/online transactions. If you cannot access the app, call your bank customer care immediately.'
                    },
                    {
                        'step_number': 2,
                        'title': 'Change NetBanking & UPI Passwords',
                        'detail': 'Log in to your banking portal from a secure device and change your login password, transaction password, and UPI PIN.'
                    },
                    {
                        'step_number': 3,
                        'title': 'Check Account Statement for Unauthorized Debits',
                        'detail': 'Check if any money has been deducted. If any debit occurred, call 1930 immediately.'
                    },
                    {
                        'step_number': 4,
                        'title': 'Monitor SIM Card Signal (SIM Swap Guard)',
                        'detail': 'If your phone suddenly loses network signal completely, contact your mobile telecom operator immediately from another phone; scammers may have initiated a fraudulent SIM swap.'
                    }
                ],
                'evidence_checklist': [
                    'Screenshot of the original OTP message (masking the code for third parties)',
                    'Phone number or platform through which the OTP was solicited',
                    'Exact timestamp of sharing'
                ],
                'official_hotlines': {
                    'primary': '1930 (Cyber Crime Helpline)',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        elif key == 'approved_upi':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "URGENT: You approved a collect request or entered your PIN. Money has likely transferred.",
                'severity': 'HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'Capture the UPI Transaction Reference (UTR)',
                        'detail': 'Open PhonePe, GPay, or Paytm transaction history. Tap on the transaction and copy down the 12-digit UTR / UPI Reference Number.'
                    },
                    {
                        'step_number': 2,
                        'title': 'Dial 1930 Within 2 Hours',
                        'detail': 'Report the fraudulent debit with the UTR number. The cyber team will flag the receiving bank to freeze the recipient VPA.'
                    },
                    {
                        'step_number': 3,
                        'title': 'Report Fraud Inside Your UPI App',
                        'detail': 'Use the "Having an Issue / Report Fraud" button directly inside PhonePe, GPay, or Paytm to flag the receiver\'s VPA.'
                    },
                    {
                        'step_number': 4,
                        'title': 'Change Your UPI PIN',
                        'detail': 'Reset your UPI PIN in your UPI app using your debit card or Aadhaar OTP as a precautionary measure.'
                    }
                ],
                'evidence_checklist': [
                    '12-digit UPI UTR number and timestamp',
                    'Screenshot of the collect request note or payment screen',
                    'Beneficiary UPI ID (e.g. name@okhdfcbank)'
                ],
                'official_hotlines': {
                    'primary': '1930 (National Cyber Crime Helpline)',
                    'portal': 'https://cybercrime.gov.in',
                    'npci': 'https://www.npci.org.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        elif key == 'threat_call':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "REMINDER: Digital Arrest has NO legal validity in India. Real police officers NEVER issue arrest warrants over Skype/WhatsApp or demand money transfers.",
                'severity': 'MEDIUM_TO_HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'Disconnect and Block the Caller Immediately',
                        'detail': 'Hang up immediately. Do not stay on video calls or follow their instructions to sit in an isolated room.'
                    },
                    {
                        'step_number': 2,
                        'title': 'Do NOT Transfer Any Money for "Verification"',
                        'detail': 'Scammers claim funds will be refunded after verification. No Indian agency (CBI, ED, Police, Supreme Court) ever holds citizen funds in "safe escrow accounts".'
                    },
                    {
                        'step_number': 3,
                        'title': 'Consult Trusted Family or Visit Local Police',
                        'detail': 'Talk calmly to your family members or visit your local police station to verify peace of mind.'
                    },
                    {
                        'step_number': 4,
                        'title': 'Report Caller on Chakshu Portal',
                        'detail': 'Report the fraud mobile number on the Government of India\'s Chakshu portal at https://sancharsaathi.gov.in/sfc/ to have their telecom connections disconnected.'
                    }
                ],
                'evidence_checklist': [
                    'Phone number or Skype/WhatsApp ID of the caller',
                    'Call recording or screenshots if available',
                    'Any fake ID cards or documents sent by the caller'
                ],
                'official_hotlines': {
                    'primary': '1930 (Cyber Crime Helpline)',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        else: # clicked_link or shared_banking_info
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "PREVENTIVE ACTION: Act swiftly to secure accounts before unauthorized actions can be executed.",
                'severity': 'HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'Disconnect Internet / Mobile Data',
                        'detail': 'Turn off Wi-Fi and Mobile Data on your smartphone immediately if an unknown file or APK began downloading.'
                    },
                    {
                        'step_number': 2,
                        'title': 'Freeze Cards & Change Banking Passwords',
                        'detail': 'From another secure phone or computer, log into your official bank portal and block your debit/credit card and change your NetBanking login password.'
                    },
                    {
                        'step_number': 3,
                        'title': 'Uninstall Any Suspicious Apps',
                        'detail': 'Check your phone’s installed apps list in Settings. Remove any recent app (especially AnyDesk, TeamViewer, or unknown APKs).'
                    },
                    {
                        'step_number': 4,
                        'title': 'Check Bank Transactions',
                        'detail': 'Verify your current account balance. If any unauthorized transaction has occurred, call 1930 immediately.'
                    }
                ],
                'evidence_checklist': [
                    'The exact URL link that was clicked',
                    'SMS or message containing the link',
                    'Name of any downloaded file'
                ],
                'official_hotlines': {
                    'primary': '1930 (National Cyber Crime Helpline)',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

    @staticmethod
    def _get_hindi_triage(key: str, title: str) -> Dict[str, Any]:
        golden_hour_alert = "महत्वपूर्ण सूचना: साइबर फ्रॉड होने के पहले 2 घंटे 'गोल्डन ऑवर' कहलाते हैं। तुरंत 1930 और बैंक को सूचित करने पर पैसे को ठगों के खाते से निकलने से पहले फ्रीज किया जा सकता है।"

        if key == 'money_lost':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': golden_hour_alert,
                'severity': 'CRITICAL',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें',
                        'detail': 'बिना किसी देरी के अपने फोन से 1930 डायल करें। उन्हें अपने बैंक का नाम, खाता संख्या, कटे हुए पैसे की राशि और ट्रांजेक्शन आईडी बताएं। 1930 सीधे बैंकों के नोडल अधिकारियों से संपर्क करके ठग के खाते को तुरंत सीज (Freeze) कराती है।'
                    },
                    {
                        'step_number': 2,
                        'title': 'अपने बैंक के 24x7 हेल्पलाइन पर तुरंत बात करें',
                        'detail': 'अपने बैंक कस्टमर केयर को कॉल करें और स्पष्ट कहें: "मेरे खाते से अनधिकृत धोखाधड़ी लेनदेन हुआ है।" अपने डेबिट/क्रेडिट कार्ड, यूपीआई और नेटबैंकिंग को तुरंत ब्लॉक कराएं और शिकायत टिकट नंबर नोट करें।'
                    },
                    {
                        'step_number': 3,
                        'title': 'सभी जरूरी सबूत सुरक्षित रखें',
                        'detail': 'बैंक द्वारा आए पैसे कटने के एसएमएस का स्क्रीनशॉट (जिसमें 12 अंकों का UTR नंबर हो), ठग से हुई चैट या कॉल का स्क्रीनशॉट और बैंक पासबुक का स्क्रीनशॉट सुरक्षित रखें।'
                    },
                    {
                        'step_number': 4,
                        'title': 'cybercrime.gov.in पर आधिकारिक शिकायत दर्ज करें',
                        'detail': 'https://cybercrime.gov.in वेबसाइट पर जाकर "Financial Fraud" में शिकायत दर्ज कराएं और 1930 से मिला एकनॉलेजमेंट नंबर वहां भरें।'
                    },
                    {
                        'step_number': 5,
                        'title': 'सोशल मीडिया पर पैसे वापस कराने वाले फर्जी लोगों से बचें',
                        'detail': 'इंस्टाग्राम, टेलीग्राम या फेसबुक पर किसी भी ऐसे व्यक्ति को पैसे न दें जो कहे कि "मैं हैकर हूं और आपके पैसे वापस दिला दूंगा"। सिर्फ पुलिस और बैंक ही कानूनी रूप से पैसे रोक सकते हैं।'
                    }
                ],
                'evidence_checklist': [
                    'बैंक का एसएमएस जिसमें UTR / ट्रांजेक्शन नंबर और कटी हुई राशि हो',
                    'बैंक स्टेटमेंट / पासबुक की कॉपी',
                    'धोखेबाज का मोबाइल नंबर, यूपीआई आईडी या बैंक खाता विवरण',
                    'व्हाट्सएप चैट या कॉल रिकॉर्डिंग'
                ],
                'official_hotlines': {
                    'primary': '1930 (राष्ट्रीय साइबर क्राइम हेल्पलाइन - 24 घंटे)',
                    'portal': 'https://cybercrime.gov.in',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        elif key == 'shared_otp':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "अति आवश्यक: धोखेबाज चुराए गए ओटीपी का उपयोग करके खाते से पैसे निकाल सकते हैं।",
                'severity': 'HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'तुरंत अपने कार्ड और नेटबैंकिंग को ब्लॉक करें',
                        'detail': 'अपने असली बैंक ऐप में जाकर डेबिट कार्ड को अस्थायी रूप से बंद (Freeze/Block) करें या बैंक कस्टमर केयर को कॉल करके तुरंत ब्लॉक कराएं।'
                    },
                    {
                        'step_number': 2,
                        'title': 'नेटबैंकिंग और यूपीआई पिन तुरंत बदलें',
                        'detail': 'किसी सुरक्षित फोन या कंप्यूटर से अपने बैंक खाते का पासवर्ड और यूपीआई पिन बदल लें।'
                    },
                    {
                        'step_number': 3,
                        'title': 'खाते से कटे पैसों की जांच करें',
                        'detail': 'जांचें कि क्या कोई पैसा कटा है। यदि पैसा कट चुका है, तो तुरंत 1930 पर कॉल करें।'
                    }
                ],
                'evidence_checklist': [
                    'ओटीपी वाले एसएमएस का स्क्रीनशॉट',
                    'जिस नंबर या प्लेटफॉर्म पर ओटीपी साझा हुआ उसकी जानकारी'
                ],
                'official_hotlines': {
                    'primary': '1930 (साइबर क्राइम हेल्पलाइन)',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        elif key == 'threat_call':
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "ध्यान रखें: भारतीय कानून में 'डिजिटल अरेस्ट' का कोई अस्तित्व नहीं है। असली पुलिस कभी व्हाट्सएप/स्काइप पर अरेस्ट नहीं करती और न ही पैसे मांगती है।",
                'severity': 'MEDIUM_TO_HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'कॉल तुरंत काटें और नंबर ब्लॉक करें',
                        'detail': 'धमकी भरे कॉल को तुरंत डिस्कनेक्ट करें। कमरे में अकेले बंद होने या वीडियो कॉल जारी रखने की उनकी बात बिल्कुल न मानें।'
                    },
                    {
                        'step_number': 2,
                        'title': 'जांच या सत्यापन के नाम पर कोई पैसा न भेजें',
                        'detail': 'सीबीआई, पुलिस या कस्टम विभाग कभी भी नागरिक से पैसे ट्रांसफर करने को नहीं कहते।'
                    },
                    {
                        'step_number': 3,
                        'title': 'परिवार या स्थानीय पुलिस को सूचित करें',
                        'detail': 'शांत मन से अपने परिवारजनों से बात करें और पास के पुलिस थाने जाएं।'
                    },
                    {
                        'step_number': 4,
                        'title': 'चक्षु पोर्टल (Chakshu Portal) पर रिपोर्ट करें',
                        'detail': 'संचार साथी के चक्षु पोर्टल (https://sancharsaathi.gov.in/sfc/) पर उस नंबर की शिकायत करें ताकि उसका सिम बंद किया जा सके।'
                    }
                ],
                'evidence_checklist': [
                    'कॉल करने वाले का मोबाइल नंबर या व्हाट्सएप आईडी',
                    'कॉल की रिकॉर्डिंग या स्क्रीनशॉट'
                ],
                'official_hotlines': {
                    'primary': '1930 (साइबर हेल्पलाइन)',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

        else: # Default/clicked_link/approved_upi
            return {
                'incident_key': key,
                'incident_title': title,
                'golden_hour_notice': "तुरंत सतर्कता: खाते की सुरक्षा सुनिश्चित करने के लिए तुरंत आवश्यक कदम उठाएं।",
                'severity': 'HIGH',
                'step_by_step': [
                    {
                        'step_number': 1,
                        'title': 'इंटरनेट / मोबाइल डेटा बंद करें',
                        'detail': 'यदि कोई अनजान ऐप या फाइल डाउनलोड होना शुरू हुई है, तो तुरंत फोन का इंटरनेट और वाई-फाई बंद कर दें।'
                    },
                    {
                        'step_number': 2,
                        'title': 'कार्ड ब्लॉक करें और पासवर्ड बदलें',
                        'detail': 'बैंक के आधिकारिक हेल्पलाइन पर कॉल करके कार्ड ब्लॉक कराएं और पासवर्ड बदलें।'
                    },
                    {
                        'step_number': 3,
                        'title': 'संदिग्ध ऐप को तुरंत अनइंस्टॉल करें',
                        'detail': 'फोन की सेटिंग्स में जाकर हाल ही में डाउनलोड हुए AnyDesk, TeamViewer या किसी भी अनजान ऐप को डिलीट करें।'
                    },
                    {
                        'step_number': 4,
                        'title': 'पैसे कटने पर 1930 पर तुरंत कॉल करें',
                        'detail': 'यदि खाते से पैसे कट चुके हैं, तो 1930 पर कॉल करें और बैंक को सूचित करें।'
                    }
                ],
                'evidence_checklist': [
                    'क्लिक किए गए लिंक का स्क्रीनशॉट',
                    'संदेश भेजने वाले का नंबर'
                ],
                'official_hotlines': {
                    'primary': '1930 (राष्ट्रीय साइबर हेल्पलाइन)',
                    'portal': 'https://cybercrime.gov.in'
                },
                'bank_directory': EmergencyResponseAssistant.BANK_DIRECTORIES
            }

