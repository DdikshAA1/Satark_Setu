"""
Next Best Action (NBA) Engine for Satark Setu.
The central innovation of the platform: Transforms raw risk scores and heuristic
flags into structured, actionable, practical, and situation-aware user guidance.

Four key dimensions:
1. Why this is suspicious (plain-language explanation)
2. What the user should AVOID doing (concrete pitfalls)
3. Immediate safe actions (defensive steps to take right now)
4. Recovery protocol (if user already clicked, shared OTP, or sent money)
"""

from typing import Dict, Any, List

class NextBestActionEngine:
    
    @staticmethod
    def generate_action_plan(
        category_key: str,
        risk_level: str,
        indicators: List[str],
        lang: str = 'en'
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive, situation-specific action plan.
        """
        lang = 'hi' if lang == 'hi' else 'en'
        
        # Base templates per category
        if lang == 'hi':
            return NextBestActionEngine._generate_hindi_plan(category_key, risk_level, indicators)
        else:
            return NextBestActionEngine._generate_english_plan(category_key, risk_level, indicators)

    @staticmethod
    def _generate_english_plan(cat: str, risk: str, indicators: List[str]) -> Dict[str, Any]:
        if risk == 'LOW':
            return {
                'headline': 'Standard Transaction or Informational Alert',
                'why_suspicious': 'This message matches the standard format of a legitimate financial institution or merchant alert. It does not contain threats of disconnection, unsolicited links, or requests for PIN/OTP.',
                'what_to_avoid': [
                    'Never share any OTP or UPI PIN even if someone calls claiming to be from your bank regarding this message.',
                    'Do not forward bank transaction alerts to unknown third parties.'
                ],
                'immediate_actions': [
                    'Review your account statement in your official banking app if you want to verify the transaction.',
                    'Ensure your SMS alerts and notifications from your bank remain active.',
                    'If you did not initiate this transaction, immediately contact your bank\'s official helpline listed on the back of your debit card.'
                ],
                'if_already_interacted': [
                    'If this transaction was unauthorized, call your bank customer care immediately to lock your card/netbanking.',
                    'Call the National Cyber Crime Helpline at 1930 within the golden hour to report unauthorized debits.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in',
                    'rbi_sachet': 'https://sachet.rbi.org.in'
                }
            }

        # Medium or High Risk scenarios
        if cat == 'fake_kyc':
            return {
                'headline': 'High Alert: Fake KYC / Account Suspension Scam',
                'why_suspicious': 'Legitimate banks NEVER threaten to block your account within hours over SMS or WhatsApp, nor do they send third-party web links (.top, .xyz, bit.ly) for KYC verification. Indian banking regulations mandate official in-branch or certified in-app KYC.',
                'what_to_avoid': [
                    'DO NOT click the link provided in the message.',
                    'DO NOT call the phone number given in the text message.',
                    'NEVER enter your NetBanking username, password, debit card details, or OTP on any webpage reached via SMS.'
                ],
                'immediate_actions': [
                    'Open your official bank mobile app (e.g., YONO SBI, HDFC Mobile, iMobile) directly from your app drawer to verify your real account status.',
                    'Visit your nearest bank branch if you have any genuine doubts regarding your KYC status.',
                    'Block the sender’s number or report the SMS as SPAM in your messaging app.'
                ],
                'if_already_interacted': [
                    'If you clicked the link and entered card/banking details: Immediately open your official bank app and block your debit/credit card and NetBanking.',
                    'If money has been deducted, immediately call 1930 (National Cyber Crime Reporting Helpline) and report the transaction.',
                    'File an official incident report on https://cybercrime.gov.in and save all screenshots and SMS headers.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930 (Toll Free, 24x7)',
                    'cybercrime_portal': 'https://cybercrime.gov.in',
                    'chakshu_portal': 'Report fraud SMS at https://sancharsaathi.gov.in/sfc/'
                }
            }

        elif cat == 'upi_pin_trap':
            return {
                'headline': 'Severe Threat: UPI PIN To Receive Money Trap',
                'why_suspicious': 'The request asks you to enter your UPI PIN, scan a QR code, or approve a collect request to "receive money" or "claim cashback". This is a fundamental mathematical impossibility in UPI: entering your UPI PIN ALWAYS transfers money OUT of your bank account.',
                'what_to_avoid': [
                    'NEVER enter your UPI PIN on your phone screen when expecting to receive money.',
                    'DO NOT scan any QR code sent to you on WhatsApp or OLX to receive payment.',
                    'DO NOT click "Approve" or "Pay" on unexpected collect requests in PhonePe, Google Pay, or Paytm.'
                ],
                'immediate_actions': [
                    'Decline or reject the collect request immediately inside your UPI app.',
                    'Tap "Report as Fraud / Spam" next to the sender\'s VPA in your UPI app history.',
                    'Remind the sender: "In India, money can be credited directly to a UPI ID or mobile number without the receiver entering any PIN."'
                ],
                'if_already_interacted': [
                    'If you entered your PIN and money was debited: Open your UPI app transaction history immediately, note the UTR / Transaction ID.',
                    'Call your bank\'s fraud desk immediately to raise a chargeback on the fraudulent UPI transaction.',
                    'Dial 1930 right away. Prompt reporting within 2 hours enables law enforcement to freeze the money in the recipient account.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'npci_dispute': 'https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        elif cat == 'digital_arrest':
            return {
                'headline': 'Severe Threat: Digital Arrest / Fake Law Enforcement Call',
                'why_suspicious': 'Scammers impersonate Police, CBI, ED, Mumbai Police, or Supreme Court judges on Skype/WhatsApp video calls claiming you are under "Digital Arrest" for money laundering, parcels containing narcotics, or cybercrimes. Indian law has NO legal concept of "Digital Arrest".',
                'what_to_avoid': [
                    'DO NOT stay on the video call or agree to isolate yourself in a closed room.',
                    'DO NOT transfer any "verification deposit", "bail amount", or "safe custody funds" to any account given by them.',
                    'DO NOT share your Aadhaar, PAN card, or bank account statements under intimidation.'
                ],
                'immediate_actions': [
                    'Immediately disconnect the call. Do not entertain threats.',
                    'Remember: Real law enforcement agencies NEVER conduct arrests over Skype or WhatsApp, nor do they ask citizens to transfer money to "clear" their name.',
                    'Discuss the call calmly with a family member, trusted friend, or local police station.'
                ],
                'if_already_interacted': [
                    'If you transferred funds into any bank account provided during the call: Immediately dial 1930 and state that you were a victim of a Digital Arrest fraud.',
                    'Visit your nearest local Cyber Crime Police Station immediately with transaction slips and bank statements.',
                    'Freeze all affected bank accounts through your official branch or netbanking portal.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/'
                }
            }

        elif cat == 'electricity_threat':
            return {
                'headline': 'Urgent Threat: Electricity Disconnection Scam',
                'why_suspicious': 'Electricity distribution companies (DISCOMs) do not send SMS warnings from personal 10-digit mobile numbers threatening disconnection "tonight at 9:30 PM", nor do they ask consumers to call a personal number or download remote APKs.',
                'what_to_avoid': [
                    'DO NOT call the mobile number listed in the SMS.',
                    'DO NOT download any app or APK file suggested by the caller (such as AnyDesk, TeamViewer, QuickSupport).',
                    'DO NOT make any token Rs 5 or Rs 10 payment on an unverified link or app.'
                ],
                'immediate_actions': [
                    'Check your real electricity bill status through your state DISCOM\'s official app or consumer portal (e.g., BESCOM, Mahavitaran, BSES, TNEB).',
                    'Call the official customer care number printed on your physical paper electricity bill.',
                    'Report the scammer\'s mobile number on the Sanchar Saathi Chakshu portal.'
                ],
                'if_already_interacted': [
                    'If you installed any remote assistance app (AnyDesk/TeamViewer/QuickSupport): Turn off WiFi and Mobile Data immediately, then uninstall the app.',
                    'Restart your phone in safe mode if the app cannot be uninstalled.',
                    'If banking credentials were entered while the app was running: Log in from another trusted device and change your passwords and block cards immediately.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/'
                }
            }

        elif cat == 'lottery_prize':
            return {
                'headline': 'Warning: Lottery / Prize / Advance Fee Scam',
                'why_suspicious': 'You are promised a large sum (e.g. KBC lottery, lucky draw, car prize) but asked to pay a small "processing fee", "registration charge", or "GST clearance". Legitimate lotteries never ask winners to pay upfront fees to claim prizes.',
                'what_to_avoid': [
                    'DO NOT send any registration fee, GST, or processing amount.',
                    'DO NOT share your bank account, Aadhaar, or PAN details to "verify" the prize.'
                ],
                'immediate_actions': [
                    'Recognize the trap: If you did not enter a lottery ticket, you cannot win a lottery.',
                    'Block and report the contact on WhatsApp/SMS.'
                ],
                'if_already_interacted': [
                    'If you paid any advance fee via UPI or NetBanking, immediately file a fraud report on 1930 and your UPI app with the recipient UPI VPA and transaction ID.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        elif cat == 'task_scam':
            return {
                'headline': 'Warning: Part-Time Job / Task / Telegram Scam',
                'why_suspicious': 'Offers easy earnings (Rs 2,000 to Rs 8,000 per day) for liking YouTube videos, rating Google Maps locations, or reviewing hotels. The scam gives small initial payouts of Rs 150-500, then asks you to deposit large sums into a "crypto wallet" or "prepaid task account".',
                'what_to_avoid': [
                    'DO NOT deposit any money to "upgrade VIP tier" or "unlock prepaid tasks".',
                    'DO NOT join unauthorized Telegram investment groups.'
                ],
                'immediate_actions': [
                    'Cease all communication and exit the Telegram group.',
                    'Remember: Genuine employers never demand payment from employees to work.'
                ],
                'if_already_interacted': [
                    'If you deposited money into the scammer’s accounts, gather all payment UTRs, bank account numbers of beneficiaries, and Telegram chat exports.',
                    'Dial 1930 and file an FIR on cybercrime.gov.in under financial task fraud.'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        # Default fallback for other high risk patterns
        return {
            'headline': 'High Alert: Deceptive Financial Communication',
            'why_suspicious': 'This message exhibits pressure tactics, unverified links, or requests for sensitive banking credentials designed to bypass your security defenses.',
            'what_to_avoid': [
                'Do not click any unverified links.',
                'Never share OTPs, PINs, or banking credentials under any circumstance.',
                'Do not make payments under urgency or emotional duress.'
            ],
            'immediate_actions': [
                'Verify the communication independently through official bank helplines or in person.',
                'Report the sender number as spam and block it.'
            ],
            'if_already_interacted': [
                'Immediately contact your bank to freeze netbanking or cards if credentials were typed.',
                'Call 1930 if funds were debited.'
            ],
            'official_contacts': {
                'cybercrime_helpline': '1930',
                'cybercrime_portal': 'https://cybercrime.gov.in'
            }
        }

    @staticmethod
    def _generate_hindi_plan(cat: str, risk: str, indicators: List[str]) -> Dict[str, Any]:
        if risk == 'LOW':
            return {
                'headline': 'सामान्य बैंक सूचना या नियमित लेनदेन अलर्ट',
                'why_suspicious': 'यह संदेश सामान्य बैंक या व्यापारी सूचना जैसा है। इसमें खाता बंद करने की कोई धमकी, संदिग्ध लिंक या पिन मांगने की बात नहीं पाई गई है।',
                'what_to_avoid': [
                    'यदि कोई व्यक्ति बैंक अधिकारी बनकर कॉल करे और इस संदेश के बारे में ओटीपी या पिन मांगे, तो बिल्कुल न दें।',
                    'बैंक के गोपनीय संदेश किसी अनजान व्यक्ति को फॉरवर्ड न करें।'
                ],
                'immediate_actions': [
                    'यदि आप पुष्टि करना चाहते हैं, तो अपने बैंक के आधिकारिक मोबाइल ऐप में जाकर खाता पासबुक देखें।',
                    'यदि आपने यह लेनदेन नहीं किया है, तो अपने डेबिट कार्ड के पीछे लिखे बैंक हेल्पलाइन नंबर पर तुरंत कॉल करें।'
                ],
                'if_already_interacted': [
                    'यदि खाते से अनजाने में पैसे कटे हैं, तो तुरंत बैंक कस्टमर केयर को कॉल करके कार्ड या नेटबैंकिंग ब्लॉक कराएं।',
                    'साइबर हेल्पलाइन 1930 पर तुरंत कॉल करें ताकि पैसे को आगे ट्रांसफर होने से रोका जा सके।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930 (टोल-फ्री, 24 घंटे)',
                    'cybercrime_portal': 'https://cybercrime.gov.in',
                    'rbi_sachet': 'https://sachet.rbi.org.in'
                }
            }

        if cat == 'fake_kyc':
            return {
                'headline': 'गंभीर चेतावनी: फर्जी केवाईसी / खाता बंद करने का फ्रॉड',
                'why_suspicious': 'असली बैंक कभी भी एसएमएस या व्हाट्सएप पर लिंक भेजकर केवाईसी करने को नहीं कहते, और न ही कुछ घंटों में खाता बंद करने की धमकी देते हैं। यह आपके खाते का पासवर्ड और पैसे चुराने का प्रयास है।',
                'what_to_avoid': [
                    'मैसेज में दिए गए किसी भी लिंक पर कभी क्लिक न करें।',
                    'मैसेज में दिए गए किसी भी मोबाइल नंबर पर फोन न करें।',
                    'किसी भी वेबसाइट पर अपना नेटबैंकिंग यूजरनेम, पासवर्ड, कार्ड नंबर या ओटीपी न भरें।'
                ],
                'immediate_actions': [
                    'अपने फोन में बैंक का असली आधिकारिक ऐप (जैसे YONO, HDFC, iMobile) खोलकर खाते की सही स्थिति देखें।',
                    'यदि केवाईसी की कोई शंका हो, तो पास की असली बैंक शाखा (Branch) में जाकर सीधे बात करें।',
                    'संदेश भेजने वाले नंबर को फोन में ब्लॉक और स्पैम (Spam) रिपोर्ट करें।'
                ],
                'if_already_interacted': [
                    'यदि आप लिंक खोलकर कार्ड या बैंक की जानकारी भर चुके हैं: तुरंत अपने बैंक ऐप से कार्ड और नेटबैंकिंग ब्लॉक करें।',
                    'यदि खाते से पैसे कट गए हैं, तो तुरंत 1930 (राष्ट्रीय साइबर क्राइम हेल्पलाइन) पर कॉल करें।',
                    'https://cybercrime.gov.in पोर्टल पर शिकायत दर्ज कराएं और मैसेज का स्क्रीनशॉट संभाल कर रखें।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930 (टोल-फ्री, 24 घंटे)',
                    'cybercrime_portal': 'https://cybercrime.gov.in',
                    'chakshu_portal': 'संदिग्ध एसएमएस की रिपोर्ट करें: https://sancharsaathi.gov.in/sfc/'
                }
            }

        elif cat == 'upi_pin_trap':
            return {
                'headline': 'अत्यधिक गंभीर: पैसे पाने के लिए यूपीआई पिन मांगने का धोखा',
                'why_suspicious': 'इस संदेश या रिक्वेस्ट में आपको पैसे पाने या कैशबैक लेने के लिए UPI PIN डालने या QR कोड स्कैन करने को कहा जा रहा है। यूपीआई में यह तकनीकी रूप से असंभव है: UPI PIN केवल आपके खाते से पैसे काटने के लिए ही डाला जाता है!',
                'what_to_avoid': [
                    'पैसे प्राप्त करने के लिए अपने फोन पर कभी भी UPI PIN दर्ज न करें।',
                    'व्हाट्सएप या OLX पर किसी अनजान व्यक्ति द्वारा भेजा गया QR कोड कभी स्कैन न करें।',
                    'PhonePe, Google Pay या Paytm में आए किसी भी अनजान "Collect Request" या "Pay" बटन को न दबाएं।'
                ],
                'immediate_actions': [
                    'अपने यूपीआई ऐप में इस रिक्वेस्ट को तुरंत "Decline / Reject" (अस्वीकार) करें।',
                    'यूपीआई ऐप में भेजने वाले को "Report as Fraud / Spam" करें।',
                    'सामने वाले को स्पष्ट कहें: "भारत में पैसे लेने के लिए पिन डालने की जरूरत नहीं होती, पैसे सीधे मोबाइल नंबर या यूपीआई आईडी पर आ जाते हैं।"'
                ],
                'if_already_interacted': [
                    'यदि आपने पिन डाल दिया और पैसे कट गए: तुरंत यूपीआई ऐप में ट्रांजेक्शन आईडी (UTR नंबर) नोट करें।',
                    'तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें। पहले 2 घंटों में शिकायत करने पर पैसे वापस मिलने की संभावना सबसे ज्यादा होती है।',
                    'अपने बैंक कस्टमर केयर को कॉल करके उस फ्रॉड ट्रांजेक्शन की शिकायत दर्ज कराएं।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'npci_dispute': 'https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        elif cat == 'digital_arrest':
            return {
                'headline': 'गंभीर चेतावनी: फर्जी डिजिटल अरेस्ट व पुलिस/सीबीआई का डर',
                'why_suspicious': 'धोखेबाज पुलिस, सीबीआई, नारकोटिक्स या सुप्रीम कोर्ट का फर्जी अधिकारी बनकर वीडियो कॉल करते हैं और कहते हैं कि आप "डिजिटल अरेस्ट" में हैं। भारतीय कानून में "डिजिटल अरेस्ट" नाम की कोई चीज नहीं होती!',
                'what_to_avoid': [
                    'वीडियो कॉल पर बिल्कुल न रहें और कमरे में खुद को बंद न करें।',
                    'उनके कहने पर जांच या सत्यापन के नाम पर किसी भी खाते में एक भी रुपया न भेजें।',
                    'डरकर अपने आधार कार्ड, पैन कार्ड या बैंक पासबुक की फोटो बिल्कुल न भेजें।'
                ],
                'immediate_actions': [
                    'तुरंत कॉल काट दें। उनके किसी भी डर या धमकी की परवाह न करें।',
                    'याद रखें: असली पुलिस कभी भी व्हाट्सएप या स्काइप पर अरेस्ट नहीं करती और न ही पैसे मांगती है।',
                    'शांत रहें और अपने परिवार के सदस्यों या स्थानीय पुलिस थाने जाकर बात करें।'
                ],
                'if_already_interacted': [
                    'यदि डर के मारे आपने पैसे ट्रांसफर कर दिए हैं: बिना एक पल गंवाए 1930 पर कॉल करें और बताएं कि आपके साथ डिजिटल अरेस्ट फ्रॉड हुआ है।',
                    'तुरंत अपने नजदीकी साइबर पुलिस स्टेशन में बैंक ट्रांजेक्शन की रसीद लेकर जाएं।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        elif cat == 'electricity_threat':
            return {
                'headline': 'चेतावनी: आज रात बिजली काटने का फर्जी संदेश',
                'why_suspicious': 'बिजली कंपनियां कभी भी किसी 10-अंकों के आम मोबाइल नंबर से एसएमएस भेजकर यह नहीं कहतीं कि "आज रात 9:30 बजे बिजली काट दी जाएगी"। यह धोखेबाजों का जाल है।',
                'what_to_avoid': [
                    'मैसेज में दिए गए मोबाइल नंबर पर बिल्कुल फोन न करें।',
                    'फोन पर बात करते हुए उनके कहने पर AnyDesk, TeamViewer या QuickSupport जैसा कोई ऐप डाउनलोड न करें।',
                    'सत्यापन के नाम पर 5 या 10 रुपये का भी कोई भुगतान न करें।'
                ],
                'immediate_actions': [
                    'अपने बिजली बिल के कागज़ पर लिखे असली कस्टमर केयर नंबर पर फोन करके बिल का पता करें।',
                    'बिजली विभाग के असली ऐप या वेबसाइट पर जाकर अपना बिल चेक करें।',
                    'इस फर्जी नंबर को संचार साथी चक्षु पोर्टल (Chakshu Portal) पर रिपोर्ट करें।'
                ],
                'if_already_interacted': [
                    'यदि आपने उनके कहने पर AnyDesk या TeamViewer ऐप डाउनलोड किया है: तुरंत फोन का इंटरनेट बंद करें और उस ऐप को डिलीट (Uninstall) करें।',
                    'यदि आपने बैंक विवरण भरा था, तो दूसरे सुरक्षित फोन से तुरंत अपना बैंक पासवर्ड बदलें और कार्ड ब्लॉक कराएं।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'chakshu': 'https://sancharsaathi.gov.in/sfc/'
                }
            }

        elif cat == 'lottery_prize':
            return {
                'headline': 'चेतावनी: लॉटरी और फर्जी ईनाम का लालच (Advance Fee Fraud)',
                'why_suspicious': 'आपको लाखों रुपये की लॉटरी या गाड़ी जीतने की बात कही जा रही है और उसे पाने के लिए प्रोसेसिंग फीस या टैक्स जमा करने को कहा जा रहा है। असली लॉटरी में पहले पैसे नहीं मांगे जाते।',
                'what_to_avoid': [
                    'इनाम पाने के लालच में कोई भी रजिस्ट्रेशन फीस, जीएसटी या फाइल चार्ज न भेजें।',
                    'बैंक खाता नंबर या आधार कार्ड साझा न करें।'
                ],
                'immediate_actions': [
                    'सीधा नियम याद रखें: जब आपने कोई लॉटरी टिकट ही नहीं खरीदा, तो आप लॉटरी कैसे जीत सकते हैं?',
                    'नंबर को तुरंत ब्लॉक और रिपोर्ट करें।'
                ],
                'if_already_interacted': [
                    'यदि आप पैसे भेज चुके हैं, तो तुरंत 1930 पर कॉल करें और पेमेंट ऐप में फ्रॉड दर्ज कराएं।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        elif cat == 'task_scam':
            return {
                'headline': 'चेतावनी: घर बैठे पैसे कमाने / यूट्यूब लाइक टास्क फ्रॉड',
                'why_suspicious': 'यूट्यूब वीडियो लाइक करने या होटल रिव्यू करने के बदले रोजाना ₹2000-₹5000 देने का लालच दिया जाता है। पहले छोटे ₹150-₹200 देकर विश्वास जीतते हैं, फिर बड़ा पैसा जमा कराकर ठग लेते हैं।',
                'what_to_avoid': [
                    'टास्क अनलॉक करने या वीआईपी बनने के लिए एक भी रुपया जमा न करें।',
                    'किसी भी अनधिकृत टेलीग्राम ग्रुप में न जुड़ें।'
                ],
                'immediate_actions': [
                    'धोखेबाजों से तुरंत बात बंद करें और टेलीग्राम ग्रुप छोड़ दें।',
                    'याद रखें: कोई भी असली कंपनी काम देने के बदले कर्मचारी से पैसे नहीं मांगती।'
                ],
                'if_already_interacted': [
                    'यदि पैसे जमा करा दिए हैं, तो सभी ट्रांजेक्शन आईडी और चैट के स्क्रीनशॉट लेकर 1930 पर रिपोर्ट करें।'
                ],
                'official_contacts': {
                    'cybercrime_helpline': '1930',
                    'cybercrime_portal': 'https://cybercrime.gov.in'
                }
            }

        # Fallback for general high risk
        return {
            'headline': 'अत्यधिक सतर्कता: संदिग्ध धोखाधड़ी संदेश',
            'why_suspicious': 'इस संदेश में आपको डराकर या लालच देकर जल्दबाजी में संवेदनशील जानकारी लेने या पैसे ट्रांसफर कराने के संकेत मिले हैं।',
            'what_to_avoid': [
                'संदेश में दिए गए किसी भी लिंक पर क्लिक न करें।',
                'किसी भी अनजान व्यक्ति को अपना ओटीपी (OTP), पासवर्ड या पिन न बताएं।',
                'जल्दबाजी या घबराहट में कोई निर्णय न लें।'
            ],
            'immediate_actions': [
                'बैंक या संबंधित विभाग के असली हेल्पलाइन नंबर पर बात करके पुष्टि करें।',
                'संदेश भेजने वाले नंबर को ब्लॉक करें।'
            ],
            'if_already_interacted': [
                'यदि पैसे कट गए हैं या गोपनीय जानकारी साझा हुई है, तो तुरंत 1930 पर कॉल करें और बैंक को सूचित करें।'
            ],
            'official_contacts': {
                'cybercrime_helpline': '1930',
                'cybercrime_portal': 'https://cybercrime.gov.in'
            }
        }

