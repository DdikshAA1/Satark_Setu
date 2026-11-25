"""
URL Safety Scanner Service for Satark Setu.
Analyzes suspicious URLs structurally WITHOUT visiting or executing them.
Evaluates brand impersonation, typosquatting, deceptive subdomains,
unusual TLDs, IP-address hostnames, dangerous extensions, and security protocols.
Does NOT claim external threat intelligence verification or guaranteed safety.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from services.nba_engine import NextBestActionEngine
from services.localization import get_text, get_indicator_label, get_category_label

class URLSafetyScanner:

    SUSPICIOUS_TLDS = {
        'top', 'xyz', 'click', 'live', 'club', 'site', 'online', 'pw', 'vip',
        'apk', 'link', 'work', 'loan', 'support', 'cc', 'rest', 'guru', 'tokyo'
    }

    TRUSTED_INDIAN_DOMAINS = {
        'onlinesbi.sbi': 'State Bank of India',
        'sbi.co.in': 'State Bank of India',
        'hdfcbank.com': 'HDFC Bank',
        'icicibank.com': 'ICICI Bank',
        'axisbank.com': 'Axis Bank',
        'punjabnationalbank.in': 'Punjab National Bank',
        'pnbindia.in': 'Punjab National Bank',
        'bankofbaroda.in': 'Bank of Baroda',
        'canarabank.com': 'Canara Bank',
        'paytm.com': 'Paytm Payments',
        'phonepe.com': 'PhonePe',
        'bhimupi.org.in': 'BHIM UPI (NPCI)',
        'npci.org.in': 'National Payments Corporation of India',
        'rbi.org.in': 'Reserve Bank of India',
        'sancharsaathi.gov.in': 'Department of Telecom, India',
        'cybercrime.gov.in': 'National Cyber Crime Reporting Portal',
        'uidai.gov.in': 'Unique Identification Authority of India',
        'incometax.gov.in': 'Income Tax Department, India'
    }

    TARGET_BRANDS = [
        'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'icici', 'icicibank', 'axis',
        'pnb', 'punjabnationalbank', 'bankofbaroda', 'bob', 'canara',
        'paytm', 'phonepe', 'gpay', 'googlepay', 'bhim', 'aadhaar', 'uidai',
        'incometax', 'pan', 'mahavitaran', 'bses', 'bescom', 'indpost', 'indiapost'
    ]

    @classmethod
    def scan_url(cls, raw_url: str, lang: str = 'en') -> Dict[str, Any]:
        """
        Analyze the URL structure safely without network requests.
        """
        if not raw_url or not raw_url.strip():
            return {
                'risk_level': 'LOW',
                'risk_score': 0,
                'category_key': 'suspicious_url',
                'category_label': get_category_label('suspicious_url', lang),
                'indicators': [],
                'indicator_details': [],
                'explanation': 'No URL provided to scan.',
                'action_plan': NextBestActionEngine.generate_action_plan('suspicious_url', 'LOW', [], lang),
                'url_parsed': {}
            }

        url_to_parse = raw_url.strip()
        # Add scheme if missing for parsing purposes
        has_original_scheme = bool(re.match(r'^[a-zA-Z]+://', url_to_parse))
        if not has_original_scheme:
            url_to_parse = 'http://' + url_to_parse

        try:
            parsed = urlparse(url_to_parse)
            hostname = parsed.hostname or ''
            path = parsed.path or ''
            scheme = parsed.scheme.lower()
        except Exception:
            hostname = url_to_parse
            path = ''
            scheme = 'unknown'

        detected_indicators = []
        score = 0

        # Check: Missing HTTPS
        if scheme == 'http':
            detected_indicators.append('no_https')
            score += 15

        # Check: IP Address Hostname
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, hostname):
            detected_indicators.append('ip_host')
            score += 50

        # Check: Legitimate Known Official Domain
        is_known_trusted = False
        for trusted_dom, brand_title in cls.TRUSTED_INDIAN_DOMAINS.items():
            if hostname == trusted_dom or hostname.endswith('.' + trusted_dom):
                is_known_trusted = True
                break

        if is_known_trusted:
            score = 5
            risk_level = 'LOW'
            explanation = (
                f"यह वेबसाइट ({hostname}) एक सत्यापित आधिकारिक संस्था का पंजीकृत डोमेन प्रतीत होता है।"
                if lang == 'hi' else
                f"This domain ({hostname}) matches an officially recognized institutional or governmental portal."
            )
            return {
                'risk_level': risk_level,
                'risk_score': score,
                'category_key': 'legitimate_bank',
                'category_label': get_category_label('legitimate_bank', lang),
                'indicators': [],
                'indicator_details': [{'code': 'trusted_domain', 'label': f'Verified Official Domain: {hostname}', 'type': 'safe'}],
                'explanation': explanation,
                'action_plan': NextBestActionEngine.generate_action_plan('legitimate_bank', 'LOW', [], lang),
                'url_parsed': {
                    'hostname': hostname,
                    'scheme': scheme,
                    'path': path
                }
            }

        # Check: Suspicious or Low-Cost TLD
        host_parts = hostname.split('.')
        tld = host_parts[-1].lower() if host_parts else ''
        if tld in cls.SUSPICIOUS_TLDS:
            detected_indicators.append('suspicious_tld')
            score += 35

        # Check: Dangerous file download in path (.apk, .exe, .scr)
        if re.search(r'\.(apk|exe|scr|bat|vbs)$', path, re.IGNORECASE):
            detected_indicators.append('apk_download_prompt')
            score += 45

        # Check: Shortened URL
        if hostname in ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'cutt.ly', 'rb.gy']:
            detected_indicators.append('shortened_url')
            score += 30

        # Check: Brand Typosquatting & Deceptive Subdomains
        # Example: sbi-kyc-update.com or hdfc.bank-security.xyz
        found_brand = None
        for brand in cls.TARGET_BRANDS:
            if brand in hostname.lower():
                found_brand = brand
                # If the brand is present but the domain is NOT the trusted domain
                if not is_known_trusted:
                    detected_indicators.append('brand_typosquatting')
                    score += 45
                    break

        # Check: Excessive subdomains (e.g. login.sbi.banking.secure.phish.com)
        if len(host_parts) >= 4:
            detected_indicators.append('suspicious_link')
            score += 20

        # Suspicious path keywords (kyc, verify, update, pan, password, refund)
        if re.search(r'(?i)(kyc|pan-update|refund|rewards|redeem|bank-verify|aadhar-link)', path):
            score += 25

        score = max(0, min(100, score))

        if score >= 65:
            risk_level = 'HIGH'
        elif score >= 35:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # Localized indicator details
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
            if 'brand_typosquatting' in detected_indicators:
                explanation = f"चेतावनी! इस लिंक में किसी प्रसिद्ध बैंक या ब्रांड नाम ({found_brand or ''}) का उपयोग किया गया है, लेकिन यह बैंक की असली वेबसाइट नहीं है। यह फिशिंग (Phishing) का प्रयास है।"
            elif 'ip_host' in detected_indicators:
                explanation = "चेतावनी! यह लिंक वेबसाइट नाम के बजाय एक सीधे आईपी एड्रेस (IP Address) का उपयोग कर रहा है। वित्तीय संस्थान कभी आईपी एड्रेस वाले लिंक नहीं भेजते।"
            elif 'suspicious_tld' in detected_indicators:
                explanation = f"यह वेबसाइट संदिग्ध एक्सटेंशन (.{tld}) का उपयोग कर रही है, जो आमतौर पर साइबर ठगों द्वारा सस्ती व फर्जी वेबसाइट बनाने के लिए उपयोग किए जाते हैं।"
            elif risk_level == 'LOW':
                explanation = "इस लिंक की संरचना में कोई सीधा दुर्भावनापूर्ण पैटर्न नहीं मिला है। फिर भी, किसी भी अनजान वेबसाइट पर बैंक पासवर्ड या ओटीपी दर्ज न करें।"
            else:
                explanation = "इस यूआरएल में असुरक्षित प्रोटोकॉल या असामान्य सबडोमेन जैसी संदिग्ध विशेषताएं पाई गई हैं।"
        else:
            if 'brand_typosquatting' in detected_indicators:
                explanation = f"HIGH RISK: The domain name mimics a legitimate brand ({found_brand or 'financial institution'}) using typosquatting or misleading subdomains. This is a classic hallmark of credential-harvesting phishing sites."
            elif 'ip_host' in detected_indicators:
                explanation = "HIGH RISK: The URL utilizes a raw IP address as its host. Legitimate Indian banks and payment providers NEVER serve customer portals from bare IP addresses."
            elif 'suspicious_tld' in detected_indicators:
                explanation = f"HIGH RISK: The link resolves to a suspicious or disposable top-level domain (.{tld}) frequently leveraged in financial fraud campaigns."
            elif risk_level == 'LOW':
                explanation = "No overt structural red flags were detected. Remember that the presence of HTTPS alone does not guarantee a site's legitimacy."
            else:
                explanation = "Unusual subdomain depth, plain unencrypted HTTP, or unverified URL components detected."

        category_key = 'fake_kyc' if found_brand else 'suspicious_url'
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
            'url_parsed': {
                'hostname': hostname,
                'scheme': scheme,
                'path': path,
                'tld': tld
            }
        }

