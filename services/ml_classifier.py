"""
Machine Learning Classifier for Satark Setu.
Uses Scikit-Learn TF-IDF Vectorizer and Logistic Regression / MultinomialNB
trained on a rich, representative corpus of Indian digital payment communications:
- Phishing & SMS scam patterns (KYC, electricity disconnect, lottery, digital arrest, task fraud)
- Legitimate bank transactional SMS (debit, credit, OTP login, balance inquiries)
"""

import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

# Curated dataset representing authentic Indian digital payment communications
# Label 1: Fraudulent / Phishing / Scam
# Label 0: Legitimate Bank / Merchant Transaction Notification
TRAINING_DATA = [
    # Fraudulent KYC / Account blocking
    ("Dear SBI user, your bank account has been blocked today. Please click http://sbi-kyc-verify.top to update your PAN card immediately.", 1),
    ("Your HDFC bank account will be suspended within 24 hours due to pending KYC update. Click http://hdfc-kyc-login.xyz to avoid suspension.", 1),
    ("Urgent: Your PNB account service stopped due to incomplete KYC documents. Update now at http://pnb-documents-verify.live to continue banking.", 1),
    ("Dear customer, your ICICI bank netbanking is deactivated. Kindly update your Aadhar and Pan card here: http://bit.ly/icici-kyc-update", 1),
    ("Alert: Your account has been temporarily frozen. Please complete biometric verification at http://bank-kyc-portal.click immediately.", 1),
    ("Your bank account will be blocked today. Update your KYC immediately using this link.", 1),
    ("Bank alert: Important notice. Your saving account is blocked. Update Pan card by clicking here.", 1),

    # Fraudulent Lotteries & Fake Cashbacks
    ("Congratulations! You won a lottery of Rs 25,00,000 from KBC Lucky Draw. Call 9876543210 to claim your cash prize.", 1),
    ("Congratulations! You won a lottery. Pay a processing fee to receive your prize.", 1),
    ("You have won Rs 50,000 Flipkart cashback! Enter your UPI PIN to claim money directly to your bank account.", 1),
    ("Paytm reward alert: You have won a festive scratch card of Rs 4,999. Click http://paytm-rewards.online to redeem.", 1),
    ("Dear user, you have been selected for Jio Lucky Draw 2026. Deposit Rs 1,500 security deposit to receive brand new iPhone 16.", 1),
    ("Congratulations! Your mobile number won Rs 10 Lakhs in international remittance. Contact manager immediately.", 1),

    # Fraudulent UPI & PIN to receive traps
    ("Enter your UPI PIN to receive your cashback.", 1),
    ("Ramesh requests Rs 3,500 on PhonePe. Note: Enter UPI PIN to accept incoming payment of Rs 3,500.", 1),
    ("Collect request for Rs 5,000. Approve collect request and enter secret PIN to receive refund from Google Pay.", 1),
    ("OLX buyer: I have scanned the QR code to send you payment. Now enter your 6-digit UPI PIN to confirm receipt of funds.", 1),
    ("You received a refund of Rs 1,200. Click approve in Paytm and type UPI PIN to collect money into your account.", 1),

    # Electricity & Utility Disconnection Threats
    ("Dear consumer, your electricity power will be disconnected tonight at 9.30 pm from electricity office because your previous month bill was not updated. Please call on our officer number 9123456789.", 1),
    ("URGENT: Mahavitaran power supply will be cut off today at 8:30 PM due to unpaid electricity bill. Contact officer immediately at 9876501234.", 1),
    ("BSES Notice: Your power connection is scheduled for immediate disconnection. Dial billing officer 8765432109 to stop meter removal.", 1),
    ("Dear consumer your gas pipeline connection will be suspended today. Download GasCare APK to verify connection.", 1),

    # Digital Arrest & Police Impersonation
    ("Cyber Crime Cell Notice: A digital arrest warrant has been issued in your name under Section 420 for money laundering. Join Skype interrogation immediately.", 1),
    ("Mumbai Police: A parcel containing narcotics and fake passports has been intercepted in your name. Connect on WhatsApp video call or face immediate arrest.", 1),
    ("CBI Notice: Your Aadhaar has been linked to illegal bank accounts. Transfer Rs 2,00,000 to government safe custody account for verification.", 1),
    ("TRAI Alert: All mobile numbers registered to your Aadhaar will be disconnected within 2 hours for illegal broadcasting. Press 9 to speak with police officer.", 1),

    # Task & Part-Time Job Scams
    ("Earn Rs 3,000 to Rs 8,000 daily from home! Like YouTube videos and review hotels on Google. Join Telegram channel @earn_daily_cash now.", 1),
    ("Work from home job: Part time data entry and social media rating. Earn Rs 500 per hour. No investment required initially. Message on WhatsApp.", 1),
    ("Amazon affiliate part-time recruitment: Earn daily profits by completing prepaid orders. Upgrade to VIP level for higher returns.", 1),

    # Malicious APK & Remote App scams
    ("Dear customer, your SIM card KYC is pending. Download JioSupport.apk from http://192.168.0.5/jio.apk to prevent SIM block.", 1),
    ("Bank customer care: Install AnyDesk app and share 9-digit code to complete pending transaction refund.", 1),
    ("Customer support: Download TeamViewer QuickSupport to update your credit card limit immediately.", 1),

    # Legitimate Bank / Merchant Transaction Notifications
    ("Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank", 0),
    ("Rs 450.00 debited from your A/C 9876 on 23-Nov-26 through UPI. Bal: Rs 12,300. If not done by you, SMS BLOCK to 567676 - SBI", 0),
    ("Dear Customer, INR 45,000.00 credited to your A/C XX1234 on 24-Nov-26 by NEFT/CMS/INFOSYS LTD. Total Bal: INR 92,100.00. - ICICI Bank", 0),
    ("Your OTP for transaction of Rs 899.00 on Amazon at 24-Nov-26 14:20 is 492018. OTP is valid for 5 mins. Do not share OTP with anyone.", 0),
    ("INR 250.00 received in your Paytm Wallet from Kirana Store. Updated balance: INR 1,450.00.", 0),
    ("Dear Customer, your monthly e-statement for Account XX8890 for the period Oct 2026 has been sent to your registered email address.", 0),
    ("Thank you for using SBI Debit Card ending 4321 for Rs 2,400.00 at RELIANCE RETAIL. Avail Bal: Rs 18,900.00.", 0),
    ("Your electricity bill of Rs 1,420 for Consumer No 10293847 is due on 05-Dec-2026. Pay safely through BESCOM portal or BBPS.", 0),
    ("Dear customer, salary of Rs 65,000 has been credited to your account XX7788 on 31-Oct-2026. Ref: SAL/OCT/2026.", 0),
    ("Rs 50.00 paid to Metro Rail UPI. Available balance in SBI Account XX5544 is Rs 8,430. Call 1800112211 for queries.", 0),
    ("Your request for cheque book for A/C XX3322 has been received and will be dispatched within 3 working days. - PNB", 0),
    ("INR 12,000 transferred to Ramesh via NEFT with Ref UTR N334455221. Available balance INR 44,200. - Axis Bank", 0)
]

class ScamClassifier:
    """
    NLP-based scam classifier leveraging TF-IDF features and a calibrated
    Logistic Regression classifier.
    """
    _instance = None

    def __init__(self):
        texts, labels = zip(*TRAINING_DATA)
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 2), lowercase=True, max_features=1000)),
            ('clf', LogisticRegression(C=2.0, class_weight='balanced', random_state=42))
        ])
        self.pipeline.fit(texts, labels)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict_fraud_probability(self, text: str) -> float:
        """
        Predict probability of the text being a financial scam / fraud (0.0 to 1.0).
        """
        if not text or not text.strip():
            return 0.0
        try:
            probs = self.pipeline.predict_proba([text])[0]
            # Probability of class 1 (Fraud)
            return float(probs[1])
        except Exception:
            return 0.5

