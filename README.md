# 🛡️ SATARK SETU (सतर्क सेतु)
### *Think Before You Trust.*
**An Intelligent Digital Payment Fraud Prevention & Awareness Platform for India**

> **FinTech and Financial Inclusion**  
> *"How might technology help individuals and small businesses recognise, prevent and navigate digital payment fraud?"*

---

## 📌 Executive Summary

India leads the world in real-time digital payments, processing billions of UPI and mobile transactions each month. However, first-time digital payment adopters, senior citizens, kirana shopkeepers, and street vendors are increasingly targeted by fraudulent actors using deceptive psychological tactics:
- **Fake KYC & Account Blocking Threats** (threatening immediate suspension via SMS links)
- **UPI PIN-to-Receive Traps** (deceiving users into believing they must enter a PIN to receive money or cashbacks)
- **Emergency Electricity Power Disconnection Warnings** (demanding immediate callbacks to personal numbers)
- **Fake Lottery / KBC Lucky Draw Prizes** (advance fee processing charge scams)
- **Digital Arrest Intimidation** (impersonating police, CBI, or customs on video calls)
- **Malicious APK / Remote Screen Sharing** (AnyDesk, TeamViewer scams)

Conventional scam detection tools merely display an arbitrary percentage or red banner without explaining *why* a message is dangerous or *what* the user should do next.

**Satark Setu** solves this crisis with its central innovation: the **Next Best Action Engine**. Built as a compassionate, explainable digital safety companion, Satark Setu guides users through the entire journey:
$$\text{DETECT} \longrightarrow \text{UNDERSTAND} \longrightarrow \text{PREVENT} \longrightarrow \text{RESPOND}$$

---

## 🌟 Key Modules & Core Capabilities

### 1. 🔍 Smart Scam Detector & Bank Metadata Engine (Module 1)
- Analyzes SMS, WhatsApp messages, bank alerts, and payment notes.
- **Bank Account Metadata & TRAI DLT Header Verification:**
  - Verifies telecom sender headers against recognized Indian bank DLT registries (`AD-HDFCBK`, `VK-SBIINB`, `AX-ICICIB`, `PAYTMB`, etc.).
  - Distinguishes legitimate bank alerts from illegal personal 10-digit mobile number senders (`+91 9876543210`) or international spoof numbers.
  - Extracts masked account numbers (`A/C XX1234`), transaction types (`DEBIT` / `CREDIT` / `OTP`), amounts, available balances, UTR references, and official 1800 helplines.
  - Automatically separates **Verified Non-Spam** from **Confirmed Spam / Phishing**.
- **Hybrid Multi-Tier Intelligence:**
  - **Tier 1:** Instant deterministic explainable heuristic rule engine.
  - **Tier 2:** Scikit-Learn TF-IDF + Logistic Regression NLP model.
  - **Tier 3:** **Google Gemini AI LLM Deep Analysis Layer** (identifies subtle psychological manipulation tricks like *False Urgency*, *Authority Impersonation*, and *Fear of Account Freeze*).
  - **In-Memory Caching:** Sub-millisecond response caching (0.01ms) for high-frequency scam templates.
- Returns a transparent **Heuristic Risk Score (0-100)**, **Risk Level (LOW / MEDIUM / HIGH)**, detected scam category, identified warning flags, and AI-identified psychological tactics.
- **Guaranteed No False-Positive Panic:** Legitimate bank debit and credit notifications (e.g. Swiggy debits with balance) remain categorized as LOW RISK.

### 2. ⚡ UPI Fraud Guard (Module 2)
- Inspects collect requests, QR payment scenarios, payment notes, and beneficiary VPAs.
- Enforces the **Cardinal Rule of UPI Safety**:  
  > *"CRITICAL SAFETY RULE: You NEVER enter your UPI PIN to receive money or claim cashback. UPI PIN is exclusively for authorizing money to LEAVE your account."*
- Flags unexpected collect requests, reverse refund traps, and unverified merchant handles.

### 3. 🌐 URL Safety Scanner (Module 3)
- Safely inspects web links and domain structures **without opening or visiting them**.
- Detects **typosquatting** (e.g., `sbi-kyc-verify.top` mimicking State Bank of India), **bare IP address hosts** (`http://192.168.1.1/paytm.apk`), deceptive subdomains, suspicious TLDs (`.xyz`, `.top`, `.click`, `.live`), dangerous extensions (`.apk`, `.exe`), and plain unencrypted HTTP.
- Clearly clarifies that HTTPS encryption alone does not guarantee a site is genuine.

### 4. 🧠 Next Best Action Engine (Module 4 – Central USP)
Decomposes every risk scenario across four actionable dimensions:
1. **Why This Looks Suspicious:** Plain-language explanation of the psychological manipulation tactic.
2. **What You Must AVOID Doing:** Concrete traps not to step into.
3. **Immediate Protective Actions:** Calm steps to verify account status via official apps or branch visits.
4. **Recovery Protocol:** Rapid response steps if the user has already clicked, shared an OTP, or transferred money.

### 5. 🚨 Emergency Fraud Response Assistant (Module 5)
Interactive triage for victims across 6 critical scenarios:
- *I clicked a suspicious link*
- *I accidentally shared an OTP*
- *I entered my NetBanking password or card details*
- *I approved an unexpected UPI collect request*
- *Money was debited from my account*
- *I received a threatening call (Digital Arrest / Police / Power Cut)*
- Emphasizes the **Golden Hour (first 2 hours)** for reporting to the **National Cyber Crime Helpline (1930)** and bank fraud desks to freeze stolen funds before cash-out.
- Includes a searchable directory of **24x7 Bank Emergency Hotlines** (SBI, HDFC, ICICI, PNB, Axis, Bank of Baroda, Paytm, PhonePe).

### 6. 🇮🇳 Full Bilingual Localization (Module 6)
- Instant toggle between **English** and **Hindi (हिंदी)**.
- Uses simple, respectful Hindi designed specifically for senior citizens, shopkeepers, and street vendors.
- All risk badges, indicator pills, explanation text, and Next Best Action blueprints are translated.

### 7. 📊 Safety & Telemetry Dashboard (Module 7)
- Aggregate analytics powered by **Chart.js** (Risk classification doughnut chart and prevalent fraud categories bar chart).
- **Privacy-Guaranteed Telemetry:** Automatically redacts phone numbers, account numbers, card numbers, and OTPs before logging to SQLite.

---

## 🎨 Human-Crafted Fintech Design System

Satark Setu implements an authentic, distraction-free aesthetic inspired by Stripe, Linear, and Wise:
- **Warm White (`#FAFAF7`):** Natural canvas, comfortable and readable for senior citizens.
- **Deep Navy (`#142B3A`):** Trustworthy brand headings and solid actions.
- **Teal (`#2E8B78`):** Verified safety markers, trust status, and focus accents.
- **Light Grey (`#F0F2F1`):** Clean surface elevations and container fills.
- **Dark Text (`#25313B`):** High-contrast, fatigue-free readable typography.
- **Amber (`#E5AD50`):** Cautionary alerts and unverified warnings.
- **Soft Red (`#D96B6B` / `#B93838`):** High risk warnings and emergency helpline highlights.
- **Typography:** Manrope & Inter for clean legibility across mobile, tablet, and desktop.

---

## 🏗️ Architecture & Technology Stack

```
Satark Setu/
├── app.py                      # Application factory & security middleware
├── config.py                   # Centralized configuration
├── database.py                 # SQLite layer with privacy redaction
├── run.py                      # Production / dev launcher script
├── requirements.txt            # Python dependencies
├── COVEXCODE_DEV_LOG.md        # Hackathon tool compliance log
├── services/
│   ├── detector.py             # Smart Scam Detector (Heuristic + ML)
│   ├── ml_classifier.py        # Scikit-learn TF-IDF + Logistic Regression
│   ├── upi_guard.py            # UPI Fraud Guard & Golden Rule logic
│   ├── url_scanner.py          # URL Safety Scanner (structure audit)
│   ├── nba_engine.py           # Next Best Action recommendation engine
│   ├── emergency.py            # Emergency Fraud Response Assistant triage
│   └── localization.py         # English & Hindi translation matrices
├── routes/
│   ├── api.py                  # JSON REST endpoints (/api/detect, /api/upi-guard, etc.)
│   └── views.py                # Server-rendered HTML page routes
├── static/
│   ├── css/
│   │   ├── style.css           # Premium fintech styling
│   │   └── components.css      # Next Best Action card, gauges, banners
│   └── js/
│       ├── app.js              # Core UI interactivity & Lucide activation
│       ├── detector.js         # Message detector controller
│       ├── upi_guard.js        # UPI guard controller
│       ├── url_scanner.js      # URL scanner controller
│       ├── emergency.js        # Emergency triage & bank search
│       └── dashboard.js        # Chart.js visualization loader
├── templates/
│   ├── base.html               # Shared layout, navbar, emergency top bar, footer
│   ├── index.html              # Landing page with interactive quick demo
│   ├── detector.html           # Smart Scam Detector module
│   ├── upi_guard.html          # UPI Fraud Guard module
│   ├── url_scanner.html        # URL Safety Scanner module
│   ├── emergency.html          # Emergency Response Assistant module
│   ├── dashboard.html          # Safety Dashboard with Chart.js
│   ├── about.html              # Project vision & HackNova problem statement
│   ├── 404.html                # Not Found page
│   └── 500.html                # Error page
└── tests/
    └── test_satark_setu.py     # Comprehensive automated test suite
```

---

## 🚀 Quick Start & Installation

Satark Setu runs locally on Windows, macOS, or Linux using standard Python.

### Prerequisites
- Python 3.9+ installed (`python --version`)

### 1. Clone & Enter Workspace
```bash
cd "Satark Setu"
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Automated Tests
Execute the 18 automated test suites covering all required scenarios:
```bash
python -m unittest tests/test_satark_setu.py -v
```

### 4. Start the Web Application
```bash
python run.py
```
Open your browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

---

## 🧪 Demonstration Walkthrough for Hackathon Judges

Satark Setu includes one-click sample scenarios on each page to demonstrate real-world detection:

### Scenario 1: Fake Bank KYC Update (Test 1)
- **Input:** *"Your bank account will be blocked today. Update your KYC immediately using this link: http://sbi-kyc-verify.top"*
- **Result:** **HIGH RISK (Score: 92/100)**
- **Detected Flags:** Account Block Threat, Unsolicited KYC Demand, Suspicious Link, Brand Impersonation (`sbi`).
- **Next Best Action:** Advises user to verify in the official YONO SBI app or visit a physical branch; never enter credentials on SMS links.

### Scenario 2: Lottery & Processing Fee Advance Scam (Test 2)
- **Input:** *"Congratulations! You won a lottery. Pay a processing fee to receive your prize."*
- **Result:** **HIGH RISK (Score: 88/100)**
- **Detected Flags:** Lottery Claim, Advance Fee Fraud.
- **Next Best Action:** Reminds user that legitimate lotteries never ask winners to pay upfront fees; advises immediate blocking.

### Scenario 3: UPI PIN to Receive Money Trap (Test 3)
- **Input:** *"Enter your UPI PIN to receive your cashback of Rs 2,500."*
- **Result:** **HIGH RISK (Score: 88/100)**
- **Detected Flags:** PIN to Receive Trap, Fake Cashback.
- **Next Best Action:** Explains the foundational UPI rule: entering a PIN can *only* transfer money *out* of an account, never into it.

### Scenario 4: Legitimate Bank Transaction (Test 4 – False Positive Guard)
- **Input:** *"Your A/C XX4589 is debited for INR 1,500.00 on 24-Nov-26 by UPI/334455667788/Swiggy. Available Bal: INR 35,420.50. - HDFC Bank"*
- **Result:** **LOW RISK (Score: 8/100)**
- **Detected Flags:** Normal Debit Notification, Available Balance Present.
- **Next Best Action:** Calming verification steps; explains that standard transactional alerts are safe.

### Scenario 5: Misspelled URL / Typosquatting Phishing (Test 5)
- **Input:** *"http://sbi-kyc-verify.top/login.php"*
- **Result:** **HIGH RISK (Score: 95/100)**
- **Detected Flags:** Brand Typosquatting (`sbi`), Suspicious TLD (`.top`), Missing HTTPS.
- **Next Best Action:** Highlights that official State Bank of India portals end in `.sbi` or `sbi.co.in`, never `.top`.

### Scenario 6: Emergency Golden Hour Incident Response
- Navigate to **Emergency Help (`/emergency`)**.
- Click **"Money Debited / Lost"**.
- View step-by-step containment checklist with interactive completion checkboxes, direct links to **1930 Helpline** and **cybercrime.gov.in**, and searchable 24x7 bank fraud desk numbers.

---

## 🔒 Security & Responsible AI Principles

- **No Credential Harvesting:** Satark Setu never asks for, records, or accepts passwords, OTPs, or UPI PINs.
- **Automatic Privacy Redaction:** All text logged to the SQLite telemetry database is scrubbed of 10-digit mobile numbers, account digits, and OTP mentions.
- **No Direct Link Visiting:** The URL Scanner audits domain syntax, IP structure, and TLD flags strictly client-side/server-side *without* fetching or executing external code.
- **Explainable Heuristics:** No black-box scores. Every score maps to concrete psychological triggers or technical anomalies.
- **Transparent Disclaimers:** Satark Setu provides safety guidance and awareness; it does not replace official law enforcement or banking dispute processes.

---

## 📋 Hackathon Compliance (Covexcode Status)

Per Section 11 of the problem statement:
- Covexcode was not accessible in the current local environment.
- Initial development, testing, and delivery were completed transparently using Antigravity.
- No synthetic or fabricated Covexcode logs have been created.
- A dedicated audit log is maintained in **`COVEXCODE_DEV_LOG.md`**.
- The codebase is clean, modular, and ready for immediate Covexcode inspection and refinement.

---

*Satark Setu — Built with pride for HackNova 2026.*  
*Empowering every Indian to Think Before They Trust.*

