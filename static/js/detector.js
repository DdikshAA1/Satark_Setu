/**
 * Smart Scam Detector Module JavaScript.
 * Clean, human-designed fintech & cybersecurity interface.
 * Handles user input, sample loading, API invocation,
 * and dynamic rendering of explainable scam detection results.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scamDetectorForm');
  const messageInput = document.getElementById('messageInput');
  const senderInput = document.getElementById('senderInput');
  const submitBtn = document.getElementById('analyzeBtn');
  const clearBtn = document.getElementById('clearBtn');
  const resultPanel = document.getElementById('analysisResultPanel');

  if (!form || !messageInput) return;

  const currentLang = SatarkApp.getLang();

  // Load sample messages
  document.querySelectorAll('.sample-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleText = btn.getAttribute('data-sample');
      const sampleSender = btn.getAttribute('data-sender');
      if (sampleText) {
        messageInput.value = sampleText;
        if (senderInput && sampleSender) {
          senderInput.value = sampleSender;
        } else if (senderInput) {
          senderInput.value = '';
        }
        messageInput.focus();
        SatarkApp.showToast(currentLang === 'hi' ? 'नमूना संदेश एवं प्रेषक लोड किया गया!' : 'Sample message & sender header loaded!', 'info');
      }
    });
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      messageInput.value = '';
      if (senderInput) senderInput.value = '';
      if (resultPanel) resultPanel.classList.remove('visible');
      messageInput.focus();
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    const sender = senderInput ? senderInput.value.trim() : '';

    if (!text) {
      SatarkApp.showToast(currentLang === 'hi' ? 'कृपया जांचने के लिए कोई संदेश दर्ज करें।' : 'Please enter a message to analyze.', 'warning');
      messageInput.focus();
      return;
    }

    // Set subtle loading state
    const originalBtnText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="width: 13px; height: 13px; border: 2px solid #FFFFFF; border-top-color: transparent; border-radius: 50%; display: inline-block; animation: spin 0.6s linear infinite;"></span>
      <span>${currentLang === 'hi' ? 'जांच जारी है...' : 'Analyzing text...'}</span>
    `;

    try {
      const response = await fetch('/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text, sender: sender, lang: currentLang })
      });

      const resData = await response.json();
      if (resData.success && resData.data) {
        renderAnalysisResults(resData.data);
      } else {
        SatarkApp.showToast('Analysis error occurred. Please try again.', 'danger');
      }
    } catch (err) {
      console.error(err);
      SatarkApp.showToast('Connection error. Please check backend server.', 'danger');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnText;
      if (window.lucide) window.lucide.createIcons();
    }
  });

  function renderAnalysisResults(data) {
    if (!resultPanel) return;

    const riskLevel = data.risk_level; // 'LOW', 'MEDIUM', 'HIGH'
    const score = data.risk_score;
    const plan = data.action_plan || {};

    let badgeClass = 'badge-low';
    let scoreColorClass = 'score-low';
    let fillClass = 'fill-low';
    let badgeText = currentLang === 'hi' ? 'कम जोखिम (सामान्य)' : 'Low Risk / Standard';

    if (riskLevel === 'HIGH') {
      badgeClass = 'badge-high';
      scoreColorClass = 'score-high';
      fillClass = 'fill-high';
      badgeText = currentLang === 'hi' ? 'अत्यधिक जोखिम (सावधान!)' : 'High Risk / Severe Warning';
    } else if (riskLevel === 'MEDIUM') {
      badgeClass = 'badge-medium';
      scoreColorClass = 'score-medium';
      fillClass = 'fill-medium';
      badgeText = currentLang === 'hi' ? 'मध्यम जोखिम (सावधानी बरतें)' : 'Medium Risk / Caution';
    }

    // Render Indicator Badges
    const indicatorsHtml = (data.indicator_details || []).map(ind => {
      const tagClass = ind.type === 'safe' ? 'safe' : 'warning';
      const icon = ind.type === 'safe' ? 'check-circle' : 'alert-triangle';
      return `<span class="indicator-tag ${tagClass}"><i data-lucide="${icon}" style="width: 12px; height: 12px;"></i> ${ind.label}</span>`;
    }).join('');

    // Render Avoid List
    const avoidHtml = (plan.what_to_avoid || []).map(item => `
      <li>
        <i data-lucide="x-circle" style="width: 14px; height: 14px; color: #B93838;"></i>
        <span>${item}</span>
      </li>
    `).join('');

    // Render Immediate List
    const immediateHtml = (plan.immediate_actions || []).map(item => `
      <li>
        <i data-lucide="check-circle-2" style="width: 14px; height: 14px; color: var(--brand-teal);"></i>
        <span>${item}</span>
      </li>
    `).join('');

    // Render Recovery List
    const recoveryHtml = (plan.if_already_interacted || []).map(item => `
      <li>
        <i data-lucide="shield-alert" style="width: 14px; height: 14px; color: var(--status-caution);"></i>
        <span>${item}</span>
      </li>
    `).join('');

    // Render Psychological Tactics if AI enhanced
    const tacticsHtml = (data.psychological_tactics || []).map(t => `
      <span class="badge" style="background-color: #F8F9FA; color: var(--brand-navy); border: 1px solid var(--border-subtle); font-size: 11px;">
        <i data-lucide="brain" style="width: 11px; height: 11px; color: var(--brand-teal);"></i> ${t}
      </span>
    `).join('');

    // Render Bank Metadata & TRAI DLT Verification Dossier
    let bankMetaHtml = '';
    if (data.bank_metadata) {
      const bm = data.bank_metadata;
      const sa = bm.sender_analysis || {};
      const em = bm.extracted_metadata || {};

      let senderStatusBadge = '';
      if (!sa.provided) {
        senderStatusBadge = `<span class="badge" style="background:#F0F2F1; color:var(--text-muted); font-size:11.5px;"><i data-lucide="info" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'एसएमएस प्रेषक आईडी नहीं दी गई (सामान्य परीक्षण)' : 'SMS Sender Header Not Provided (Generic Mode)'}</span>`;
      } else if (sa.is_registered_bank_header) {
        senderStatusBadge = `<span class="badge" style="background:#EBF7F2; color:#1F6E5F; border:1px solid #C4E5DB; font-size:12px;"><i data-lucide="check-circle" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'सत्यापित TRAI DLT आधिकारिक हेडर' : 'Verified TRAI DLT Header'}: <strong>${sa.raw_sender}</strong> (${sa.bank_name || 'Bank'})</span>`;
      } else if (sa.sender_type === 'PERSONAL_MOBILE_NUMBER') {
        senderStatusBadge = `<span class="badge" style="background:#FDEBEB; color:#902626; border:1px solid #F5C6C6; font-size:12px;"><i data-lucide="alert-octagon" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'अवैध व्यक्तिगत 10-अंकों का प्रेषक' : 'Unofficial 10-Digit Mobile Sender'}: <strong>${sa.raw_sender}</strong> (TRAI Violation)</span>`;
      } else if (sa.sender_type === 'INTERNATIONAL_NUMBER') {
        senderStatusBadge = `<span class="badge" style="background:#FDEBEB; color:#902626; border:1px solid #F5C6C6; font-size:12px;"><i data-lucide="alert-octagon" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'अंतर्राष्ट्रीय प्रेषक नंबर' : 'International Sender Number'}: <strong>${sa.raw_sender}</strong></span>`;
      } else {
        senderStatusBadge = `<span class="badge" style="background:#FFF9EB; color:#8C6212; border:1px solid #F8E3B0; font-size:12px;"><i data-lucide="help-circle" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'गैर-मानक कॉर्पोरेट प्रेषक' : 'Unregistered Corporate Header'}: <strong>${sa.raw_sender}</strong></span>`;
      }

      let authBadge = '';
      if (bm.classification === 'VERIFIED_LEGITIMATE_BANK_ALERT') {
        authBadge = `<span class="badge" style="background:#EBF7F2; color:#1F6E5F; font-weight:700;"><i data-lucide="shield-check" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'वास्तविक बैंक अलर्ट (Non-Spam Verified)' : 'Authentic Bank Alert (Non-Spam Verified)'}</span>`;
      } else if (bm.classification === 'CONFIRMED_FINANCIAL_SPAM_OR_PHISHING') {
        authBadge = `<span class="badge" style="background:#FDEBEB; color:#902626; font-weight:700;"><i data-lucide="shield-alert" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'वित्तीय धोखाधड़ी / स्पैम (Confirmed Scam)' : 'Financial Fraud / Phishing (Confirmed Scam)'}</span>`;
      } else {
        authBadge = `<span class="badge" style="background:#F0F2F1; color:var(--text-secondary);"><i data-lucide="help-circle" style="width:12px;height:12px;"></i> ${currentLang === 'hi' ? 'अनिश्चित संचार' : 'Unverified Communication'}</span>`;
      }

      bankMetaHtml = `
        <div style="background: #FFFFFF; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px 16px; margin-top: 14px;">
          <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 10px;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <i data-lucide="landmark" style="width: 15px; height: 15px; color: var(--brand-teal);"></i>
              <span style="font-size: 13px; font-weight: 700; color: var(--brand-navy);">${currentLang === 'hi' ? 'बैंक मेटाडेटा एवं प्रेषक सत्यापन' : 'Bank Account Metadata & TRAI Sender Verification'}</span>
            </div>
            <div>${authBadge}</div>
          </div>

          <div style="margin-bottom: 10px;">${senderStatusBadge}</div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; background: #F8F9FA; padding: 10px; border-radius: 6px; font-size: 12px; margin-bottom: 8px;">
            <div>
              <span style="color: var(--text-muted); display: block; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${currentLang === 'hi' ? 'खाता संदर्भ' : 'Account'}</span>
              <strong style="font-family: monospace; color: var(--brand-navy);">${em.account_number || (em.has_masked_account ? 'Masked' : 'Not Specified')}</strong>
            </div>
            <div>
              <span style="color: var(--text-muted); display: block; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${currentLang === 'hi' ? 'लेनदेन प्रकार' : 'Txn Type'}</span>
              <strong style="color: var(--brand-navy);">${em.transaction_type || 'N/A'}</strong>
            </div>
            <div>
              <span style="color: var(--text-muted); display: block; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${currentLang === 'hi' ? 'राशि / बैलेंस' : 'Amount / Bal'}</span>
              <strong style="color: var(--brand-navy);">${em.balance_extracted || em.amount_extracted || 'None'}</strong>
            </div>
            <div>
              <span style="color: var(--text-muted); display: block; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${currentLang === 'hi' ? 'संदर्भ / यूटीआर' : 'Ref / UTR'}</span>
              <strong style="font-family: monospace; color: var(--brand-navy);">${em.reference_no || 'None'}</strong>
            </div>
          </div>

          ${(bm.legitimate_signals && bm.legitimate_signals.length > 0) ? `
            <div style="font-size: 11.5px; color: #1F6E5F; margin-top: 6px;">
              ${bm.legitimate_signals.map(s => `<div style="display: flex; align-items: center; gap: 4px; margin-bottom: 2px;"><i data-lucide="check" style="width: 12px; height: 12px;"></i> <span>${s}</span></div>`).join('')}
            </div>
          ` : ''}

          ${(bm.spam_signals && bm.spam_signals.length > 0) ? `
            <div style="font-size: 11.5px; color: #902626; margin-top: 6px;">
              ${bm.spam_signals.map(s => `<div style="display: flex; align-items: center; gap: 4px; margin-bottom: 2px;"><i data-lucide="alert-triangle" style="width: 12px; height: 12px;"></i> <span>${s}</span></div>`).join('')}
            </div>
          ` : ''}
        </div>
      `;
    }

    resultPanel.innerHTML = `
      <div class="result-verdict-box">
        <div class="result-verdict-header">
          <div>
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <span class="badge ${badgeClass}">${badgeText}</span>
              ${data.ai_enhanced ? `<span class="badge" style="background-color: var(--brand-teal-light); color: var(--brand-teal); border: 1px solid var(--status-safe-border); font-size: 11px;"><i data-lucide="sparkles" style="width: 11px; height: 11px;"></i> Gemini AI Analysis</span>` : ''}
              <span style="font-size: 12.5px; color: var(--text-secondary);">${currentLang === 'hi' ? 'पैटर्न:' : 'Category:'} <strong style="color: var(--brand-navy);">${data.category_label}</strong></span>
            </div>
            <p style="margin-top: 8px; font-size: 14px; color: var(--text-primary); line-height: 1.5;">${data.explanation}</p>
            ${tacticsHtml ? `
              <div style="margin-top: 8px; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted);">${currentLang === 'hi' ? 'पहचाने गए छल:' : 'Deceptive Tactics:'}</span>
                ${tacticsHtml}
              </div>
            ` : ''}
            <div class="indicators-wrapper">
              ${indicatorsHtml || `<span style="font-size: 12px; color: var(--text-muted);">${currentLang === 'hi' ? 'कोई खतरनाक संकेतक नहीं मिला' : 'No overt red flags detected'}</span>`}
            </div>
          </div>
          <div>
            <div class="score-meter-wrap">
              <div style="text-align: right;">
                <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted);">${currentLang === 'hi' ? 'जोखिम स्कोर' : 'Risk Score'}</div>
                <div class="score-display-num ${scoreColorClass}">${score}<span style="font-size: 14px; font-weight: 600; color: var(--text-muted);">/100</span></div>
              </div>
              <div class="score-bar-bg">
                <div class="score-bar-fill ${fillClass}" style="width: ${score}%;"></div>
              </div>
            </div>
          </div>
        </div>

        <div style="font-size: 11.5px; color: var(--text-muted); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
          <span>${data.ai_enhanced ? (currentLang === 'hi' ? 'गूगल जेमिनी एआई एवं व्याख्यात्मक सुरक्षा नियमों द्वारा सत्यापित।' : 'Verified by Google Gemini AI & explainable indicator matrix.') : (currentLang === 'hi' ? 'सटीक व्याख्यात्मक नियम व प्राकृतिक भाषा मॉडल द्वारा सत्यापित।' : 'Verified by explainable heuristic indicator matrix and trained NLP model.')}</span>
          <span style="font-family: monospace;">${data.ai_model || 'Local NLP'}: ${data.ml_confidence}</span>
        </div>
      </div>

      ${bankMetaHtml}

      <!-- NEXT BEST ACTION ENGINE (Structured Guidance Blueprint) -->
      <div class="nba-plan-card">
        <div class="nba-card-header">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="nba-badge-usp">Next Best Action Engine</span>
            <h4 style="margin: 0; font-size: 1.15rem; color: var(--brand-navy);">${plan.headline || 'Actionable Safety Blueprint'}</h4>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" id="copyPlanBtn">
            <i data-lucide="copy" style="width: 13px; height: 13px;"></i>
            <span>${currentLang === 'hi' ? 'सलाह कॉपी करें' : 'Copy Advice'}</span>
          </button>
        </div>

        <div class="nba-grid-2x2">
          <!-- Quadrant 1: Why Suspicious -->
          <div class="nba-quadrant quadrant-why">
            <div class="quadrant-header">
              <i data-lucide="help-circle" style="width: 15px; height: 15px; color: var(--brand-navy);"></i>
              <h5>${currentLang === 'hi' ? 'यह संदिग्ध क्यों है?' : 'Why This Looks Suspicious'}</h5>
            </div>
            <p style="font-size: 13px; line-height: 1.5; color: var(--text-secondary); margin: 0;">${plan.why_suspicious || data.explanation}</p>
          </div>

          <!-- Quadrant 2: What to Avoid -->
          <div class="nba-quadrant quadrant-avoid">
            <div class="quadrant-header">
              <i data-lucide="ban" style="width: 15px; height: 15px; color: #B93838;"></i>
              <h5 style="color: #902626;">${currentLang === 'hi' ? 'क्या बिल्कुल न करें' : 'What You Must AVOID Doing'}</h5>
            </div>
            <ul class="nba-list">
              ${avoidHtml}
            </ul>
          </div>

          <!-- Quadrant 3: Immediate Actions -->
          <div class="nba-quadrant quadrant-immediate">
            <div class="quadrant-header">
              <i data-lucide="shield-check" style="width: 15px; height: 15px; color: var(--brand-teal);"></i>
              <h5 style="color: var(--brand-teal);">${currentLang === 'hi' ? 'तुरंत क्या सुरक्षित कदम उठाएं' : 'Immediate Protective Steps'}</h5>
            </div>
            <ul class="nba-list">
              ${immediateHtml}
            </ul>
          </div>

          <!-- Quadrant 4: If Already Interacted -->
          <div class="nba-quadrant quadrant-recovery">
            <div class="quadrant-header">
              <i data-lucide="life-buoy" style="width: 15px; height: 15px; color: var(--status-caution);"></i>
              <h5 style="color: var(--status-caution);">${currentLang === 'hi' ? 'यदि आप पहले ही क्लिक कर चुके हैं' : 'If You Already Interacted'}</h5>
            </div>
            <ul class="nba-list">
              ${recoveryHtml}
            </ul>
          </div>
        </div>

        <!-- Official Indian Contacts Footer inside NBA -->
        <div style="margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border-subtle); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; font-size: 12px; color: var(--text-secondary);">
          <div>
            <span>${currentLang === 'hi' ? 'राष्ट्रीय साइबर हेल्पलाइन:' : 'National Cyber Crime Helpline:'}</span>
            <strong style="color: #B93838; margin-left: 4px;">1930 (Toll Free, 24x7)</strong>
          </div>
          <div>
            <span>${currentLang === 'hi' ? 'आधिकारिक पोर्टल:' : 'Official Portal:'}</span>
            <a href="https://cybercrime.gov.in" target="_blank" rel="noopener" style="margin-left: 4px; font-weight: 600;">cybercrime.gov.in</a>
          </div>
        </div>
      </div>
    `;

    resultPanel.classList.add('visible');
    resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    if (window.lucide) window.lucide.createIcons();

    // Bind copy button
    const copyBtn = document.getElementById('copyPlanBtn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        const textToCopy = `SATARK SETU FRAUD ADVISORY\nCategory: ${data.category_label}\nRisk: ${riskLevel} (${score}/100)\n\nIMMEDIATE ACTIONS:\n${(plan.immediate_actions || []).join('\n')}\n\nWHAT TO AVOID:\n${(plan.what_to_avoid || []).join('\n')}\n\nEMERGENCY HELPLINE: 1930 / https://cybercrime.gov.in`;
        SatarkApp.copyToClipboard(textToCopy, currentLang === 'hi' ? 'सुरक्षा सलाह कॉपी हो गई!' : 'Safety plan copied to clipboard!');
      });
    }
  }
});
