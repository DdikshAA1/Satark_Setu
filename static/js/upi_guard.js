/**
 * UPI Fraud Guard JavaScript.
 * Clean, human-designed fintech & cybersecurity interface.
 * Handles UPI payment scenario evaluations, collect request inspections,
 * and highlights the core principle: "UPI PIN is only for sending money, never receiving."
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('upiGuardForm');
  const upiTextInput = document.getElementById('upiTextInput');
  const vpaInput = document.getElementById('vpaInput');
  const amountInput = document.getElementById('amountInput');
  const submitBtn = document.getElementById('checkUpiBtn');
  const clearBtn = document.getElementById('clearUpiBtn');
  const resultPanel = document.getElementById('upiResultPanel');

  if (!form || !upiTextInput) return;

  const currentLang = SatarkApp.getLang();

  // Bind sample buttons
  document.querySelectorAll('.sample-upi-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.getAttribute('data-text') || '';
      const vpa = btn.getAttribute('data-vpa') || '';
      const amt = btn.getAttribute('data-amt') || '';

      upiTextInput.value = text;
      if (vpaInput) vpaInput.value = vpa;
      if (amountInput) amountInput.value = amt;

      SatarkApp.showToast(currentLang === 'hi' ? 'यूपीआई उदाहरण लोड किया गया!' : 'UPI scenario loaded!', 'info');
      upiTextInput.focus();
    });
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      upiTextInput.value = '';
      if (vpaInput) vpaInput.value = '';
      if (amountInput) amountInput.value = '';
      if (resultPanel) resultPanel.classList.remove('visible');
      upiTextInput.focus();
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = upiTextInput.value.trim();
    const vpa = vpaInput ? vpaInput.value.trim() : '';
    const amount = amountInput ? amountInput.value.trim() : '';

    if (!text && !vpa) {
      SatarkApp.showToast(currentLang === 'hi' ? 'कृपया यूपीआई संदेश या अनुरोध विवरण भरें।' : 'Please enter UPI message or collect details.', 'warning');
      upiTextInput.focus();
      return;
    }

    const originalBtnText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>${currentLang === 'hi' ? 'जांच हो रही है...' : 'Evaluating UPI request...'}</span>`;

    try {
      const response = await fetch('/api/upi-guard', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: text,
          vpa: vpa,
          amount: amount,
          lang: currentLang
        })
      });

      const resData = await response.json();
      if (resData.success && resData.data) {
        renderUpiResults(resData.data);
      } else {
        SatarkApp.showToast('Evaluation failed. Please try again.', 'danger');
      }
    } catch (err) {
      console.error(err);
      SatarkApp.showToast('Connection error with server.', 'danger');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnText;
      if (window.lucide) window.lucide.createIcons();
    }
  });

  function renderUpiResults(data) {
    if (!resultPanel) return;

    const riskLevel = data.risk_level;
    const score = data.risk_score;
    const plan = data.action_plan || {};

    let badgeClass = 'badge-low';
    let scoreColorClass = 'score-low';
    let fillClass = 'fill-low';
    let badgeText = currentLang === 'hi' ? 'सुरक्षित / सामान्य भुगतान' : 'Low Risk / Standard UPI';

    if (riskLevel === 'HIGH') {
      badgeClass = 'badge-high';
      scoreColorClass = 'score-high';
      fillClass = 'fill-high';
      badgeText = currentLang === 'hi' ? 'सावधान! यूपीआई फ्रॉड का खतरा' : 'High Risk / Severe UPI Trap';
    } else if (riskLevel === 'MEDIUM') {
      badgeClass = 'badge-medium';
      scoreColorClass = 'score-medium';
      fillClass = 'fill-medium';
      badgeText = currentLang === 'hi' ? 'मध्यम जोखिम (जांच जरूरी)' : 'Medium Risk / Caution';
    }

    const indicatorsHtml = (data.indicator_details || []).map(ind => {
      const tagClass = ind.type === 'safe' ? 'safe' : 'warning';
      return `<span class="indicator-tag ${tagClass}"><i data-lucide="alert-circle" style="width: 12px; height: 12px;"></i> ${ind.label}</span>`;
    }).join('');

    const avoidHtml = (plan.what_to_avoid || []).map(item => `
      <li>
        <i data-lucide="x-circle" style="width: 14px; height: 14px; color: #B93838;"></i>
        <span>${item}</span>
      </li>
    `).join('');

    const immediateHtml = (plan.immediate_actions || []).map(item => `
      <li>
        <i data-lucide="check-circle-2" style="width: 14px; height: 14px; color: var(--brand-teal);"></i>
        <span>${item}</span>
      </li>
    `).join('');

    const recoveryHtml = (plan.if_already_interacted || []).map(item => `
      <li>
        <i data-lucide="shield-alert" style="width: 14px; height: 14px; color: var(--status-caution);"></i>
        <span>${item}</span>
      </li>
    `).join('');

    resultPanel.innerHTML = `
      <div class="result-verdict-box">
        <div class="result-verdict-header">
          <div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="badge ${badgeClass}">${badgeText}</span>
              <span style="font-size: 12.5px; color: var(--text-secondary);">${currentLang === 'hi' ? 'प्रकार:' : 'Type:'} <strong style="color: var(--brand-navy);">${data.category_label}</strong></span>
            </div>
            <p style="margin-top: 8px; font-size: 14px; color: var(--text-primary); line-height: 1.5;">${data.explanation}</p>
            <div class="indicators-wrapper">
              ${indicatorsHtml || `<span style="font-size: 12px; color: var(--text-muted);">${currentLang === 'hi' ? 'कोई खतरनाक यूपीआई संकेतक नहीं' : 'No overt UPI traps detected'}</span>`}
            </div>
          </div>
          <div>
            <div class="score-meter-wrap">
              <div style="text-align: right;">
                <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted);">${currentLang === 'hi' ? 'यूपीआई जोखिम' : 'UPI Risk'}</div>
                <div class="score-display-num ${scoreColorClass}">${score}<span style="font-size: 14px; font-weight: 600; color: var(--text-muted);">/100</span></div>
              </div>
              <div class="score-bar-bg">
                <div class="score-bar-fill ${fillClass}" style="width: ${score}%;"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- UPI SEND vs RECEIVE CARDINAL RULE BANNER -->
      <div class="upi-rule-card">
        <div class="upi-rule-grid" style="margin-top: 0;">
          <div class="upi-rule-box upi-rule-send">
            <h5>
              <i data-lucide="arrow-up-right" style="width: 16px; height: 16px; color: var(--brand-navy);"></i>
              <span>${currentLang === 'hi' ? 'पैसे भेजते समय (Debit)' : 'When You SEND Money'}</span>
            </h5>
            <p style="color: var(--text-secondary); margin: 0;">
              ${currentLang === 'hi' ? 'केवल भुगतान करते समय पिन डालना होता है।' : 'UPI PIN is strictly required to authorize money leaving your account.'}
            </p>
          </div>
          <div class="upi-rule-box upi-rule-receive">
            <h5>
              <i data-lucide="ban" style="width: 16px; height: 16px; color: #B93838;"></i>
              <span style="color: #902626;">${currentLang === 'hi' ? 'पैसे प्राप्त करते समय (Credit)' : 'When You RECEIVE Money'}</span>
            </h5>
            <p style="color: #7A2828; margin: 0; font-weight: 600;">
              ${data.golden_rule}
            </p>
          </div>
        </div>
      </div>

      <!-- NEXT BEST ACTION ENGINE FOR UPI -->
      <div class="nba-plan-card">
        <div class="nba-card-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="nba-badge-usp">Next Best Action Engine</span>
            <h4 style="margin: 0; font-size: 1.15rem; color: var(--brand-navy);">${plan.headline || 'UPI Safety Guidance'}</h4>
          </div>
        </div>

        <div class="nba-grid-2x2">
          <div class="nba-quadrant quadrant-why">
            <div class="quadrant-header">
              <i data-lucide="help-circle" style="width: 15px; height: 15px; color: var(--brand-navy);"></i>
              <h5>${currentLang === 'hi' ? 'यह जोखिम भरा क्यों है?' : 'Why This Is Dangerous'}</h5>
            </div>
            <p style="font-size: 13px; line-height: 1.5; color: var(--text-secondary); margin: 0;">${plan.why_suspicious || data.explanation}</p>
          </div>

          <div class="nba-quadrant quadrant-avoid">
            <div class="quadrant-header">
              <i data-lucide="ban" style="width: 15px; height: 15px; color: #B93838;"></i>
              <h5 style="color: #902626;">${currentLang === 'hi' ? 'क्या बिल्कुल न करें' : 'What You Must AVOID Doing'}</h5>
            </div>
            <ul class="nba-list">
              ${avoidHtml}
            </ul>
          </div>

          <div class="nba-quadrant quadrant-immediate">
            <div class="quadrant-header">
              <i data-lucide="shield-check" style="width: 15px; height: 15px; color: var(--brand-teal);"></i>
              <h5 style="color: var(--brand-teal);">${currentLang === 'hi' ? 'तुरंत क्या सुरक्षित कदम उठाएं' : 'Immediate Defensive Steps'}</h5>
            </div>
            <ul class="nba-list">
              ${immediateHtml}
            </ul>
          </div>

          <div class="nba-quadrant quadrant-recovery">
            <div class="quadrant-header">
              <i data-lucide="life-buoy" style="width: 15px; height: 15px; color: var(--status-caution);"></i>
              <h5 style="color: var(--status-caution);">${currentLang === 'hi' ? 'यदि पैसे कट चुके हैं' : 'If Money Has Been Debited'}</h5>
            </div>
            <ul class="nba-list">
              ${recoveryHtml}
            </ul>
          </div>
        </div>
      </div>
    `;

    resultPanel.classList.add('visible');
    resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    if (window.lucide) window.lucide.createIcons();
  }
});
