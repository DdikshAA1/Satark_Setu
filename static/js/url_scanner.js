/**
 * URL Safety Scanner JavaScript.
 * Clean, human-designed fintech & cybersecurity interface.
 * Structural inspection of domains and web links without visiting them.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('urlScannerForm');
  const urlInput = document.getElementById('urlInput');
  const submitBtn = document.getElementById('scanUrlBtn');
  const clearBtn = document.getElementById('clearUrlBtn');
  const resultPanel = document.getElementById('urlResultPanel');

  if (!form || !urlInput) return;

  const currentLang = SatarkApp.getLang();

  // Bind sample URL pills
  document.querySelectorAll('.sample-url-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      if (url) {
        urlInput.value = url;
        SatarkApp.showToast(currentLang === 'hi' ? 'नमूना लिंक लोड किया गया!' : 'Sample URL loaded!', 'info');
        urlInput.focus();
      }
    });
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      urlInput.value = '';
      if (resultPanel) resultPanel.classList.remove('visible');
      urlInput.focus();
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      SatarkApp.showToast(currentLang === 'hi' ? 'कृपया जांचने के लिए यूआरएल दर्ज करें।' : 'Please enter a URL to scan.', 'warning');
      urlInput.focus();
      return;
    }

    const originalBtnText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>${currentLang === 'hi' ? 'संरचना जांची जा रही है...' : 'Inspecting URL structure...'}</span>`;

    try {
      const response = await fetch('/api/url-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, lang: currentLang })
      });

      const resData = await response.json();
      if (resData.success && resData.data) {
        renderUrlResults(resData.data);
      } else {
        SatarkApp.showToast('Scan failed. Please verify the URL.', 'danger');
      }
    } catch (err) {
      console.error(err);
      SatarkApp.showToast('Connection error.', 'danger');
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnText;
      if (window.lucide) window.lucide.createIcons();
    }
  });

  function renderUrlResults(data) {
    if (!resultPanel) return;

    const riskLevel = data.risk_level;
    const score = data.risk_score;
    const plan = data.action_plan || {};
    const parsed = data.url_parsed || {};

    let badgeClass = 'badge-low';
    let scoreColorClass = 'score-low';
    let fillClass = 'fill-low';
    let badgeText = currentLang === 'hi' ? 'कम जोखिम (आधिकारिक / सामान्य)' : 'Low Risk / Standard Domain';

    if (riskLevel === 'HIGH') {
      badgeClass = 'badge-high';
      scoreColorClass = 'score-high';
      fillClass = 'fill-high';
      badgeText = currentLang === 'hi' ? 'सावधान! खतरनाक फिशिंग लिंक' : 'High Risk / Phishing Warning';
    } else if (riskLevel === 'MEDIUM') {
      badgeClass = 'badge-medium';
      scoreColorClass = 'score-medium';
      fillClass = 'fill-medium';
      badgeText = currentLang === 'hi' ? 'मध्यम जोखिम (सावधानी जरूरी)' : 'Medium Risk / Caution';
    }

    const indicatorsHtml = (data.indicator_details || []).map(ind => {
      const tagClass = ind.type === 'safe' ? 'safe' : 'warning';
      return `<span class="indicator-tag ${tagClass}"><i data-lucide="shield" style="width: 12px; height: 12px;"></i> ${ind.label}</span>`;
    }).join('');

    resultPanel.innerHTML = `
      <div class="result-verdict-box">
        <div class="result-verdict-header">
          <div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="badge ${badgeClass}">${badgeText}</span>
              <span style="font-size: 12.5px; color: var(--text-secondary);">${currentLang === 'hi' ? 'श्रेणी:' : 'Type:'} <strong style="color: var(--brand-navy);">${data.category_label}</strong></span>
            </div>
            <p style="margin-top: 8px; font-size: 14px; color: var(--text-primary); line-height: 1.5;">${data.explanation}</p>
            <div class="indicators-wrapper">
              ${indicatorsHtml || `<span style="font-size: 12px; color: var(--text-muted);">${currentLang === 'hi' ? 'कोई खतरनाक संकेतक नहीं मिला' : 'No overt URL anomalies detected'}</span>`}
            </div>
          </div>
          <div>
            <div class="score-meter-wrap">
              <div style="text-align: right;">
                <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted);">${currentLang === 'hi' ? 'यूआरएल जोखिम' : 'URL Risk'}</div>
                <div class="score-display-num ${scoreColorClass}">${score}<span style="font-size: 14px; font-weight: 600; color: var(--text-muted);">/100</span></div>
              </div>
              <div class="score-bar-bg">
                <div class="score-bar-fill ${fillClass}" style="width: ${score}%;"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Domain Structure Breakdown (VirusTotal style) -->
        <div style="background-color: var(--surface-alt); border-radius: var(--radius-sm); padding: 14px; border: 1px solid var(--border-subtle); margin-top: 14px;">
          <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--brand-navy); margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
            <i data-lucide="code" style="width: 14px; height: 14px; color: var(--brand-teal);"></i>
            <span>${currentLang === 'hi' ? 'संरचनात्मक विश्लेषण (बिना वेबसाइट खोले सुरक्षित रूप से जाँचा गया)' : 'Structural Domain Audit (Safely analyzed without visiting)'}</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; font-size: 12.5px;">
            <div>
              <div style="color: var(--text-muted); font-size: 10.5px; font-weight: 700;">HOSTNAME</div>
              <div style="font-weight: 700; color: var(--brand-navy); word-break: break-all; margin-top: 2px;">${parsed.hostname || 'N/A'}</div>
            </div>
            <div>
              <div style="color: var(--text-muted); font-size: 10.5px; font-weight: 700;">PROTOCOL</div>
              <div style="font-weight: 700; color: ${parsed.scheme === 'https' ? 'var(--status-safe)' : '#B93838'}; margin-top: 2px;">
                ${(parsed.scheme || 'http').toUpperCase()} ${parsed.scheme === 'http' ? '(Unencrypted)' : ''}
              </div>
            </div>
            <div>
              <div style="color: var(--text-muted); font-size: 10.5px; font-weight: 700;">TOP-LEVEL DOMAIN</div>
              <div style="font-weight: 700; color: var(--brand-navy); margin-top: 2px;">.${parsed.tld || 'com'}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Action Plan -->
      <div class="nba-plan-card">
        <div class="nba-card-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="nba-badge-usp">Next Best Action Engine</span>
            <h4 style="margin: 0; font-size: 1.15rem; color: var(--brand-navy);">${plan.headline || 'URL Action Guidance'}</h4>
          </div>
        </div>

        <div class="nba-grid-2x2">
          <div class="nba-quadrant quadrant-avoid">
            <div class="quadrant-header">
              <i data-lucide="ban" style="width: 15px; height: 15px; color: #B93838;"></i>
              <h5 style="color: #902626;">${currentLang === 'hi' ? 'क्या बिल्कुल न करें' : 'What You Must AVOID Doing'}</h5>
            </div>
            <ul class="nba-list">
              ${(plan.what_to_avoid || []).map(i => `<li><i data-lucide="x-circle" style="width: 14px; height: 14px; color: #B93838;"></i><span>${i}</span></li>`).join('')}
            </ul>
          </div>
          <div class="nba-quadrant quadrant-immediate">
            <div class="quadrant-header">
              <i data-lucide="shield-check" style="width: 15px; height: 15px; color: var(--brand-teal);"></i>
              <h5 style="color: var(--brand-teal);">${currentLang === 'hi' ? 'तुरंत क्या सुरक्षित कदम उठाएं' : 'Immediate Recommended Actions'}</h5>
            </div>
            <ul class="nba-list">
              ${(plan.immediate_actions || []).map(i => `<li><i data-lucide="check-circle" style="width: 14px; height: 14px; color: var(--brand-teal);"></i><span>${i}</span></li>`).join('')}
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
