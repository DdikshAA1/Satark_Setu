/**
 * Emergency Fraud Response Assistant JavaScript.
 * Clean, human-designed fintech & cybersecurity interface.
 * Interactive incident triage workflow, checklist tracking,
 * and 24x7 bank helpline search directory.
 */

document.addEventListener('DOMContentLoaded', () => {
  const triageContainer = document.getElementById('emergencyTriageOutput');
  const incidentCards = document.querySelectorAll('.incident-btn-card');
  const bankSearchInput = document.getElementById('bankSearchInput');
  const bankDirectoryBody = document.getElementById('bankDirectoryBody');

  const currentLang = SatarkApp.getLang();

  let activeIncident = 'money_lost';

  incidentCards.forEach(card => {
    card.addEventListener('click', () => {
      incidentCards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      activeIncident = card.getAttribute('data-incident');
      loadTriage(activeIncident);
    });
  });

  // Search filter for bank directory
  if (bankSearchInput && bankDirectoryBody) {
    bankSearchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();
      const rows = bankDirectoryBody.querySelectorAll('tr');
      rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
      });
    });
  }

  async function loadTriage(incidentKey) {
    if (!triageContainer) return;

    triageContainer.innerHTML = `
      <div style="text-align: center; padding: 36px; color: var(--text-muted);">
        <i data-lucide="loader" style="width: 24px; height: 24px; animation: spin 0.8s linear infinite;"></i>
        <p style="margin-top: 8px; font-size: 13px;">${currentLang === 'hi' ? 'आपातकालीन सहायता लोड हो रही है...' : 'Loading emergency response steps...'}</p>
      </div>
    `;
    if (window.lucide) window.lucide.createIcons();

    try {
      const response = await fetch(`/api/emergency?incident=${incidentKey}&lang=${currentLang}`);
      const resData = await response.json();
      if (resData.success && resData.data) {
        renderTriage(resData.data);
      }
    } catch (err) {
      console.error(err);
      triageContainer.innerHTML = `<p style="color: #B93838;">Failed to load guidance.</p>`;
    }
  }

  function renderTriage(data) {
    if (!triageContainer) return;

    const stepsHtml = (data.step_by_step || []).map(step => `
      <div class="timeline-step-item">
        <div class="step-index-circle">${step.step_number}</div>
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <h5 style="font-size: 14px; margin-bottom: 4px; color: var(--brand-navy);">${step.title}</h5>
            <label style="display: inline-flex; align-items: center; gap: 5px; font-size: 11.5px; color: var(--text-muted); cursor: pointer;">
              <input type="checkbox" class="step-check" style="cursor: pointer; accent-color: var(--brand-teal);">
              <span>${currentLang === 'hi' ? 'पूर्ण' : 'Mark Done'}</span>
            </label>
          </div>
          <p style="font-size: 13px; line-height: 1.5; color: var(--text-secondary); margin: 0;">${step.detail}</p>
        </div>
      </div>
    `).join('');

    const evidenceHtml = (data.evidence_checklist || []).map(item => `
      <li style="display: flex; align-items: flex-start; gap: 7px; font-size: 13px; color: var(--text-primary); margin-bottom: 6px;">
        <i data-lucide="camera" style="width: 14px; height: 14px; color: var(--brand-navy); flex-shrink: 0; margin-top: 3px;"></i>
        <span>${item}</span>
      </li>
    `).join('');

    triageContainer.innerHTML = `
      <!-- Golden Hour Notice -->
      <div style="background-color: var(--status-danger-bg); border: 1px solid var(--status-danger-border); border-radius: var(--radius-sm); padding: 16px 18px; margin-bottom: 20px; display: flex; align-items: center; gap: 14px;">
        <i data-lucide="clock" style="width: 24px; height: 24px; color: #B93838; flex-shrink: 0;"></i>
        <div>
          <h5 style="color: #902626; margin-bottom: 2px; font-size: 13.5px; font-weight: 700;">${currentLang === 'hi' ? 'गोल्डन ऑवर (पहला 2 घंटा) सूचना' : 'Golden Hour Notice (First 2 Hours)'}</h5>
          <p style="font-size: 13px; color: #7A2828; margin: 0; line-height: 1.45;">${data.golden_hour_notice}</p>
        </div>
      </div>

      <!-- Emergency Helpline Callout Banner (Deep Navy + Direct 1930) -->
      <div style="background-color: var(--brand-navy); color: #FFFFFF; border-radius: var(--radius-sm); padding: 18px 22px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 24px;">
        <div>
          <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.85;">${currentLang === 'hi' ? 'राष्ट्रीय साइबर वित्तीय अपराध हेल्पलाइन' : 'National Cyber Crime Helpline'}</div>
          <div style="font-size: 1.85rem; font-weight: 800; margin-top: 2px;">
            <a href="tel:1930" style="color: #FFFFFF; text-decoration: none;">📞 1930</a>
          </div>
          <div style="font-size: 11.5px; opacity: 0.8;">${currentLang === 'hi' ? '24 घंटे चालू • भारत सरकार • गृह मंत्रालय' : '24x7 Toll Free • Ministry of Home Affairs, Govt. of India'}</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <a href="tel:1930" class="btn btn-danger btn-lg">
            <i data-lucide="phone-call" style="width: 15px; height: 15px;"></i>
            <span>${currentLang === 'hi' ? '1930 डायल करें' : 'Call 1930 Now'}</span>
          </a>
          <a href="https://cybercrime.gov.in" target="_blank" rel="noopener" class="btn btn-secondary btn-lg" style="background-color: transparent; color: #FFFFFF; border-color: rgba(255,255,255,0.4);">
            <i data-lucide="external-link" style="width: 15px; height: 15px;"></i>
            <span>cybercrime.gov.in</span>
          </a>
        </div>
      </div>

      <!-- Step by Step Timeline -->
      <div class="surface-card">
        <h4 style="margin-bottom: 16px; display: flex; align-items: center; gap: 8px; font-size: 1.15rem; color: var(--brand-navy);">
          <i data-lucide="list-checks" style="width: 18px; height: 18px; color: var(--brand-teal);"></i>
          <span>${currentLang === 'hi' ? 'कदम-दर-कदम रोकथाम एवं राहत चेकलिस्ट' : 'Step-by-Step Incident Containment Checklist'}</span>
        </h4>
        <div class="timeline-steps">
          ${stepsHtml}
        </div>
      </div>

      <!-- Evidence Preservation -->
      <div class="surface-card" style="margin-top: 20px;">
        <h4 style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px; font-size: 1.1rem; color: var(--brand-navy);">
          <i data-lucide="archive" style="width: 18px; height: 18px; color: var(--brand-navy);"></i>
          <span>${currentLang === 'hi' ? 'शिकायत के लिए कौन से सबूत संभाल कर रखें?' : 'Evidence to Preserve for FIR and Bank Dispute'}</span>
        </h4>
        <ul style="list-style: none; padding: 0; margin: 0;">
          ${evidenceHtml}
        </ul>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();

    // Bind checklist strike-through
    document.querySelectorAll('.step-check').forEach(chk => {
      chk.addEventListener('change', (e) => {
        const item = e.target.closest('.timeline-step-item');
        if (item) {
          if (e.target.checked) {
            item.style.opacity = '0.55';
            item.style.backgroundColor = 'var(--surface-alt)';
          } else {
            item.style.opacity = '1';
            item.style.backgroundColor = '#FFFFFF';
          }
        }
      });
    });
  }

  // Load default
  loadTriage(activeIncident);
});
