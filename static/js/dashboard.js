/**
 * Safety Dashboard JavaScript.
 * Clean, human-designed fintech & cybersecurity interface.
 * Fetches real aggregate metrics from SQLite database,
 * initializes Chart.js visualizations (risk breakdown & category bars),
 * and renders recent analysis history with privacy-masked text.
 */

document.addEventListener('DOMContentLoaded', () => {
  const totalCountEl = document.getElementById('statTotalAnalyses');
  const highCountEl = document.getElementById('statHighRisk');
  const medCountEl = document.getElementById('statMediumRisk');
  const lowCountEl = document.getElementById('statLowRisk');
  const historyTableBody = document.getElementById('recentHistoryTableBody');

  const currentLang = SatarkApp.getLang();

  loadDashboardData();

  async function loadDashboardData() {
    try {
      const response = await fetch('/api/dashboard');
      const resData = await response.json();
      if (resData.success && resData.data) {
        const stats = resData.data;
        renderSummaryCounters(stats);
        renderCharts(stats);
        renderRecentHistory(stats.recent_history || []);
      }
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    }
  }

  function renderSummaryCounters(stats) {
    if (totalCountEl) totalCountEl.innerText = stats.total || 0;
    if (highCountEl) highCountEl.innerText = stats.high_risk || 0;
    if (medCountEl) medCountEl.innerText = stats.medium_risk || 0;
    if (lowCountEl) lowCountEl.innerText = stats.low_risk || 0;
  }

  function renderCharts(stats) {
    // 1. Risk Breakdown Doughnut Chart (Minimal & Clean)
    const riskCtx = document.getElementById('riskBreakdownChart');
    if (riskCtx && window.Chart) {
      new Chart(riskCtx, {
        type: 'doughnut',
        data: {
          labels: [
            currentLang === 'hi' ? 'उच्च जोखिम (High)' : 'High Risk',
            currentLang === 'hi' ? 'मध्यम जोखिम (Medium)' : 'Medium Risk',
            currentLang === 'hi' ? 'कम जोखिम (Low)' : 'Low Risk'
          ],
          datasets: [{
            data: [stats.high_risk || 0, stats.medium_risk || 0, stats.low_risk || 0],
            backgroundColor: ['#D96B6B', '#E5AD50', '#2E8B78'],
            borderColor: '#FFFFFF',
            borderWidth: 2,
            hoverOffset: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#25313B',
                font: { family: 'Manrope', size: 12, weight: '600' },
                padding: 14
              }
            }
          },
          cutout: '70%'
        }
      });
    }

    // 2. Prevalent Scam Categories Bar Chart
    const catCtx = document.getElementById('topCategoriesChart');
    if (catCtx && window.Chart) {
      const categories = stats.top_categories || [];
      const labels = categories.map(c => c.category);
      const counts = categories.map(c => c.count);

      new Chart(catCtx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: currentLang === 'hi' ? 'मामले' : 'Detections',
            data: counts,
            backgroundColor: '#2E8B78',
            borderRadius: 4,
            barThickness: 16
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          scales: {
            x: {
              grid: { color: '#EAECEB' },
              ticks: { color: '#5A6B78', stepSize: 1, font: { family: 'Manrope', size: 11 } }
            },
            y: {
              grid: { display: false },
              ticks: { color: '#25313B', font: { family: 'Manrope', size: 11, weight: '600' } }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  function renderRecentHistory(history) {
    if (!historyTableBody) return;

    if (!history || history.length === 0) {
      historyTableBody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">
            ${currentLang === 'hi' ? 'कोई हालिया इतिहास उपलब्ध नहीं है।' : 'No scan history recorded yet.'}
          </td>
        </tr>
      `;
      return;
    }

    historyTableBody.innerHTML = history.map(item => {
      let badgeClass = 'badge-low';
      if (item.risk_level === 'HIGH') badgeClass = 'badge-high';
      else if (item.risk_level === 'MEDIUM') badgeClass = 'badge-medium';

      return `
        <tr>
          <td style="font-family: monospace; font-size: 11.5px; color: var(--text-muted);">#${item.id}</td>
          <td><span class="badge badge-neutral" style="text-transform: uppercase; font-size: 10.5px;">${item.analysis_type}</span></td>
          <td style="max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-primary); font-size: 12.5px;" title="${item.snippet_masked}">
            ${item.snippet_masked}
          </td>
          <td><span class="badge ${badgeClass}">${item.risk_level} (${item.risk_score})</span></td>
          <td style="font-size: 11.5px; color: var(--text-muted);">${item.created_at || 'Just now'}</td>
        </tr>
      `;
    }).join('');
  }
});
