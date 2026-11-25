/**
 * Core Application JavaScript for Satark Setu.
 * Handles Lucide icon activation, language switching state,
 * global toast notifications, and mobile navigation toggling.
 */

const SatarkApp = (function() {
  // Determine current active language from URL query or localStorage
  const urlParams = new URLSearchParams(window.location.search);
  const currentLang = urlParams.get('lang') || localStorage.getItem('satark_lang') || 'en';

  function init() {
    // Save language
    localStorage.setItem('satark_lang', currentLang);

    // Initialize Lucide icons
    if (window.lucide) {
      window.lucide.createIcons();
    }

    // Bind mobile menu toggle
    const toggleBtn = document.getElementById('mobileNavToggle');
    const navLinks = document.getElementById('navLinks');
    if (toggleBtn && navLinks) {
      toggleBtn.addEventListener('click', () => {
        navLinks.classList.toggle('mobile-open');
      });
    }

    // Bind language switches
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetLang = btn.getAttribute('data-lang');
        if (targetLang && targetLang !== currentLang) {
          localStorage.setItem('satark_lang', targetLang);
          const newUrl = new URL(window.location.href);
          newUrl.searchParams.set('lang', targetLang);
          window.location.href = newUrl.toString();
        }
      });
    });
  }

  function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconName = 'info';
    if (type === 'success') iconName = 'check-circle';
    if (type === 'error' || type === 'danger') iconName = 'alert-triangle';
    if (type === 'warning') iconName = 'alert-circle';

    toast.innerHTML = `
      <i data-lucide="${iconName}" style="width: 17px; height: 17px; color: ${type === 'success' ? '#2E8B78' : (type === 'error' || type === 'danger') ? '#B93838' : '#C28929'}; flex-shrink: 0; margin-top: 1px;"></i>
      <div style="flex: 1;">${message}</div>
    `;

    container.appendChild(toast);
    if (window.lucide) window.lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showToast(successMsg, 'success');
      }).catch(() => {
        showToast('Failed to copy. Please select and copy manually.', 'warning');
      });
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast(successMsg, 'success');
    }
  }

  return {
    init,
    getLang: () => currentLang,
    showToast,
    copyToClipboard
  };
})();

document.addEventListener('DOMContentLoaded', SatarkApp.init);

