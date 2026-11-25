"""
Frontend View Routes for Satark Setu.
Serves full-page server-rendered views equipped with client-side reactive components.
"""

from flask import Blueprint, render_template, request
from services.localization import TRANSLATIONS, get_text

views_bp = Blueprint('views', __name__)

@views_bp.context_processor
def inject_localization():
    """Inject language dictionary into all rendered Jinja templates."""
    lang = request.args.get('lang', 'en')
    if lang != 'hi':
        lang = 'en'
    return {
        'current_lang': lang,
        't': TRANSLATIONS.get(lang, TRANSLATIONS['en']),
        'get_text': lambda key: get_text(key, lang)
    }

@views_bp.route('/')
def home():
    return render_template('index.html', active_page='home')

@views_bp.route('/detector')
def detector_view():
    return render_template('detector.html', active_page='detector')

@views_bp.route('/upi-guard')
def upi_guard_view():
    return render_template('upi_guard.html', active_page='upi_guard')

@views_bp.route('/url-scanner')
def url_scanner_view():
    return render_template('url_scanner.html', active_page='url_scanner')

@views_bp.route('/emergency')
def emergency_view():
    return render_template('emergency.html', active_page='emergency')

@views_bp.route('/dashboard')
def dashboard_view():
    return render_template('dashboard.html', active_page='dashboard')

@views_bp.route('/about')
def about_view():
    return render_template('about.html', active_page='about')

