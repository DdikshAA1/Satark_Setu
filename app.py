"""
Main Application Factory for Satark Setu.
Configures Flask, initializes SQLite, registers blueprints,
and defines security and error handling policies.
"""

import os
from flask import Flask, render_template, request
from config import Config
import database

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure database directory exists (failsafe for serverless read-only filesystems)
    try:
        db_dir = os.path.dirname(Config.DATABASE_PATH)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    except Exception:
        pass

    # Initialize SQLite database schema and baseline telemetry
    with app.app_context():
        try:
            database.init_db()
        except Exception:
            pass

    # Register blueprints
    from routes.api import api_bp
    from routes.views import views_bp
    from services.localization import TRANSLATIONS, get_text
    app.register_blueprint(api_bp)
    app.register_blueprint(views_bp)

    # Global context processor for all templates including error handlers
    @app.context_processor
    def inject_global_localization():
        try:
            lang = request.args.get('lang', 'en')
        except Exception:
            lang = 'en'
        if lang != 'hi':
            lang = 'en'
        return {
            'current_lang': lang,
            't': TRANSLATIONS.get(lang, TRANSLATIONS['en']),
            'get_text': lambda key: get_text(key, lang)
        }

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500

    return app

app = create_app()

if __name__ == '__main__':
    print(f"🚀 Satark Setu is launching on http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
