import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Automatically load .env file if present
env_file = BASE_DIR / '.env'
if env_file.exists():
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except Exception:
        pass

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'satark-setu-production-key-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'satark_setu.db')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    JSON_AS_ASCII = False
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '').strip()
