"""
Satark Setu Convenience Launcher.
Usage: python run.py
"""

from app import create_app
from config import Config

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("   SATARK SETU - Think Before You Trust")
    print("   Intelligent Digital Payment Fraud Prevention Platform")

    print("=" * 60)
    print(f"Server is active at: http://{Config.HOST}:{Config.PORT}")
    print("Press CTRL+C to stop.")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)

