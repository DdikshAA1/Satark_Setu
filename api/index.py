"""
Vercel Serverless Function Entrypoint for Satark Setu.
Exposes the WSGI Flask application instance 'app' for Vercel Python Runtime.
Includes WSGI middleware to map Vercel path rewrites seamlessly to Flask routes.
"""

import sys
import os

# Ensure the root project directory is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app as flask_app

class VercelPathFixer:
    """
    WSGI Middleware to restore original request path from Vercel's x-matched-path header.
    Ensures Flask receives '/', '/detector', '/api/detect' etc., rather than '/api/index'.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched = environ.get('HTTP_X_MATCHED_PATH') or environ.get('x-matched-path')
        if matched:
            path = matched.split('?')[0]
            if path.startswith('/api/index'):
                path = path[len('/api/index'):] or '/'
            environ['PATH_INFO'] = path
        return self.wsgi_app(environ, start_response)

app = VercelPathFixer(flask_app)

if __name__ == '__main__':
    flask_app.run()
