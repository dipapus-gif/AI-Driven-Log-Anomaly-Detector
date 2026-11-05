"""Vercel entrypoint: exposes the FastAPI app from src/api.py as `app`.

(src/app.py is the command line tool, so Vercel's default entrypoint lookup
would pick the wrong file.)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from api import app  # noqa: E402,F401
