import sys
from pathlib import Path

# Add backend directory to sys.path for Vercel Serverless Function execution
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.main import app
