DebugIsh language upgrade

Added:
- Top-left language selector with mini flags
- English, Turkish, Russian, and Simplified Chinese UI localization
- LocalStorage language memory
- Localized scan status, verification flow, result cards, issue cards, and downloadable TXT report labels
- gunicorn added to requirements.txt for Render

Important:
- Keep logo.png and favicon.png inside the static/ folder:
  static/logo.png
  static/favicon.png

Render:
Build Command:
pip install -r requirements.txt

Start Command:
gunicorn app:app
