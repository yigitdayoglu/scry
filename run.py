"""Çalıştırma noktası: python run.py"""

import os

from web.app import create_app

# use_reloader=False: reloader süreci iki kez başlatıp scheduler'ı çiftler.
app = create_app(start_scheduler=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
